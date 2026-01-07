import grp
import pwd
import time
from os import chown, walk
from pathlib import Path

from verve_management.appliance import (
    agent_functions,
    integration_namespace_functions,
    licensing_functions,
    sftpgo_functions,
    support_pack_functions,
    verve_docker_networks,
    vsm_functions,
)
from verve_management.shared import docker_functions, docker_stacks, logger

STACKS_DIR = docker_stacks.STACKS_DIR
data_root = docker_functions.get_docker_data_root()
DEPLOYED_APP_DIR = data_root / 'volumes' / 'vsm-shared-configs' / '_data' / 'deployed_applications'
APPLICATIONS = docker_stacks.get_applications_list()


def get_application_menu_list():
    deployed_stacks = docker_stacks.get_docker_stack_list()
    app_stacks = docker_stacks.app_stack_lists(APPLICATIONS)
    deployed_app_list = docker_stacks.get_deployed_app_list(deployed_stacks, app_stacks)
    bundles = (licensing_functions.get_verve_license()).entitlements.bundles
    app_menu_list = []

    for app in APPLICATIONS:
        title = app['title']
        license_list = app['license']
        is_licensed = False

        if app['name'] in deployed_app_list:
            deployed = True
        else:
            deployed = False

        for license_bundle in license_list:
            if license_bundle in bundles:
                is_licensed = True

        # add to list if licensed or deployed
        if is_licensed or deployed:
            menu_item = {'title': title, 'deployed': deployed, 'app': app}
            app_menu_list.append(menu_item)

    return app_menu_list


def auto_deploy_applications(deploy_application_list):
    deployed_stacks = docker_stacks.get_docker_stack_list()
    app_stacks = docker_stacks.app_stack_lists(APPLICATIONS)
    deployed_app_list = docker_stacks.get_deployed_app_list(deployed_stacks, app_stacks)
    bundles = (licensing_functions.get_verve_license()).entitlements.bundles

    for application in APPLICATIONS:
        title = application['title']
        license_list = application['license']
        is_licensed = False

        if application['name'] in deployed_app_list:
            # already deployed
            continue

        if application['name'] not in deploy_application_list:
            # not in the provided list, so skip
            continue

        for license_bundle in license_list:
            if license_bundle in bundles:
                is_licensed = True

        if not is_licensed:
            logger.log_warning(f"Application [{title}] is not licensed for this server - skipping deployment")
            continue

        deploy_application(application)


def deploy_application(application, stacks_dir=STACKS_DIR):
    # make sure networks exist before deploying applications
    verve_docker_networks.setup_networks_if_missing()

    logger.log_information(f"Deploying application {application['title']}")
    app_stacks = application.get('stacks', [])
    app_configs = application.get('configs', [])
    app_secrets = application.get('secrets', [])

    for secret in app_secrets:
        docker_functions.create_docker_secret_if_missing(secret)

    for config in app_configs:
        docker_functions.create_docker_config_if_missing(config)

    for stack in app_stacks:
        try:
            stack_path = stacks_dir / stack['file']
            name = stack['name']

            application_prereqs(name)

            docker_stacks.docker_stack_deploy(name, stack_path)

            application_overrides(name)

            if "wait_for" in stack:
                # wait_for = stack['wait_for']
                # Temporary simple delay until a better solution is implemented.
                # PowerShell version waited for container to start and stop, but there are discussions about
                # using temp files to determine when a container is done starting up to trigger additional processing.
                time.sleep(60)

        except Exception as e:
            logger.log_error(f"Failed to deploy {name}: {e}")

    if vsm_functions.vsm_is_vam():
        # update namespace file for deployed vam applications including distributed adi
        integration_namespace_functions.add_integration_if_missing(application['name'])

        add_deployed_app_file(application['name'])


def application_prereqs(stack):
    if stack == 'AssetManager':
        agent_functions.enable_agent_settings()
        # volumes need to exist before the DatabaseImporter stack is deployed
        docker_functions.create_docker_volume_if_missing('IntVAMVendorInformationLookup_data')
        docker_functions.create_docker_volume_if_missing('IntVAMVulnerability_cvedata')
        support_pack_functions.stage_support_pack_docs()


def application_overrides(stack):
    if stack == 'AssetManager':
        for volume_name in ['AssetManager_adi', 'AssetManager_attachments', 'AssetManager_logs', 'host-imports', 'vsm-migrations']:
            update_volume_permissions(volume_name, "1654:1654")

    if stack == 'IntVAMAssetDiscovery':
        add_deployed_app_file('AssetDiscovery')
        integration_namespace_functions.add_integration_if_missing('AssetDiscovery')

    if stack == 'IntVAMConfigExport':
        update_volume_permissions('IntVAMConfigExport_exportsftpinput', "1000:1000")

    if stack == 'IntVAMDatabaseImporter':
        add_deployed_app_file('DatabaseImporter')
        integration_namespace_functions.add_integration_if_missing('DatabaseImporter')

    if stack == 'IntVAMDataImport':
        for volume_name in ['IntVAMDataImport_importotdevicecsv', 'IntVAMDataImport_importsftpadiex', 'IntVAMDataImport_importsftpinput']:
            update_volume_permissions(volume_name, "1000:1000")

    if stack == 'IntVAMExport':
        add_deployed_app_file('ReportingTransfer')
        integration_namespace_functions.add_integration_if_missing('ReportingTransfer')

    if stack == 'IntVAMIPScanner':
        add_deployed_app_file('IPScanner')
        integration_namespace_functions.add_integration_if_missing('IPScanner')

    if stack == 'IntVAMLogManagement':
        add_deployed_app_file('LogManagement')
        integration_namespace_functions.add_integration_if_missing('LogManagement')

    if stack == 'IntVAMMACVendorLookup':
        add_deployed_app_file('MacAddress')
        integration_namespace_functions.add_integration_if_missing('MacAddress')

    if stack == 'IntVAMVendorInformationLookup':
        add_deployed_app_file('VendorInformationLookup')
        integration_namespace_functions.add_integration_if_missing('VendorInformationLookup')

    if stack == 'IntVAMVulnerability':
        add_deployed_app_file('Vulnerability')
        integration_namespace_functions.add_integration_if_missing('Vulnerability')

    if stack == "Reporting":
        sftpgo_functions.update_service_sftpgo()


def update_volume_permissions(volume_name, accounts):
    data_root = docker_functions.get_docker_data_root()
    volume_path = data_root / 'volumes' / volume_name / '_data'

    start = time.time()
    while volume_path.exists() is False:
        # delay to give the volume time to be created the first time
        time.sleep(1)
        end = time.time()
        delta = end - start
        if delta > 30:
            break

    chown_volume(volume_path, accounts)
    chmod_volume(volume_path)


def chown_volume(volume_path=None, accounts='root:root'):
    if volume_path is None:
        logger.log_warning("No volume supplied to update permissions")
        return

    if volume_path.exists():
        names = accounts.split(":")
        if not names[0].isnumeric() or not names[1].isnumeric():
            uid = names[0]
            gid = names[1]
            # get ids for account names for comparison checks
            if not uid.isnumeric():
                uid = pwd.getpwnam(uid).pw_uid

            if not gid.isnumeric():
                gid = grp.getgrnam(gid).gr_gid

            logger.log_verbose(f"Reassigning [{accounts}] to be [{uid}:{gid}] for comparison checks")
            accounts = f"{uid}:{gid}"

        stat_info = volume_path.stat()
        current_owner = f"{stat_info.st_uid}:{stat_info.st_gid}"
        if current_owner != accounts:
            names = accounts.split(":")
            uid = int(names[0])
            gid = int(names[1])
            logger.log_verbose(f"{volume_path.as_posix()} - Attempting to update owner from [{current_owner}] to [{accounts}]")
            # B007 Loop control variable 'directories' not used within the loop body. If this is intended, start the name with an underscore.
            for root, _directories, files in walk(volume_path):
                chown(root, uid, gid)
                for file in files:
                    chown(Path(root) / file, uid, gid)
            stat_info = volume_path.stat()
            current_owner = f"{stat_info.st_uid}:{stat_info.st_gid}"
            if current_owner == accounts:
                logger.log_verbose(f"{volume_path.as_posix()} - Owner updated to [{accounts}]")
            else:
                logger.log_error(f"{volume_path.as_posix()} - Failed to update owner from [{current_owner}] to [{accounts}]")
        else:
            logger.log_verbose(f"{volume_path.as_posix()} - Owner already updated to [{accounts}]")
    else:
        logger.log_error(f"{volume_path.as_posix()} - Volume not found")


def chmod_volume(volume_path=None, volume_name=None, verbose_mode=False):
    if volume_path is None and volume_name is None:
        logger.log_warning("No volume supplied to update permissions")
        return

    if volume_path is None:
        data_root = docker_functions.get_docker_data_root()
        volume_path = data_root / 'volumes' / volume_name / '_data'

    mode_dir = 0o755
    mode_file = 0o644

    if volume_path.exists():
        # B007 Loop control variable 'directories' not used within the loop body. If this is intended, start the name with an underscore.
        for root, _directories, files in walk(volume_path):
            Path(root).chmod(mode_dir)
            for file in files:
                (Path(root) / file).chmod(mode_file)
        logger.print_if_verbose(f"Updated folder and file permissions for volume {volume_path}", verbose_mode)
    else:
        logger.log_error(f"{volume_path.as_posix()} - Volume not found")


def remove_application(application):
    # remove application
    app_stacks = application['stacks']
    app_name = application['name']
    for stack in app_stacks:
        stack_name = stack['name']
        if docker_stacks.is_stack_deployed(stack_name):
            # upgrades from older versions may have overlap for some stacks
            # there are no longer any requirements to have a stack still deployed when another application gets removed
            # example of shared stack is IntVAMLogsVSCMonitoring in both ADI and VAM with logging
            docker_stacks.docker_stack_remove(stack_name)
        remove_application_overrides(stack_name)

    remove_deployed_app_file(app_name)


def remove_application_overrides(stack):
    if stack == 'IntVAMAssetDiscovery':
        remove_deployed_app_file('AssetDiscovery')

    if stack == 'IntVAMDatabaseImporter':
        remove_deployed_app_file('DatabaseImporter')

    if stack == 'IntVAMExport':
        remove_deployed_app_file('ReportingTransfer')

    if stack == 'IntVAMIPScanner':
        remove_deployed_app_file('IPScanner')

    if stack == 'IntVAMLogManagement':
        remove_deployed_app_file('LogManagement')

    if stack == 'IntVAMMACVendorLookup':
        remove_deployed_app_file('MacAddress')

    if stack == 'IntVAMVendorInformationLookup':
        remove_deployed_app_file('VendorInformationLookup')

    if stack == 'IntVAMVulnerability':
        remove_deployed_app_file('Vulnerability')


def add_deployed_app_file(app_name):
    # add deployed applications file
    if DEPLOYED_APP_DIR.exists() is False:
        # make sure directory exists
        DEPLOYED_APP_DIR.mkdir()

    deployed_app_file = DEPLOYED_APP_DIR / app_name
    if deployed_app_file.exists() is False:
        with open(deployed_app_file, mode='a'):
            pass


def remove_deployed_app_file(app_name):
    # remove deployed applications file
    deployed_app_file = DEPLOYED_APP_DIR / app_name
    if deployed_app_file.exists():
        deployed_app_file.unlink()


def cycle_deployed_applications():
    deployed_stacks = docker_stacks.get_docker_stack_list()
    app_stacks = docker_stacks.app_stack_lists(APPLICATIONS)
    deployed_app_list = docker_stacks.get_deployed_app_list(deployed_stacks, app_stacks)

    remove_deployed_applications(deployed_app_list)
    redeploy_applications(deployed_app_list)


def remove_deployed_applications(deployed_app_list, applications=APPLICATIONS):
    print("\nRemoving running applications...\n")
    # removing applications may require using the old application list during an upgrade
    for application in applications:
        if application['name'] in deployed_app_list:
            remove_application((application))
    verve_docker_networks.remove_docker_networks()


def redeploy_applications(deployed_app_list):
    print("\nRe-deploying custom networks and applications...\n")
    for application in APPLICATIONS:
        if application['name'] in deployed_app_list:
            deploy_application(application)


def get_display_title(name):
    # return application title if it exists in the list otherwise use the name
    application_list = get_application_menu_list()
    application = next((x for x in application_list if x['app']['name'] == name), None)
    if application is None:
        return name
    else:
        return application['title']
