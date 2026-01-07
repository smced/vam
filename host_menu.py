import sys
import traceback
from pathlib import Path

from . import legacy_bash, packet_capture, vsm_certificates
from .appliance import (
    agent_functions,
    application_functions,
    docker_backups,
    health_check_functions,
    import_cve_database,
    integration_namespace_functions,
    licensing_functions,
    local_host_functions,
    sftpgo_functions,
    support_functions,
    support_pack_functions,
    upgrade_software,
    verve_docker_networks,
    verve_settings,
    vsm_functions,
)
from .appliance.sftpgo_functions import SFTPGO_CONFIG
from .appliance.support_pack_functions import (
    SUPPORT_PACK_EXTENDED_REQUEST,
    SUPPORT_PACK_INGEST_REQUEST,
    SUPPORT_PACK_MINIMAL_REQUEST,
    SUPPORT_PACK_STANDARD_REQUEST,
)
from .appliance.vsm_functions import CONFIG_APPLIANCETYPE, SECRET_AGENT_LEADER_KEY_PASS, SECRET_ROOT_CA_KEY_PASS, SECRET_VSM_LOCAL_KEY_PASS
from .shared import colors, docker_functions, docker_stacks, logger, openssl, utilities
from .shared.menu import Menu, MenuItem

ORIGINAL_BUILD = verve_settings.get_verve_settings_value('build')
certificate_secret_list = [SECRET_AGENT_LEADER_KEY_PASS, SECRET_ROOT_CA_KEY_PASS, SECRET_VSM_LOCAL_KEY_PASS]

MISSING_LOCAL_SERVER_CERT_MESSAGE = (
    "You have not setup the local server certificates. "
    "You must go back and setup the local server certificates "
    "via the 'Install SSL Certificate' menu option before continuing."
)

MISSING_OR_INVALID_LICENSE_MESSAGE = (
    "You have not imported a valid Verve license. "
    "You must go back and import a valid license via the 'Manage Licensing' menu option before continuing."
)


def main() -> int:
    # wrapper around main so that we can catch exceptions and log them
    try:
        return main_logic()
    except Exception as e:
        logger.log_verbose(traceback.format_exc())
        logger.log_error(f"An error occurred: {e}")
        return 1


def main_logic() -> int:
    # print a blank line for readability
    print("")

    # print menu diagnostics
    verve_settings.print_verve_settings()
    local_host_functions.print_system_resources()

    if docker_functions.is_docker_swarm_active():
        # make sure this is always set for now to allow legacy processes to still function
        docker_functions.create_docker_config_if_missing(CONFIG_APPLIANCETYPE, value='local')
    else:
        advanced_docker_menu()

    while True:
        verve_settings.force_update_verve_settings_file()
        current_build = verve_settings.get_verve_settings_value('build')
        logger.log_verbose(f"Original Build = {ORIGINAL_BUILD}")
        logger.log_verbose(f"Current Build = {current_build}")

        if ORIGINAL_BUILD != current_build:
            logger.log_information("Closing open menu to apply new changes")

            # menu should show up 2 (rhel/ol) or 3 (ubuntu) times in the ps -ef output for each user running it depending on the OS
            if local_host_functions.get_running_process_count('/usr/lib/verve/verve_main.py') > 3:
                logger.log_warning(
                    "Other open instances of the Menu were detected in different sessions. They need to be closed before they will use the new functionality."
                )

            exit()

        # new dynamic menu instance each iteration
        main_menu = Menu('Main Menu:', exit)

        # unified menu structure
        main_menu.add_option(MenuItem(main_menu.get_next_increment(), True, 'Setup and Configure Application', configuration_menu))
        main_menu.add_option(MenuItem(main_menu.get_next_increment(), True, 'Diagnostics and Troubleshooting', diagnostics_menu))
        main_menu.add_option(MenuItem(main_menu.get_next_increment(), True, 'Upgrade Software', upgrade_menu))

        main_menu.add_option(MenuItem(main_menu.get_next_increment(), True, 'Reboot', local_host_functions.reboot))

        # hidden options
        main_menu.add_option(MenuItem('support', False, 'Support Menu', support_menu))

        main_menu.show_menu()


def configuration_menu():
    while True:
        # new menu instance each iteration
        configuration_menu = Menu('Setup and Configuration Menu:', main)

        # add options
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Install SSL Certificate', certificate_menu))
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Deploy/Remove Applications', application_menu))
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage Licensing', licensing_menu))
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage Encrypted Drive', legacy_bash.manage_drive_enc))
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage CA Certificates', ca_certificate_menu))
        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage Docker Networks', docker_network_menu))

        if docker_stacks.is_stack_deployed('AssetManager'):
            configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage Agent Settings', agent_menu))
            configuration_menu.add_option(
                MenuItem(configuration_menu.get_next_increment(), True, 'Manage Multi-Namespace Applications', namespace_menu)
            )

        if docker_stacks.is_stack_deployed('Reporting'):
            configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Manage SFTP / FTP Settings', sftpgo_menu))

        if docker_stacks.is_stack_deployed('IntVAMVulnerability'):
            configuration_menu.add_option(
                MenuItem(
                    configuration_menu.get_next_increment(),
                    True,
                    'Upload Vulnerability Database Update',
                    import_cve_database.upload_new_database_menu,
                )
            )

        configuration_menu.add_option(MenuItem(configuration_menu.get_next_increment(), True, 'Set Cloud Update Proxy Server URL', proxy_menu))

        if local_host_functions.is_journald_persistent() is False:
            configuration_menu.add_option(
                MenuItem(
                    configuration_menu.get_next_increment(), True, 'Enable Persistent Journald Logs', legacy_bash.enable_persistent_journald_logs
                )
            )

        # hidden options
        configuration_menu.add_option(MenuItem('support', False, 'Support Menu', support_menu))

        configuration_menu.show_menu()


def diagnostics_menu():
    while True:
        # new menu instance each iteration
        diagnostics_menu = Menu('Diagnostics Menu:', main)

        # add options
        diagnostics_menu.add_option(
            MenuItem(diagnostics_menu.get_next_increment(), True, 'View License Information', licensing_functions.print_license_info)
        )
        diagnostics_menu.add_option(MenuItem(diagnostics_menu.get_next_increment(), True, 'Generate Support Package', support_pack_menu))
        diagnostics_menu.add_option(MenuItem(diagnostics_menu.get_next_increment(), True, 'Perform Packet Capture', packet_capture.run_pcap))
        diagnostics_menu.add_option(MenuItem(diagnostics_menu.get_next_increment(), True, 'Run Health Checks', health_check_menu))
        diagnostics_menu.add_option(MenuItem(diagnostics_menu.get_next_increment(), True, 'Show Docker Configs', show_configs_menu))
        diagnostics_menu.add_option(MenuItem(diagnostics_menu.get_next_increment(), True, 'Show Docker Service Logs', show_service_logs_menu))
        diagnostics_menu.add_option(
            MenuItem(diagnostics_menu.get_next_increment(), True, 'List Docker Secrets', docker_functions.list_docker_secrets)
        )
        diagnostics_menu.add_option(
            MenuItem(diagnostics_menu.get_next_increment(), True, 'List Docker Services', docker_functions.list_docker_services)
        )
        diagnostics_menu.add_option(
            MenuItem(diagnostics_menu.get_next_increment(), True, 'List Docker Volumes', docker_functions.list_docker_volumes)
        )

        # hidden options
        diagnostics_menu.add_option(MenuItem('support', False, 'Support Menu', support_menu))

        diagnostics_menu.show_menu()


def support_menu():
    # included in main, configuration, and diagnostic menus
    logger.print_warning("This advanced administration menu should only be used with assistance from Verve support.")
    vam_server_file = Path('/etc/verve/temp/vamserver')
    while True:

        # make sure default values always exist if they get removed
        health_check_functions.verify_default_docker_secrets_exist()
        health_check_functions.verify_default_docker_configs_exist()

        # new menu instance each iteration
        support_menu = Menu('Advanced Admin Menu:', main)

        # add options
        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Legacy Support Pack Menu', legacy_support_pack_menu))
        if vam_server_file.exists():
            support_menu.add_option(
                MenuItem(support_menu.get_next_increment(), True, 'Force removal of previous failed Agent generator files', vam_server_file.unlink)
            )
        if docker_stacks.is_stack_deployed('AssetManager'):
            support_menu.add_option(
                MenuItem(support_menu.get_next_increment(), True, 'Manage Asset Manager Agent Settings', agent_menu, args=(True,))
            )

        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Manage CA Certificates', ca_certificate_menu, args=(True,)))
        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Manage Cloud Update Channel', cloud_update_channel_menu))
        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Advanced Docker Tasks', advanced_docker_menu))
        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Remove Docker Configs Menu', remove_docker_configs_menu))
        support_menu.add_option(MenuItem(support_menu.get_next_increment(), True, 'Remove Docker Secrets Menu', remove_docker_secrets_menu))

        support_menu.show_menu()


def agent_menu(advanced=False):
    while True:

        agent_leader_config_file = docker_functions.get_agent_leader_config_file()
        agent_installers_created = agent_functions.are_agent_installers_created()
        ca_certs_setup = agent_functions.are_agent_ca_certs_setup()
        server_certs_setup = agent_functions.are_agent_server_certs_setup()

        if not agent_installers_created:
            logger.print_warning("The agent installers are currently missing.")

        # new menu instance each iteration
        if advanced:
            agent_menu = Menu('Manage Advanced Asset Manager Agent Menu:', support_menu)
        else:
            agent_menu = Menu('Manage Asset Manager Agent Menu:', configuration_menu)

        # add options
        if server_certs_setup and ca_certs_setup:
            agent_menu.add_option(MenuItem(agent_menu.get_next_increment(), True, 'Build Installers', agent_functions.generate_agent_installers))
        else:
            agent_menu.add_option(MenuItem(agent_menu.get_next_increment(), True, 'Enable Settings', agent_functions.enable_agent_settings))

        if agent_leader_config_file.exists():
            agent_menu.add_option(MenuItem(agent_menu.get_next_increment(), True, 'Manage Aliases (SAN)', agent_san_menu, args=(advanced,)))
            if agent_functions.is_leader_host_set():
                # Custom rules only needed if LeaderHost is set to value other than vamserver or the LeaderHostPort is set.
                # LeaderHost and possibly LeaderHostPort need to be manually set in the config file for extreme edge cases.
                configuration_menu.add_option(
                    MenuItem(configuration_menu.get_next_increment(), True, 'Manage Firewall', legacy_bash.manage_agent_firewall)
                )

            if advanced:
                agent_menu.add_option(
                    MenuItem(agent_menu.get_next_increment(), True, 'Manage Enrollment Keys', agent_enrollment_menu, args=(advanced,))
                )

                timeout = agent_functions.get_creation_timeout()
                agent_menu.add_option(
                    MenuItem(
                        agent_menu.get_next_increment(),
                        True,
                        f'Manage Installer Creation Timeout ({timeout} seconds)',
                        agent_functions.prompt_creation_timeout,
                    )
                )

        if ca_certs_setup and advanced:
            agent_menu.add_option(
                MenuItem(
                    agent_menu.get_next_increment(),
                    True,
                    'Regenerate ICA Certificates',
                    agent_functions.regenerate_agent_ca_certificates,
                )
            )

        if server_certs_setup:
            agent_menu.add_option(
                MenuItem(
                    agent_menu.get_next_increment(),
                    True,
                    'Regenerate Server Certificates',
                    agent_functions.regenerate_agent_server_certificates,
                )
            )

        if ca_certs_setup and advanced:
            agent_menu.add_option(
                MenuItem(
                    agent_menu.get_next_increment(),
                    True,
                    'Remove ICA Certificates and Private Keys',
                    agent_functions.remove_agent_ca_certificates,
                )
            )

        if server_certs_setup and advanced:
            agent_menu.add_option(
                MenuItem(
                    agent_menu.get_next_increment(),
                    True,
                    'Remove Server Certificates and Private Keys',
                    agent_functions.remove_agent_server_certificates,
                )
            )

        if agent_installers_created:
            agent_menu.add_option(MenuItem(agent_menu.get_next_increment(), True, 'Remove Installers', agent_functions.remove_agent_installers))

        if advanced:
            agent_menu.add_option(MenuItem(agent_menu.get_next_increment(), True, 'Factory Reset', agent_functions.agent_factory_reset))

        agent_menu.show_menu()


def advanced_docker_menu():
    while True:
        # new menu instance each iteration
        advanced_docker_menu = Menu('Advanced Docker Tasks Menu:', support_menu)

        # add options
        advanced_docker_menu.add_option(
            MenuItem(advanced_docker_menu.get_next_increment(), True, 'Backup Docker Settings', docker_backups.backup_docker_settings)
        )
        advanced_docker_menu.add_option(
            MenuItem(advanced_docker_menu.get_next_increment(), True, 'Reset Docker Swarm', docker_backups.reset_docker_swarm)
        )
        advanced_docker_menu.add_option(
            MenuItem(advanced_docker_menu.get_next_increment(), True, 'Restore Docker Settings', docker_backups.restore_docker_settings)
        )
        advanced_docker_menu.add_option(
            MenuItem(advanced_docker_menu.get_next_increment(), True, 'Remove Docker Settings Backup', docker_backups.cleanup_docker_settings_backup)
        )

        advanced_docker_menu.show_menu()


def ca_certificate_menu(show_hidden=False):
    while True:
        # new menu instance each iteration
        if show_hidden:
            # return to support menu if showing hidden options
            ca_certificate_menu = Menu('Manage CA Menu', support_menu)

            # add options
            if openssl.verify_root_ca_exists():
                if docker_stacks.is_blocker_stack_deployed():
                    logger.print_warning(docker_stacks.REMOVE_RUNNING_APPLICATIONS_MESSAGE)
                else:
                    # Removing CA cert is not recommended because of the Agent certs, but may be needed for edge cases,
                    # so this menu is shown only in the hidden support menu
                    ca_certificate_menu.add_option(
                        MenuItem(ca_certificate_menu.get_next_increment(), True, "Remove CA Certificate", openssl.remove_root_ca)
                    )
            else:
                # option to manually generate the CA certs if they are missing
                ca_certificate_menu.add_option(
                    MenuItem(ca_certificate_menu.get_next_increment(), True, "Generate New CA Certificate", vsm_certificates.setup_ca_certificates)
                )
        else:
            # return to configuration menu when viewing normal options
            ca_certificate_menu = Menu('Manage CA Menu', configuration_menu)

        # edge case where the central vam needs to export the cert to be imported on a different server
        if openssl.verify_root_ca_exists():
            ca_certificate_menu.add_option(
                MenuItem(ca_certificate_menu.get_next_increment(), True, "Export CA Certificate", vsm_certificates.prompt_export_root_ca)
            )

        # edge case import other CA certs that should be trusted
        ca_certificate_menu.add_option(
            MenuItem(ca_certificate_menu.get_next_increment(), True, "Import New CA Certificate", vsm_certificates.prompt_import_new_ca)
        )

        # edge case for removing non-critical CA certs
        files = openssl.list_ca_certs()
        for fp in files:
            ca_certificate_menu.add_option(
                MenuItem(ca_certificate_menu.get_next_increment(), True, f"Remove {fp.name}", vsm_certificates.remove_ca_cert, args=(fp,))
            )

        ca_certificate_menu.show_menu()


def remove_docker_configs_menu():
    if docker_stacks.is_blocker_stack_deployed():
        logger.print_warning("Applications must all be removed before configs can be removed and reset.")
        return

    while True:
        # new menu instance each iteration
        remove_docker_configs_menu = Menu('Remove Docker Configs Menu', support_menu)

        # add options
        configs = docker_functions.get_docker_config_name_list()
        for config in configs:
            remove_docker_configs_menu.add_option(
                MenuItem(remove_docker_configs_menu.get_next_increment(), True, config, support_functions.support_remove_config, args=(config,))
            )

        remove_docker_configs_menu.show_menu()


def remove_docker_secrets_menu():
    if docker_stacks.is_blocker_stack_deployed():
        logger.print_warning("Applications must all be removed before secrets can be removed and reset.")
        return

    while True:
        # new menu instance each iteration
        remove_docker_secrets_menu = Menu('Remove Docker Secrets Menu', support_menu)

        # add options
        secrets = docker_functions.get_docker_secret_name_list()
        for secret in secrets:
            if secret in certificate_secret_list:
                removal_prompt = True
            else:
                removal_prompt = False

            remove_docker_secrets_menu.add_option(
                MenuItem(
                    remove_docker_secrets_menu.get_next_increment(),
                    True,
                    secret,
                    support_functions.support_remove_secret,
                    args=(secret, removal_prompt),
                )
            )

        remove_docker_secrets_menu.show_menu()


def cloud_update_channel_menu():
    message = (
        "Modifying this setting is not supported and will impair your ability to receive future support. "
        "This hidden setting is only intended for internal use and should never be used in production environments."
    )
    logger.print_warning(message)

    while True:
        current_channel = verve_settings.get_verve_settings_value('channel')
        if current_channel == 'key-not-found':
            current_channel = 'Production'

        print(f"The current channel is: {current_channel}")

        # new menu instance each iteration
        cloud_update_channel_menu = Menu('Manage Cloud Update Channel Menu:', support_menu)

        # add options
        if current_channel != "Production":
            cloud_update_channel_menu.add_option(
                MenuItem(
                    cloud_update_channel_menu.get_next_increment(),
                    True,
                    'Production channel',
                    verve_settings.update_verve_settings_channel,
                    args=(current_channel, 'Production'),
                )
            )

        if current_channel != "Development":
            cloud_update_channel_menu.add_option(
                MenuItem(
                    cloud_update_channel_menu.get_next_increment(),
                    True,
                    'Development channel',
                    verve_settings.update_verve_settings_channel,
                    args=(current_channel, 'Development'),
                )
            )

        cloud_update_channel_menu.add_option(
            MenuItem(
                cloud_update_channel_menu.get_next_increment(),
                True,
                'Manually add new channel',
                verve_settings.update_verve_settings_channel,
                args=(current_channel, ''),
            )
        )

        cloud_update_channel_menu.show_menu()


def support_pack_menu():
    # new menu instance each iteration
    support_pack_menu = Menu('Generate Support Package Menu:', diagnostics_menu)

    # add options
    support_pack_menu.add_option(
        MenuItem(
            support_pack_menu.get_next_increment(),
            True,
            'Generate Standard Support Package',
            support_pack_functions.build_support_pack_from_request,
            args=(SUPPORT_PACK_STANDARD_REQUEST,),
        )
    )
    support_pack_menu.add_option(
        MenuItem(
            support_pack_menu.get_next_increment(),
            True,
            'Generate Standard Support Package with Reporting Ingest Data',
            support_pack_functions.build_support_pack_from_request,
            args=(SUPPORT_PACK_INGEST_REQUEST,),
        )
    )
    support_pack_menu.add_option(
        MenuItem(
            support_pack_menu.get_next_increment(),
            True,
            'Generate Extended Support Package',
            support_pack_functions.build_support_pack_from_request,
            args=(SUPPORT_PACK_EXTENDED_REQUEST,),
        )
    )
    support_pack_menu.add_option(
        MenuItem(
            support_pack_menu.get_next_increment(),
            True,
            'Generate Minimal Support Package',
            support_pack_functions.build_support_pack_from_request,
            args=(SUPPORT_PACK_MINIMAL_REQUEST,),
        )
    )

    support_pack_menu.show_menu()


def legacy_support_pack_menu():
    # new menu instance each iteration
    legacy_support_pack_menu = Menu('Legacy Generate Support Package Menu:', support_menu)

    # add options
    legacy_support_pack_menu.add_option(
        MenuItem(legacy_support_pack_menu.get_next_increment(), True, 'Generate Standard Support Package', legacy_bash.build_support_pack)
    )
    legacy_support_pack_menu.add_option(
        MenuItem(
            legacy_support_pack_menu.get_next_increment(),
            True,
            'Generate Standard Support Package with Reporting Ingest Data',
            legacy_bash.build_support_pack,
            "i",
        )
    )
    legacy_support_pack_menu.add_option(
        MenuItem(legacy_support_pack_menu.get_next_increment(), True, 'Generate Extended Support Package', legacy_bash.build_support_pack, "e")
    )
    legacy_support_pack_menu.add_option(
        MenuItem(legacy_support_pack_menu.get_next_increment(), True, 'Generate Minimal Support Package', legacy_bash.build_support_pack, "m")
    )

    legacy_support_pack_menu.show_menu()


def licensing_menu():
    # new menu instance each iteration
    licensing_menu = Menu('Manage Licensing Menu:', configuration_menu)

    # add options
    licensing_menu.add_option(MenuItem(licensing_menu.get_next_increment(), True, 'Update License', licensing_functions.prompt_import_new_license))
    licensing_menu.add_option(MenuItem(licensing_menu.get_next_increment(), True, 'Remove License', licensing_functions.remove_license))

    licensing_menu.show_menu()


def show_configs_menu():
    while True:
        # new menu instance each iteration
        show_configs_menu = Menu('Show Configs Menu', diagnostics_menu)

        # add options
        configs = docker_functions.get_docker_config_name_list()
        for config in configs:
            show_configs_menu.add_option(
                MenuItem(show_configs_menu.get_next_increment(), True, config, docker_functions.show_docker_config, args=(config,))
            )

        show_configs_menu.show_menu()


def show_service_logs_menu():
    while True:
        # new menu instance each iteration
        show_service_logs_menu = Menu('Show Service Logs Menu', diagnostics_menu)

        # add options
        services = docker_functions.get_docker_service_list()
        for service in services:
            show_service_logs_menu.add_option(
                MenuItem(show_service_logs_menu.get_next_increment(), True, service.name, docker_functions.show_docker_service_logs, args=(service,))
            )

        show_service_logs_menu.show_menu()


def application_menu():
    # make sure the local server certificate is setup to avoid errors when deploying applications
    if openssl.verify_local_server_cert_exists() is False:
        logger.log_warning(MISSING_LOCAL_SERVER_CERT_MESSAGE)
        return

    if not licensing_functions.is_verve_license_valid():
        logger.log_warning(MISSING_OR_INVALID_LICENSE_MESSAGE)
        return

    try:
        # make sure default networks exist
        verve_docker_networks.setup_networks_if_missing()
        while True:
            # new menu instance each iteration
            application_menu = Menu('Application Menu', configuration_menu)

            # allow multiple options
            application_menu.allow_multiple_options()

            # add options
            application_list = application_functions.get_application_menu_list()
            for application in application_list:
                if application['deployed']:
                    name = colors.text_green(f"* Remove - {application['title']}")
                    application_menu.add_option(
                        MenuItem(
                            application_menu.get_next_increment(), True, name, application_functions.remove_application, args=(application['app'],)
                        )
                    )
                else:
                    name = f"  Deploy - {application['title']}"
                    application_menu.add_option(
                        MenuItem(
                            application_menu.get_next_increment(), True, name, application_functions.deploy_application, args=(application['app'],)
                        )
                    )

            application_menu.show_menu()
    except Exception as e:
        logger.log_error(f"An error occurred while displaying the application menu: {e}")
        return


def proxy_menu():
    while True:
        proxy_url_status = local_host_functions.get_proxy_status()
        print(f"\n{proxy_url_status}")

        if proxy_url_status == "No existing proxy server configuration set.":
            action = "Set"
            is_removable = False
        else:
            action = "Update"
            is_removable = True

        # new menu instance each iteration
        proxy_menu = Menu('Cloud Updates Proxy Server Menu', configuration_menu)

        proxy_menu.add_option(
            MenuItem(proxy_menu.get_next_increment(), True, f"{action} Proxy Server URL", local_host_functions.set_cloud_update_proxy)
        )

        if is_removable:
            proxy_menu.add_option(
                MenuItem(proxy_menu.get_next_increment(), True, "Remove Proxy Server URL", local_host_functions.remove_cloud_update_proxy)
            )

        proxy_menu.show_menu()


def namespace_menu():
    # make sure namespace file exists
    integration_namespace_functions.initialize_integration_namespaces()

    while True:
        filtered_namespace_list = integration_namespace_functions.filter_multi_namespace_list()

        # new menu instance each iteration
        namespace_menu = Menu('Manage Multi-Namespace Applications Menu', configuration_menu)

        for application in filtered_namespace_list:
            title = application_functions.get_display_title(application['name'])
            namespace_menu.add_option(
                MenuItem(namespace_menu.get_next_increment(), True, title, update_namespace_menu, args=(application['name'], title))
            )

        namespace_menu.show_menu()


def agent_enrollment_menu(advanced=False):
    while True:
        enrollment_keys = agent_functions.get_enrollment_key_list()

        # new menu instance each iteration
        agent_enrollment_menu = Menu('Manage Agent Enrollment Keys Menu', agent_menu, args=(advanced,))

        agent_enrollment_menu.add_option(
            MenuItem(agent_enrollment_menu.get_next_increment(), True, "Add Enrollment Key", agent_functions.add_enrollment_key)
        )

        for enrollment_key in enrollment_keys:
            agent_enrollment_menu.add_option(
                MenuItem(
                    agent_enrollment_menu.get_next_increment(),
                    True,
                    f"Remove Enrollment Key: {enrollment_key['CreationTime']}",
                    agent_functions.remove_enrollment_key,
                    args=(enrollment_key['Value'],),
                )
            )

        agent_enrollment_menu.add_option(
            MenuItem(agent_enrollment_menu.get_next_increment(), True, "Rebuild Agent Installers", agent_functions.generate_agent_installers)
        )

        agent_enrollment_menu.show_menu()


def agent_san_menu(advanced=False):
    vam_server = vsm_functions.get_server_value()
    while True:
        san_list = agent_functions.get_san_list()

        # new menu instance each iteration
        agent_san_menu = Menu('Manage Asset Manager Agent Aliases (SAN) Menu', agent_menu, args=(advanced,))

        agent_san_menu.add_option(MenuItem(agent_san_menu.get_next_increment(), True, "Add new alias (SAN)", agent_functions.prompt_new_san))

        if vam_server not in san_list:
            agent_san_menu.add_option(
                MenuItem(
                    agent_san_menu.get_next_increment(),
                    True,
                    f"Add VAM Server: {vam_server}",
                    agent_functions.add_new_san,
                    args=(vam_server, True),
                )
            )

        for san in san_list:
            agent_san_menu.add_option(
                MenuItem(
                    agent_san_menu.get_next_increment(),
                    True,
                    f"Remove {san}",
                    agent_functions.remove_san,
                    args=(san, True),
                )
            )

        agent_san_menu.show_menu()


def sftpgo_menu():
    enable_ftp = sftpgo_functions.ENABLE_FTP
    disable_ftp = sftpgo_functions.DISABLE_FTP

    while True:
        configs = utilities.get_no_section_config_values(SFTPGO_CONFIG)

        # new menu instance each iteration
        sftpgo_menu = Menu('Manage SFTP / FTP Settings', configuration_menu)

        if configs['SFTPGO_FTPD__BINDINGS__0__PORT'] == '0':
            sftpgo_menu.add_option(
                MenuItem(
                    sftpgo_menu.get_next_increment(),
                    True,
                    "Enable FTP for Data Diodes",
                    sftpgo_functions.update_sftpgo_config_value,
                    args=(disable_ftp, enable_ftp),
                )
            )
        else:
            sftpgo_menu.add_option(
                MenuItem(
                    sftpgo_menu.get_next_increment(),
                    True,
                    "Disable FTP for Data Diodes",
                    sftpgo_functions.update_sftpgo_config_value,
                    args=(enable_ftp, disable_ftp),
                )
            )

        sftpgo_menu.add_option(
            MenuItem(sftpgo_menu.get_next_increment(), True, "Import SSH key for SFTP Authentication", sftpgo_functions.upload_ssh_key, args=(True,))
        )

        auth_key_list = sftpgo_functions.get_auth_key_list()
        for auth_key in auth_key_list:
            key_path = Path(auth_key)
            sftpgo_menu.add_option(
                MenuItem(
                    sftpgo_menu.get_next_increment(), True, f"Remove SSH key: {key_path.name}", sftpgo_functions.remove_ssh_key, args=(key_path,)
                )
            )

        sftpgo_menu.add_option(
            MenuItem(sftpgo_menu.get_next_increment(), True, "Apply changes now", sftpgo_functions.update_service_sftpgo, args=(True,))
        )

        sftpgo_menu.show_menu()


def update_namespace_menu(integration, title):
    while True:
        full_namespace_list = integration_namespace_functions.get_integration_namespace_manifest()

        # filter namespace list for current values of specified integration
        application = next((x for x in full_namespace_list if x['name'] == integration), None)

        # new menu instance each iteration
        update_namespace_menu = Menu(f'Update {title} Namespace Menu', namespace_menu)

        update_namespace_menu.add_option(
            MenuItem(
                update_namespace_menu.get_next_increment(),
                True,
                "Add new Namespace",
                integration_namespace_functions.add_new_namespace,
                args=(integration,),
            )
        )

        # unpack syntax '*' to convert dict into a list of keys
        namespaces = [*application['namespaces']]
        namespaces.sort()

        # rename namespaces
        for namespace in namespaces:
            update_namespace_menu.add_option(
                MenuItem(
                    update_namespace_menu.get_next_increment(),
                    True,
                    f"Rename {namespace} Namespace",
                    integration_namespace_functions.rename_existing_namespace,
                    args=(integration, namespace),
                )
            )

        # remove namespaces but always leave at least 1
        if len(namespaces) > 1:
            for namespace in namespaces:
                update_namespace_menu.add_option(
                    MenuItem(
                        update_namespace_menu.get_next_increment(),
                        True,
                        f"Remove {namespace} Namespace",
                        integration_namespace_functions.remove_existing_namespace,
                        args=(integration, namespace),
                    )
                )

        update_namespace_menu.show_menu()


def certificate_menu():
    if openssl.verify_root_ca_exists() is False:
        # make sure the root ca is setup
        vsm_certificates.setup_ca_certificates()

    while True:
        # new menu instance each iteration
        certificate_menu = Menu('Certificate Management Menu', configuration_menu)

        # add options
        if openssl.verify_local_server_cert_exists():
            if docker_stacks.is_blocker_stack_deployed():
                logger.print_warning(docker_stacks.REMOVE_RUNNING_APPLICATIONS_MESSAGE)
            else:
                certificate_menu.add_option(
                    MenuItem(
                        certificate_menu.get_next_increment(), True, 'Remove SSL Public Certificate and Private Key', openssl.remove_local_server_cert
                    )
                )
        else:
            # option to manually generate the or import server certificate
            certificate_menu.add_option(
                MenuItem(
                    certificate_menu.get_next_increment(),
                    True,
                    'Generate self-signed certificate and key',
                    vsm_certificates.setup_local_server_certificates,
                )
            )
            certificate_menu.add_option(
                MenuItem(
                    certificate_menu.get_next_increment(),
                    True,
                    'Import certificate and key',
                    vsm_certificates.prompt_import_local_server_certificates,
                )
            )

        certificate_menu.show_menu()


def health_check_menu():
    skip_prompts = False
    show_missing_error = True
    verbose_mode = True

    while True:
        # new menu instance each iteration
        health_check_menu = Menu('Health Check Menu', diagnostics_menu)

        # add options

        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Run All Pre-Checks',
                health_check_functions.run_pre_checks,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Check Host Operating System Support',
                health_check_functions.verify_os_version_support,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Check Data Drive Mount',
                health_check_functions.check_data_drive_mount,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Check Verve License Imported',
                health_check_functions.verify_license_file_exists,
                args=(show_missing_error, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Confirm Verve License Is Valid',
                health_check_functions.verify_license_file_is_valid,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Print Condensed License Info',
                health_check_functions.print_condensed_license_info,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify License Valid For Configuration',
                health_check_functions.verify_license_config_still_valid,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify Valid Issue Date',
                health_check_functions.verify_issue_date_valid,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify Docker Volumes',
                health_check_functions.verify_default_docker_volumes_exist,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify Docker Secrets',
                health_check_functions.verify_default_docker_secrets_exist,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify Docker Configs',
                health_check_functions.verify_default_docker_configs_exist,
                args=(skip_prompts, verbose_mode),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Export Docker Networks to VAM',
                health_check_functions.export_docker_networks,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Verify Certificates Expirations',
                health_check_functions.verify_certificates,
                args=(verbose_mode,),
            )
        )
        health_check_menu.add_option(
            MenuItem(
                health_check_menu.get_next_increment(),
                True,
                'Check Journald Persistence',
                health_check_functions.verify_journald_is_persistent,
                args=(verbose_mode,),
            )
        )

        health_check_menu.show_menu()


def docker_network_menu():
    while True:
        subnet_reporting = verve_docker_networks.get_network_reporting()
        subnet_vam = verve_docker_networks.get_network_vam()
        docker_default = verve_docker_networks.get_docker_swarm_default_ip_pool()
        ingress = verve_docker_networks.get_network_ingress()
        gw_bridge = verve_docker_networks.get_network_gw_bridge()
        bridge = verve_docker_networks.get_network_bridge()

        # make sure file is updated after any changes
        verve_docker_networks.export_network_information(bridge, gw_bridge, ingress, docker_default, subnet_vam, subnet_reporting)

        message = f"""
Contact support to change these network pools:
    Docker Default Pool : {docker_default}
    Docker Ingress Pool : {ingress}
    Docker Bridge Pool  : {bridge}
    Docker GWBridge Pool: {gw_bridge}"""

        print(message)

        networks = {'Reporting': subnet_reporting, 'VAM': subnet_vam, 'default': docker_default}

        # new menu instance each iteration
        docker_network_menu = Menu('Manage Docker Networks Menu', configuration_menu)

        # add options
        docker_network_menu.add_option(
            MenuItem(
                docker_network_menu.get_next_increment(),
                True,
                f'Reporting Network --- {subnet_reporting}',
                verve_docker_networks.update_docker_networks,
                args=('Reporting', 'network-reporting', subnet_reporting, networks),
            )
        )
        docker_network_menu.add_option(
            MenuItem(
                docker_network_menu.get_next_increment(),
                True,
                f'VAM Network --------- {subnet_vam}',
                verve_docker_networks.update_docker_networks,
                args=('VAM', 'network-vam', subnet_vam, networks),
            )
        )
        docker_network_menu.add_option(
            MenuItem(
                docker_network_menu.get_next_increment(),
                True,
                'Apply Changes and Restart Running Applications Now',
                application_functions.cycle_deployed_applications,
            )
        )

        docker_network_menu.show_menu()


def upgrade_menu():
    software_upgrade_menu = Menu('Software Upgrade Menu', main)

    software_upgrade_menu.add_option(
        MenuItem(
            software_upgrade_menu.get_next_increment(),
            True,
            'Upgrade Software from ISO',
            upgrade_software.upgrade_from_iso,
        )
    )

    software_upgrade_menu.add_option(
        MenuItem(
            software_upgrade_menu.get_next_increment(),
            True,
            'Upgrade Software from CD-ROM',
            upgrade_software.upgrade_from_cdrom,
        )
    )

    software_upgrade_menu.add_option(
        MenuItem(
            software_upgrade_menu.get_next_increment(),
            True,
            'Upgrade Software using SecureOT Cloud Update',
            upgrade_software.upgrade_from_cloud_wrapper,
        )
    )

    software_upgrade_menu.show_menu()


if __name__ == '__main__':
    sys.exit(main())
