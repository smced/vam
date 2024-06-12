/*
Finder
SELECT *
FROM  "PropertyValue" as a1 
WHERE 1=1
--and a1."PropertyName" = ('ADI - Namespace');
and a1."PropertyName"::text collate "C" ilike '%vuln%'
*/






--asset build
drop   table assets;
CREATE temp TABLE assets (ID serial primary key);

--ASSETID
alter table assets  add assetid uuid;
INSERT INTO  assets (assetid)
SELECT  DISTINCT
      a1."AssetId" as assetid
FROM "PropertyValue" as a1 
ORDER BY a1."AssetId"; 

--ADI_NAME
alter table assets  add ADI_NAME character (105);
UPDATE assets
set ADI_NAME = a1."Value"#>>'{}'
FROM "PropertyValue" AS a1
WHERE assets.AssetId= a1."AssetId"
AND a1."PropertyName" = 'ADI - Client - Connection String';


--PLANT
alter table assets  add PLANT character (20);
UPDATE assets
SET PLANT = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('ADI - Namespace - Name');
			--SELECT * FROM assets ORDER BY RANDOM() LIMIT 5;
			
DELETE from assets where plant not like 'hunt%';
DELETE from assets where plant is null;

			-- select * from assets where adi_name = '10.1.51.116';

--BES_NAME
alter table assets  add BES_NAME character (75);
UPDATE assets
SET BES_NAME = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('BES - Network - Hostname');
--SELECT * from assets where BES_NAME is not null; 
 
--ANSIBLE_HOST 
alter table assets  add ansible_host character (50);
UPDATE assets
set ansible_host = replace(replace(a1."Value"::text, '"ansible_host: \"',''),'\""','')			 
FROM "PropertyValue" AS a1
WHERE assets.AssetId= a1."AssetId"
AND a1."PropertyName" = 'ADI - Client - Host Variables'
and a1."Value"::text like '%ansible_host%'; 

		--  SELECT * from assets where assetid in ('7392990f-c467-4f24-a50f-f995a0218868');
		--  SELECT * from assets where ADI_NAME in ('192.168.101.100');
		-- SELECT * from assets where ADI_NAME = 'V0001P000BSN00334AB7-1756-CNB-D-5-050-Build-010';
        -- select  a1."PropertyName", a1."Value" 
		   FROM "PropertyValue" AS a1 
		   WHERE a1."AssetId" = '6840b20b-a30f-4242-977d-0dd52a752072' 
		   AND a1."PropertyName" COLLATE "C" NOT LIKE 'CVE%'
		   order by 1;
		   --AND a1."PropertyName" = 'ADI - Network - IP Addresses';
		   
		   select 
			   a1."AssetId"  
			 ,a1."PropertyName"  
			 ,a1."Value"  
			 ,a1."Order"  
			 ,b1.*  
			from "PropertyValue" as a1
			left outer join "PropertyValueContent" as b1 on replace(replace(a1."Reference",'/propertyvalues?propertyvalueids=',''),'&requestedfields=value','') = b1."PropertyValueId"::text  
			where a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73')  
			and a1."PropertyName" IN ('ADI - Client - Host Variables')  
			order by a1."Order";

--ADI - Network - IP Addresses
alter table assets  add ADI_IP character (20);
UPDATE assets
set ADI_IP = a1."Value"->'display' 
FROM "PropertyValue" AS a1
WHERE assets.AssetId= a1."AssetId"
AND a1."PropertyName" = 'ADI - Network - IP Addresses';

UPDATE assets set ADI_IP = replace(ADI_IP,'"','');

--CIP_ROUTE
alter table assets  add cip_route character (200);
--alter table assets  drop cip_route ;
UPDATE assets
set cip_route = replace(replace(a1."Value"::text, '"cip_route_path: \"',''),'\""','') 
FROM "PropertyValue" AS a1
WHERE assets.AssetId= a1."AssetId"
AND a1."PropertyName" = 'ADI - Client - Host Variables'
AND a1."Value"::text like '%cip_route_path%';

			--	select * from assets where ansible_host = '10.1.51.116';
			-- xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
			--	select left(adi_name,50) as adi_name 
						,left(ansible_host,20) as ansible_host
						,adi_ip
						,left(cip_route,30) as cip_route  
				from assets 
				--where ansible_host = '10.1.51.116'
				where assetid in ('7392990f-c467-4f24-a50f-f995a0218868');
				
				SELECT * from assets where assetid in ('7392990f-c467-4f24-a50f-f995a0218868');
				order by 4;

			select max(length(a1."Value"#>>'{}'))
			FROM "PropertyValue" AS a1
			WHERE  a1."PropertyName" = 'ADI - Client - Host Variables';
			
			select ADI_IP2 from assets order by length(ADI_IP2) asc limit 10;
			
			SELECT replace(replace(a1."Value"::text, '"cip_route_path: \"',''),'\""','')
			FROM "PropertyValue" AS a1
			WHERE a1."PropertyName" = 'ADI - Client - Host Variables'
			AND a1."Value"::text like '%cip_route_path%'
			and  a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73') ;

--  SELECT * from assets where assetid in ('d9b81d54-933f-41c7-9d6c-259ab1957b73');

			select a1."Value",
				length(a1."Value"::text)
			FROM "PropertyValue" AS a1
			WHERE a1."PropertyName" = 'ADI - Client - Host Variables'
			AND a1."Value"::text like '%cip_route_path%'
			order by 2 desc
			limit 5;
			--  SELECT * from assets where assetid in ('d9b81d54-933f-41c7-9d6c-259ab1957b73');

---
---------------------------------
--PHASE 1 DONE
---------------------------------


Phase 2 = get the CIP ROUTE IF A CIP ROUTE Exists

--prep
			select 
			   a1."AssetId"  
			 ,a1."PropertyName"  
			 ,a1."Value"  
			 ,a1."Order"  
			 ,b1.*  
			from "PropertyValue" as a1
			left outer join "PropertyValueContent" as b1 on replace(replace(a1."Reference",'/propertyvalues?propertyvalueids=',''),'&requestedfields=value','') = b1."PropertyValueId"::text  
			where a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73')  
			and a1."PropertyName" IN ('ADI - Client - Host Variables')  
			order by a1."Order";

			select 
			   a1."AssetId"  
			 ,a1."PropertyName"  
			 ,json_extract_path_text(a1."Value"::json, 'ansible_host') AS "IP_Address"  
			 ,a1."Order"  
			 --,json_extract_path_text(b1."Value"::json, 'ansible_host') AS "IP_Address"
			from "PropertyValue" as a1
			left outer join "PropertyValueContent" as b1 on replace(replace(a1."Reference",'/propertyvalues?propertyvalueids=',''),'&requestedfields=value','') = b1."PropertyValueId"::text  
			where a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73')  
			and a1."PropertyName" IN ('ADI - Client - Host Variables')  
			--and b1."Value"::json->>'ansible_host' ilike '%ansible_host%'
			order by a1."Order";
			
			SELECT a1."Value"
			FROM  "PropertyValue" as a1 
			where a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73') 
			and a1."PropertyName" IN ('ADI - Client - Host Variables');


			 SELECT 	a1."Value" r
						, a1."Value"->>'ansible_host' AS r1 
						, a1."Value"::text   AS r2
						, TRIM(BOTH '"' FROM jsonb_path_query_first(a1."Value",'$.ansible_host'::jsonpath)::text) AS "IP_Address"
                        FROM  "PropertyValue" as a1
                        where a1."AssetId" in ('d9b81d54-933f-41c7-9d6c-259ab1957b73')
                        and a1."PropertyName" IN ('ADI - Client - Host Variables');
             TRIM(BOTH '"' FROM jsonb_path_query_first(a1."Value",'$.ansible_host'::jsonpath)::text) AS "IP_Address"
			 
			 Value
			-------------------------------------------------------------------------
			"ansible_host: \"192.168.101.100\""
			"cip_route_path: \"1/3/2/2/1/1/2/192.168.101.111/1/1/2/192.168.1.104\""

			
			SELECT
			a1."ID",
			a1."Value"::text AS "Raw_Value",
			replace(replace(a1."Value"::text, '"ansible_host: \"',''),'\""','')			AS "Raw_Value"
			FROM
			"PropertyValue" AS a1
			WHERE
			a1."AssetId" = 'd9b81d54-933f-41c7-9d6c-259ab1957b73'
			AND a1."PropertyName" = 'ADI - Client - Host Variables'
			and a1."Value"::text like '%ansible_host%';
 
			SELECT
			a1."ID",
			a1."Value"::text AS "Raw_Value",
			replace(replace(a1."Value"::text, '"cip_route_path: \"',''),'\""','')			AS "Raw_Value"
			FROM
			"PropertyValue" AS a1
			WHERE
			a1."AssetId" = 'd9b81d54-933f-41c7-9d6c-259ab1957b73'
			AND a1."PropertyName" = 'ADI - Client - Host Variables'
			and a1."Value"::text like '%cip_route_path%';
			
			
--------
PHASE II
----------
ALTER TABLE assets DROP COLUMN Child1, DROP COLUMN Child2;
ALTER TABLE assets ADD COLUMN Child1 character(200), ADD COLUMN Child2 character(200);

WITH ip_extraction AS (
    SELECT
        assetid,
        cip_route,
        regexp_split_to_table(cip_route, '/') AS split_segment
    FROM assets
),
extracted_ips AS (
    SELECT
        assetid,
        split_segment AS ip,
        ROW_NUMBER() OVER (PARTITION BY assetid ORDER BY split_segment) AS rn
    FROM ip_extraction
    WHERE split_segment ~ '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
)
UPDATE assets
SET
    Child1 = extracted_data.Child1,
    Child2 = extracted_data.Child2
FROM (
    SELECT
        assetid,
        MAX(CASE WHEN rn = 1 THEN ip END) AS Child1,
        MAX(CASE WHEN rn = 2 THEN ip END) AS Child2
    FROM extracted_ips
    GROUP BY assetid
) AS extracted_data
WHERE assets.assetid = extracted_data.assetid;
		YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY
		select left(adi_name,50) as adi_name 
						,left(ansible_host,20) as ansible_host
						,adi_ip
						,left(cip_route,30) as cip_route  
						,left(child1,30) as child1
						,left(child2,30) as child2
				from assets 
				--where ansible_host = '10.1.51.116'
				where assetid in ('7392990f-c467-4f24-a50f-f995a0218868');
				
				SELECT * from assets where assetid in ('7392990f-c467-4f24-a50f-f995a0218868');
				order by 4;
		
		
		SELECT * from assets where assetid in ('d9b81d54-933f-41c7-9d6c-259ab1957b73');
		SELECT ansible_host, child1, child2 from assets where ansible_host = '192.168.101.100';

			SELECT
				ansible_host
				, child1
				, child2
			from assets
			order by ansible_host
			limit 10;

-- Create the network_tree table
DROP table network_tree;
CREATE temp TABLE network_tree (
    host character(130),
    parent character(130),
	cip_route character(200)
);
INSERT INTO network_tree (host) VALUES ('Hunt Valley');

INSERT INTO network_tree (host, parent,cip_route)
SELECT DISTINCT
    coalesce(adi_ip,child1)
    ,ansible_host
	,cip_route
FROM assets
WHERE ansible_host IS NOT NULL
AND child1 is not null
AND ansible_host != '';
--ON CONFLICT (host, parent) DO NOTHING;

INSERT INTO network_tree (host, parent)
SELECT DISTINCT
    adi_ip
    ,'Hunt Valley'
FROM assets
WHERE ansible_host IS NULL
AND child1 is null
AND adi_ip is not null;
--ON CONFLICT (host, parent) DO NOTHING;

		select 
			left(host,30) as host 
			,left(parent,30) as parent
			,left(cip_route, 50) as cip_route
		from network_tree where parent = '10.1.51.116'
		UNION
		select 
			left(host,30) as host 
			,left(parent,30) as parent
			,left(cip_route, 50) as cip_route
		from network_tree where host = '10.1.51.116'
				UNION
		select 
			left(host,30) as host 
			,left(parent,30) as parent
			,left(cip_route, 50) as cip_route
		from network_tree where host = 'Hunt Valley';

INSERT INTO network_tree (host, parent,cip_route)
SELECT DISTINCT
    child2,
    child1
	,cip_route
FROM assets
WHERE child2 IS NOT NULL
AND child2 != ''
ON CONFLICT (host, parent) DO NOTHING;

--exceptions like V0001P000BSN00334AB7-1756-CNB-D-5-050-Build-010
INSERT INTO network_tree (host, parent,cip_route)
SELECT DISTINCT
    trim(adi_name),
    trim(ansible_host)
	,cip_route
FROM assets
WHERE ADI_IP is null
and ansible_host is not null
ON CONFLICT (host, parent) DO NOTHING;


					-- Insert unique pairs from ansible_host and parent
					INSERT INTO network_tree (host, parent,cip_route)
					SELECT DISTINCT
						trim(adi_ip),
						trim(ansible_host)
						,cip_route
					FROM assets
					WHERE child1 IS NOT NULL
					AND child1 != ''
					AND adi_ip != ''
					ON CONFLICT (host, parent) DO NOTHING;


				INSERT INTO network_tree (host, parent,cip_route)
				SELECT DISTINCT
					trim(adi_ip),
					trim(ansible_host)
					,cip_route
				FROM assets
				WHERE child1 IS NOT NULL
				AND child1 != ''
				AND adi_ip != ''
				ON CONFLICT (host, parent) DO NOTHING;


			-- SELECT * FROM network_tree;






			SELECT * from network_tree where host = '192.168.101.100' order by 2;
			SELECT * from network_tree where host = '192.168.101.111' order by 2;
			
			SELECT * from network_tree where host = '192.168.1.104';   
			
			SELECT left(adi_name,30), ansible_host , adi_ip , cip_route, child1 , child2 from assets where ansible_host = '192.168.101.100'
			order by 2,3;
			
			;
			and adi_ip like '192.168.101.111';

			SELECT * from assets where child1 = '192.168.101.111';
			SELECT * from assets where adi_Ip = '192.168.101.111';

          id | assetid | adi_name | plant | bes_name | ansible_host | adi_ip | cip_route | child1 | child2
			adi_name= 'V0001P000BSN00334AB7-1756-CNB-D-5-050-Build-010'


		select * from assets where adi_Ip ilike '%192.168.1.104%';   
		select * from network_tree where host like '192.168.1.104';








In postgres
I have a json field called "Value" with data like this ""ansible_host: \"192.168.101.100\"""
I need to first filter by WHERE by this value
and then only pull IP address
Table name is PropertyValueContent with an ID column 


			SELECT
			  "ID",
			  json_extract_path_text("Value"::json, 'ansible_host') AS "IP_Address"
			FROM
			  "PropertyValueContent"
			WHERE
			  "Value"::json->>'ansible_host' = '192.168.101.100';


alter table assets  add Ansible_host character (75);
UPDATE assets
SET Ansible_host = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('BES - Network - Hostname');








select b1."Value"-->'Name'
from "PropertyValueContent" as b1
where b1."ID" = '87a4da58-a4d3-49f4-8c3e-e1a7deb21add';

SELECT jsonb_extract_path_text(b1."Value", 'mac_address') as mac_address
FROM "PropertyValueContent" as b1
WHERE b1."ID" = '87a4da58-a4d3-49f4-8c3e-e1a7deb21add';




 
 
--SELECT * FROM assets WHERE IP is not null limit 10;
alter table assets  add ADI_Namespace character (75);
UPDATE assets
SET ADI_Namespace = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('ADI - Namespace');



alter table assets  add BES_Namespace character (75);
UPDATE assets
SET BES_Namespace = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('BES - Namespace');



alter table assets  add plant character (50);
UPDATE assets
SET plant = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('Manual - Lifecycle - Plant');

SELECT * FROM assets where ip like '10.19.7.254';
SELECT * FROM assets where assetid = '14ecd936-1281-415f-9b53-b764b314578a';

SELECT plant,count(*) as count1 FROM assets group by plant order by plant;
SELECT IP from assets where plant like ' South%';


alter table assets  add subnet character (20);
UPDATE assets
SET subnet = substring(ip from '(\d+\.\d+\.\d+)\.\d+');

CREATE temp TABLE ADI_installs   (adi_namespace character(50), adi_name character(40));
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('a5461301-94cf-447e-bc90-f113f0845af3', 'Clarke Road');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('b2a6361c-d816-4681-a369-a0ad8e673a0c', 'Hunt Valley');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('e16234e4-cdf7-477d-94e6-68fb1ba0e437', 'Springfield');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('75464601-da6e-4679-9fe8-7ab346a8c13a', 'Stefanowo');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('a449b0af-8cc1-4a88-a5a0-8fa8923bff83', 'Haddenham');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('e52aefd7-ef22-43d4-bd07-428fe2f53260', 'Carpentras');
INSERT INTO ADI_installs(adi_namespace,adi_name) VALUES ('b016e6a6-efdd-4f5b-bbad-73e7f2dfcd51', 'Azure VAM');

alter table assets  add adi_name character (30);
UPDATE assets
set adi_name = ADI_installs.adi_name
FROM ADI_installs where assets.adi_namespace = ADI_installs.adi_namespace;


/*
SELECT * FROM assets where ip is not null;

SELECT  
 substring(ip from '(\d+\.\d+\.\d+)\.\d+') AS last_octet
 FROM assets
 WHERE IP is not null
 GROUP BY substring(ip from '(\d+\.\d+\.\d+)\.\d+')
 order by split_part(ip, '.',1), split_part(ip, '.',2),split_part(ip, '.',3);
*/

SELECT 
	  adi_name 		as adi_name_fixed
	, plant 		as plant_manual
	, subnet 		as subnet_from_connection_string_calc
	, count(*) 		as asset_count
FROM assets 
where ip is not null
and plant is not null
and subnet is not null
GROUP BY ADI_Namespace,adi_name,plant, subnet, split_part(ip, '.',1),split_part(ip, '.',2),split_part(ip, '.',3)
order by cast(split_part(ip, '.',1) as integer),cast(split_part(ip, '.',2) as integer),cast(split_part(ip, '.',3) as integer);

 






alter table assets  add MAC1 character (20);
UPDATE assets
SET mac1 = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
--and a1."PropertyName" IN ('Network - MAC Addresses')
and a1."PropertyName" IN ('Manual - Network - MAC Addresses')
and a1."Order" = 0;

alter table assets  add MAC_Vendor2 character (1000);
UPDATE assets
SET MAC_Vendor2 = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
--and a1."PropertyName" IN ('Network - MAC Addresses')
and a1."PropertyName" IN ('Manual - Network - MAC Address Vendor')
and a1."Order" = 0;
