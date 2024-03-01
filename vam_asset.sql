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
CREATE temp TABLE assets AS (
SELECT  DISTINCT
      a1."AssetId" as assetid
FROM "PropertyValue" as a1 
ORDER BY a1."AssetId"
); 

alter table assets  add ADI_IP character (75);
UPDATE assets
SET ADI_IP = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN ('ADI - Client - Connection String');
 
alter table assets  add NET_IP character (75);
UPDATE assets
SET IP = a1."Value"#>>'{}'
FROM  "PropertyValue" as a1 
WHERE assets.AssetId= a1."AssetId"
and a1."PropertyName" IN xxx ('ADI - Client - Connection String');
 
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
