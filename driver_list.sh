sudo docker exec -i $(sudo docker ps --filter "name=AssetManager_postgres" --format "{{.ID}}") \
  psql -U 'Ap1D4t4b4s3%4dm1nUs3rn4m3' -d vam --csv \
  -c "
WITH asset_props AS (
  SELECT \"AssetId\", \"PropertyName\", \"Value\"::text AS \"Value\"
  FROM \"PropertyValue\"
  WHERE \"PropertyName\" IN (
    'ADI - Configuration - Driver Name',
    'ADI - Network - Hostname',
    'Network - MAC Address Vendor',
    'Network - TCP Listening Ports'
  )
)
SELECT
  string_agg(CASE WHEN \"PropertyName\" = 'ADI - Configuration - Driver Name' THEN \"Value\" END, ', ') AS \"DriverName\",
  string_agg(CASE WHEN \"PropertyName\" = 'ADI - Network - Hostname'          THEN \"Value\" END, ', ') AS \"Hostname\",
  string_agg(CASE WHEN \"PropertyName\" = 'Network - MAC Address Vendor'      THEN \"Value\" END, ', ') AS \"MACAddressVendor\",
  string_agg(CASE WHEN \"PropertyName\" = 'Network - TCP Listening Ports'     THEN \"Value\" END, ', ') AS \"TCPListeningPorts\"
FROM asset_props
GROUP BY \"AssetId\"
ORDER BY \"AssetId\"
" | tee ~/driver_list.csv
