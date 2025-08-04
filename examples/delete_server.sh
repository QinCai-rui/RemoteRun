#!/bin/bash
# Delete a server
# Usage: set TOKEN and SERVER_ID env vars
curl -X DELETE http://localhost:8012/servers/${SERVER_ID} \
  -H "Authorization: Bearer ${TOKEN}"
