#!/bin/bash
# Delete a server (replace TOKEN and SERVER_ID)
curl -X DELETE http://localhost:8012/servers/SERVER_ID \
  -H "Authorization: Bearer TOKEN"
