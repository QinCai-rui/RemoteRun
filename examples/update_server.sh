#!/bin/bash
# Update a server (replace TOKEN and SERVER_ID, and values as needed)
curl -X PUT http://localhost:8012/servers/SERVER_ID \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "MyServerUpdated",
    "host": "192.168.1.100",
    "ssh_username": "ubuntu",
    "ssh_password": "yourpassword"
  }'
