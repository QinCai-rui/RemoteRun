#!/bin/bash
# Update a server
# Usage: set TOKEN, SERVER_ID, SERVER_NAME, SERVER_HOST, SERVER_USER, SERVER_PASSWORD/PRIVKEY
curl -X PUT http://localhost:8012/servers/${SERVER_ID} \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "'${SERVER_NAME}'",
    "host": "'${SERVER_HOST}'",
    "ssh_username": "'${SERVER_USER}'",
    "ssh_password": "'${SERVER_PASSWORD}'"
  }'
