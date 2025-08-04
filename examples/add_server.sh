#!/bin/bash
curl -X POST http://localhost:8012/servers \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "name": "${SERVER_NAME}",
  "host": "${SERVER_HOST}",
  "ssh_username": "${SERVER_USER}",
  "ssh_privkey": "${SERVER_PRIVKEY}"
}
EOF