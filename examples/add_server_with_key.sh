#!/bin/bash
# Add a server using the test SSH private key
# need these environment variables before running:
# TOKEN, SERVER_NAME, SERVER_HOST, SERVER_USER

# Load the private key from file. this is mine
SERVER_PRIVKEY="$(cat /home/qincai/RemoteRun/examples/test_ed25519)"

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
