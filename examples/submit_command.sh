#!/bin/bash
# Submit a command to run on a server
# Usage: set TOKEN, SERVER_ID, and COMMAND env vars
curl -X POST http://localhost:8012/commands \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "server_id": "'${SERVER_ID}'",
    "command": "'${COMMAND}'"
  }'
