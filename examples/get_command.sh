#!/bin/bash
# Get details of a specific command
# Usage: set TOKEN and COMMAND_ID env vars
curl -X GET http://localhost:8012/commands/${COMMAND_ID} \
  -H "Authorization: Bearer ${TOKEN}"
