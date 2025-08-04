#!/bin/bash
# Delete a command
# Usage: set TOKEN and COMMAND_ID env vars
curl -X DELETE http://localhost:8012/commands/${COMMAND_ID} \
  -H "Authorization: Bearer ${TOKEN}"
