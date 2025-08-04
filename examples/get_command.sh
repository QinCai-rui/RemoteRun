#!/bin/bash
# Get details of a specific command (Replace TOKEN and COMMAND_ID)
curl -X GET http://localhost:8012/commands/COMMAND_ID \
  -H "Authorization: Bearer TOKEN"
