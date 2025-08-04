#!/bin/bash
# Delete a command (replace TOKEN and COMMAND_ID)
curl -X DELETE http://localhost:8012/commands/COMMAND_ID \
  -H "Authorization: Bearer TOKEN"
