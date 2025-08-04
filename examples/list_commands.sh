#!/bin/bash
# List your command history (replace TOKEN)
curl -X GET http://localhost:8012/commands \
  -H "Authorization: Bearer TOKEN"
