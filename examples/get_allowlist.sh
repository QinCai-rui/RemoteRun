#!/bin/bash
# Get the list of allowed commands (replace TOKEN)
curl -X GET http://localhost:8012/allowlist \
  -H "Authorization: Bearer TOKEN"
