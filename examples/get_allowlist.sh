#!/bin/bash
# Get the list of allowed commands
# Usage: set TOKEN env var
curl -X GET http://localhost:8012/allowlist \
  -H "Authorization: Bearer ${TOKEN}"
