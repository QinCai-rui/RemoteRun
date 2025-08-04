#!/bin/bash
# List your command history
# Usage: set TOKEN env var
curl -X GET http://localhost:8012/commands \
  -H "Authorization: Bearer ${TOKEN}"
