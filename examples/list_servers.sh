#!/bin/bash
# List your servers
# Usage: set TOKEN env var
curl -X GET http://localhost:8012/servers \
  -H "Authorization: Bearer ${TOKEN}"
