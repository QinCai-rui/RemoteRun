#!/bin/bash
# List your servers (replace TOKEN with your JWT)
curl -X GET http://localhost:8012/servers \
  -H "Authorization: Bearer TOKEN"
