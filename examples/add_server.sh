#!/bin/bash
# Add a new server (replace _TOKEN_ with your JWT, and other values as needed)
curl -X POST http://localhost:8012/servers \
  -H "Authorization: Bearer _TOKEN_" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "this-is-my-server-yaya",
    "host": "192.168.1.100",
    "ssh_username": "user",
    "ssh_password": "linux on top"
  }'
