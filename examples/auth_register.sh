#!/bin/bash
# Register a new user
curl -X POST \
  -F "username=testuser" \
  -F "password=testpwd" \
  http://localhost:8012/auth/register
