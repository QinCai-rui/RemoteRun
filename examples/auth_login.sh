#!/bin/bash
# Log in and get a JWT token
curl -X POST \
  -F "username=testuser" \
  -F "password=testpwd" \
  http://localhost:8012/auth/login
