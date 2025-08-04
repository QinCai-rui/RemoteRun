#!/bin/bash
# Log in and get a JWT token
# Usage: set USERNAME and PASSWORD env vars
curl -X POST \
  -F "username=${USERNAME}" \
  -F "password=${PASSWORD}" \
  http://localhost:8012/auth/login
