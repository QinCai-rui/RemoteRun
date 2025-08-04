#!/bin/bash
# Register a new user
# Usage: set USERNAME and PASSWORD env vars
curl -X POST \
  -F "username=${USERNAME}" \
  -F "password=${PASSWORD}" \
  http://localhost:8012/auth/register
