#!/bin/bash
# Complete end-to-end test of RemoteRun API with SSH key
# This is 70% made by GitHub Copilot

set -e  # Exit on any error
trap 'echo "❌ Script failed at line $LINENO. Exit code: $?"; exit $?' ERR

echo "=== RemoteRun Full Test ==="

# Configuration
export USERNAME="testuser"
export PASSWORD="testpass123"
export SERVER_NAME="hackclub nest"
export SERVER_HOST="hackclub.app"  
export SERVER_USER="qincai"    
export COMMAND="uptime"

# Set the Fernet key
export CMD_EXEC_FERNET_KEY="IJdqfc8AfSVQzHk28Ntargel6IyUCS3uqtlZtQWmQjE="

echo "1. Trying to authenticate..."
# Try login first with existing user
LOGIN_RESPONSE=$(curl -s -X POST \
  -F "username=${USERNAME}" \
  -F "password=${PASSWORD}" \
  http://localhost:8012/auth/login)

echo "Login response: $LOGIN_RESPONSE"
export TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

# If login failed, try registration with unique username
if [ "$TOKEN" = "null" ]; then
    echo "Login failed, trying registration..."
    export USERNAME="testuser$(date +%s)"  # Add timestamp to make it unique
    REGISTER_RESPONSE=$(curl -s -X POST \
      -F "username=${USERNAME}" \
      -F "password=${PASSWORD}" \
      http://localhost:8012/auth/register)
    echo "Register response: $REGISTER_RESPONSE"
    export TOKEN=$(echo "$REGISTER_RESPONSE" | jq -r '.access_token')
fi

echo "Got token: ${TOKEN:0:20}..."

echo "2. Loading SSH private key..."
# Load and format SSH private key with proper JSON escaping (convert newlines to \n)
export SERVER_PRIVKEY="$(cat /home/qincai/RemoteRun/examples/test_ed25519 | sed ':a;N;$!ba;s/\n/\\n/g')"
echo "Key loaded, length: ${#SERVER_PRIVKEY} characters"

echo "3. Adding server with SSH key..."
ADD_SERVER_RESPONSE=$(curl -s -X POST http://localhost:8012/servers \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "name": "${SERVER_NAME}",
  "host": "${SERVER_HOST}",
  "ssh_username": "${SERVER_USER}",
  "ssh_privkey": "${SERVER_PRIVKEY}"
}
EOF
)

echo "Add server response: $ADD_SERVER_RESPONSE"

# Extract server ID
export SERVER_ID=$(echo "$ADD_SERVER_RESPONSE" | jq -r '.id')
echo "Got server ID: $SERVER_ID"

echo "4. Submitting command..."
SUBMIT_RESPONSE=$(curl -s -X POST http://localhost:8012/commands \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "server_id": "${SERVER_ID}",
  "command": "${COMMAND}"
}
EOF
)

echo "Submit response: $SUBMIT_RESPONSE"

# Extract command ID
export COMMAND_ID=$(echo "$SUBMIT_RESPONSE" | jq -r '.id')
echo "Got command ID: $COMMAND_ID"

echo "5. Waiting 3 seconds for command to execute..."
sleep 3

echo "6. Checking command result..."
ATTEMPTS=(0.5 1 2)  # wait times in seconds. first wait 0.5 sec, then 1 sec, then 2 secs, then FAIL
RESULT_RESPONSE=""
STATUS=""
for WAIT in "${ATTEMPTS[@]}"; do
  RESULT_RESPONSE=$(curl -s -X GET http://localhost:8012/commands/${COMMAND_ID} \
    -H "Authorization: Bearer ${TOKEN}")
  STATUS=$(echo "$RESULT_RESPONSE" | jq -r '.status')
  if [ "$STATUS" = "completed" ]; then
    break
  fi
  echo "Not completed yet (status: $STATUS), waiting $WAIT sec..."
  sleep $WAIT
done

echo "=== FINAL RESULT ==="
echo "$RESULT_RESPONSE" | jq .

# Check if successful

if [ "$STATUS" = "completed" ]; then
    echo "✅ SUCCESS: Command executed successfully!"
    OUTPUT=$(echo "$RESULT_RESPONSE" | jq -r '.output')
    echo "Command output: $OUTPUT"
else
    echo "❌ FAILED: Command status is $STATUS"
    ERROR=$(echo "$RESULT_RESPONSE" | jq -r '.output')
    echo "Error: $ERROR"
    exit 1
fi
