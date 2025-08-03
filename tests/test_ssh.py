#!/usr/bin/env python3
# this is to test in github codespaces. quality is bad, but it works.


import requests
import os
import time

BASE_URL = "http://localhost:8000"

# Login
r = requests.post(f"{BASE_URL}/auth/login", data={"username": "testuser", "password": "testpass"})
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print("Token OK")

# Read SSH key
with open(os.path.expanduser("~/.ssh/test_key")) as f:
    key = f.read()

# Add server
srv = {
    "name": "localhost",
    "host": "localhost:2222",
    "ssh_username": "codespace",
    "ssh_privkey": key
}
r = requests.post(f"{BASE_URL}/servers", headers=headers, json=srv)
server_id = r.json()["id"]
print("Server added")

# Run commands
for cmd in ["whoami", "uptime", "uname -a"]:
    r = requests.post(f"{BASE_URL}/commands", headers=headers, json={"server_id": server_id, "command": cmd})
    cmd_id = r.json()["id"]
    print(f"Ran: {cmd}")
    time.sleep(2)
    r = requests.get(f"{BASE_URL}/commands/{cmd_id}", headers=headers)
    print(r.json()["output"])