# RemoteRun: Remote Command Executor API

RemoteRun is a FastAPI-based web service that lets you securely manage remote servers and execute (allowlisted) shell commands over SSH. 

## Features

TODO

## Demo

[Video Demo](https://go.qincai.xyz/remoterun-demo-vid)

## Quick Start

1. **Install dependencies**:

   ```bash
   pip install -r src/requirements.txt
   ```

2. **Run the server**:

   ```bash
   cd src
   uvicorn main:app --reload --host 0.0.0.0 --port 8013
   ```

   or

   ```bash
   python3 src/main.py
   ```

3. **Access the API docs**: Open [http://localhost:8013/docs](http://localhost:8013/docs) in your browser.

## API Overview. See API docs for more.

- `POST /auth/register` — Register a new user
- `POST /auth/login` — Obtain a JWT token
- `POST /servers` — Add a new server
- `GET /servers` — List your servers
- `PUT /servers/{server_id}` — Update a server
- `DELETE /servers/{server_id}` — Delete a server
- `POST /commands` — Submit a command to run on a server
- `GET /commands` — List your command history
- `GET /commands/{command_id}` — Get details of a specific command
- `GET /allowlist` — See which commands are allowed

## License

See [LICENSE](LICENSE) for details.
