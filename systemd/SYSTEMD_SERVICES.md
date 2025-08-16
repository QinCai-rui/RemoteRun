# RemoteRun SystemD Services

This directory contains systemd service files for the RemoteRun application.

This README files is made by GitHub Copilot, with instructions from myself

## Services

### remoterun-celery.service
- Runs the Celery worker for background task processing
- Depends on Redis server
- Manages SSH command execution tasks

### remoterun-api.service  
- Runs the main FastAPI application
- Depends on the Celery worker service
- Provides the REST API endpoints

## Installation

1. Copy the environment file to `/etc/`:
   ```bash
   sudo cp remoterun.env /etc/remoterun.env
   sudo chmod 600 /etc/remoterun.env
   sudo chown root:root /etc/remoterun.env
   ```

2. Copy the service files to `/etc/systemd/system/`:
   ```bash
   sudo cp remoterun-*.service /etc/systemd/system/
   ```

3. Reload systemd to recognize the new services:

   ```bash
   sudo systemctl daemon-reload
   ```

4. Enable the services to start on boot:

   ```bash
   sudo systemctl enable remoterun-celery.service
   sudo systemctl enable remoterun-api.service
   ```

5. Start the services:

   ```bash
   sudo systemctl start remoterun-celery.service
   sudo systemctl start remoterun-api.service
   ```

## Configuration

Before installing, update the environment file `/etc/remoterun.env` with your specific configuration:

1. **Security Keys**: Generate secure values for:
   - `CMD_EXEC_SECRET_KEY` - Used for JWT token signing
   - `CMD_EXEC_FERNET_KEY` - Used for encrypting stored SSH credentials

2. **Database**: Update `DATABASE_URL` if not using SQLite or different path

3. **Redis**: Update `CELERY_BROKER_URL` and `CELERY_RESULT_BACKEND` if Redis is not on localhost

4. **File Permissions**: Ensure the environment file has proper permissions:
   ```bash
   sudo chmod 600 /etc/remoterun.env
   sudo chown root:root /etc/remoterun.env
   ```

You may also need to update the service files with:

1. **User/Group**: Change `www-data` to your preferred user/group
2. **Paths**: Update `WorkingDirectory` and `Environment=PATH` to match your installation

## Prerequisites

- Redis server installed and running
- Python virtual environment at `/home/qincai/RemoteRun/.venv`
- All Python dependencies installed in the virtual environment

## Management Commands

```bash
# Check service status
sudo systemctl status remoterun-api.service
sudo systemctl status remoterun-celery.service

# View logs
sudo journalctl -u remoterun-api.service -f
sudo journalctl -u remoterun-celery.service -f

# Restart services
sudo systemctl restart remoterun-api.service
sudo systemctl restart remoterun-celery.service

# Stop services
sudo systemctl stop remoterun-api.service
sudo systemctl stop remoterun-celery.service
```
