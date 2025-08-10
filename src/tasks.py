from celery_app import celery_app
from datetime import datetime
import sys
import os

# Add the src directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

@celery_app.task
def execute_and_store_ssh(command_id: str):
    # Import here to avoid circular imports
    from main import SessionLocal, CommandDB, ServerDB, run_ssh_command
    
    db = SessionLocal()
    try:
        db_cmd = db.query(CommandDB).filter(CommandDB.id == command_id).first()
        if not db_cmd:
            db.close()
            return
        db_server = db.query(ServerDB).filter(ServerDB.id == db_cmd.server_id).first()
        if not db_server:
            db_cmd.status = "failed"
            db_cmd.output = "Server not found"
            db_cmd.finished_at = datetime.utcnow()
            db.commit()
            db.close()
            return
        try:
            db_cmd.status = "running"
            db.commit()
            db.refresh(db_cmd)
            output = run_ssh_command(db_server, str(db_cmd.command))
            db_cmd.output = output
            db_cmd.status = "completed"
        except Exception as e:
            import traceback
            error_msg = str(e) if str(e) else f"Unknown error: {type(e).__name__}"
            db_cmd.output = f"Error: {error_msg}\nTraceback: {traceback.format_exc()}"
            db_cmd.status = "failed"
        db_cmd.finished_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()
