'''Main module for RemoteRun API (using FastAPI and SQLAlchemy).'''
# The SQL sections of this are created with help from GitHub Copilot
# and are not directly copied from any source.

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi import Request
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
import uuid
import paramiko
from cryptography.fernet import Fernet
import os
from celery import Celery

# load env variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), '.env'))

# --- Celery ---
celery_app = Celery(
    'remoterun',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./cmdexec.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Config ---
SECRET_KEY = os.getenv("CMD_EXEC_SECRET_KEY", "CHANGEME_SUPERSECRET_DEV_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Fernet encryption key for secrets (set in env for prod)
FERNET_KEY = os.getenv("CMD_EXEC_FERNET_KEY")
if not FERNET_KEY:
    # Generate a key for dev if not set (not secure for prod, ONLY USE IN DEV)
    FERNET_KEY = Fernet.generate_key().decode()
fernet = Fernet(FERNET_KEY.encode())

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Only these commands are allowed to run remotely (security reasons)
ALLOWED_COMMANDS = ["uptime", "df", "whoami", "cat", "ls", "uname", "free", "top", "ps"]

# --- SQL ---
class UserDB(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    servers = relationship("ServerDB", back_populates="owner")
    commands = relationship("CommandDB", back_populates="user")

class ServerDB(Base):
    __tablename__ = "servers"
    id = Column(String, primary_key=True, index=True)
    name = Column(String)
    host = Column(String)
    ssh_username = Column(String)
    ssh_password_enc = Column(String, nullable=True)  # base64-encoded ###################not secure for now#####################
    ssh_privkey_enc = Column(Text, nullable=True)     # base64-encoded PEM ###############not secure for now#####################
    owner_id = Column(String, ForeignKey("users.id"))
    owner = relationship("UserDB", back_populates="servers")
    commands = relationship("CommandDB", back_populates="server")

class CommandDB(Base):
    __tablename__ = "commands"
    id = Column(String, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id"))
    server_id = Column(String, ForeignKey("servers.id"))
    command = Column(String)
    status = Column(String)
    output = Column(Text)
    submitted_at = Column(DateTime)
    finished_at = Column(DateTime, nullable=True)
    user = relationship("UserDB", back_populates="commands")
    server = relationship("ServerDB", back_populates="commands")

Base.metadata.create_all(bind=engine)

# ---Pydantic Schemas. Errors were fixed by GitHub Copilot ---
class User(BaseModel):
    id: str
    username: str
    email: str
    class Config:
        from_attributes = True

class Server(BaseModel):
    id: str
    name: str
    host: str
    ssh_username: str
    class Config:
        from_attributes = True

class ServerCreate(BaseModel):
    name: str
    host: str
    ssh_username: str
    ssh_password: Optional[str] = None
    ssh_privkey: Optional[str] = None

class Command(BaseModel):
    id: str
    user_id: str
    server_id: str
    command: str
    status: str
    output: Optional[str] = ""
    submitted_at: datetime
    finished_at: Optional[datetime] = None
    class Config:
        from_attributes = True

class CommandCreate(BaseModel):
    server_id: str
    command: str

class Token(BaseModel):
    access_token: str
    token_type: str

# --- utils ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_user_by_username(db: Session, username: str):
    return db.query(UserDB).filter(UserDB.username == username).first()

def get_user(db: Session, user_id: str):
    return db.query(UserDB).filter(UserDB.id == user_id).first()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not isinstance(username, str):
            raise credentials_exception
        user = get_user_by_username(db, username)
        if user is None:
            raise credentials_exception
        return user
    except JWTError as exc:
        raise credentials_exception from exc

def encode_secret(s: str) -> str:
    return fernet.encrypt(s.encode("utf-8")).decode("utf-8") if s else ""

def decode_secret(s: str) -> str:
    return fernet.decrypt(s.encode("utf-8")).decode("utf-8") if s else ""

# --- SSH Command Execution ---
def run_ssh_command(server: ServerDB, command: str) -> str:
    # Only run allowlisted commands (safety reasons)
    import re
    # Allow any command that starts with a base command in ALLOWED_COMMANDS (with any options)
    allowed_bases = [cmd.split()[0] for cmd in ALLOWED_COMMANDS]
    if not any(re.match(rf'^{re.escape(base)}(\s|$)', command) for base in allowed_bases):
        raise ValueError("Command not in allowlist.")

    host_str = str(server.host)
    username = str(server.ssh_username)
    password = decode_secret(str(server.ssh_password_enc)) if getattr(server, 'ssh_password_enc', None) else None
    privkey = decode_secret(str(server.ssh_privkey_enc)) if getattr(server, 'ssh_privkey_enc', None) else None
    
    # Debug: print the key format (this is very much needed in dev for me)
    if privkey:
        print(f"DEBUG: Private key length: {len(privkey)}")
        print(f"DEBUG: Key starts with: {repr(privkey[:50])}")
        print(f"DEBUG: Key ends with: {repr(privkey[-50:])}")
        print(f"DEBUG: Has newlines: {chr(10) in privkey}")

    # Parse host and port
    if ':' in host_str:
        host, port = host_str.split(':', 1)
        port = int(port)
    else:
        host = host_str
        port = 22

    import io
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if privkey:
            # Always treat stored keys as key content (not file paths)
            pkey = None
            
            # Try Ed25519 first
            try:
                pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(privkey))
            except Exception as ed25519_err:
                # Fall back to RSA
                try:
                    pkey = paramiko.RSAKey.from_private_key(io.StringIO(privkey))
                except Exception as rsa_err:
                    # Fall back to ECDSA
                    try:
                        pkey = paramiko.ECDSAKey.from_private_key(io.StringIO(privkey))
                    except Exception as ecdsa_err:
                        # Skip DSS as it's not available in newer paramiko versions
                        raise ValueError(f"Could not load SSH private key. Tried Ed25519: {ed25519_err}, RSA: {rsa_err}, ECDSA: {ecdsa_err}")
            
            if not pkey:
                raise ValueError("Could not load SSH private key")
            client.connect(hostname=host, port=port, username=username, pkey=pkey, timeout=6)
        elif password:
            client.connect(hostname=host, port=port, username=username, password=password, timeout=6)
        else:
            raise ValueError("No authentication found for SSH.")
        _stdin, stdout, stderr = client.exec_command(command, timeout=10)
        stdout.channel.settimeout(10.0)  # Set timeout for reading
        stderr.channel.settimeout(10.0)
        try:
            out = stdout.read().decode()
            err = stderr.read().decode()
            return (out + ("\n" + err if err else "")).strip()
        except Exception:
            # If reading fails due to timeout, try to get partial output
            stdout.channel.settimeout(1.0)
            stderr.channel.settimeout(1.0)
            try:
                out = stdout.read().decode()
                err = stderr.read().decode()
                return (out + ("\n" + err if err else "")).strip()
            except Exception:
                return "Command timed out or connection lost"
    finally:
        client.close()

# --- FastAPI app ---
app = FastAPI(title="Remote Command Executor API (SSH)")

# --- Rate Limiting ---
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(429, _rate_limit_exceeded_handler)

# --- Auth Endpoints ---
@app.post("/auth/register", response_model=Token)
@limiter.limit("5/minute")
def register(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    if get_user_by_username(db, form.username):
        raise HTTPException(status_code=400, detail="Username already registered")
    user_id = str(uuid.uuid4())
    hashed_password = get_password_hash(form.password)
    user = UserDB(id=user_id, username=form.username, email=form.username, hashed_password=hashed_password)
    db.add(user)
    db.commit()
    db.refresh(user)
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/auth/login", response_model=Token)
@limiter.limit("15/minute")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_username(db, form.username)
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Server Endpoints ---
@app.post("/servers", response_model=Server)
@limiter.limit("20/minute")
def add_server(request: Request, server: ServerCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    server_id = str(uuid.uuid4())
    ssh_password_enc = encode_secret(server.ssh_password) if server.ssh_password else ""
    ssh_privkey_enc = encode_secret(server.ssh_privkey) if server.ssh_privkey else ""
    db_server = ServerDB(
        id=server_id,
        name=server.name,
        host=server.host,
        ssh_username=server.ssh_username,
        ssh_password_enc=ssh_password_enc,
        ssh_privkey_enc=ssh_privkey_enc,
        owner_id=current_user.id
    )
    db.add(db_server)
    db.commit()
    db.refresh(db_server)
    return db_server

@app.get("/servers", response_model=List[Server])
def list_servers(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    servers = db.query(ServerDB).filter(ServerDB.owner_id == current_user.id).all()
    return servers

@app.put("/servers/{server_id}", response_model=Server)
def update_server(server_id: str, server: ServerCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_server = db.query(ServerDB).filter(ServerDB.id == server_id, ServerDB.owner_id == current_user.id).first()
    if not db_server:
        raise HTTPException(status_code=404, detail="Server not found or unauthorized")
    db_server.name = server.name
    db_server.host = server.host
    db_server.ssh_username = server.ssh_username
    if server.ssh_password:
        db_server.ssh_password_enc = encode_secret(server.ssh_password)
    if server.ssh_privkey:
        db_server.ssh_privkey_enc = encode_secret(server.ssh_privkey)
    db.commit()
    db.refresh(db_server)
    return db_server

@app.delete("/servers/{server_id}")
def delete_server(server_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_server = db.query(ServerDB).filter(ServerDB.id == server_id, ServerDB.owner_id == current_user.id).first()
    if not db_server:
        raise HTTPException(status_code=404, detail="Server not found or unauthorized")
    db.delete(db_server)
    db.commit()
    return {"detail": "Server deleted"}

# --- Command Endpoints ---
@app.post("/commands", response_model=Command)
@limiter.limit("30/minute")
def submit_command(request: Request, cmd: CommandCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    import re
    allowed_bases = [cmd.split()[0] for cmd in ALLOWED_COMMANDS]
    if not any(re.match(rf'^{re.escape(base)}(\s|$)', cmd.command) for base in allowed_bases):
        raise HTTPException(status_code=400, detail="Command not allowed")
    db_server = db.query(ServerDB).filter(ServerDB.id == cmd.server_id, ServerDB.owner_id == current_user.id).first()
    if not db_server:
        raise HTTPException(status_code=404, detail="Server not found or unauthorized")
    cmd_id = str(uuid.uuid4())
    now = datetime.utcnow()
    db_cmd = CommandDB(
        id=cmd_id,
        user_id=current_user.id,
        server_id=cmd.server_id,
        command=cmd.command,
        status="pending",
        output="",
        submitted_at=now,
        finished_at=None
    )
    db.add(db_cmd)
    db.commit()
    db.refresh(db_cmd)

    # Schedule SSH execution in Celery
    celery_app.send_task('main.execute_and_store_ssh', args=[str(db_cmd.id)])
    return db_cmd

@celery_app.task
def execute_and_store_ssh(command_id: str):
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

@app.get("/commands", response_model=List[Command])
@limiter.limit("60/minute")
def list_commands(request: Request, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    cmds = db.query(CommandDB).filter(CommandDB.user_id == current_user.id).order_by(CommandDB.submitted_at.desc()).all()
    return cmds

@app.get("/commands/{command_id}", response_model=Command)
def get_command(command_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_cmd = db.query(CommandDB).filter(CommandDB.id == command_id, CommandDB.user_id == current_user.id).first()
    if not db_cmd:
        raise HTTPException(status_code=404, detail="Command not found or unauthorized")
    return db_cmd

@app.put("/commands/{command_id}", response_model=Command)
def update_command(command_id: str, status: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_cmd = db.query(CommandDB).filter(CommandDB.id == command_id, CommandDB.user_id == current_user.id).first()
    if not db_cmd:
        raise HTTPException(status_code=404, detail="Command not found or unauthorized")
    db_cmd.status = status
    db.commit()
    db.refresh(db_cmd)
    return db_cmd

@app.delete("/commands/{command_id}")
def delete_command(command_id: str, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
    db_cmd = db.query(CommandDB).filter(CommandDB.id == command_id, CommandDB.user_id == current_user.id).first()
    if not db_cmd:
        raise HTTPException(status_code=404, detail="Command not found or unauthorized")
    db.delete(db_cmd)
    db.commit()
    return {"detail": "Command deleted"}

# --- Allowlist endpoint ---
@app.get("/allowlist", response_model=List[str])
def get_allowlist(current_user: UserDB = Depends(get_current_user)):
    return ALLOWED_COMMANDS

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8013, reload=True)