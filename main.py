# The SQL sections of this are created with help from GitHub Copilot
# and are not directly copied from any source.

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
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
import base64
import os

DATABASE_URL = "sqlite:///./cmdexec.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

SECRET_KEY = os.getenv("CMD_EXEC_SECRET_KEY", "CHANGEME_SUPERSECRET_DEV_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Only these commands are allowed to run remotely (security resons)
ALLOWED_COMMANDS = ["uptime", "df -h", "whoami", "cat /etc/os-release", "uname -a", "free -h", "top -h"]

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

# ---Pydantic Schemas ---
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
    return base64.b64encode(s.encode("utf-8")).decode("utf-8") if s else ""

def decode_secret(s: str) -> str:
    return base64.b64decode(s).decode("utf-8") if s else ""

# --- SSH Command Execution ---
def run_ssh_command(server: ServerDB, command: str) -> str:
    # Only run allowlisted commands (safety reasons)
    if command not in ALLOWED_COMMANDS:
        raise ValueError("Command not in allowlist.")

    host = server.host if not hasattr(server.host, 'expression') else server.host.__str__()
    username = server.ssh_username if not hasattr(server.ssh_username, 'expression') else server.ssh_username.__str__()
    password = decode_secret(server.ssh_password_enc) if getattr(server, 'ssh_password_enc', None) else None
    privkey = decode_secret(server.ssh_privkey_enc) if getattr(server, 'ssh_privkey_enc', None) else None

    import io
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if privkey:
            if os.path.exists(privkey):
                pkey = paramiko.RSAKey.from_private_key_file(privkey)
            else:
                pkey = paramiko.RSAKey.from_private_key(io.StringIO(privkey))
            client.connect(hostname=host, username=username, pkey=pkey, timeout=6)
        elif password:
            client.connect(hostname=host, username=username, password=password, timeout=6)
        else:
            raise ValueError("No authentication found for SSH.")
        _stdin, stdout, stderr = client.exec_command(command)
        out = stdout.read().decode()
        err = stderr.read().decode()
        return (out + ("\n" + err if err else "")).strip()
    finally:
        client.close()

# --- FastAPI app ---
app = FastAPI(title="Remote Command Executor API (Real SSH)")

# --- Auth Endpoints ---
@app.post("/auth/register", response_model=Token)
def register(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_username(db, form.username)
    if not user or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# --- Server Endpoints ---
@app.post("/servers", response_model=Server)
def add_server(server: ServerCreate, current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
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
def submit_command(
    cmd: CommandCreate,
    background_tasks: BackgroundTasks,
    current_user: UserDB = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if cmd.command not in ALLOWED_COMMANDS:
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

    # Schedule real SSH execution in background
    background_tasks.add_task(execute_and_store_ssh, db_cmd.id)
    return db_cmd

def execute_and_store_ssh(command_id: str):
    # For use in background task (has its own DB session)
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
            output = run_ssh_command(db_server, db_cmd.command)
            db_cmd.output = output
            db_cmd.status = "completed"
        except Exception as e:
            db_cmd.output = f"Error: {e}"
            db_cmd.status = "failed"
        db_cmd.finished_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()

@app.get("/commands", response_model=List[Command])
def list_commands(current_user: UserDB = Depends(get_current_user), db: Session = Depends(get_db)):
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