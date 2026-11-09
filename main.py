
import os
import secrets
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from jose import jwt, JWTError

# CONFIGURATION
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./golden.db")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SECRET_KEY = os.getenv("SECRET_KEY", "development-only-change-before-deployment")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
    if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

app = FastAPI(title="GOLDEN ROUTINE AI")
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)

# DATABASE TABLES
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    email = Column(String(200), unique=True, index=True)
    password_hash = Column(String(300))
    role = Column(String(20), default="user")
    blocked = Column(Integer, default=0)

class Task(Base):
    __tablename__ = "tasks"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String(200))
    category = Column(String(80))
    task_date = Column(String(20))
    completed = Column(Integer, default=0)

Base.metadata.create_all(bind=engine)

# DATABASE SESSION
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# PASSWORD SECURITY
def hash_password(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 200000
    ).hex()
    return salt + "$" + digest

def verify_password(password, stored):
    try:
        salt, digest = stored.split("$")
        check = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 200000
        ).hex()
        return secrets.compare_digest(check, digest)
    except Exception:
        return False

# LOGIN TOKENS
def create_token(user):
    payload = {
        "sub": str(user.id),
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    try:
        data = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=["HS256"]
        )
        user = db.query(User).filter(User.id == int(data["sub"])).first()
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401, "Invalid or expired login")

    if not user or user.blocked:
        raise HTTPException(403, "Account unavailable")
    return user

def admin_only(user=Depends(current_user)):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")
    return user

# REQUEST MODELS
class RegisterData(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginData(BaseModel):
    email: EmailStr
    password: str

class TaskData(BaseModel):
    title: str
    category: str = "General"
    task_date: str

# BASIC ROUTES
from fastapi.responses import FileResponse

@app.get("/")
def home():
    return FileResponse("index.html")

@app.get("/health")
def health():
    return {"status": "healthy"}

# REGISTER
@app.post("/register")
def register(data: RegisterData, db: Session = Depends(get_db)):
    if len(data.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")

    email = str(data.email).lower()
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(400, "Email already registered")

    user = User(
        name=data.name,
        email=email,
        password_hash=hash_password(data.password),
        role="user"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"token": create_token(user), "name": user.name}

# LOGIN
@app.post("/login")
def login(data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(
        User.email == str(data.email).lower()
    ).first()

    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Incorrect email or password")

    if user.blocked:
        raise HTTPException(403, "Account blocked")

    return {
        "token": create_token(user),
        "name": user.name,
        "role": user.role
    }

@app.get("/me")
def me(user=Depends(current_user)):
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role
    }

# PRIVATE USER TASKS
@app.post("/tasks")
def add_task(
    data: TaskData,
    user=Depends(current_user),
    db: Session = Depends(get_db)
):
    task = Task(
        user_id=user.id,
        title=data.title,
        category=data.category,
        task_date=data.task_date
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return {"message": "Task saved", "id": task.id}

@app.get("/tasks")
def my_tasks(user=Depends(current_user), db: Session = Depends(get_db)):
    tasks = db.query(Task).filter(Task.user_id == user.id).all()
    return [
        {
            "id": t.id,
            "title": t.title,
            "category": t.category,
            "date": t.task_date,
            "completed": bool(t.completed)
        }
        for t in tasks
    ]

@app.patch("/tasks/{task_id}/complete")
def complete_task(
    task_id: int,
    user=Depends(current_user),
    db: Session = Depends(get_db)
):
    task = db.query(Task).filter(
        Task.id == task_id,
        Task.user_id == user.id
    ).first()

    if not task:
        raise HTTPException(404, "Task not found")

    task.completed = 1
    db.commit()
    return {"message": "Task completed"}

# ADMIN DASHBOARD API
@app.get("/admin/users")
def admin_users(
    admin=Depends(admin_only),
    db: Session = Depends(get_db)
):
    users = db.query(User).all()
    return [
        {
            "id": u.id,
            "name": u.name,
            "email": u.email,
            "role": u.role,
            "blocked": bool(u.blocked)
        }
        for u in users
    ]

@app.patch("/admin/users/{user_id}/block")
def block_user(
    user_id: int,
    admin=Depends(admin_only),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user or user.role == "admin":
        raise HTTPException(404, "User not found")
    user.blocked = 1
    db.commit()
    return {"message": "User blocked"}

@app.patch("/admin/users/{user_id}/unblock")
def unblock_user(
    user_id: int,
    admin=Depends(admin_only),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(404, "User not found")
    user.blocked = 0
    db.commit()
    return {"message": "User unblocked"}

# CREATE ADMIN FROM HOSTING ENVIRONMENT
@app.on_event("startup")
def create_admin():
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return

    db = SessionLocal()
    try:
        existing = db.query(User).filter(
            User.email == ADMIN_EMAIL
        ).first()

        if not existing:
            db.add(User(
                name="Administrator",
                email=ADMIN_EMAIL,
                password_hash=hash_password(ADMIN_PASSWORD),
                role="admin"
            ))
            db.commit()
    finally:
        db.close()
