import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_PATH", "users.db")
SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_THIS_DEVELOPMENT_SECRET_BEFORE_DEPLOYMENT")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(
    title="SecureAuth API",
    description="User registration, JWT login, protected routes, and role-based access control.",
    version="1.0.0",
)

password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# -------------------------------------------------------------------
# Database helpers (SQLite)
# -------------------------------------------------------------------
@contextmanager
def get_connection():
    connection = sqlite3.connect(DATABASE_URL)
    connection.row_factory = sqlite3.Row
    try:
        yield connection
    finally:
        connection.close()


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                hashed_password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            )
        """)
        connection.commit()


@app.on_event("startup")
def startup_event():
    initialize_database()
    create_admin_from_environment()


def create_admin_from_environment():
    """Optionally create the first admin using environment variables."""
    username = os.getenv("ADMIN_USERNAME")
    password = os.getenv("ADMIN_PASSWORD")
    email = os.getenv("ADMIN_EMAIL", "admin@example.com")

    if not username or not password:
        return

    with get_connection() as connection:
        existing = connection.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if existing:
            return

        hashed_password = password_context.hash(password)
        try:
            connection.execute(
                """INSERT INTO users
                   (username, email, hashed_password, role, created_at)
                   VALUES (?, ?, ?, 'admin', ?)""",
                (username, email, hashed_password, datetime.now(timezone.utc).isoformat()),
            )
            connection.commit()
        except sqlite3.IntegrityError:
            # The email or username may already belong to another account.
            pass


# -------------------------------------------------------------------
# Pydantic request/response models
# -------------------------------------------------------------------
class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class UserResponse(BaseModel):
    id: int
    username: str
    email: EmailStr
    role: str
    created_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


# -------------------------------------------------------------------
# Password and user helpers
# -------------------------------------------------------------------
def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_context.verify(plain_password, hashed_password)


def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    with get_connection() as connection:
        return connection.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()


def public_user(user: sqlite3.Row) -> dict:
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "created_at": user["created_at"],
    }


# -------------------------------------------------------------------
# JWT helpers
# -------------------------------------------------------------------
def create_access_token(subject: str) -> str:
    expires_at = datetime.now(timezone.utc) + timedelta(
        minutes=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {"sub": subject, "exp": expires_at}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = get_user_by_username(username)
    if user is None:
        raise credentials_exception
    return user


def require_admin(current_user=Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


# -------------------------------------------------------------------
# API endpoints
# -------------------------------------------------------------------
@app.get("/")
def home():
    return {
        "message": "Welcome to SecureAuth API",
        "docs": "/docs",
        "available_endpoints": [
            "POST /register",
            "POST /login",
            "GET /users/me",
            "GET /protected",
            "GET /admin/users",
        ],
    }


@app.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreate):
    if get_user_by_username(user_data.username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered",
        )

    with get_connection() as connection:
        existing_email = connection.execute(
            "SELECT id FROM users WHERE email = ?", (str(user_data.email),)
        ).fetchone()
        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered",
            )

        created_at = datetime.now(timezone.utc).isoformat()
        hashed_password = hash_password(user_data.password)

        try:
            cursor = connection.execute(
                """INSERT INTO users
                   (username, email, hashed_password, role, created_at)
                   VALUES (?, ?, ?, 'user', ?)""",
                (user_data.username, str(user_data.email), hashed_password, created_at),
            )
            connection.commit()
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already registered",
            )

    return {
        "id": user_id,
        "username": user_data.username,
        "email": str(user_data.email),
        "role": "user",
        "created_at": created_at,
    }


@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user_by_username(form_data.username)

    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user["username"])
    return {"access_token": token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserResponse)
def read_my_profile(current_user=Depends(get_current_user)):
    return public_user(current_user)


@app.get("/protected")
def protected_route(current_user=Depends(get_current_user)):
    return {
        "message": "You have successfully accessed protected data.",
        "authenticated_user": current_user["username"],
        "role": current_user["role"],
    }


@app.get("/admin/users")
def list_all_users(admin_user=Depends(require_admin)):
    with get_connection() as connection:
        users = connection.execute(
            """SELECT id, username, email, role, created_at
               FROM users ORDER BY id"""
        ).fetchall()

    return {
        "message": "Admin access granted",
        "requested_by": admin_user["username"],
        "users": [public_user(user) for user in users],
    }
