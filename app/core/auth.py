"""
Authentication module for AI-SOC
==================================
Provides:
  - JWT Bearer token auth  (for browser / Swagger UI users)
  - Static API key auth    (for the log-agent internal service)

Two built-in accounts are seeded at startup from environment variables:
  ADMIN_PASSWORD  → 'admin'   account  (full access)
  ANALYST_PASSWORD → 'analyst' account (read + alert management)

Usage in route handlers:
  require_auth  = accepts EITHER a valid JWT OR a valid API key
  require_jwt   = accepts ONLY a valid JWT  (human users)
"""
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Security, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
    APIKeyHeader,
)
from jose import JWTError, jwt
import bcrypt as _bcrypt
from pydantic import BaseModel

from app.core.config import get_settings

settings = get_settings()

# ── Crypto helpers ────────────────────────────────────────────────────────────
# NOTE: passlib 1.7.4 is incompatible with bcrypt>=5.0.0 — use bcrypt directly.

def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return _bcrypt.checkpw(plain.encode(), hashed.encode())

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# ── Built-in users (resolved from settings at import time) ────────────────────

def _make_users():
    return {
        "admin": {
            "username": "admin",
            "hashed_password": hash_password(settings.admin_password),
            "role": "admin",
        },
        "analyst": {
            "username": "analyst",
            "hashed_password": hash_password(settings.analyst_password),
            "role": "analyst",
        },
    }

# Lazy-initialised so tests can override env vars before import
_USERS: Optional[dict] = None

def _users() -> dict:
    global _USERS
    if _USERS is None:
        _USERS = _make_users()
    return _USERS


# ── Token helpers ─────────────────────────────────────────────────────────────

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    username: str
    role: str


def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    payload["exp"] = expire
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def _verify_jwt(token: str) -> TokenData:
    """Decode and validate a JWT, return TokenData or raise 401."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: str = payload.get("sub")
        role: str = payload.get("role", "analyst")
        if username is None:
            raise ValueError("missing sub")
        return TokenData(username=username, role=role)
    except (JWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── Dependencies ──────────────────────────────────────────────────────────────

def require_jwt(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
) -> TokenData:
    """Dependency: requires a valid JWT Bearer token."""
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _verify_jwt(credentials.credentials)


def require_auth(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_scheme),
    api_key: Optional[str] = Security(api_key_header),
) -> TokenData:
    """Dependency: accepts EITHER a valid JWT OR a valid API key.

    The log-agent uses the API key so it never needs to manage token refresh.
    Human users (browser / Swagger) use JWT Bearer tokens.
    """
    # Try API key first (log agent path)
    if api_key and api_key == settings.api_key:
        return TokenData(username="log-agent", role="agent")

    # Fall back to JWT (human user path)
    if credentials and credentials.scheme.lower() == "bearer":
        return _verify_jwt(credentials.credentials)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required — provide a Bearer token or X-API-Key header",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── Auth router ───────────────────────────────────────────────────────────────

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login", response_model=Token, summary="Obtain a JWT access token")
async def login(body: LoginRequest):
    """
    Authenticate with username + password → returns a signed JWT.

    Built-in accounts:
    - **admin** — full access (train models, manage alerts)
    - **analyst** — alert management only

    Passwords are set via ADMIN_PASSWORD / ANALYST_PASSWORD env vars.
    """
    user = _users().get(body.username)
    if not user or not verify_password(body.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return Token(
        access_token=token,
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.get("/me", summary="Get current user info")
async def me(current_user: TokenData = Depends(require_jwt)):
    """Return info about the currently authenticated user."""
    return {"username": current_user.username, "role": current_user.role}
