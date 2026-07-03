"""
JWT + password utilities.

Security design:
 - Access token:  short-lived (30 min), signed HS256 JWT
 - Refresh token: long-lived (30 days), stored as bcrypt hash in DB
 - Both delivered as httpOnly, Secure, SameSite=Strict cookies
 - Refresh token rotation on every use (old token revoked)
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from backend.config import get_settings
from backend.models import RefreshToken, User

settings = get_settings()


# ── Password hashing ─────────────────────────────────────────────────────────

# Pre-computed bcrypt hash of a random string.
# Used in login when the email doesn't exist so we always run bcrypt,
# making response time identical regardless of whether the email is registered.
DUMMY_HASH = "$2b$12$WNdqBFPQqYGPY6P2T.BjmelMjPOivSMiDzVYmNDk9bOBM.a9SGKXO"


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


# ── Access token ──────────────────────────────────────────────────────────────

def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub":  user_id,
        "exp":  expire,
        "iat":  datetime.now(timezone.utc),
        "type": "access",
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> str | None:
    """Return user_id on success, None on any failure."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload.get("sub")
    except JWTError:
        return None


# ── Refresh token ─────────────────────────────────────────────────────────────

def _hash_token(raw: str) -> str:
    """SHA-256 hash for DB storage (never store raw refresh token)."""
    return hashlib.sha256(raw.encode()).hexdigest()


def create_refresh_token(user_id: str, db: Session) -> str:
    raw = secrets.token_urlsafe(48)
    token_hash = _hash_token(raw)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    db_token = RefreshToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(db_token)
    db.commit()
    return raw


def rotate_refresh_token(raw: str, db: Session) -> tuple[str, str] | None:
    """
    Validate old refresh token, revoke it, and issue new access + refresh tokens.
    Returns (new_access_token, new_refresh_token) or None if invalid.
    """
    token_hash = _hash_token(raw)
    record = db.query(RefreshToken).filter_by(token_hash=token_hash, is_revoked=False).first()

    if not record:
        return None
    if record.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        return None

    # Revoke old token (rotation)
    record.is_revoked = True
    db.commit()

    new_access  = create_access_token(record.user_id)
    new_refresh = create_refresh_token(record.user_id, db)
    return new_access, new_refresh


def revoke_all_refresh_tokens(user_id: str, db: Session) -> None:
    db.query(RefreshToken).filter_by(user_id=user_id, is_revoked=False).update({"is_revoked": True})
    db.commit()


# ── Cookie helpers ────────────────────────────────────────────────────────────

COOKIE_SECURE    = settings.APP_ENV == "production"
COOKIE_SAMESITE  = "strict"


def set_auth_cookies(response, access_token: str, refresh_token: str) -> None:
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        path="/api/v1/auth/refresh",  # narrow path – only sent to refresh endpoint
    )


def clear_auth_cookies(response) -> None:
    response.delete_cookie("access_token",  path="/")
    response.delete_cookie("refresh_token", path="/api/v1/auth/refresh")


# ── Dependency: get current user ──────────────────────────────────────────────

from fastapi import Cookie, Depends, HTTPException, status
from sqlalchemy.orm import Session as DBSession

from backend.database import get_db


def get_current_user(
    access_token: str | None = Cookie(default=None),
    db: DBSession = Depends(get_db),
) -> User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not access_token:
        raise credentials_exc

    user_id = decode_access_token(access_token)
    if not user_id:
        raise credentials_exc

    user = db.query(User).filter_by(id=user_id, is_active=True).first()
    if not user:
        raise credentials_exc
    return user
