"""
Authentication routes.

POST /api/v1/auth/register
POST /api/v1/auth/login
POST /api/v1/auth/logout
POST /api/v1/auth/refresh
GET  /api/v1/auth/me
"""
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from backend.auth import (
    clear_auth_cookies,
    create_access_token,
    create_refresh_token,
    hash_password,
    revoke_all_refresh_tokens,
    rotate_refresh_token,
    set_auth_cookies,
    verify_password,
    get_current_user,
    DUMMY_HASH,
)
from backend.database import get_db
from backend.models import User

router  = APIRouter(prefix="/api/v1/auth", tags=["auth"])
limiter = Limiter(key_func=get_remote_address)

# ── Schemas ───────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email:     EmailStr
    password:  str = Field(..., min_length=8, max_length=128)

    @field_validator("full_name")
    @classmethod
    def no_html(cls, v: str) -> str:
        if re.search(r"[<>\"'`]", v):
            raise ValueError("Name contains invalid characters")
        return v.strip()

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Must contain at least one uppercase letter")
        if not re.search(r"[0-9]", v):
            raise ValueError("Must contain at least one digit")
        if not re.search(r"[^A-Za-z0-9]", v):
            raise ValueError("Must contain at least one special character")
        return v


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str = Field(..., min_length=1, max_length=128)


class UserResponse(BaseModel):
    id:           str
    full_name:    str
    email:        str
    plan:         str
    plan_display: str
    is_verified:  bool
    created_at:   datetime

    class Config:
        from_attributes = True


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def register(
    request: Request,
    body: RegisterRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    existing = db.query(User).filter_by(email=body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email already exists.",
        )

    user = User(
        full_name=body.full_name,
        email=body.email,
        hashed_password=hash_password(body.password),
        plan="starter",  # always starter — upgraded only via Stripe webhook
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    access_token  = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id, db)
    set_auth_cookies(response, access_token, refresh_token)

    return {"message": "Account created successfully", "user_id": user.id}


@router.post("/login")
@limiter.limit("20/minute")
async def login(
    request: Request,
    body: LoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    user = db.query(User).filter_by(email=body.email).first()
    # Always run bcrypt to prevent timing-based user enumeration.
    # Even when user doesn't exist we hash against a dummy value so the
    # response time is identical whether the email exists or not.
    hash_to_check = user.hashed_password if user else DUMMY_HASH
    password_ok   = verify_password(body.password, hash_to_check)
    if not user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact support.",
        )

    access_token  = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id, db)
    set_auth_cookies(response, access_token, refresh_token)

    return {"message": "Logged in successfully"}


@router.post("/logout")
async def logout(
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    revoke_all_refresh_tokens(current_user.id, db)
    clear_auth_cookies(response)
    return {"message": "Logged out successfully"}


@router.post("/refresh")
async def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    refresh_token_cookie = request.cookies.get("refresh_token")
    if not refresh_token_cookie:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No refresh token.")

    result = rotate_refresh_token(refresh_token_cookie, db)
    if not result:
        clear_auth_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token.")

    new_access, new_refresh = result
    set_auth_cookies(response, new_access, new_refresh)
    return {"message": "Token refreshed"}


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return current_user
