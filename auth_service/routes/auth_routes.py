"""Authentication routes – register, MFA setup, login, refresh, me."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Header, HTTPException
from pydantic import BaseModel

from auth_service.auth_db import create_user, get_user, verify_password
from auth_service.jwt_utils import create_access_token, create_refresh_token, decode_token
from auth_service.mfa import generate_qr_code, generate_totp_secret, verify_totp

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str


class VerifyMFARequest(BaseModel):
    username: str
    totp_code: str


class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: str


class RefreshRequest(BaseModel):
    refresh_token: str


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/register")
async def register(body: RegisterRequest) -> dict:
    # Validation
    if len(body.username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if "@" not in body.email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    if len(body.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    if get_user(body.username) is not None:
        raise HTTPException(status_code=409, detail="Username already exists")

    totp_secret = generate_totp_secret()
    user = create_user(
        username=body.username,
        email=body.email,
        password=body.password,
        totp_secret=totp_secret,
    )
    qr_code = generate_qr_code(body.username, totp_secret)

    return {
        "user_id": user["username"],
        "qr_code": qr_code,
        "totp_secret": totp_secret,
        "message": "Scan QR code with your authenticator app, then verify with /auth/verify-mfa-setup",
    }


@router.post("/verify-mfa-setup")
async def verify_mfa_setup(body: VerifyMFARequest) -> dict:
    user = get_user(body.username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_totp(user["totp_secret"], body.totp_code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    user["mfa_verified"] = True
    return {"verified": True}


@router.post("/login")
async def login(body: LoginRequest) -> dict:
    user = get_user(body.username)
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not verify_password(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get("mfa_verified"):
        raise HTTPException(status_code=403, detail="MFA not set up. Complete /auth/verify-mfa-setup first.")

    if not verify_totp(user["totp_secret"], body.totp_code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    access_token = create_access_token(body.username, user["role"])
    refresh_token = create_refresh_token(body.username)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "username": user["username"],
        "role": user["role"],
    }


@router.post("/refresh")
async def refresh(body: RefreshRequest) -> dict:
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Token is not a refresh token")

    username: str = payload["sub"]
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=401, detail="User no longer exists")

    access_token = create_access_token(username, user["role"])
    return {"access_token": access_token}


@router.get("/me")
async def me(authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = authorization.split(" ", 1)[1]
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    username: str = payload["sub"]
    user = get_user(username)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    return {
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
        "mfa_verified": user["mfa_verified"],
        "created_at": user["created_at"],
    }
