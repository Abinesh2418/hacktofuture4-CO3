"""JWT creation and verification utilities."""

from __future__ import annotations

import datetime
import os
from typing import Dict

import jwt  # PyJWT

SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "htf-arena-secret-key-change-me")
ALGORITHM: str = "HS256"


def create_access_token(username: str, role: str) -> str:
    """Return a signed JWT access token (expires in 60 minutes)."""
    payload: Dict[str, object] = {
        "sub": username,
        "role": role,
        "type": "access",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(username: str) -> str:
    """Return a signed JWT refresh token (expires in 24 hours)."""
    payload: Dict[str, object] = {
        "sub": username,
        "type": "refresh",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and validate a JWT. Raises jwt.ExpiredSignatureError or jwt.InvalidTokenError."""
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
