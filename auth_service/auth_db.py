"""In-memory user store with bcrypt password hashing."""

from __future__ import annotations

import datetime
from typing import Dict, Optional

try:
    import bcrypt

    def _hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def _check_password(password: str, password_hash: str) -> bool:
        return bcrypt.checkpw(password.encode(), password_hash.encode())

except ImportError:
    import hashlib

    def _hash_password(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def _check_password(password: str, password_hash: str) -> bool:
        return hashlib.sha256(password.encode()).hexdigest() == password_hash


# ---------------------------------------------------------------------------
# In-memory store: keyed by username
# ---------------------------------------------------------------------------
users: Dict[str, dict] = {}


def create_user(
    username: str,
    email: str,
    password: str,
    totp_secret: str,
    role: str = "player",
) -> dict:
    """Create a new user and return the stored dict (without the hash)."""
    password_hash = _hash_password(password)
    user = {
        "username": username,
        "email": email,
        "password_hash": password_hash,
        "totp_secret": totp_secret,
        "mfa_verified": False,
        "created_at": datetime.datetime.utcnow().isoformat(),
        "role": role,
    }
    users[username] = user
    return user


def get_user(username: str) -> Optional[dict]:
    """Return user dict or None."""
    return users.get(username)


def verify_password(username: str, password: str) -> bool:
    """Check a plain-text password against the stored hash."""
    user = get_user(username)
    if user is None:
        return False
    return _check_password(password, user["password_hash"])


def list_users() -> list:
    """Return a list of all users (without password hashes)."""
    safe: list = []
    for u in users.values():
        entry = {k: v for k, v in u.items() if k != "password_hash"}
        safe.append(entry)
    return safe
