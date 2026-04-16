"""MFA utilities – TOTP generation and QR code rendering."""

from __future__ import annotations

import base64
import io

import pyotp
import qrcode  # type: ignore[import-untyped]


def generate_totp_secret() -> str:
    """Return a fresh base32-encoded TOTP secret."""
    return pyotp.random_base32()


def generate_qr_code(username: str, secret: str) -> str:
    """Return a base64-encoded PNG of the provisioning QR code."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name="HTF Arena")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return base64.b64encode(buf.read()).decode()


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (allows +/-1 window for clock drift)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)
