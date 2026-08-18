"""Password hashing, token handling and HTTP security headers."""

from __future__ import annotations

import hmac
import secrets
from hashlib import sha256

from argon2 import PasswordHasher
from argon2 import exceptions as argon2_exceptions
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Argon2id with deliberately modest parameters: this guards a single admin
# password on a small Railway container, so login latency matters.
_hasher = PasswordHasher(time_cost=2, memory_cost=64 * 1024, parallelism=2, hash_len=32, salt_len=16)

SESSION_COOKIE_NAME = "railgate_session"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FIELD_NAME = "csrf_token"


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Constant-time-ish verification that never raises on a bad password."""
    if not stored_hash or not password:
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.VerificationError,
        argon2_exceptions.InvalidHashError,
    ):
        return False


def generate_token(length: int = 32) -> str:
    """A URL-safe random token for sessions and CSRF."""
    return secrets.token_urlsafe(length)


def hash_token(token: str, secret: str) -> str:
    """Keyed hash of a session token.

    Only the hash is persisted, so a leaked database cannot be replayed as a
    live session. Rotating ``ADMIN_SESSION_SECRET`` invalidates every session.
    """
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), sha256).hexdigest()


def constant_time_equals(left: str, right: str) -> bool:
    return hmac.compare_digest((left or "").encode("utf-8"), (right or "").encode("utf-8"))


def generate_ws_path(prefix: str = "/gateway") -> str:
    """An unguessable path for the WebSocket fallback."""
    return f"{prefix.rstrip('/')}/{secrets.token_hex(8)}"


CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    )
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply a strict, static set of security headers to every response."""

    def __init__(self, app, production: bool = True) -> None:
        super().__init__(app)
        self.production = production

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        headers = response.headers
        headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "no-referrer")
        headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(), interest-cohort=()")
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("X-Robots-Tag", "noindex, nofollow")
        if self.production:
            headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
