"""Admin authentication: sessions, CSRF and login rate limiting.

The admin password comes from the environment, is hashed with Argon2id at boot
and only ever compared against that hash. Sessions are server-side: the cookie
carries a random token, while the database stores a keyed hash of it.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from app.config import Settings
from app.database import get_db
from app.security import (
    constant_time_equals,
    generate_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.util import parse_iso, to_iso, utcnow


@dataclass
class SessionRecord:
    username: str
    csrf_token: str
    created_at: object
    expires_at: object
    ip: str


@dataclass
class LoginResult:
    ok: bool
    error: str = ""
    retry_after: int = 0


class RateLimiter:
    """In-memory sliding-window limiter with lockout.

    RailGate runs a single web process by design, so process-local state is both
    sufficient and immune to a database write on every failed guess.
    """

    def __init__(self, max_attempts: int, window_seconds: int, lockout_seconds: int) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._lock = threading.Lock()
        self._attempts: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def check(self, key: str) -> tuple[bool, int]:
        """``(allowed, retry_after_seconds)``."""
        now = time.monotonic()
        with self._lock:
            until = self._locked_until.get(key, 0.0)
            if until > now:
                return False, int(until - now) + 1
            if until:
                self._locked_until.pop(key, None)
                self._attempts.pop(key, None)
            return True, 0

    def register_failure(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            window = [t for t in self._attempts.get(key, []) if now - t < self.window_seconds]
            window.append(now)
            self._attempts[key] = window
            if len(window) >= self.max_attempts:
                self._locked_until[key] = now + self.lockout_seconds
            if len(self._attempts) > 4096:  # pragma: no cover - memory guard
                self._attempts.clear()

    def register_success(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)
            self._locked_until.pop(key, None)


class AuthService:
    """Everything the web layer needs to authenticate the administrator."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.db_path: Path = settings.db_path
        self._password_hash = hash_password(settings.admin_password)
        self._username = settings.admin_username
        self.limiter = RateLimiter(
            settings.login_max_attempts,
            settings.login_window_seconds,
            settings.login_lockout_seconds,
        )

    # -- credentials ---------------------------------------------------------
    def authenticate(self, username: str, password: str, client_key: str) -> LoginResult:
        allowed, retry_after = self.limiter.check(client_key)
        if not allowed:
            return LoginResult(
                ok=False,
                error=f"Too many failed attempts. Try again in {retry_after} seconds.",
                retry_after=retry_after,
            )

        username_ok = constant_time_equals(username.strip(), self._username)
        password_ok = verify_password(self._password_hash, password)
        if username_ok and password_ok:
            self.limiter.register_success(client_key)
            return LoginResult(ok=True)

        self.limiter.register_failure(client_key)
        return LoginResult(ok=False, error="Incorrect username or password.")

    # -- sessions ------------------------------------------------------------
    def create_session(self, username: str, ip: str = "", user_agent: str = "") -> tuple[str, str]:
        """Returns ``(session_token, csrf_token)``."""
        token = generate_token(32)
        csrf = generate_token(24)
        now = utcnow()
        expires = now + timedelta(hours=self.settings.admin_session_ttl_hours)
        with get_db(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO sessions
                    (token_hash, csrf_token, username, created_at, expires_at, ip, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hash_token(token, self.settings.admin_session_secret),
                    csrf,
                    username,
                    to_iso(now),
                    to_iso(expires),
                    ip[:64],
                    (user_agent or "")[:200],
                ),
            )
        self.purge_expired()
        return token, csrf

    def get_session(self, token: str | None) -> SessionRecord | None:
        if not token:
            return None
        token_hash = hash_token(token, self.settings.admin_session_secret)
        try:
            with get_db(self.db_path) as conn:
                row = conn.execute(
                    "SELECT * FROM sessions WHERE token_hash = ?", (token_hash,)
                ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None

        expires = parse_iso(row["expires_at"])
        if expires is None or expires <= utcnow():
            self.destroy_session(token)
            return None
        return SessionRecord(
            username=row["username"],
            csrf_token=row["csrf_token"],
            created_at=parse_iso(row["created_at"]),
            expires_at=expires,
            ip=row["ip"],
        )

    def destroy_session(self, token: str | None) -> None:
        if not token:
            return
        token_hash = hash_token(token, self.settings.admin_session_secret)
        try:
            with get_db(self.db_path) as conn:
                conn.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        except sqlite3.Error:  # pragma: no cover - best effort
            pass

    def destroy_all_sessions(self) -> int:
        try:
            with get_db(self.db_path) as conn:
                cursor = conn.execute("DELETE FROM sessions")
                return cursor.rowcount or 0
        except sqlite3.Error:  # pragma: no cover
            return 0

    def purge_expired(self) -> int:
        try:
            with get_db(self.db_path) as conn:
                cursor = conn.execute(
                    "DELETE FROM sessions WHERE expires_at <= ?", (to_iso(utcnow()),)
                )
                return cursor.rowcount or 0
        except sqlite3.Error:  # pragma: no cover
            return 0

    # -- CSRF ----------------------------------------------------------------
    @staticmethod
    def verify_csrf(session: SessionRecord | None, supplied: str | None) -> bool:
        if session is None or not supplied:
            return False
        return constant_time_equals(session.csrf_token, supplied)


def client_key_from_request(request) -> str:
    """Best-effort client identity for rate limiting.

    Railway sits in front of the app, so the socket peer is always the edge
    proxy. ``X-Forwarded-For`` is client-controlled and therefore only used as a
    bucketing hint — never for authorisation.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64] or "unknown"
    client = getattr(request, "client", None)
    return (getattr(client, "host", "") or "unknown")[:64]
