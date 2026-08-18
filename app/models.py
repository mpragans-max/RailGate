"""VPN account records and the repository functions that manipulate them."""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from app.credential_generator import new_uuid
from app.database import get_db, transaction
from app.util import humanise_delta, parse_iso, to_iso, utcnow

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")
MAX_NOTES_LENGTH = 500

# Xray identifies inbound users by e-mail. This suffix is cosmetic but must stay
# stable, because it is the key used to add/remove users at runtime.
XRAY_EMAIL_DOMAIN = "railgate"


class UserError(ValueError):
    """Raised for invalid input or a violated uniqueness constraint."""


def validate_username(username: str) -> str:
    name = (username or "").strip()
    if not name:
        raise UserError("Username is required.")
    if not USERNAME_PATTERN.match(name):
        raise UserError(
            f"Username {username!r} is invalid. Use 2-32 characters: letters, "
            "digits, dot, dash or underscore, starting with a letter or digit."
        )
    return name


def validate_notes(notes: str | None) -> str:
    text = (notes or "").strip()
    if len(text) > MAX_NOTES_LENGTH:
        raise UserError(f"Notes are limited to {MAX_NOTES_LENGTH} characters.")
    return text


@dataclass
class VpnUser:
    id: int
    username: str
    uuid: str
    created_at: datetime | None
    updated_at: datetime | None
    expires_at: datetime | None
    enabled: bool
    notes: str = ""
    protocol: str = "vless-reality"
    flow: str = "xtls-rprx-vision"

    # -- derived -------------------------------------------------------------
    @property
    def email(self) -> str:
        """Identifier used inside the Xray configuration."""
        return f"{self.username}@{XRAY_EMAIL_DOMAIN}"

    def is_expired(self, now: datetime | None = None) -> bool:
        if self.expires_at is None:
            return False
        return self.expires_at <= (now or utcnow())

    def is_active(self, now: datetime | None = None) -> bool:
        """Only active accounts are written into the Xray configuration."""
        return self.enabled and not self.is_expired(now)

    def status(self, now: datetime | None = None) -> str:
        if self.is_expired(now):
            return "expired"
        if not self.enabled:
            return "disabled"
        return "active"

    @property
    def expires_display(self) -> str:
        return "Never" if self.expires_at is None else (to_iso(self.expires_at) or "Never")

    @property
    def remaining_display(self) -> str:
        return humanise_delta(self.expires_at)

    def as_dict(self, include_uuid: bool = True) -> dict[str, object]:
        data: dict[str, object] = {
            "id": self.id,
            "username": self.username,
            "created_at": to_iso(self.created_at),
            "updated_at": to_iso(self.updated_at),
            "expires_at": to_iso(self.expires_at),
            "expires_display": self.expires_display,
            "remaining": self.remaining_display,
            "enabled": self.enabled,
            "status": self.status(),
            "notes": self.notes,
            "protocol": self.protocol,
            "flow": self.flow,
        }
        if include_uuid:
            data["uuid"] = self.uuid
        return data


def _row_to_user(row: sqlite3.Row) -> VpnUser:
    return VpnUser(
        id=int(row["id"]),
        username=row["username"],
        uuid=row["uuid"],
        created_at=parse_iso(row["created_at"]),
        updated_at=parse_iso(row["updated_at"]),
        expires_at=parse_iso(row["expires_at"]),
        enabled=bool(row["enabled"]),
        notes=row["notes"] or "",
        protocol=row["protocol"] or "vless-reality",
        flow=row["flow"] or "xtls-rprx-vision",
    )


# --------------------------------------------------------------------------- #
# queries
# --------------------------------------------------------------------------- #
def list_users(db_path: Path) -> list[VpnUser]:
    with get_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM users ORDER BY LOWER(username) ASC"
        ).fetchall()
    return [_row_to_user(row) for row in rows]


def get_user(db_path: Path, user_id: int) -> VpnUser | None:
    with get_db(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row) if row else None


def get_user_by_username(db_path: Path, username: str) -> VpnUser | None:
    with get_db(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),)
        ).fetchone()
    return _row_to_user(row) if row else None


def require_user(db_path: Path, username: str) -> VpnUser:
    user = get_user_by_username(db_path, username)
    if user is None:
        raise UserError(f"No account named {username!r} exists.")
    return user


def active_users(db_path: Path, now: datetime | None = None) -> list[VpnUser]:
    """Accounts that belong in the running Xray configuration."""
    reference = now or utcnow()
    return [user for user in list_users(db_path) if user.is_active(reference)]


def user_stats(db_path: Path, now: datetime | None = None) -> dict[str, int]:
    reference = now or utcnow()
    users = list_users(db_path)
    return {
        "total": len(users),
        "active": sum(1 for u in users if u.status(reference) == "active"),
        "disabled": sum(1 for u in users if u.status(reference) == "disabled"),
        "expired": sum(1 for u in users if u.status(reference) == "expired"),
    }


# --------------------------------------------------------------------------- #
# mutations
# --------------------------------------------------------------------------- #
def create_user(
    db_path: Path,
    username: str,
    *,
    expires_at: datetime | None = None,
    notes: str = "",
    user_uuid: str | None = None,
    flow: str = "xtls-rprx-vision",
) -> VpnUser:
    name = validate_username(username)
    note_text = validate_notes(notes)
    account_uuid = user_uuid or new_uuid()
    now = utcnow()

    if get_user_by_username(db_path, name) is not None:
        raise UserError(f"An account named {name!r} already exists.")

    try:
        with transaction(db_path) as conn:
            cursor = conn.execute(
                """
                INSERT INTO users
                    (username, uuid, created_at, updated_at, expires_at, enabled, notes, protocol, flow)
                VALUES (?, ?, ?, ?, ?, 1, ?, 'vless-reality', ?)
                """,
                (
                    name,
                    account_uuid,
                    to_iso(now),
                    to_iso(now),
                    to_iso(expires_at),
                    note_text,
                    flow,
                ),
            )
            user_id = int(cursor.lastrowid or 0)
    except sqlite3.IntegrityError as exc:
        raise UserError(f"Could not create {name!r}: {exc}") from exc

    created = get_user(db_path, user_id)
    if created is None:  # pragma: no cover - defensive
        raise UserError(f"Account {name!r} vanished immediately after creation.")
    return created


def delete_user(db_path: Path, username: str) -> VpnUser:
    user = require_user(db_path, username)
    with transaction(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user.id,))
    return user


def delete_user_by_id(db_path: Path, user_id: int) -> VpnUser:
    user = get_user(db_path, user_id)
    if user is None:
        raise UserError(f"No account with id {user_id} exists.")
    with transaction(db_path) as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return user


def _touch(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("UPDATE users SET updated_at = ? WHERE id = ?", (to_iso(utcnow()), user_id))


def set_enabled(db_path: Path, user_id: int, enabled: bool) -> VpnUser:
    user = get_user(db_path, user_id)
    if user is None:
        raise UserError(f"No account with id {user_id} exists.")
    if enabled and user.is_expired():
        raise UserError(
            f"{user.username!r} has expired. Renew it first, e.g. "
            f"`vpnctl renew {user.username} --days 30`."
        )
    with transaction(db_path) as conn:
        conn.execute("UPDATE users SET enabled = ? WHERE id = ?", (1 if enabled else 0, user_id))
        _touch(conn, user_id)
    return get_user(db_path, user_id)  # type: ignore[return-value]


def set_expiry(db_path: Path, user_id: int, expires_at: datetime | None, *, enable: bool = True) -> VpnUser:
    """Set an absolute expiry. Renewing re-enables the account by default."""
    user = get_user(db_path, user_id)
    if user is None:
        raise UserError(f"No account with id {user_id} exists.")
    still_valid = expires_at is None or expires_at > utcnow()
    with transaction(db_path) as conn:
        if enable and still_valid:
            conn.execute(
                "UPDATE users SET expires_at = ?, enabled = 1 WHERE id = ?",
                (to_iso(expires_at), user_id),
            )
        else:
            conn.execute(
                "UPDATE users SET expires_at = ? WHERE id = ?", (to_iso(expires_at), user_id)
            )
        _touch(conn, user_id)
    return get_user(db_path, user_id)  # type: ignore[return-value]


def regenerate_uuid(db_path: Path, user_id: int) -> VpnUser:
    """Rotate the account's UUID, invalidating every previously issued link."""
    user = get_user(db_path, user_id)
    if user is None:
        raise UserError(f"No account with id {user_id} exists.")
    with transaction(db_path) as conn:
        conn.execute(
            "UPDATE users SET uuid = ?, updated_at = ? WHERE id = ?",
            (new_uuid(), to_iso(utcnow()), user_id),
        )
    return get_user(db_path, user_id)  # type: ignore[return-value]


def update_notes(db_path: Path, user_id: int, notes: str) -> VpnUser:
    text = validate_notes(notes)
    user = get_user(db_path, user_id)
    if user is None:
        raise UserError(f"No account with id {user_id} exists.")
    with transaction(db_path) as conn:
        conn.execute("UPDATE users SET notes = ? WHERE id = ?", (text, user_id))
        _touch(conn, user_id)
    return get_user(db_path, user_id)  # type: ignore[return-value]


def disable_expired_users(db_path: Path, now: datetime | None = None) -> list[VpnUser]:
    """Flip expired-but-still-enabled accounts to disabled.

    Returns the accounts that were changed so the caller can log and resync.
    """
    reference = now or utcnow()
    changed: list[VpnUser] = []
    for user in list_users(db_path):
        if user.enabled and user.is_expired(reference):
            with transaction(db_path) as conn:
                conn.execute("UPDATE users SET enabled = 0 WHERE id = ?", (user.id,))
                _touch(conn, user.id)
            user.enabled = False
            changed.append(user)
    return changed
