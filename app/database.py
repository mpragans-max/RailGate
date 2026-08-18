"""SQLite persistence with a simple, safe forward-only migration mechanism.

A fresh connection is opened per operation. SQLite handles that efficiently and
it sidesteps every cross-thread connection problem — the admin app, the expiry
sweeper and the ``vpnctl`` CLI all touch the same file concurrently.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from app.util import to_iso, utcnow

_INIT_LOCK = threading.Lock()
_INITIALISED: set[str] = set()


class DatabaseError(RuntimeError):
    """Raised when the database cannot be opened or migrated."""


# --------------------------------------------------------------------------- #
# Migrations. Append only — never edit an already-released migration.
# --------------------------------------------------------------------------- #
MIGRATIONS: list[tuple[int, str, tuple[str, ...]]] = [
    (
        1,
        "initial schema",
        (
            """
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                uuid        TEXT    NOT NULL UNIQUE,
                created_at  TEXT    NOT NULL,
                updated_at  TEXT    NOT NULL,
                expires_at  TEXT,
                enabled     INTEGER NOT NULL DEFAULT 1,
                notes       TEXT    NOT NULL DEFAULT '',
                protocol    TEXT    NOT NULL DEFAULT 'vless-reality',
                flow        TEXT    NOT NULL DEFAULT 'xtls-rprx-vision'
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_users_enabled ON users (enabled)",
            "CREATE INDEX IF NOT EXISTS idx_users_expires ON users (expires_at)",
            """
            CREATE TABLE IF NOT EXISTS settings (
                key        TEXT PRIMARY KEY,
                value      TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token_hash  TEXT    NOT NULL UNIQUE,
                csrf_token  TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                created_at  TEXT    NOT NULL,
                expires_at  TEXT    NOT NULL,
                ip          TEXT    NOT NULL DEFAULT '',
                user_agent  TEXT    NOT NULL DEFAULT ''
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions (expires_at)",
            """
            CREATE TABLE IF NOT EXISTS events (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT NOT NULL,
                level    TEXT NOT NULL,
                category TEXT NOT NULL,
                message  TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_events_ts ON events (id DESC)",
        ),
    ),
]

SCHEMA_VERSION = max(version for version, _, _ in MIGRATIONS)


def _configure(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")


def connect(db_path: Path) -> sqlite3.Connection:
    """Open a configured connection, creating the parent directory if needed."""
    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path), timeout=15.0, isolation_level=None)
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseError(
            f"Cannot open the database at {db_path}: {exc}. "
            "Is the persistent volume mounted and writable?"
        ) from exc
    _configure(conn)
    return conn


@contextmanager
def get_db(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Context manager yielding a connection that always gets closed."""
    conn = connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Context manager running the block inside a single transaction."""
    conn = connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()


def _applied_versions(conn: sqlite3.Connection) -> set[int]:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version    INTEGER PRIMARY KEY,
            name       TEXT NOT NULL DEFAULT '',
            applied_at TEXT NOT NULL
        )
        """
    )
    rows = conn.execute("SELECT version FROM schema_migrations").fetchall()
    return {int(row["version"]) for row in rows}


def init_db(db_path: Path, force: bool = False) -> int:
    """Create/upgrade the schema. Idempotent and safe to call on every boot.

    Returns the number of migrations applied during this call.
    """
    key = str(db_path)
    with _INIT_LOCK:
        if key in _INITIALISED and not force:
            return 0
        applied_count = 0
        conn = connect(db_path)
        try:
            applied = _applied_versions(conn)
            for version, name, statements in sorted(MIGRATIONS, key=lambda item: item[0]):
                if version in applied:
                    continue
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    for statement in statements:
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
                        (version, name, to_iso(utcnow())),
                    )
                    conn.execute("COMMIT")
                except sqlite3.Error as exc:
                    conn.execute("ROLLBACK")
                    raise DatabaseError(
                        f"Database migration {version} ({name}) failed: {exc}"
                    ) from exc
                applied_count += 1
        finally:
            conn.close()
        _INITIALISED.add(key)
        return applied_count


def database_status(db_path: Path) -> dict[str, object]:
    """Lightweight health probe used by /health and diagnostics."""
    try:
        with get_db(db_path) as conn:
            conn.execute("SELECT 1").fetchone()
            version_row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations"
            ).fetchone()
            users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
        size = db_path.stat().st_size if db_path.exists() else 0
        return {
            "ok": True,
            "path": str(db_path),
            "schema_version": int(version_row["v"]),
            "expected_schema_version": SCHEMA_VERSION,
            "user_count": int(users["c"]),
            "size_bytes": size,
            "error": "",
        }
    except (DatabaseError, sqlite3.Error, OSError) as exc:
        return {
            "ok": False,
            "path": str(db_path),
            "schema_version": 0,
            "expected_schema_version": SCHEMA_VERSION,
            "user_count": 0,
            "size_bytes": 0,
            "error": str(exc),
        }


# --------------------------------------------------------------------------- #
# key/value settings
# --------------------------------------------------------------------------- #
def get_setting(db_path: Path, key: str, default: str | None = None) -> str | None:
    with get_db(db_path) as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(db_path: Path, key: str, value: str) -> None:
    with get_db(db_path) as conn:
        conn.execute(
            """
            INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, to_iso(utcnow())),
        )


def all_settings(db_path: Path) -> dict[str, str]:
    with get_db(db_path) as conn:
        rows = conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
    return {row["key"]: row["value"] for row in rows}
