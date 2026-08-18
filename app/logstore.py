"""Application event log.

Events are written to the database (so the dashboard can show them) *and* to
stdout (so ``railway logs`` shows them). Secrets are scrubbed on the way in and
browsing activity is never recorded — this is a personal gateway, not a
surveillance system.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from app.database import get_db
from app.util import parse_iso, scrub_line, to_iso, utcnow

logger = logging.getLogger("railgate")

# Categories used across the app; keeps the log filter UI predictable.
CATEGORY_SYSTEM = "system"
CATEGORY_XRAY = "xray"
CATEGORY_USER = "user"
CATEGORY_AUTH = "auth"
CATEGORY_CONFIG = "config"

MAX_EVENTS = 2000
_TRIM_EVERY = 50
_write_counter = 0


def log_event(
    db_path: Path,
    level: str,
    category: str,
    message: str,
    *,
    echo: bool = True,
) -> None:
    """Record an application event. Never raises — logging must not break a request."""
    global _write_counter

    clean = scrub_line(str(message))[:1000]
    normalised_level = (level or "info").lower()

    if echo:
        log_method = {
            "debug": logger.debug,
            "info": logger.info,
            "warning": logger.warning,
            "error": logger.error,
        }.get(normalised_level, logger.info)
        log_method("[%s] %s", category, clean)

    try:
        with get_db(db_path) as conn:
            conn.execute(
                "INSERT INTO events (ts, level, category, message) VALUES (?, ?, ?, ?)",
                (to_iso(utcnow()), normalised_level, category, clean),
            )
            _write_counter += 1
            if _write_counter % _TRIM_EVERY == 0:
                conn.execute(
                    """
                    DELETE FROM events
                     WHERE id <= (SELECT MAX(id) - ? FROM events)
                    """,
                    (MAX_EVENTS,),
                )
    except (sqlite3.Error, OSError) as exc:  # pragma: no cover - defensive
        logger.warning("Could not persist event: %s", exc)


def recent_events(
    db_path: Path, limit: int = 100, category: str = "", level: str = ""
) -> list[dict[str, object]]:
    """Most recent events first."""
    query = "SELECT id, ts, level, category, message FROM events"
    clauses: list[str] = []
    params: list[object] = []
    if category:
        clauses.append("category = ?")
        params.append(category)
    if level:
        clauses.append("level = ?")
        params.append(level.lower())
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 1000)))

    try:
        with get_db(db_path) as conn:
            rows = conn.execute(query, params).fetchall()
    except sqlite3.Error:
        return []

    return [
        {
            "id": int(row["id"]),
            "ts": row["ts"],
            "timestamp": parse_iso(row["ts"]),
            "level": row["level"],
            "category": row["category"],
            "message": row["message"],
        }
        for row in rows
    ]


def tail_file(path: Path, lines: int = 120) -> list[str]:
    """Return the last ``lines`` lines of a log file, scrubbed of secrets."""
    try:
        if not path.exists():
            return []
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            block = 8192
            data = b""
            while size > 0 and data.count(b"\n") <= lines:
                step = min(block, size)
                size -= step
                handle.seek(size)
                data = handle.read(step) + data
        text = data.decode("utf-8", errors="replace")
        return [scrub_line(line) for line in text.splitlines()[-lines:]]
    except OSError:
        return []
