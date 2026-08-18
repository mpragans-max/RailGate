"""Small shared helpers: time handling, formatting and redaction."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
DATE_FORMATS = ("%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d")


def utcnow() -> datetime:
    """Timezone-aware current UTC time."""
    return datetime.now(timezone.utc)


def to_iso(value: datetime | None) -> str | None:
    """Serialise a datetime to a stable UTC ISO-8601 string."""
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime(ISO_FORMAT)


def parse_iso(value: str | None) -> datetime | None:
    """Parse a stored timestamp. Returns ``None`` for empty/invalid input."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def parse_expiry_date(value: str) -> datetime:
    """Parse a user-supplied ``--expire`` date into an end-of-day UTC instant."""
    text = (value or "").strip()
    if not text:
        raise ValueError("Expiry date is empty.")
    for fmt in DATE_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed.replace(hour=23, minute=59, second=59, tzinfo=timezone.utc)
    parsed_iso = parse_iso(text)
    if parsed_iso is not None:
        return parsed_iso
    raise ValueError(
        f"{value!r} is not a valid date. Use YYYY-MM-DD, for example 2026-12-31."
    )


def expiry_from_days(days: int, base: datetime | None = None) -> datetime | None:
    """``days <= 0`` means the account never expires."""
    if days is None or days <= 0:
        return None
    return (base or utcnow()) + timedelta(days=days)


def humanise_delta(target: datetime | None, reference: datetime | None = None) -> str:
    """Render a remaining-time string such as ``29d 4h`` or ``expired``."""
    if target is None:
        return "never"
    now = reference or utcnow()
    delta = target - now
    seconds = int(delta.total_seconds())
    if seconds <= 0:
        return "expired"
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes = seconds // 60
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def format_uptime(seconds: float | None) -> str:
    """Render an uptime in a compact human form."""
    if seconds is None or seconds < 0:
        return "unknown"
    total = int(seconds)
    days, total = divmod(total, 86400)
    hours, total = divmod(total, 3600)
    minutes, secs = divmod(total, 60)
    if days:
        return f"{days}d {hours}h {minutes}m"
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_bytes(value: float | None) -> str:
    """Human-readable byte size."""
    if value is None:
        return "unknown"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} TiB"


_SECRET_PATTERN = re.compile(
    r"(?i)(password|secret|private[_-]?key|token|cookie|authorization)\s*[=:]\s*\S+"
)


def mask_secret(value: str | None, keep: int = 4) -> str:
    """Mask a sensitive value, revealing only a short prefix."""
    if not value:
        return "(unset)"
    text = str(value)
    if len(text) <= keep:
        return "*" * len(text)
    return f"{text[:keep]}{'*' * max(4, len(text) - keep)}"


def scrub_line(line: str) -> str:
    """Remove obvious secrets before a log line is shown or stored."""
    return _SECRET_PATTERN.sub(lambda m: f"{m.group(1)}=***REDACTED***", line)
