"""Account expiry enforcement.

No cron, no external scheduler: a single asyncio task inside the admin process
sweeps for expired accounts. It only touches Xray when something actually
changed, so an idle gateway never restarts itself.
"""

from __future__ import annotations

import asyncio
import logging

from app.config import Settings
from app.logstore import CATEGORY_USER, log_event
from app.models import active_users, disable_expired_users
from app.xray_manager import apply_configuration

logger = logging.getLogger("railgate.expiry")


def run_expiry_cycle(settings: Settings) -> dict[str, object]:
    """One sweep. Returns a summary; safe to call from anywhere."""
    expired = disable_expired_users(settings.db_path)
    if not expired:
        return {"expired": 0, "usernames": [], "applied": False, "message": ""}

    usernames = [user.username for user in expired]
    for username in usernames:
        log_event(
            settings.db_path,
            "warning",
            CATEGORY_USER,
            f"Account '{username}' reached its expiry date and was disabled.",
        )

    result = apply_configuration(
        settings, active_users(settings.db_path), reason="expiry sweep"
    )
    log_event(
        settings.db_path,
        "info" if result.ok else "error",
        CATEGORY_USER,
        f"Expiry sweep disabled {len(usernames)} account(s): {result.message}",
    )
    return {
        "expired": len(usernames),
        "usernames": usernames,
        "applied": result.ok,
        "message": result.message,
    }


async def expiry_loop(settings: Settings, stop_event: asyncio.Event) -> None:
    """Background task driving :func:`run_expiry_cycle` on an interval."""
    interval = settings.expiry_check_interval
    logger.info("Expiry sweeper started (every %ss).", interval)
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break  # stop_event was set
        except asyncio.TimeoutError:
            pass
        try:
            await asyncio.to_thread(run_expiry_cycle, settings)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - the loop must survive anything
            logger.error("Expiry sweep failed: %s", exc)
    logger.info("Expiry sweeper stopped.")
