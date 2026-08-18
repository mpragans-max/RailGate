"""Account operations shared by the web API and the ``vpnctl`` CLI.

Both front-ends go through here so that behaviour, logging and Xray
synchronisation can never drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.config import Settings
from app.logstore import CATEGORY_USER, log_event
from app.models import (
    UserError,
    VpnUser,
    active_users,
    create_user,
    delete_user_by_id,
    get_user,
    get_user_by_username,
    regenerate_uuid,
    set_enabled,
    set_expiry,
    update_notes,
)
from app.util import expiry_from_days, parse_expiry_date, to_iso
from app.xray_manager import ApplyResult, apply_configuration


@dataclass
class OperationResult:
    user: VpnUser | None
    apply_result: ApplyResult

    @property
    def ok(self) -> bool:
        return self.apply_result.ok

    @property
    def message(self) -> str:
        return self.apply_result.message


def resolve_expiry(
    *, days: int | None = None, expire: str | None = None, default_days: int = 0
) -> datetime | None:
    """Turn CLI/form input into an absolute expiry instant.

    ``None`` means the account never expires.
    """
    if expire:
        normalised = expire.strip().lower()
        if normalised in {"never", "none", "0"}:
            return None
        return parse_expiry_date(expire)
    if days is not None:
        return expiry_from_days(days)
    return expiry_from_days(default_days)


def sync(settings: Settings, reason: str, *, force_restart: bool = False) -> ApplyResult:
    """Re-render and apply the Xray configuration from the database."""
    result = apply_configuration(
        settings, active_users(settings.db_path), reason=reason, force_restart=force_restart
    )
    if not result.ok:
        log_event(settings.db_path, "error", "config", f"{reason}: {result.message}")
    return result


def create_account(
    settings: Settings,
    username: str,
    *,
    expires_at: datetime | None = None,
    notes: str = "",
) -> OperationResult:
    user = create_user(settings.db_path, username, expires_at=expires_at, notes=notes)
    log_event(
        settings.db_path,
        "info",
        CATEGORY_USER,
        f"Account '{user.username}' created (expires: {user.expires_display}).",
    )
    return OperationResult(user, sync(settings, f"create {user.username}"))


def delete_account(settings: Settings, user_id: int) -> OperationResult:
    user = delete_user_by_id(settings.db_path, user_id)
    log_event(settings.db_path, "warning", CATEGORY_USER, f"Account '{user.username}' deleted.")
    return OperationResult(user, sync(settings, f"delete {user.username}"))


def set_account_enabled(settings: Settings, user_id: int, enabled: bool) -> OperationResult:
    user = set_enabled(settings.db_path, user_id, enabled)
    log_event(
        settings.db_path,
        "info",
        CATEGORY_USER,
        f"Account '{user.username}' {'enabled' if enabled else 'disabled'}.",
    )
    return OperationResult(user, sync(settings, f"{'enable' if enabled else 'disable'} {user.username}"))


def renew_account(
    settings: Settings,
    user_id: int,
    *,
    days: int | None = None,
    expire: str | None = None,
) -> OperationResult:
    current = get_user(settings.db_path, user_id)
    if current is None:
        raise UserError(f"No account with id {user_id} exists.")

    if expire:
        expires_at = resolve_expiry(expire=expire)
    elif days is not None:
        if days <= 0:
            expires_at = None
        else:
            # Extend from the current expiry when it is still in the future.
            base = current.expires_at if (current.expires_at and not current.is_expired()) else None
            expires_at = expiry_from_days(days, base=base)
    else:
        raise UserError("Specify either --days or --expire.")

    user = set_expiry(settings.db_path, user_id, expires_at)
    log_event(
        settings.db_path,
        "info",
        CATEGORY_USER,
        f"Account '{user.username}' renewed (expires: {user.expires_display}).",
    )
    return OperationResult(user, sync(settings, f"renew {user.username}"))


def regenerate_account_uuid(settings: Settings, user_id: int) -> OperationResult:
    user = regenerate_uuid(settings.db_path, user_id)
    log_event(
        settings.db_path,
        "warning",
        CATEGORY_USER,
        f"Credentials regenerated for '{user.username}'. Previously issued links no longer work.",
    )
    return OperationResult(user, sync(settings, f"regenerate {user.username}"))


def set_account_notes(settings: Settings, user_id: int, notes: str) -> OperationResult:
    user = update_notes(settings.db_path, user_id, notes)
    return OperationResult(user, ApplyResult(ok=True, method="none", message="Notes updated."))


def find_account(settings: Settings, reference: str) -> VpnUser:
    """Look up an account by username, or by numeric id."""
    text = (reference or "").strip()
    if not text:
        raise UserError("Specify a username.")
    user = get_user_by_username(settings.db_path, text)
    if user is None and text.isdigit():
        user = get_user(settings.db_path, int(text))
    if user is None:
        raise UserError(
            f"No account named {text!r} exists. Run `vpnctl list` to see the accounts."
        )
    return user


def account_summary(settings: Settings, user: VpnUser) -> dict[str, object]:
    return {
        **user.as_dict(),
        "created_display": to_iso(user.created_at) or "-",
    }
