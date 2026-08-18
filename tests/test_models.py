"""Database operations, account state machine and expiry handling."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.database import SCHEMA_VERSION, database_status, get_setting, init_db, set_setting
from app.models import (
    UserError,
    active_users,
    create_user,
    delete_user,
    disable_expired_users,
    get_user_by_username,
    list_users,
    regenerate_uuid,
    require_user,
    set_enabled,
    set_expiry,
    user_stats,
    validate_username,
)
from app.util import expiry_from_days, humanise_delta, parse_expiry_date, utcnow


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #
def test_init_db_is_idempotent(settings):
    assert init_db(settings.db_path, force=True) >= 0
    again = init_db(settings.db_path, force=True)
    assert again == 0
    status = database_status(settings.db_path)
    assert status["ok"] is True
    assert status["schema_version"] == SCHEMA_VERSION


def test_settings_key_value_round_trip(settings):
    assert get_setting(settings.db_path, "missing") is None
    set_setting(settings.db_path, "colour", "blue")
    assert get_setting(settings.db_path, "colour") == "blue"
    set_setting(settings.db_path, "colour", "green")
    assert get_setting(settings.db_path, "colour") == "green"


# --------------------------------------------------------------------------- #
# creation & validation
# --------------------------------------------------------------------------- #
def test_create_user_defaults(settings):
    user = create_user(settings.db_path, "phone-main")
    assert user.username == "phone-main"
    assert user.enabled is True
    assert user.expires_at is None
    assert user.status() == "active"
    assert user.email == "phone-main@railgate"
    assert len(user.uuid) == 36


def test_usernames_must_be_unique(settings):
    create_user(settings.db_path, "phone")
    with pytest.raises(UserError, match="already exists"):
        create_user(settings.db_path, "phone")


@pytest.mark.parametrize("name", ["", "a", "-bad", "with space", "sym$bol", "x" * 40, "../etc"])
def test_invalid_usernames_are_rejected(name):
    with pytest.raises(UserError):
        validate_username(name)


@pytest.mark.parametrize("name", ["ab", "phone-main", "user_1", "A.B", "x" * 32])
def test_valid_usernames_are_accepted(name):
    assert validate_username(name) == name


def test_lookup_is_case_insensitive(settings):
    create_user(settings.db_path, "PhoneMain")
    assert get_user_by_username(settings.db_path, "phonemain") is not None
    assert require_user(settings.db_path, "PHONEMAIN").username == "PhoneMain"


def test_notes_length_is_capped(settings):
    with pytest.raises(UserError, match="500"):
        create_user(settings.db_path, "noisy", notes="x" * 501)


# --------------------------------------------------------------------------- #
# state machine
# --------------------------------------------------------------------------- #
def test_disable_and_enable(settings):
    user = create_user(settings.db_path, "phone")
    disabled = set_enabled(settings.db_path, user.id, False)
    assert disabled.enabled is False
    assert disabled.status() == "disabled"
    assert disabled.is_active() is False

    enabled = set_enabled(settings.db_path, user.id, True)
    assert enabled.enabled is True
    assert enabled.is_active() is True


def test_expired_user_is_not_active(settings):
    past = utcnow() - timedelta(days=1)
    user = create_user(settings.db_path, "old", expires_at=past)
    assert user.is_expired() is True
    assert user.is_active() is False
    assert user.status() == "expired"


def test_enabling_an_expired_account_is_refused(settings):
    user = create_user(settings.db_path, "old", expires_at=utcnow() - timedelta(days=1))
    set_enabled(settings.db_path, user.id, False)
    with pytest.raises(UserError, match="expired"):
        set_enabled(settings.db_path, user.id, True)


def test_renewing_re_enables(settings):
    user = create_user(settings.db_path, "phone", expires_at=utcnow() - timedelta(days=2))
    set_enabled(settings.db_path, user.id, False)
    renewed = set_expiry(settings.db_path, user.id, utcnow() + timedelta(days=30))
    assert renewed.enabled is True
    assert renewed.status() == "active"


def test_set_expiry_to_never(settings):
    user = create_user(settings.db_path, "phone", expires_at=utcnow() + timedelta(days=5))
    updated = set_expiry(settings.db_path, user.id, None)
    assert updated.expires_at is None
    assert updated.expires_display == "Never"


def test_regenerate_uuid_changes_only_the_uuid(settings):
    user = create_user(settings.db_path, "phone")
    original = user.uuid
    rotated = regenerate_uuid(settings.db_path, user.id)
    assert rotated.uuid != original
    assert rotated.username == user.username
    assert rotated.id == user.id


def test_delete_removes_the_account(settings):
    create_user(settings.db_path, "phone")
    delete_user(settings.db_path, "phone")
    assert get_user_by_username(settings.db_path, "phone") is None
    with pytest.raises(UserError):
        delete_user(settings.db_path, "phone")


# --------------------------------------------------------------------------- #
# aggregates & sweeping
# --------------------------------------------------------------------------- #
def test_active_users_excludes_disabled_and_expired(settings):
    create_user(settings.db_path, "good")
    disabled = create_user(settings.db_path, "off")
    set_enabled(settings.db_path, disabled.id, False)
    create_user(settings.db_path, "gone", expires_at=utcnow() - timedelta(minutes=1))

    names = {user.username for user in active_users(settings.db_path)}
    assert names == {"good"}

    stats = user_stats(settings.db_path)
    assert stats == {"total": 3, "active": 1, "disabled": 1, "expired": 1}


def test_disable_expired_users_flips_only_expired(settings):
    create_user(settings.db_path, "keep", expires_at=utcnow() + timedelta(days=1))
    create_user(settings.db_path, "drop", expires_at=utcnow() - timedelta(seconds=5))
    create_user(settings.db_path, "forever")

    changed = disable_expired_users(settings.db_path)
    assert [user.username for user in changed] == ["drop"]
    assert get_user_by_username(settings.db_path, "drop").enabled is False
    assert get_user_by_username(settings.db_path, "keep").enabled is True
    assert get_user_by_username(settings.db_path, "forever").enabled is True

    # Second sweep has nothing left to do.
    assert disable_expired_users(settings.db_path) == []


def test_users_are_listed_alphabetically(settings):
    for name in ("zeta", "Alpha", "mid"):
        create_user(settings.db_path, name)
    assert [u.username for u in list_users(settings.db_path)] == ["Alpha", "mid", "zeta"]


# --------------------------------------------------------------------------- #
# expiry helpers
# --------------------------------------------------------------------------- #
def test_expiry_from_days():
    assert expiry_from_days(0) is None
    assert expiry_from_days(-3) is None
    target = expiry_from_days(30)
    assert 29 < (target - utcnow()).days + 1 <= 31


@pytest.mark.parametrize("text", ["2026-12-31", "31-12-2026", "2026/12/31"])
def test_parse_expiry_date_accepts_common_formats(text):
    parsed = parse_expiry_date(text)
    assert (parsed.year, parsed.month, parsed.day) == (2026, 12, 31)
    assert (parsed.hour, parsed.minute, parsed.second) == (23, 59, 59)


@pytest.mark.parametrize("text", ["", "tomorrow", "2026-13-45", "not-a-date"])
def test_parse_expiry_date_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_expiry_date(text)


def test_humanise_delta():
    assert humanise_delta(None) == "never"
    assert humanise_delta(utcnow() - timedelta(hours=1)) == "expired"
    assert humanise_delta(utcnow() + timedelta(days=2, hours=3)).startswith("2d")
