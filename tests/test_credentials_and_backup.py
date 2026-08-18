"""Credential assembly, QR rendering, backups and configuration validation."""

from __future__ import annotations

import pytest

from app.backup import BackupError, create_backup, inspect_backup, list_backups, restore_backup
from app.config import ConfigError, load_settings
from app.credentials import build_credentials, client_config_json, qr_ascii, qr_svg
from app.models import create_user, get_user_by_username
from app.xray_manager import ensure_reality_keys, ensure_ws_path


# --------------------------------------------------------------------------- #
# credential bundles
# --------------------------------------------------------------------------- #
def test_bundle_reports_missing_tcp_proxy_instead_of_failing(settings, monkeypatch):
    monkeypatch.setattr("app.credentials.load_reality_keys", lambda _s: None)
    user = create_user(settings.db_path, "phone")
    bundle = build_credentials(settings, user)
    assert bundle.primary.available is False
    assert bundle.primary.uri == ""
    assert "REALITY key material" in bundle.primary.reason
    assert bundle.any_available is False
    assert bundle.best_uri == ""


def test_bundle_builds_a_link_once_the_endpoint_exists(clean_env, settings, reality_keys):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    user = create_user(settings.db_path, "phone")

    bundle = build_credentials(settings, user, keys=reality_keys)
    assert bundle.primary.available is True
    assert bundle.primary.uri.startswith(f"vless://{user.uuid}@metro.proxy.rlwy.net:18423?")
    assert bundle.best_uri == bundle.primary.uri
    assert bundle.primary.fields["Short ID"] == reality_keys.short_id


def test_bundle_never_exposes_the_private_key(clean_env, settings, reality_keys):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
    user = create_user(settings.db_path, "phone")

    serialised = str(build_credentials(settings, user, keys=reality_keys).as_dict())
    assert reality_keys.private_key not in serialised
    assert reality_keys.public_key in serialised


def test_fallback_link_uses_the_public_domain(clean_env, settings, reality_keys):
    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "app.up.railway.app")
    user = create_user(settings.db_path, "phone")
    bundle = build_credentials(settings, user, keys=reality_keys)

    assert bundle.fallback.available is True
    assert bundle.fallback.port == 443
    assert "type=ws" in bundle.fallback.uri
    assert "flow=" not in bundle.fallback.uri
    assert bundle.any_available is True
    # With no TCP proxy configured, the fallback becomes the usable link.
    assert bundle.primary.available is False
    assert bundle.best_uri == bundle.fallback.uri


def test_ws_path_is_random_persisted_and_unguessable(settings):
    first = ensure_ws_path(settings)
    assert first.startswith("/gateway/")
    assert len(first) > len("/gateway/") + 8
    assert ensure_ws_path(settings) == first


def test_ws_path_override_is_honoured(clean_env, settings):
    clean_env.setenv("WS_FALLBACK_PATH", "custom/path/")
    assert ensure_ws_path(load_settings()) == "/custom/path"


def test_client_config_export(clean_env, settings, reality_keys, monkeypatch):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    monkeypatch.setattr("app.credentials.load_reality_keys", lambda _s: reality_keys)
    user = create_user(settings.db_path, "phone")

    exported = client_config_json(settings, user, "reality")
    assert user.uuid in exported
    assert reality_keys.public_key in exported
    assert reality_keys.private_key not in exported


# --------------------------------------------------------------------------- #
# QR codes
# --------------------------------------------------------------------------- #
def test_qr_svg_is_a_self_contained_document():
    svg = qr_svg("vless://3a6fccfc-0c1b-4138-8dac-d20010ede80c@h.example:443?type=tcp#phone")
    assert svg.startswith("<?xml") or svg.lstrip().startswith("<svg")
    assert "<svg" in svg and "</svg>" in svg
    assert "<script" not in svg.lower()


def test_qr_ascii_is_printable():
    art = qr_ascii("vless://3a6fccfc-0c1b-4138-8dac-d20010ede80c@h.example:443")
    assert len(art.splitlines()) > 10


def test_qr_rejects_an_empty_payload():
    from app.credential_generator import CredentialError

    with pytest.raises(CredentialError):
        qr_svg("")


# --------------------------------------------------------------------------- #
# backup / restore
# --------------------------------------------------------------------------- #
@pytest.mark.xray
def test_backup_and_restore_round_trip(xray_settings):
    ensure_reality_keys(xray_settings)
    original = create_user(xray_settings.db_path, "phone")
    backup = create_backup(xray_settings, label="test")

    assert backup.path.exists()
    assert backup.user_count == 1
    assert oct(backup.path.stat().st_mode)[-3:] == "600"
    assert inspect_backup(backup.path)["user_count"] == 1
    assert any(entry["filename"] == backup.path.name for entry in list_backups(xray_settings))

    # Destroy the account, then restore it.
    from app.models import delete_user

    delete_user(xray_settings.db_path, "phone")
    assert get_user_by_username(xray_settings.db_path, "phone") is None

    result = restore_backup(xray_settings, backup.path, confirm=True)
    assert "vpn.db" in result["restored"]
    recovered = get_user_by_username(xray_settings.db_path, "phone")
    assert recovered is not None
    assert recovered.uuid == original.uuid


def test_restore_requires_explicit_confirmation(settings):
    create_user(settings.db_path, "phone")
    backup = create_backup(settings)
    with pytest.raises(BackupError, match="confirmation"):
        restore_backup(settings, backup.path)


def test_backup_excludes_logs(settings):
    create_user(settings.db_path, "phone")
    settings.xray_log_path.write_text("noisy log line\n", encoding="utf-8")
    manifest = inspect_backup(create_backup(settings).path)
    assert all(not name.endswith(".log") for name in manifest["includes"])


# --------------------------------------------------------------------------- #
# configuration validation
# --------------------------------------------------------------------------- #
def test_production_requires_an_admin_password(clean_env, tmp_path):
    clean_env.setenv("APP_ENV", "production")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    with pytest.raises(ConfigError, match="ADMIN_PASSWORD is missing"):
        load_settings()


def test_development_generates_a_bootstrap_password(clean_env, tmp_path):
    clean_env.setenv("APP_ENV", "development")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    resolved = load_settings()
    assert resolved.admin_password_is_bootstrap is True
    assert len(resolved.admin_password) >= 16


def test_short_passwords_are_rejected(clean_env, tmp_path):
    clean_env.setenv("APP_ENV", "production")
    clean_env.setenv("ADMIN_PASSWORD", "short")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    with pytest.raises(ConfigError, match="8 characters"):
        load_settings()


def test_port_conflicts_are_rejected(clean_env, tmp_path):
    clean_env.setenv("APP_ENV", "development")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    clean_env.setenv("PORT", "2443")
    clean_env.setenv("XRAY_PORT", "2443")
    with pytest.raises(ConfigError, match="Port conflict"):
        load_settings()


@pytest.mark.parametrize(
    "name,value,message",
    [
        ("REALITY_DESTINATION", "example.com:notaport", "REALITY_DESTINATION"),
        ("REALITY_FINGERPRINT", "netscape", "REALITY_FINGERPRINT"),
        ("URI_NETWORK_ALIAS", "grpc", "URI_NETWORK_ALIAS"),
        ("XRAY_LOG_LEVEL", "verbose", "XRAY_LOG_LEVEL"),
        ("LOG_LEVEL", "chatty", "LOG_LEVEL"),
        ("ENABLE_WS_FALLBACK", "maybe", "boolean"),
        ("XRAY_PORT", "99999", "maximum"),
    ],
)
def test_invalid_environment_values_fail_loudly(clean_env, tmp_path, name, value, message):
    clean_env.setenv("APP_ENV", "development")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    clean_env.setenv(name, value)
    with pytest.raises(ConfigError, match=message):
        load_settings()


def test_reality_destination_gets_a_default_port(clean_env, tmp_path):
    clean_env.setenv("APP_ENV", "development")
    clean_env.setenv("DATA_DIR", str(tmp_path))
    clean_env.setenv("REALITY_DESTINATION", "www.apple.com")
    assert load_settings().reality_destination == "www.apple.com:443"
