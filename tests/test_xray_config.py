"""Xray configuration rendering, structural signatures and real validation."""

from __future__ import annotations

from datetime import timedelta

import pytest

from app.config import load_settings
from app.models import active_users, create_user, set_enabled
from app.util import utcnow
from app.xray_manager import (
    REALITY_INBOUND_TAG,
    WS_BACKEND_INBOUND_TAG,
    _parse_x25519_output,
    ensure_reality_keys,
    load_template,
    render_config,
    structural_signature,
    validate_config,
)


def _inbound(config, tag):
    return next((ib for ib in config["inbounds"] if ib.get("tag") == tag), None)


def _render(settings, keys, users=None):
    return render_config(
        settings, users if users is not None else active_users(settings.db_path), keys, "/gateway/test"
    )


# --------------------------------------------------------------------------- #
# structure
# --------------------------------------------------------------------------- #
def test_rendered_config_has_expected_shape(settings, reality_keys):
    config = _render(settings, reality_keys)
    assert _inbound(config, REALITY_INBOUND_TAG) is not None
    assert _inbound(config, WS_BACKEND_INBOUND_TAG) is not None
    assert config["api"]["listen"] == f"127.0.0.1:{settings.xray_api_port}"
    assert config["log"]["loglevel"] == settings.xray_log_level
    # Comment keys from the template must not survive into the runtime config.
    assert "_comment" not in config
    assert all("_comment" not in rule for rule in config["routing"]["rules"])


def test_reality_inbound_is_configured_from_settings(settings, reality_keys):
    reality = _inbound(_render(settings, reality_keys), REALITY_INBOUND_TAG)
    stream = reality["streamSettings"]
    assert reality["port"] == settings.xray_port
    assert reality["listen"] == "0.0.0.0"
    assert reality["settings"]["decryption"] == "none"
    assert stream["network"] == "raw"
    assert stream["security"] == "reality"
    assert stream["realitySettings"]["target"] == settings.reality_destination
    assert stream["realitySettings"]["serverNames"] == [settings.reality_server_name]
    assert stream["realitySettings"]["privateKey"] == reality_keys.private_key
    assert stream["realitySettings"]["shortIds"] == [reality_keys.short_id]


def test_ws_backend_is_loopback_only(settings, reality_keys):
    backend = _inbound(_render(settings, reality_keys), WS_BACKEND_INBOUND_TAG)
    assert backend["listen"] == "127.0.0.1"
    assert backend["port"] == settings.xray_ws_backend_port
    assert backend["streamSettings"]["security"] == "none"


def test_private_networks_are_blocked(settings, reality_keys):
    rules = _render(settings, reality_keys)["routing"]["rules"]
    blocking = [r for r in rules if r.get("outboundTag") == "block" and "ip" in r]
    assert blocking, "expected a rule blocking private address space"
    blocked = set(blocking[0]["ip"])
    for cidr in ("127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "::1/128"):
        assert cidr in blocked


def test_api_is_bound_to_loopback(settings, reality_keys):
    assert _render(settings, reality_keys)["api"]["listen"].startswith("127.0.0.1:")


# --------------------------------------------------------------------------- #
# account membership — the security-critical part
# --------------------------------------------------------------------------- #
def test_active_users_appear_in_both_inbounds(settings, reality_keys):
    create_user(settings.db_path, "phone")
    config = _render(settings, reality_keys)

    reality_clients = _inbound(config, REALITY_INBOUND_TAG)["settings"]["clients"]
    ws_clients = _inbound(config, WS_BACKEND_INBOUND_TAG)["settings"]["clients"]
    assert [c["email"] for c in reality_clients] == ["phone@railgate"]
    assert [c["email"] for c in ws_clients] == ["phone@railgate"]
    assert reality_clients[0]["flow"] == "xtls-rprx-vision"
    # Vision is invalid over WebSocket, so the backend inbound must not set it.
    assert "flow" not in ws_clients[0]


def test_disabled_users_are_absent_from_the_config(settings, reality_keys):
    keep = create_user(settings.db_path, "keep")
    drop = create_user(settings.db_path, "drop")
    set_enabled(settings.db_path, drop.id, False)

    config = _render(settings, reality_keys)
    emails = {c["email"] for c in _inbound(config, REALITY_INBOUND_TAG)["settings"]["clients"]}
    assert emails == {keep.email}
    assert drop.uuid not in str(config)


def test_expired_users_are_absent_from_the_config(settings, reality_keys):
    create_user(settings.db_path, "current", expires_at=utcnow() + timedelta(days=1))
    expired = create_user(settings.db_path, "lapsed", expires_at=utcnow() - timedelta(seconds=1))

    config = _render(settings, reality_keys)
    emails = {c["email"] for c in _inbound(config, REALITY_INBOUND_TAG)["settings"]["clients"]}
    assert emails == {"current@railgate"}
    assert expired.uuid not in str(config)


def test_no_accounts_yields_empty_client_lists(settings, reality_keys):
    config = _render(settings, reality_keys)
    assert _inbound(config, REALITY_INBOUND_TAG)["settings"]["clients"] == []


# --------------------------------------------------------------------------- #
# toggles
# --------------------------------------------------------------------------- #
def test_disabling_the_fallback_removes_the_backend_inbound(clean_env, settings, reality_keys, tmp_path):
    clean_env.setenv("ENABLE_WS_FALLBACK", "false")
    without_fallback = load_settings()
    config = render_config(without_fallback, [], reality_keys, "/gateway/test")
    assert _inbound(config, WS_BACKEND_INBOUND_TAG) is None
    assert _inbound(config, REALITY_INBOUND_TAG) is not None


def test_bittorrent_rule_is_removed_when_disabled(clean_env, settings, reality_keys):
    with_rule = _render(settings, reality_keys)
    assert any("bittorrent" in (r.get("protocol") or []) for r in with_rule["routing"]["rules"])

    clean_env.setenv("BLOCK_BITTORRENT", "false")
    without_rule = render_config(load_settings(), [], reality_keys, "/gateway/test")
    assert not any("bittorrent" in (r.get("protocol") or []) for r in without_rule["routing"]["rules"])


# --------------------------------------------------------------------------- #
# structural signature drives restart-vs-live-sync
# --------------------------------------------------------------------------- #
def test_signature_ignores_account_changes(settings, reality_keys):
    empty = _render(settings, reality_keys)
    create_user(settings.db_path, "phone")
    with_user = _render(settings, reality_keys)
    assert structural_signature(empty) == structural_signature(with_user)


def test_signature_changes_with_the_transport(clean_env, settings, reality_keys):
    baseline = _render(settings, reality_keys)
    clean_env.setenv("REALITY_SERVER_NAME", "www.apple.com")
    clean_env.setenv("REALITY_DESTINATION", "www.apple.com:443")
    changed = render_config(load_settings(), [], reality_keys, "/gateway/test")
    assert structural_signature(baseline) != structural_signature(changed)


def test_signature_changes_with_the_port(clean_env, settings, reality_keys):
    baseline = _render(settings, reality_keys)
    clean_env.setenv("XRAY_PORT", "3443")
    changed = render_config(load_settings(), [], reality_keys, "/gateway/test")
    assert structural_signature(baseline) != structural_signature(changed)


# --------------------------------------------------------------------------- #
# template & key parsing
# --------------------------------------------------------------------------- #
def test_template_is_valid_json_with_required_tags(settings):
    template = load_template(settings)
    tags = {ib.get("tag") for ib in template["inbounds"]}
    assert {REALITY_INBOUND_TAG, WS_BACKEND_INBOUND_TAG} <= tags


def test_x25519_parser_handles_the_v26_format():
    private, public = _parse_x25519_output(
        "PrivateKey: SDfzz6AVB2ZvagZrHkZ5QLzKTPQWu2mdz5PX8TOEkEQ\n"
        "Password (PublicKey): 4Kp94-un_UP_rt5UOgWj9iSZ5Td1xmukCRQMqmaA6zA\n"
        "Hash32: lWGbFSvd8y-1cgeG4uZFUGHu375sKb-xSNE4uEnDxHU\n"
    )
    assert private == "SDfzz6AVB2ZvagZrHkZ5QLzKTPQWu2mdz5PX8TOEkEQ"
    assert public == "4Kp94-un_UP_rt5UOgWj9iSZ5Td1xmukCRQMqmaA6zA"


def test_x25519_parser_handles_the_legacy_format():
    private, public = _parse_x25519_output("Private key: aaa\nPublic key: bbb\n")
    assert (private, public) == ("aaa", "bbb")


def test_x25519_parser_rejects_garbage():
    from app.xray_manager import XrayError

    with pytest.raises(XrayError, match="x25519"):
        _parse_x25519_output("something unexpected")


# --------------------------------------------------------------------------- #
# real binary
# --------------------------------------------------------------------------- #
@pytest.mark.xray
def test_generated_config_passes_real_xray_validation(xray_settings):
    keys = ensure_reality_keys(xray_settings)
    create_user(xray_settings.db_path, "phone")
    create_user(xray_settings.db_path, "laptop", expires_at=utcnow() + timedelta(days=30))

    config = _render(xray_settings, keys)
    ok, output = validate_config(xray_settings, config)
    assert ok, output
    assert "Configuration OK" in output


@pytest.mark.xray
def test_empty_config_passes_real_xray_validation(xray_settings):
    keys = ensure_reality_keys(xray_settings)
    ok, output = validate_config(xray_settings, _render(xray_settings, keys))
    assert ok, output


@pytest.mark.xray
def test_reality_keys_are_persisted_and_reused(xray_settings):
    first = ensure_reality_keys(xray_settings)
    second = ensure_reality_keys(xray_settings)
    assert first == second
    assert xray_settings.reality_private_key_path.read_text().strip() == first.private_key
    assert oct(xray_settings.reality_private_key_path.stat().st_mode)[-3:] == "600"
    assert len(first.short_id) == 16
    int(first.short_id, 16)  # must be hex


@pytest.mark.xray
def test_invalid_config_is_rejected_by_validation(xray_settings):
    keys = ensure_reality_keys(xray_settings)
    config = _render(xray_settings, keys)
    config["inbounds"][0]["protocol"] = "definitely-not-a-protocol"
    ok, output = validate_config(xray_settings, config)
    assert ok is False
    assert output
