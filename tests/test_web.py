"""End-to-end tests for the admin HTTP surface: auth, CSRF, API and health."""

from __future__ import annotations

import importlib
import re

import pytest
from fastapi.testclient import TestClient

from app.models import get_user_by_username
from app.xray_manager import REALITY_INBOUND_TAG, ensure_reality_keys, render_config

CSRF_RE = re.compile(r'<meta name="csrf-token" content="([^"]*)"')
PASSWORD = "test-password-123"


@pytest.fixture
def web(clean_env, settings):
    """A TestClient bound to a freshly configured app instance."""
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "railgate.up.railway.app")

    from app import config as config_module

    config_module.get_settings.cache_clear()
    main_module = importlib.import_module("app.main")
    importlib.reload(main_module)

    with TestClient(main_module.app) as client:
        yield client, main_module


@pytest.fixture
def authed(web):
    client, module = web
    response = client.post(
        "/login",
        data={"username": "admin", "password": PASSWORD},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text
    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
    token = CSRF_RE.search(dashboard.text)
    assert token, "the dashboard must expose a CSRF token"
    client.headers.update({"X-CSRF-Token": token.group(1)})
    return client, module


# --------------------------------------------------------------------------- #
# health
# --------------------------------------------------------------------------- #
def test_health_needs_no_authentication_and_leaks_nothing(web):
    client, _ = web
    response = client.get("/health")
    assert response.status_code in (200, 503)
    payload = response.json()
    assert set(payload) == {"status", "xray", "database"}
    assert payload["database"] == "ok"
    # Xray is not running under pytest, so the probe must report degraded.
    assert payload["status"] == "degraded"
    assert payload["xray"] == "stopped"
    assert response.status_code == 503


def test_health_never_exposes_accounts(web, settings):
    from app.models import create_user

    create_user(settings.db_path, "secret-user")
    body = web[0].get("/health").text
    assert "secret-user" not in body
    assert "uuid" not in body.lower()


# --------------------------------------------------------------------------- #
# authentication
# --------------------------------------------------------------------------- #
def test_pages_require_a_session(web):
    client, _ = web
    for path in ("/dashboard", "/users", "/server", "/tools", "/settings", "/logs", "/users/new"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_api_requires_authentication(web):
    client, _ = web
    assert client.get("/api/users").status_code == 401
    assert client.get("/api/server").status_code == 401
    assert client.post("/api/tools/xray_status").status_code == 401


def test_login_rejects_a_wrong_password(web):
    client, _ = web
    response = client.post(
        "/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False
    )
    assert response.status_code == 303
    assert "error=" in response.headers["location"]
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_login_sets_a_hardened_cookie(web):
    client, _ = web
    response = client.post(
        "/login", data={"username": "admin", "password": PASSWORD}, follow_redirects=False
    )
    cookie_header = response.headers.get("set-cookie", "")
    assert "railgate_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "SameSite=lax" in cookie_header
    # APP_ENV=development in tests, so Secure is intentionally absent here.


def test_logout_invalidates_the_session(authed):
    client, _ = authed
    csrf = client.headers["X-CSRF-Token"]
    response = client.post(
        "/logout", data={"csrf_token": csrf}, follow_redirects=False
    )
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert client.get("/dashboard", follow_redirects=False).status_code == 303


def test_logout_without_a_csrf_token_is_refused(authed):
    client, _ = authed
    response = client.post("/logout", data={"csrf_token": "wrong"}, follow_redirects=False)
    assert response.status_code == 303
    assert "CSRF" in response.headers["location"]
    # The session must survive a forged logout attempt.
    assert client.get("/dashboard", follow_redirects=False).status_code == 200


def test_repeated_failures_trigger_rate_limiting(web):
    client, _ = web
    messages = []
    for _ in range(12):
        response = client.post(
            "/login", data={"username": "admin", "password": "wrong"}, follow_redirects=False
        )
        messages.append(response.headers["location"])
    assert any("Too+many" in m or "Too%20many" in m for m in messages)


def test_session_is_stored_hashed_not_in_clear(authed, settings):
    client, _ = authed
    token = client.cookies.get("railgate_session")
    from app.database import get_db

    with get_db(settings.db_path) as conn:
        rows = conn.execute("SELECT token_hash FROM sessions").fetchall()
    assert rows
    assert all(row["token_hash"] != token for row in rows)


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #
def test_state_changing_api_requires_a_csrf_token(authed):
    client, _ = authed
    without = client.post("/api/users", json={"username": "nope"}, headers={"X-CSRF-Token": ""})
    assert without.status_code == 403

    wrong = client.post(
        "/api/users", json={"username": "nope"}, headers={"X-CSRF-Token": "not-the-token"}
    )
    assert wrong.status_code == 403


def test_form_posts_require_a_csrf_token(authed):
    client, _ = authed
    response = client.post(
        "/users/new",
        data={"username": "viaform", "expiry_choice": "never", "csrf_token": "bogus"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert "CSRF" in response.headers["location"]


# --------------------------------------------------------------------------- #
# account lifecycle over the API
# --------------------------------------------------------------------------- #
def test_full_account_lifecycle(authed, settings):
    client, _ = authed

    created = client.post("/api/users", json={"username": "phone-main", "days": 30})
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["user"]["username"] == "phone-main"
    assert body["user"]["status"] == "active"
    uuid = body["user"]["uuid"]

    primary = body["credentials"]["primary"]
    assert primary["available"] is True
    assert primary["uri"].startswith(f"vless://{uuid}@metro.proxy.rlwy.net:18423?")

    listing = client.get("/api/users").json()
    assert [u["username"] for u in listing["users"]] == ["phone-main"]
    assert listing["stats"]["active"] == 1

    user_id = body["user"]["id"]

    uri_response = client.get(f"/api/users/{user_id}/uri")
    assert uri_response.json()["uri"] == primary["uri"]

    qr = client.get(f"/api/users/{user_id}/qr")
    assert qr.status_code == 200
    assert qr.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in qr.content

    config = client.get(f"/api/users/{user_id}/config")
    assert config.status_code == 200
    assert "attachment" in config.headers["content-disposition"]
    assert uuid in config.text

    assert client.post(f"/api/users/{user_id}/disable").json()["user"]["status"] == "disabled"
    assert client.post(f"/api/users/{user_id}/enable").json()["user"]["status"] == "active"

    renewed = client.post(f"/api/users/{user_id}/renew", json={"days": 90}).json()
    assert renewed["user"]["expires_at"] is not None

    rotated = client.post(f"/api/users/{user_id}/regenerate").json()
    assert rotated["user"]["uuid"] != uuid

    assert client.delete(f"/api/users/{user_id}").json()["ok"] in (True, False)
    assert get_user_by_username(settings.db_path, "phone-main") is None


def test_duplicate_username_returns_a_readable_error(authed):
    client, _ = authed
    client.post("/api/users", json={"username": "phone"})
    duplicate = client.post("/api/users", json={"username": "phone"})
    assert duplicate.status_code == 400
    assert "already exists" in duplicate.json()["error"]


def test_invalid_username_is_rejected(authed):
    client, _ = authed
    response = client.post("/api/users", json={"username": "bad name!"})
    assert response.status_code == 400
    assert "invalid" in response.json()["error"].lower()


def test_missing_account_returns_404(authed):
    client, _ = authed
    assert client.get("/api/users/9999").status_code == 404


@pytest.mark.xray
def test_disabled_user_disappears_from_the_generated_config(authed, settings):
    client, _ = authed
    keys = ensure_reality_keys(settings)

    created = client.post("/api/users", json={"username": "phone"}).json()
    user_id = created["user"]["id"]
    uuid = created["user"]["uuid"]

    from app.models import active_users

    before = render_config(settings, active_users(settings.db_path), keys, "/gateway/test")
    reality = next(ib for ib in before["inbounds"] if ib["tag"] == REALITY_INBOUND_TAG)
    assert uuid in {client_entry["id"] for client_entry in reality["settings"]["clients"]}

    client.post(f"/api/users/{user_id}/disable")

    after = render_config(settings, active_users(settings.db_path), keys, "/gateway/test")
    reality_after = next(ib for ib in after["inbounds"] if ib["tag"] == REALITY_INBOUND_TAG)
    assert reality_after["settings"]["clients"] == []
    assert uuid not in str(after)


# --------------------------------------------------------------------------- #
# pages & security headers
# --------------------------------------------------------------------------- #
def test_every_page_renders(authed):
    client, _ = authed
    client.post("/api/users", json={"username": "phone"})
    for path in ("/dashboard", "/users", "/users/new", "/server", "/tools", "/settings", "/logs"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "<html" in response.text.lower()

    detail = client.get("/users/1")
    assert detail.status_code == 200
    assert "phone" in detail.text


def test_security_headers_are_present(web):
    client, _ = web
    headers = client.get("/login").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "script-src 'self'" in headers["Content-Security-Policy"]


def test_no_secrets_are_rendered_into_the_pages(authed, settings):
    client, _ = authed
    keys = ensure_reality_keys(settings)
    for path in ("/dashboard", "/server", "/settings"):
        body = client.get(path).text
        assert PASSWORD not in body
        assert settings.admin_session_secret not in body
        if keys is not None:
            assert keys.private_key not in body


def test_server_api_exposes_no_private_key(authed, settings):
    client, _ = authed
    keys = ensure_reality_keys(settings)
    payload = client.get("/api/server").json()
    assert payload["reality"]["public_key"]
    assert keys.private_key not in str(payload)
    assert payload["vpn"]["internal_port"] == settings.xray_port
    assert payload["vpn"]["public_host"] == "metro.proxy.rlwy.net"


def test_database_is_not_downloadable_over_http(web):
    client, _ = web
    for path in ("/vpn.db", "/data/vpn.db", "/static/../vpn.db", "/api/db"):
        assert client.get(path, follow_redirects=False).status_code in (301, 307, 401, 403, 404, 405)


def test_tool_actions_are_allowlisted(authed):
    client, _ = authed
    assert client.post("/api/tools/rm_-rf").status_code == 404
    assert client.post("/api/tools/dns_test").status_code == 200
