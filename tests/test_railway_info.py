"""Railway environment detection and the manual host/port overrides."""

from __future__ import annotations

from app.config import load_settings
from app.railway_info import (
    detect_railway,
    resolve_fallback_endpoint,
    resolve_public_endpoint,
)


def test_no_railway_environment_is_detected_as_absent(settings):
    info = detect_railway()
    assert info.detected is False
    assert info.tcp_proxy_configured is False
    assert info.public_domain == ""


def test_all_railway_variables_are_read(clean_env, settings):
    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "railgate-production.up.railway.app")
    clean_env.setenv("RAILWAY_PRIVATE_DOMAIN", "railgate.railway.internal")
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    clean_env.setenv("RAILWAY_TCP_APPLICATION_PORT", "2443")
    clean_env.setenv("RAILWAY_SERVICE_NAME", "railgate")
    clean_env.setenv("RAILWAY_PROJECT_NAME", "personal-vpn")
    clean_env.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    clean_env.setenv("RAILWAY_REPLICA_REGION", "europe-west4")
    clean_env.setenv("RAILWAY_DEPLOYMENT_ID", "0f3a1c2b-dead-beef-0000-111122223333")

    info = detect_railway()
    assert info.detected is True
    assert info.public_domain == "railgate-production.up.railway.app"
    assert info.private_domain == "railgate.railway.internal"
    assert info.tcp_proxy_domain == "metro.proxy.rlwy.net"
    assert info.tcp_proxy_port == 18423
    assert info.tcp_application_port == 2443
    assert info.service_name == "railgate"
    assert info.project_name == "personal-vpn"
    assert info.environment_name == "production"
    assert info.replica_region == "europe-west4"
    assert info.short_deployment_id == "0f3a1c2b"
    assert info.tcp_proxy_configured is True
    assert info.public_url == "https://railgate-production.up.railway.app"


def test_endpoint_uses_railway_tcp_proxy(clean_env, settings):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    endpoint = resolve_public_endpoint(settings)
    assert endpoint.available is True
    assert (endpoint.host, endpoint.port) == ("metro.proxy.rlwy.net", 18423)
    assert endpoint.host_source == "RAILWAY_TCP_PROXY_DOMAIN"
    assert endpoint.port_source == "RAILWAY_TCP_PROXY_PORT"
    assert endpoint.display == "metro.proxy.rlwy.net:18423"


def test_manual_overrides_win(clean_env, settings):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    clean_env.setenv("PUBLIC_PROXY_HOST", "gateway.example.com")
    clean_env.setenv("PUBLIC_PROXY_PORT", "443")
    overridden = load_settings()
    endpoint = resolve_public_endpoint(overridden)
    assert (endpoint.host, endpoint.port) == ("gateway.example.com", 443)
    assert endpoint.host_source == "PUBLIC_PROXY_HOST"
    assert endpoint.port_source == "PUBLIC_PROXY_PORT"


def test_overrides_can_be_partial(clean_env, settings):
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "18423")
    clean_env.setenv("PUBLIC_PROXY_HOST", "gateway.example.com")
    endpoint = resolve_public_endpoint(load_settings())
    assert endpoint.available is True
    assert endpoint.host_source == "PUBLIC_PROXY_HOST"
    assert endpoint.port_source == "RAILWAY_TCP_PROXY_PORT"


def test_missing_tcp_proxy_is_reported_not_raised(settings):
    endpoint = resolve_public_endpoint(settings)
    assert endpoint.available is False
    assert endpoint.display == "NOT CONFIGURED"
    assert "TCP Proxy" in endpoint.reason
    assert str(settings.xray_port) in endpoint.reason


def test_invalid_railway_port_is_ignored(clean_env, settings):
    clean_env.setenv("RAILWAY_TCP_PROXY_DOMAIN", "metro.proxy.rlwy.net")
    clean_env.setenv("RAILWAY_TCP_PROXY_PORT", "not-a-number")
    info = detect_railway()
    assert info.tcp_proxy_port is None
    assert resolve_public_endpoint(settings, info).available is False


def test_fallback_needs_a_public_domain(clean_env, settings):
    unavailable = resolve_fallback_endpoint(settings)
    assert unavailable.available is False
    assert "Public Networking" in unavailable.reason

    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "railgate-production.up.railway.app")
    available = resolve_fallback_endpoint(settings)
    assert available.available is True
    assert available.host == "railgate-production.up.railway.app"
    assert available.port == 443


def test_fallback_can_be_disabled(clean_env, settings):
    clean_env.setenv("RAILWAY_PUBLIC_DOMAIN", "railgate-production.up.railway.app")
    clean_env.setenv("ENABLE_WS_FALLBACK", "false")
    endpoint = resolve_fallback_endpoint(load_settings())
    assert endpoint.available is False
    assert "disabled" in endpoint.reason
