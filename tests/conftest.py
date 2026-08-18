"""Shared fixtures.

Every test runs against a throwaway ``DATA_DIR`` so nothing touches a real
deployment, and no test credential is ever written into the repository.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import load_settings  # noqa: E402
from app.database import init_db  # noqa: E402

# Environment variables that must not leak in from the developer's shell.
_MANAGED_ENV = [
    "ADMIN_USERNAME", "ADMIN_PASSWORD", "ADMIN_SESSION_SECRET", "APP_ENV", "APP_NAME",
    "APP_ROOT", "DATA_DIR", "PORT", "XRAY_PORT", "XRAY_WS_BACKEND_PORT", "XRAY_API_PORT",
    "XRAY_BIN", "PUBLIC_PROXY_HOST", "PUBLIC_PROXY_PORT", "REALITY_SERVER_NAME",
    "REALITY_DESTINATION", "REALITY_FINGERPRINT", "REALITY_SPIDER_X", "ENABLE_WS_FALLBACK",
    "WS_FALLBACK_PATH", "VPN_DEFAULT_EXPIRY_DAYS", "EXPIRY_CHECK_INTERVAL", "LOG_LEVEL",
    "XRAY_LOG_LEVEL", "URI_NETWORK_ALIAS", "BLOCK_BITTORRENT", "OUTBOUND_IP_CHECK_ENABLED",
    "RAILWAY_PUBLIC_DOMAIN", "RAILWAY_PRIVATE_DOMAIN", "RAILWAY_TCP_PROXY_DOMAIN",
    "RAILWAY_TCP_PROXY_PORT", "RAILWAY_TCP_APPLICATION_PORT", "RAILWAY_SERVICE_NAME",
    "RAILWAY_PROJECT_NAME", "RAILWAY_ENVIRONMENT_NAME", "RAILWAY_ENVIRONMENT",
    "RAILWAY_PROJECT_ID", "RAILWAY_REPLICA_REGION", "RAILWAY_DEPLOYMENT_ID",
]


def find_xray_binary() -> str | None:
    """Locate a usable Xray binary for the integration-flavoured tests."""
    candidates = [
        os.environ.get("XRAY_BIN_FOR_TESTS", ""),
        "/usr/local/bin/xray",
        "/tmp/xprobe/bin/xray",
        shutil.which("xray") or "",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


@pytest.fixture
def clean_env(monkeypatch):
    for name in _MANAGED_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def settings(clean_env, tmp_path):
    """Settings pointing at an isolated temporary data directory."""
    clean_env.setenv("APP_ENV", "development")
    clean_env.setenv("ADMIN_PASSWORD", "test-password-123")
    clean_env.setenv("ADMIN_SESSION_SECRET", "0" * 64)
    clean_env.setenv("DATA_DIR", str(tmp_path / "data"))
    clean_env.setenv("APP_ROOT", str(ROOT))
    clean_env.setenv("OUTBOUND_IP_CHECK_ENABLED", "false")
    clean_env.setenv("REALITY_SERVER_NAME", "www.microsoft.com")
    clean_env.setenv("REALITY_DESTINATION", "www.microsoft.com:443")

    binary = find_xray_binary()
    if binary:
        clean_env.setenv("XRAY_BIN", binary)

    resolved = load_settings()
    for directory in resolved.required_directories():
        directory.mkdir(parents=True, exist_ok=True)
    init_db(resolved.db_path, force=True)
    return resolved


@pytest.fixture
def xray_settings(settings):
    """Settings that are guaranteed to have a real Xray binary."""
    if find_xray_binary() is None:
        pytest.skip("no Xray binary available")
    return settings


@pytest.fixture
def reality_keys():
    from app.xray_manager import RealityKeys

    return RealityKeys(
        private_key="PRIVATE-KEY-MUST-NEVER-LEAK",
        public_key="4Kp94-un_UP_rt5UOgWj9iSZ5Td1xmukCRQMqmaA6zA",
        short_id="0123456789abcdef",
    )
