"""Environment-driven configuration.

Every tunable lives here so the rest of the code never touches ``os.environ``
directly. Invalid values fail loudly at startup instead of producing a subtly
broken deployment.
"""

from __future__ import annotations

import os
import secrets
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from app import APP_VERSION

# Load a local .env when developing. Railway injects real environment variables,
# so this is a no-op in production.
try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    _dotenv = Path(__file__).resolve().parent.parent / ".env"
    if _dotenv.is_file():
        load_dotenv(_dotenv, override=False)
except Exception:  # pragma: no cover - dotenv is optional
    pass


class ConfigError(RuntimeError):
    """Raised when the environment is missing something we cannot invent."""


TRUE_VALUES = {"1", "true", "yes", "on", "y", "t"}
FALSE_VALUES = {"0", "false", "no", "off", "n", "f"}

VALID_FINGERPRINTS = {
    "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized", "unsafe",
}
VALID_XRAY_LOG_LEVELS = {"debug", "info", "warning", "error", "none"}
VALID_URI_NETWORK_ALIASES = {"tcp", "raw"}


def _str(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip()


def _bool(name: str, default: bool) -> bool:
    raw = _str(name)
    if not raw:
        return default
    lowered = raw.lower()
    if lowered in TRUE_VALUES:
        return True
    if lowered in FALSE_VALUES:
        return False
    raise ConfigError(
        f"{name}={raw!r} is not a boolean. Use one of: true/false, yes/no, 1/0."
    )


def _int(name: str, default: int, minimum: int | None = None, maximum: int | None = None) -> int:
    raw = _str(name)
    if not raw:
        value = default
    else:
        try:
            value = int(raw)
        except ValueError as exc:
            raise ConfigError(f"{name}={raw!r} is not a whole number.") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name}={value} is below the minimum of {minimum}.")
    if maximum is not None and value > maximum:
        raise ConfigError(f"{name}={value} is above the maximum of {maximum}.")
    return value


def _port(name: str, default: int) -> int:
    return _int(name, default, minimum=1, maximum=65535)


@dataclass(frozen=True)
class Settings:
    """Fully-resolved runtime configuration."""

    # -- application ---------------------------------------------------------
    app_name: str
    app_env: str
    app_version: str
    log_level: str

    # -- admin authentication ------------------------------------------------
    admin_username: str
    admin_password: str
    admin_session_secret: str
    admin_session_ttl_hours: int
    session_secret_is_ephemeral: bool
    admin_password_is_bootstrap: bool
    login_max_attempts: int
    login_window_seconds: int
    login_lockout_seconds: int

    # -- networking ----------------------------------------------------------
    port: int
    xray_port: int
    xray_ws_backend_port: int
    xray_api_port: int

    # -- paths ---------------------------------------------------------------
    app_root: Path
    data_dir: Path
    xray_bin: Path

    # -- public endpoint overrides -------------------------------------------
    public_proxy_host: str
    public_proxy_port: int | None

    # -- REALITY -------------------------------------------------------------
    reality_server_name: str
    reality_destination: str
    reality_fingerprint: str
    reality_spider_x: str

    # -- WebSocket fallback --------------------------------------------------
    enable_ws_fallback: bool
    ws_fallback_path_override: str

    # -- accounts ------------------------------------------------------------
    vpn_default_expiry_days: int
    expiry_check_interval: int

    # -- misc ----------------------------------------------------------------
    xray_log_level: str
    uri_network_alias: str
    block_bittorrent: bool
    outbound_ip_check_url: str
    outbound_ip_check_enabled: bool

    # ------------------------------------------------------------------ paths
    @property
    def db_path(self) -> Path:
        return self.data_dir / "vpn.db"

    @property
    def xray_data_dir(self) -> Path:
        return self.data_dir / "xray"

    @property
    def run_dir(self) -> Path:
        return self.data_dir / "run"

    @property
    def logs_dir(self) -> Path:
        return self.data_dir / "logs"

    @property
    def backups_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def xray_config_path(self) -> Path:
        return self.xray_data_dir / "config.json"

    @property
    def xray_config_backup_path(self) -> Path:
        return self.xray_data_dir / "config.json.previous"

    @property
    def reality_private_key_path(self) -> Path:
        return self.xray_data_dir / "reality-private-key"

    @property
    def reality_public_key_path(self) -> Path:
        return self.xray_data_dir / "reality-public-key"

    @property
    def reality_short_id_path(self) -> Path:
        return self.xray_data_dir / "short-id"

    @property
    def xray_log_path(self) -> Path:
        return self.logs_dir / "xray.log"

    @property
    def admin_log_path(self) -> Path:
        return self.logs_dir / "admin.log"

    @property
    def supervisor_socket_path(self) -> Path:
        return self.run_dir / "supervisor.sock"

    @property
    def apply_lock_path(self) -> Path:
        return self.run_dir / "apply.lock"

    @property
    def config_template_path(self) -> Path:
        return self.app_root / "xray" / "config-template.json"

    @property
    def generated_dir(self) -> Path:
        return self.xray_data_dir / "generated"

    # ----------------------------------------------------------------- flags
    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def xray_api_address(self) -> str:
        return f"127.0.0.1:{self.xray_api_port}"

    def required_directories(self) -> list[Path]:
        return [
            self.data_dir,
            self.xray_data_dir,
            self.run_dir,
            self.logs_dir,
            self.backups_dir,
            self.generated_dir,
        ]


def _resolve_admin_password(app_env: str) -> tuple[str, bool]:
    """Return ``(password, is_bootstrap)``.

    Production fails closed when ADMIN_PASSWORD is absent. Development generates
    a random bootstrap password and prints it exactly once.
    """
    password = os.environ.get("ADMIN_PASSWORD", "")
    if password:
        if len(password) < 8:
            raise ConfigError(
                "ADMIN_PASSWORD is shorter than 8 characters. Choose a stronger "
                "password, e.g. `openssl rand -base64 24`."
            )
        return password, False

    if app_env == "production":
        raise ConfigError(
            "ADMIN_PASSWORD is missing.\n"
            "  RailGate refuses to start an internet-facing admin panel without a password.\n"
            "  Fix: Railway -> your service -> Variables -> New Variable\n"
            "         ADMIN_PASSWORD = <a long random value>\n"
            "  Generate one with:  openssl rand -base64 24\n"
            "  (Set APP_ENV=development only for local testing.)"
        )

    generated = secrets.token_urlsafe(18)
    print(
        "\n"
        "==================================================================\n"
        " ADMIN_PASSWORD was not set and APP_ENV is not production.\n"
        " A temporary bootstrap password has been generated for this run.\n"
        " It is NOT persisted and changes on every restart.\n"
        "\n"
        f"     username: {os.environ.get('ADMIN_USERNAME', 'admin') or 'admin'}\n"
        f"     password: {generated}\n"
        "\n"
        " Set ADMIN_PASSWORD to make this permanent.\n"
        "==================================================================\n",
        file=sys.stderr,
        flush=True,
    )
    return generated, True


def _normalise_ws_path(raw: str) -> str:
    if not raw:
        return ""
    path = raw.strip()
    if not path.startswith("/"):
        path = "/" + path
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path


def load_settings() -> Settings:
    """Build :class:`Settings` from the environment. Raises :class:`ConfigError`."""

    app_env = (_str("APP_ENV", "production") or "production").lower()
    if app_env not in {"production", "development"}:
        raise ConfigError(
            f"APP_ENV={app_env!r} is invalid. Use 'production' or 'development'."
        )

    admin_password, password_is_bootstrap = _resolve_admin_password(app_env)

    session_secret = _str("ADMIN_SESSION_SECRET")
    session_secret_is_ephemeral = not session_secret
    if session_secret_is_ephemeral:
        session_secret = secrets.token_hex(32)

    reality_server_name = _str("REALITY_SERVER_NAME", "www.microsoft.com") or "www.microsoft.com"
    reality_destination = _str("REALITY_DESTINATION") or f"{reality_server_name}:443"
    if ":" not in reality_destination:
        reality_destination = f"{reality_destination}:443"
    host_part, _, port_part = reality_destination.rpartition(":")
    if not host_part or not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
        raise ConfigError(
            f"REALITY_DESTINATION={reality_destination!r} is invalid. "
            "Expected the form host:port, e.g. www.microsoft.com:443"
        )

    fingerprint = (_str("REALITY_FINGERPRINT", "chrome") or "chrome").lower()
    if fingerprint not in VALID_FINGERPRINTS:
        raise ConfigError(
            f"REALITY_FINGERPRINT={fingerprint!r} is not recognised. "
            f"Valid values: {', '.join(sorted(VALID_FINGERPRINTS))}"
        )

    xray_log_level = (_str("XRAY_LOG_LEVEL", "warning") or "warning").lower()
    if xray_log_level not in VALID_XRAY_LOG_LEVELS:
        raise ConfigError(
            f"XRAY_LOG_LEVEL={xray_log_level!r} is invalid. "
            f"Valid values: {', '.join(sorted(VALID_XRAY_LOG_LEVELS))}"
        )

    uri_network_alias = (_str("URI_NETWORK_ALIAS", "tcp") or "tcp").lower()
    if uri_network_alias not in VALID_URI_NETWORK_ALIASES:
        raise ConfigError(
            f"URI_NETWORK_ALIAS={uri_network_alias!r} is invalid. Use 'tcp' or 'raw'."
        )

    public_proxy_port_raw = _str("PUBLIC_PROXY_PORT")
    public_proxy_port: int | None = None
    if public_proxy_port_raw:
        public_proxy_port = _port("PUBLIC_PROXY_PORT", 0)

    xray_port = _port("XRAY_PORT", 2443)
    ws_backend_port = _port("XRAY_WS_BACKEND_PORT", 2444)
    api_port = _port("XRAY_API_PORT", 10085)
    http_port = _port("PORT", 8080)

    chosen = {
        "PORT": http_port,
        "XRAY_PORT": xray_port,
        "XRAY_WS_BACKEND_PORT": ws_backend_port,
        "XRAY_API_PORT": api_port,
    }
    seen: dict[int, str] = {}
    for name, value in chosen.items():
        if value in seen:
            raise ConfigError(
                f"Port conflict: {name} and {seen[value]} are both set to {value}. "
                "Each service needs its own port."
            )
        seen[value] = name

    log_level = (_str("LOG_LEVEL", "INFO") or "INFO").upper()
    if log_level not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        raise ConfigError(
            f"LOG_LEVEL={log_level!r} is invalid. "
            "Use DEBUG, INFO, WARNING, ERROR or CRITICAL."
        )

    return Settings(
        app_name=_str("APP_NAME", "Railway Personal Gateway") or "Railway Personal Gateway",
        app_env=app_env,
        app_version=APP_VERSION,
        log_level=log_level,
        admin_username=_str("ADMIN_USERNAME", "admin") or "admin",
        admin_password=admin_password,
        admin_session_secret=session_secret,
        admin_session_ttl_hours=_int("ADMIN_SESSION_TTL_HOURS", 12, minimum=1, maximum=720),
        session_secret_is_ephemeral=session_secret_is_ephemeral,
        admin_password_is_bootstrap=password_is_bootstrap,
        login_max_attempts=_int("LOGIN_MAX_ATTEMPTS", 8, minimum=1, maximum=1000),
        login_window_seconds=_int("LOGIN_WINDOW_SECONDS", 300, minimum=10, maximum=86400),
        login_lockout_seconds=_int("LOGIN_LOCKOUT_SECONDS", 900, minimum=10, maximum=86400),
        port=http_port,
        xray_port=xray_port,
        xray_ws_backend_port=ws_backend_port,
        xray_api_port=api_port,
        app_root=Path(_str("APP_ROOT", "") or str(Path(__file__).resolve().parent.parent)),
        data_dir=Path(_str("DATA_DIR", "/data") or "/data"),
        xray_bin=Path(_str("XRAY_BIN", "/usr/local/bin/xray") or "/usr/local/bin/xray"),
        public_proxy_host=_str("PUBLIC_PROXY_HOST"),
        public_proxy_port=public_proxy_port,
        reality_server_name=reality_server_name,
        reality_destination=reality_destination,
        reality_fingerprint=fingerprint,
        reality_spider_x=_str("REALITY_SPIDER_X", "/") or "/",
        enable_ws_fallback=_bool("ENABLE_WS_FALLBACK", True),
        ws_fallback_path_override=_normalise_ws_path(_str("WS_FALLBACK_PATH")),
        vpn_default_expiry_days=_int("VPN_DEFAULT_EXPIRY_DAYS", 0, minimum=0, maximum=36500),
        expiry_check_interval=_int("EXPIRY_CHECK_INTERVAL", 60, minimum=10, maximum=86400),
        xray_log_level=xray_log_level,
        uri_network_alias=uri_network_alias,
        block_bittorrent=_bool("BLOCK_BITTORRENT", True),
        outbound_ip_check_url=_str("OUTBOUND_IP_CHECK_URL", "https://api.ipify.org")
        or "https://api.ipify.org",
        outbound_ip_check_enabled=_bool("OUTBOUND_IP_CHECK_ENABLED", True),
    )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide cached settings."""
    return load_settings()
