"""Detection of the Railway environment.

Railway injects a set of ``RAILWAY_*`` variables. None of them are guaranteed to
exist: the very first deploy happens before a TCP Proxy is created, and running
locally there are none at all. Every accessor therefore degrades gracefully and
the caller is told *why* something is unavailable rather than crashing.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass

from app.config import Settings

# Every Railway-provided variable RailGate knows about.
RAILWAY_ENV_KEYS: tuple[str, ...] = (
    "RAILWAY_PUBLIC_DOMAIN",
    "RAILWAY_PRIVATE_DOMAIN",
    "RAILWAY_TCP_PROXY_DOMAIN",
    "RAILWAY_TCP_PROXY_PORT",
    "RAILWAY_TCP_APPLICATION_PORT",
    "RAILWAY_SERVICE_NAME",
    "RAILWAY_PROJECT_NAME",
    "RAILWAY_ENVIRONMENT_NAME",
    "RAILWAY_REPLICA_REGION",
    "RAILWAY_DEPLOYMENT_ID",
)


def _clean(name: str) -> str:
    return (os.environ.get(name) or "").strip()


def _clean_int(name: str) -> int | None:
    raw = _clean(name)
    if not raw.isdigit():
        return None
    value = int(raw)
    return value if 1 <= value <= 65535 else None


@dataclass(frozen=True)
class RailwayInfo:
    """Snapshot of the Railway-provided environment."""

    detected: bool
    public_domain: str
    private_domain: str
    tcp_proxy_domain: str
    tcp_proxy_port: int | None
    tcp_application_port: int | None
    service_name: str
    project_name: str
    environment_name: str
    replica_region: str
    deployment_id: str

    @property
    def tcp_proxy_configured(self) -> bool:
        """True only when Railway has actually provisioned a TCP Proxy."""
        return bool(self.tcp_proxy_domain) and self.tcp_proxy_port is not None

    @property
    def public_url(self) -> str:
        return f"https://{self.public_domain}" if self.public_domain else ""

    @property
    def short_deployment_id(self) -> str:
        return self.deployment_id[:8] if self.deployment_id else ""

    def as_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["tcp_proxy_configured"] = self.tcp_proxy_configured
        data["public_url"] = self.public_url
        return data


def detect_railway() -> RailwayInfo:
    """Read the Railway environment. Never raises."""
    detected = any(_clean(key) for key in RAILWAY_ENV_KEYS) or bool(
        _clean("RAILWAY_ENVIRONMENT") or _clean("RAILWAY_PROJECT_ID")
    )
    return RailwayInfo(
        detected=detected,
        public_domain=_clean("RAILWAY_PUBLIC_DOMAIN"),
        private_domain=_clean("RAILWAY_PRIVATE_DOMAIN"),
        tcp_proxy_domain=_clean("RAILWAY_TCP_PROXY_DOMAIN"),
        tcp_proxy_port=_clean_int("RAILWAY_TCP_PROXY_PORT"),
        tcp_application_port=_clean_int("RAILWAY_TCP_APPLICATION_PORT"),
        service_name=_clean("RAILWAY_SERVICE_NAME"),
        project_name=_clean("RAILWAY_PROJECT_NAME"),
        environment_name=_clean("RAILWAY_ENVIRONMENT_NAME") or _clean("RAILWAY_ENVIRONMENT"),
        replica_region=_clean("RAILWAY_REPLICA_REGION"),
        deployment_id=_clean("RAILWAY_DEPLOYMENT_ID"),
    )


# Explanation shown verbatim in the dashboard, the CLI and diagnostics.
TCP_PROXY_SETUP_HINT = (
    "Railway -> your service -> Settings -> Networking -> TCP Proxy -> "
    "Add TCP Proxy, and set the internal port to {port}. "
    "Railway then assigns a random public port; RailGate picks it up "
    "automatically (a redeploy may be required for the variables to appear)."
)


@dataclass(frozen=True)
class PublicEndpoint:
    """Where clients should connect for the primary REALITY transport."""

    host: str
    port: int | None
    host_source: str
    port_source: str
    available: bool
    reason: str

    @property
    def display(self) -> str:
        if not self.available:
            return "NOT CONFIGURED"
        return f"{self.host}:{self.port}"


def resolve_public_endpoint(settings: Settings, info: RailwayInfo | None = None) -> PublicEndpoint:
    """Work out the public host/port for generated client links.

    Priority:
        host -> ``PUBLIC_PROXY_HOST`` then ``RAILWAY_TCP_PROXY_DOMAIN``
        port -> ``PUBLIC_PROXY_PORT`` then ``RAILWAY_TCP_PROXY_PORT``

    The manual overrides exist so credentials keep working even when Railway's
    variables are missing.
    """
    info = info or detect_railway()

    if settings.public_proxy_host:
        host, host_source = settings.public_proxy_host, "PUBLIC_PROXY_HOST"
    elif info.tcp_proxy_domain:
        host, host_source = info.tcp_proxy_domain, "RAILWAY_TCP_PROXY_DOMAIN"
    else:
        host, host_source = "", "unset"

    if settings.public_proxy_port:
        port, port_source = settings.public_proxy_port, "PUBLIC_PROXY_PORT"
    elif info.tcp_proxy_port:
        port, port_source = info.tcp_proxy_port, "RAILWAY_TCP_PROXY_PORT"
    else:
        port, port_source = None, "unset"

    if host and port:
        reason = ""
    else:
        missing = []
        if not host:
            missing.append("hostname")
        if not port:
            missing.append("port")
        reason = (
            "Railway TCP Proxy has not been configured — the public "
            f"{' and '.join(missing)} is unavailable. "
            + TCP_PROXY_SETUP_HINT.format(port=settings.xray_port)
            + " Alternatively set PUBLIC_PROXY_HOST and PUBLIC_PROXY_PORT manually."
        )

    return PublicEndpoint(
        host=host,
        port=port,
        host_source=host_source,
        port_source=port_source,
        available=bool(host and port),
        reason=reason,
    )


@dataclass(frozen=True)
class FallbackEndpoint:
    """Where clients connect for the WebSocket-over-HTTPS fallback."""

    host: str
    port: int
    available: bool
    reason: str


def resolve_fallback_endpoint(settings: Settings, info: RailwayInfo | None = None) -> FallbackEndpoint:
    """The fallback rides Railway's regular public HTTPS domain on port 443."""
    info = info or detect_railway()

    if not settings.enable_ws_fallback:
        return FallbackEndpoint("", 443, False, "The WebSocket fallback is disabled (ENABLE_WS_FALLBACK=false).")

    if not info.public_domain:
        return FallbackEndpoint(
            "",
            443,
            False,
            "No public HTTP domain yet. Railway -> your service -> Settings -> "
            "Networking -> Public Networking -> Generate Domain.",
        )

    return FallbackEndpoint(info.public_domain, 443, True, "")
