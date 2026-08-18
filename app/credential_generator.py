"""Construction of client-facing VLESS share links and config exports.

This module is deliberately pure: it performs no I/O, reads no environment and
touches no database. Everything it needs is passed in, which makes it fully unit
testable — malformed share links are the single most common way a working server
still fails to connect, so the encoding rules live in one audited place.

Reference: the VLESS URI scheme used by v2rayNG / Hiddify / NekoBox, i.e.
``vless://<uuid>@<host>:<port>?<query>#<remark>``
"""

from __future__ import annotations

import ipaddress
import json
import uuid as uuid_module
from dataclasses import dataclass
from urllib.parse import quote

__all__ = [
    "CredentialError",
    "RealityProfile",
    "WebSocketProfile",
    "new_uuid",
    "build_reality_uri",
    "build_websocket_uri",
    "build_client_config",
    "build_client_config_json",
]

# Characters that are legal inside a URI query/fragment component. Everything
# else is percent-encoded. Kept intentionally strict.
_SAFE_NONE = ""

VALID_FLOWS = {"", "xtls-rprx-vision"}


class CredentialError(ValueError):
    """Raised when the inputs cannot produce a valid client link."""


def new_uuid() -> str:
    """A fresh random UUIDv4 for a VLESS account."""
    return str(uuid_module.uuid4())


# --------------------------------------------------------------------------- #
# validation helpers
# --------------------------------------------------------------------------- #
def _validate_uuid(value: str) -> str:
    if not value or not isinstance(value, str):
        raise CredentialError("UUID is missing.")
    try:
        parsed = uuid_module.UUID(value.strip())
    except (ValueError, AttributeError, TypeError) as exc:
        raise CredentialError(f"{value!r} is not a valid UUID.") from exc
    return str(parsed)


def _validate_port(value: object) -> int:
    if value is None or isinstance(value, bool):
        raise CredentialError("Port is missing.")
    try:
        port = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise CredentialError(f"{value!r} is not a valid port number.") from exc
    if not 1 <= port <= 65535:
        raise CredentialError(f"Port {port} is out of the range 1-65535.")
    return port


def _format_host(value: str) -> str:
    """Validate a hostname/IP and bracket bare IPv6 literals for URI use."""
    if not value or not isinstance(value, str):
        raise CredentialError(
            "Server host is missing. Railway TCP Proxy has not been configured "
            "and no PUBLIC_PROXY_HOST override was supplied."
        )
    host = value.strip()
    if not host:
        raise CredentialError("Server host is empty.")
    if any(ch.isspace() for ch in host):
        raise CredentialError(f"Server host {value!r} contains whitespace.")
    if "://" in host or "/" in host:
        raise CredentialError(
            f"Server host {value!r} must be a bare hostname, not a URL."
        )
    if host.startswith("[") and host.endswith("]"):
        return host
    try:
        parsed_ip = ipaddress.ip_address(host)
    except ValueError:
        return host
    return f"[{host}]" if parsed_ip.version == 6 else host


def _encode(value: str) -> str:
    return quote(str(value), safe=_SAFE_NONE)


def _build_query(params: list[tuple[str, str]]) -> str:
    """Percent-encode an ordered list of parameters, dropping empty values."""
    return "&".join(
        f"{_encode(key)}={_encode(value)}" for key, value in params if value != "" and value is not None
    )


def _normalise_path(path: str) -> str:
    if not path:
        raise CredentialError("WebSocket path is missing.")
    cleaned = path.strip()
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if any(ch.isspace() for ch in cleaned):
        raise CredentialError(f"WebSocket path {path!r} contains whitespace.")
    return cleaned


# --------------------------------------------------------------------------- #
# profiles
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RealityProfile:
    """Everything a client needs for VLESS + REALITY, minus the account UUID.

    Note that ``public_key`` is the *public* half only. The REALITY private key
    must never reach this module.
    """

    public_key: str
    short_id: str
    server_name: str
    fingerprint: str = "chrome"
    flow: str = "xtls-rprx-vision"
    spider_x: str = "/"
    network_alias: str = "tcp"

    def validated(self) -> "RealityProfile":
        if not self.public_key:
            raise CredentialError("REALITY public key is missing.")
        if not self.server_name:
            raise CredentialError("REALITY server name (SNI) is missing.")
        if self.flow not in VALID_FLOWS:
            raise CredentialError(
                f"flow={self.flow!r} is not supported. Use '' or 'xtls-rprx-vision'."
            )
        if self.network_alias not in {"tcp", "raw"}:
            raise CredentialError(
                f"network_alias={self.network_alias!r} is invalid. Use 'tcp' or 'raw'."
            )
        return self


@dataclass(frozen=True)
class WebSocketProfile:
    """VLESS over WebSocket, riding Railway's public HTTPS domain."""

    path: str
    host: str
    fingerprint: str = "chrome"
    tls: bool = True

    def validated(self) -> "WebSocketProfile":
        if not self.host:
            raise CredentialError("WebSocket host is missing.")
        _normalise_path(self.path)
        return self


# --------------------------------------------------------------------------- #
# URI builders
# --------------------------------------------------------------------------- #
def build_reality_uri(
    *,
    user_uuid: str,
    host: str,
    port: int,
    profile: RealityProfile,
    remark: str = "",
) -> str:
    """Build a ``vless://`` link for the primary REALITY transport."""
    account = _validate_uuid(user_uuid)
    server = _format_host(host)
    port_number = _validate_port(port)
    prof = profile.validated()

    params: list[tuple[str, str]] = [
        ("type", prof.network_alias),
        ("security", "reality"),
        ("encryption", "none"),
        ("headerType", "none"),
        ("flow", prof.flow),
        ("fp", prof.fingerprint),
        ("pbk", prof.public_key),
        ("sid", prof.short_id),
        ("sni", prof.server_name),
        ("spx", prof.spider_x),
    ]
    query = _build_query(params)
    uri = f"vless://{account}@{server}:{port_number}?{query}"
    if remark:
        uri += f"#{_encode(remark)}"
    return uri


def build_websocket_uri(
    *,
    user_uuid: str,
    host: str,
    port: int,
    profile: WebSocketProfile,
    remark: str = "",
) -> str:
    """Build a ``vless://`` link for the WebSocket-over-HTTPS fallback.

    XTLS Vision (``flow``) is intentionally absent: it is only valid on raw TCP
    with TLS/REALITY, never on a WebSocket transport.
    """
    account = _validate_uuid(user_uuid)
    server = _format_host(host)
    port_number = _validate_port(port)
    prof = profile.validated()
    path = _normalise_path(prof.path)

    params: list[tuple[str, str]] = [
        ("type", "ws"),
        ("security", "tls" if prof.tls else "none"),
        ("encryption", "none"),
        ("path", path),
        ("host", prof.host),
    ]
    if prof.tls:
        params.append(("sni", prof.host))
        params.append(("fp", prof.fingerprint))

    query = _build_query(params)
    uri = f"vless://{account}@{server}:{port_number}?{query}"
    if remark:
        uri += f"#{_encode(remark)}"
    return uri


# --------------------------------------------------------------------------- #
# JSON export (importable by desktop Xray, NekoBox and friends)
# --------------------------------------------------------------------------- #
def build_client_config(
    *,
    user_uuid: str,
    host: str,
    port: int,
    profile: RealityProfile | WebSocketProfile,
    remark: str = "railgate",
    socks_port: int = 10808,
    http_port: int = 10809,
) -> dict:
    """A complete Xray *client* configuration for the given account."""
    account = _validate_uuid(user_uuid)
    port_number = _validate_port(port)
    # The JSON config wants a bare host (no brackets) for IPv6.
    server = _format_host(host).strip("[]")

    if isinstance(profile, RealityProfile):
        prof = profile.validated()
        user: dict[str, object] = {"id": account, "encryption": "none"}
        if prof.flow:
            user["flow"] = prof.flow
        stream = {
            "network": "raw" if prof.network_alias == "raw" else "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": prof.server_name,
                "fingerprint": prof.fingerprint,
                "publicKey": prof.public_key,
                "shortId": prof.short_id,
                "spiderX": prof.spider_x,
            },
        }
    else:
        ws = profile.validated()
        user = {"id": account, "encryption": "none"}
        stream = {
            "network": "ws",
            "security": "tls" if ws.tls else "none",
            "wsSettings": {"path": _normalise_path(ws.path), "host": ws.host},
        }
        if ws.tls:
            stream["tlsSettings"] = {"serverName": ws.host, "fingerprint": ws.fingerprint, "allowInsecure": False}

    return {
        "remarks": remark,
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True, "auth": "noauth"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]},
            },
            {
                "tag": "http",
                "port": http_port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {"address": server, "port": port_number, "users": [user]}
                    ]
                },
                "streamSettings": stream,
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block", "protocol": "blackhole", "settings": {}},
        ],
    }


def build_client_config_json(**kwargs) -> str:
    """:func:`build_client_config` serialised for download."""
    return json.dumps(build_client_config(**kwargs), indent=2, ensure_ascii=False)
