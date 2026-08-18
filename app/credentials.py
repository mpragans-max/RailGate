"""Assembles everything a client needs from a stored account.

The pure link-building rules live in :mod:`app.credential_generator`; this
module is the glue that pulls together the account, the REALITY public material
and the Railway-derived endpoint, and reports *why* a link is unavailable
instead of silently emitting a broken one.
"""

from __future__ import annotations

import io
from dataclasses import dataclass, field

import qrcode
import qrcode.image.svg
from qrcode.constants import ERROR_CORRECT_M

from app.config import Settings
from app.credential_generator import (
    CredentialError,
    RealityProfile,
    WebSocketProfile,
    build_client_config_json,
    build_reality_uri,
    build_websocket_uri,
)
from app.models import VpnUser
from app.railway_info import (
    RailwayInfo,
    detect_railway,
    resolve_fallback_endpoint,
    resolve_public_endpoint,
)
from app.xray_manager import RealityKeys, ensure_ws_path, load_reality_keys


@dataclass
class LinkBundle:
    """One connectable transport for one account."""

    label: str
    available: bool
    reason: str = ""
    uri: str = ""
    host: str = ""
    port: int | None = None
    fields: dict[str, str] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "available": self.available,
            "reason": self.reason,
            "uri": self.uri,
            "host": self.host,
            "port": self.port,
            "fields": self.fields,
        }


@dataclass
class CredentialBundle:
    username: str
    uuid: str
    status: str
    primary: LinkBundle
    fallback: LinkBundle

    @property
    def any_available(self) -> bool:
        return self.primary.available or self.fallback.available

    @property
    def best_uri(self) -> str:
        if self.primary.available:
            return self.primary.uri
        if self.fallback.available:
            return self.fallback.uri
        return ""

    def as_dict(self) -> dict[str, object]:
        return {
            "username": self.username,
            "uuid": self.uuid,
            "status": self.status,
            "primary": self.primary.as_dict(),
            "fallback": self.fallback.as_dict(),
            "any_available": self.any_available,
        }


def _reality_profile(settings: Settings, keys: RealityKeys, user: VpnUser) -> RealityProfile:
    return RealityProfile(
        public_key=keys.public_key,
        short_id=keys.short_id,
        server_name=settings.reality_server_name,
        fingerprint=settings.reality_fingerprint,
        flow=user.flow or "xtls-rprx-vision",
        spider_x=settings.reality_spider_x,
        network_alias=settings.uri_network_alias,
    )


def build_credentials(
    settings: Settings,
    user: VpnUser,
    *,
    keys: RealityKeys | None = None,
    railway: RailwayInfo | None = None,
) -> CredentialBundle:
    """Build both transports for ``user``, never raising on missing pieces."""
    railway = railway or detect_railway()
    keys = keys or load_reality_keys(settings)

    primary = _build_primary(settings, user, keys, railway)
    fallback = _build_fallback(settings, user, railway)
    return CredentialBundle(
        username=user.username,
        uuid=user.uuid,
        status=user.status(),
        primary=primary,
        fallback=fallback,
    )


def _build_primary(
    settings: Settings, user: VpnUser, keys: RealityKeys | None, railway: RailwayInfo
) -> LinkBundle:
    label = "VLESS + REALITY (raw TCP)"
    if keys is None:
        return LinkBundle(
            label=label,
            available=False,
            reason=(
                "REALITY key material has not been generated yet. It is created "
                "automatically on first boot in $DATA_DIR/xray/."
            ),
        )

    endpoint = resolve_public_endpoint(settings, railway)
    profile = _reality_profile(settings, keys, user)
    fields = {
        "Protocol": "VLESS",
        "Transport": settings.uri_network_alias.upper(),
        "Security": "REALITY",
        "Flow": profile.flow or "(none)",
        "SNI / Server Name": profile.server_name,
        "Public Key": profile.public_key,
        "Short ID": profile.short_id,
        "Fingerprint": profile.fingerprint,
        "UUID": user.uuid,
        "Server": endpoint.host or "(unavailable)",
        "Port": str(endpoint.port) if endpoint.port else "(unavailable)",
    }

    if not endpoint.available:
        return LinkBundle(label=label, available=False, reason=endpoint.reason, fields=fields)

    try:
        uri = build_reality_uri(
            user_uuid=user.uuid,
            host=endpoint.host,
            port=endpoint.port or 0,
            profile=profile,
            remark=f"{user.username} (REALITY)",
        )
    except CredentialError as exc:
        return LinkBundle(label=label, available=False, reason=str(exc), fields=fields)

    return LinkBundle(
        label=label,
        available=True,
        uri=uri,
        host=endpoint.host,
        port=endpoint.port,
        fields=fields,
    )


def _build_fallback(settings: Settings, user: VpnUser, railway: RailwayInfo) -> LinkBundle:
    label = "VLESS + WebSocket over HTTPS"
    endpoint = resolve_fallback_endpoint(settings, railway)
    if not endpoint.available:
        return LinkBundle(label=label, available=False, reason=endpoint.reason)

    try:
        ws_path = ensure_ws_path(settings)
    except Exception as exc:  # noqa: BLE001 - surfaced to the UI
        return LinkBundle(label=label, available=False, reason=f"Could not resolve the fallback path: {exc}")

    profile = WebSocketProfile(
        path=ws_path,
        host=endpoint.host,
        fingerprint=settings.reality_fingerprint,
        tls=True,
    )
    fields = {
        "Protocol": "VLESS",
        "Transport": "WebSocket",
        "Security": "TLS (terminated by Railway)",
        "Flow": "(none — Vision is not valid over WebSocket)",
        "SNI / Host": endpoint.host,
        "Path": ws_path,
        "Fingerprint": settings.reality_fingerprint,
        "UUID": user.uuid,
        "Server": endpoint.host,
        "Port": "443",
    }
    try:
        uri = build_websocket_uri(
            user_uuid=user.uuid,
            host=endpoint.host,
            port=endpoint.port,
            profile=profile,
            remark=f"{user.username} (WS)",
        )
    except CredentialError as exc:
        return LinkBundle(label=label, available=False, reason=str(exc), fields=fields)

    return LinkBundle(
        label=label,
        available=True,
        uri=uri,
        host=endpoint.host,
        port=endpoint.port,
        fields=fields,
    )


def client_config_json(
    settings: Settings, user: VpnUser, transport: str = "reality"
) -> str:
    """A downloadable Xray client configuration for the chosen transport."""
    railway = detect_railway()
    if transport == "ws":
        endpoint = resolve_fallback_endpoint(settings, railway)
        if not endpoint.available:
            raise CredentialError(endpoint.reason)
        profile: RealityProfile | WebSocketProfile = WebSocketProfile(
            path=ensure_ws_path(settings),
            host=endpoint.host,
            fingerprint=settings.reality_fingerprint,
            tls=True,
        )
        host, port = endpoint.host, endpoint.port
    else:
        keys = load_reality_keys(settings)
        if keys is None:
            raise CredentialError("REALITY key material has not been generated yet.")
        tcp_endpoint = resolve_public_endpoint(settings, railway)
        if not tcp_endpoint.available:
            raise CredentialError(tcp_endpoint.reason)
        profile = _reality_profile(settings, keys, user)
        host, port = tcp_endpoint.host, tcp_endpoint.port or 0

    return build_client_config_json(
        user_uuid=user.uuid,
        host=host,
        port=port,
        profile=profile,
        remark=f"{user.username}-{'ws' if transport == 'ws' else 'reality'}",
    )


# --------------------------------------------------------------------------- #
# QR codes
# --------------------------------------------------------------------------- #
def _qr(data: str) -> qrcode.QRCode:
    if not data:
        raise CredentialError("There is no link to encode as a QR code.")
    code = qrcode.QRCode(error_correction=ERROR_CORRECT_M, box_size=8, border=2)
    code.add_data(data)
    code.make(fit=True)
    return code


def qr_svg(data: str) -> str:
    """Render a share link as an inline-safe SVG document."""
    image = _qr(data).make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode("utf-8")


def qr_ascii(data: str, invert: bool = True) -> str:
    """Render a share link as terminal-friendly ASCII (used by ``vpnctl qr``)."""
    buffer = io.StringIO()
    _qr(data).print_ascii(out=buffer, invert=invert)
    return buffer.getvalue()
