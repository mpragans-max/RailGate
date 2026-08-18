"""System diagnostics shared by ``vpnctl diagnose`` and ``scripts/diagnose.sh``.

Sensitive values are masked: the REALITY private key, the admin password and the
session secret never appear, and public key material is shown only in part.
"""

from __future__ import annotations

import socket
import subprocess
import time
from dataclasses import dataclass, field

from app import APP_VERSION
from app import supervisor_client
from app.config import Settings
from app.database import database_status
from app.models import list_users, user_stats
from app.railway_info import detect_railway, resolve_fallback_endpoint, resolve_public_endpoint
from app.system_info import disk_usage, memory_usage, outbound_ip, volume_writable
from app.util import format_bytes, mask_secret
from app.xray_manager import (
    ensure_ws_path,
    load_reality_keys,
    port_open,
    render_config,
    validate_config,
    xray_status,
    xray_version,
)


@dataclass
class Section:
    title: str
    rows: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _listening_sockets() -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=8, check=False
        )
    except (OSError, subprocess.SubprocessError, FileNotFoundError):
        return "unavailable (ss not present)"
    lines = [line.strip() for line in (result.stdout or "").splitlines()[1:] if line.strip()]
    return "\n".join(lines) if lines else "(none)"


def _dns_check(hostname: str = "cloudflare.com") -> tuple[bool, str]:
    started = time.monotonic()
    try:
        socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError) as exc:
        return False, f"FAIL ({exc})"
    return True, f"OK ({(time.monotonic() - started) * 1000:.0f} ms via {hostname})"


def _https_check(settings: Settings) -> tuple[bool, str]:
    host, _, port_text = settings.reality_destination.rpartition(":")
    try:
        port = int(port_text)
    except ValueError:
        return False, "FAIL (invalid REALITY_DESTINATION)"
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=6):
            pass
    except OSError as exc:
        return False, f"FAIL ({host}:{port} — {exc})"
    return True, f"OK ({host}:{port}, {(time.monotonic() - started) * 1000:.0f} ms)"


def collect(settings: Settings) -> list[Section]:
    """Gather every diagnostic section. Never raises."""
    sections: list[Section] = []
    railway = detect_railway()
    endpoint = resolve_public_endpoint(settings, railway)
    fallback = resolve_fallback_endpoint(settings, railway)
    status = xray_status(settings)
    db = database_status(settings.db_path)

    # -- application ---------------------------------------------------------
    app_section = Section("Application")
    app_section.rows += [
        ("Application version", f"RailGate {APP_VERSION}"),
        ("Environment", settings.app_env),
        ("Xray version", xray_version(settings)),
        ("Admin HTTP port", str(settings.port)),
        ("Internal Xray port", str(settings.xray_port)),
    ]
    sections.append(app_section)

    # -- processes -----------------------------------------------------------
    processes = Section("Processes")
    supervisor = supervisor_client.status(settings.supervisor_socket_path)
    if supervisor.get("ok"):
        for name, program in sorted((supervisor.get("programs") or {}).items()):
            state = "running" if program.get("running") else "stopped"
            detail = f"{state}"
            if program.get("pid"):
                detail += f", pid {program['pid']}"
            if program.get("restarts"):
                detail += f", {program['restarts']} restart(s)"
            if program.get("last_exit_code") is not None:
                detail += f", last exit {program['last_exit_code']}"
            processes.rows.append((f"{name} process", detail))
    else:
        processes.rows.append(("supervisor", f"unavailable ({supervisor.get('error', '')})"))
        processes.rows.append(("xray process", "running" if status.running else "stopped"))
    processes.rows.append(
        (
            f"Xray port {settings.xray_port}",
            "accepting connections" if status.listening else "NOT listening",
        )
    )
    processes.rows.append(
        (
            f"Admin port {settings.port}",
            "accepting connections"
            if port_open("127.0.0.1", settings.port)
            else "NOT listening",
        )
    )
    if settings.enable_ws_fallback:
        processes.rows.append(
            (
                f"WS backend {settings.xray_ws_backend_port}",
                "accepting connections"
                if port_open("127.0.0.1", settings.xray_ws_backend_port)
                else "NOT listening",
            )
        )
    sections.append(processes)

    # -- listening sockets ---------------------------------------------------
    sockets_section = Section("Listening sockets")
    sockets_section.notes.append(_listening_sockets())
    sections.append(sockets_section)

    # -- railway -------------------------------------------------------------
    railway_section = Section("Railway environment")
    railway_section.rows += [
        ("Detected", "yes" if railway.detected else "no (running outside Railway)"),
        ("Project", railway.project_name or "—"),
        ("Service", railway.service_name or "—"),
        ("Region", railway.replica_region or "—"),
        ("Deployment", railway.deployment_id or "—"),
        ("Public domain", railway.public_domain or "not generated"),
        ("TCP proxy domain", railway.tcp_proxy_domain or "NOT CONFIGURED"),
        ("TCP proxy external port", str(railway.tcp_proxy_port or "NOT CONFIGURED")),
        ("TCP internal application port", str(railway.tcp_application_port or "—")),
        ("Effective VPN endpoint", endpoint.display),
        ("Endpoint source", f"host={endpoint.host_source}, port={endpoint.port_source}"),
        (
            "WebSocket fallback",
            f"https://{fallback.host}{ensure_ws_path(settings)}"
            if fallback.available
            else f"unavailable ({fallback.reason})",
        ),
    ]
    if not endpoint.available:
        railway_section.notes.append(endpoint.reason)
    sections.append(railway_section)

    # -- storage -------------------------------------------------------------
    storage = Section("Storage")
    writable, write_error = volume_writable(settings.data_dir)
    disk = disk_usage(settings.data_dir)
    memory = memory_usage()
    storage.rows += [
        ("Data directory", str(settings.data_dir)),
        ("Writable", "yes" if writable else f"NO — {write_error}"),
        ("Database", "ok" if db["ok"] else f"ERROR: {db['error']}"),
        ("Database schema", f"v{db['schema_version']} (expected v{db['expected_schema_version']})"),
        ("Database size", format_bytes(db["size_bytes"])),
        (
            "Volume usage",
            f"{format_bytes(disk['used_bytes'])} / {format_bytes(disk['total_bytes'])} ({disk['percent']}%)",
        ),
        (
            "Memory usage",
            f"{format_bytes(memory['used_bytes'])} / {format_bytes(memory['total_bytes'])} ({memory['percent']}%)",
        ),
    ]
    sections.append(storage)

    # -- accounts ------------------------------------------------------------
    accounts = Section("Accounts")
    try:
        stats = user_stats(settings.db_path)
        accounts.rows += [
            ("Total accounts", str(stats["total"])),
            ("Enabled (active)", str(stats["active"])),
            ("Disabled", str(stats["disabled"])),
            ("Expired", str(stats["expired"])),
        ]
    except Exception as exc:  # noqa: BLE001
        accounts.rows.append(("Accounts", f"unavailable ({exc})"))
    sections.append(accounts)

    # -- configuration -------------------------------------------------------
    config_section = Section("Configuration")
    keys = load_reality_keys(settings)
    config_section.rows += [
        ("REALITY SNI", settings.reality_server_name),
        ("REALITY destination", settings.reality_destination),
        ("REALITY fingerprint", settings.reality_fingerprint),
        ("REALITY public key", mask_secret(keys.public_key, 8) if keys else "not generated"),
        ("REALITY short id", keys.short_id if keys else "not generated"),
        ("REALITY private key", "present (masked)" if keys else "not generated"),
        ("Active config", str(settings.xray_config_path)),
    ]
    if keys is not None:
        try:
            users = [u for u in list_users(settings.db_path) if u.is_active()]
            config = render_config(settings, users, keys, ensure_ws_path(settings))
            ok, output = validate_config(settings, config)
            config_section.rows.append(
                ("Config validation", "PASS" if ok else "FAIL")
            )
            if not ok:
                config_section.notes.append(output[-1500:])
        except Exception as exc:  # noqa: BLE001
            config_section.rows.append(("Config validation", f"ERROR ({exc})"))
    else:
        config_section.rows.append(("Config validation", "skipped (no keys)"))
    sections.append(config_section)

    # -- connectivity --------------------------------------------------------
    connectivity = Section("Connectivity")
    _, dns_detail = _dns_check()
    _, https_detail = _https_check(settings)
    ip_result = outbound_ip(settings)
    connectivity.rows += [
        ("DNS resolution", dns_detail),
        ("Outbound HTTPS (REALITY target)", https_detail),
        (
            "Outbound public IP",
            ip_result.get("ip") or f"unavailable ({ip_result.get('error', 'unknown')})",
        ),
    ]
    connectivity.notes.append(
        "Railway's outbound address depends on your plan/configuration; it is not "
        "guaranteed to be static unless Static Outbound IP is enabled."
    )
    sections.append(connectivity)

    return sections


def render_text(sections: list[Section], width: int = 74) -> str:
    lines: list[str] = []
    for section in sections:
        lines.append("")
        lines.append("=" * width)
        lines.append(f" {section.title}")
        lines.append("=" * width)
        label_width = max((len(label) for label, _ in section.rows), default=0)
        for label, value in section.rows:
            first, *rest = str(value).splitlines() or [""]
            lines.append(f" {label.ljust(label_width)} : {first}")
            for extra in rest:
                lines.append(f" {' ' * label_width}   {extra}")
        for note in section.notes:
            lines.append("")
            for note_line in str(note).splitlines():
                lines.append(f"   {note_line}")
    lines.append("")
    return "\n".join(lines)
