"""The fixed set of administrative actions exposed by the Tools page.

There is intentionally **no** arbitrary command execution from the browser. Each
action maps to a Python function with a fixed argument vector; the HTTP layer
only ever passes an action *name* that must exist in :data:`TOOL_ACTIONS`.
For a real shell, use ``railway ssh``.
"""

from __future__ import annotations

import json
import socket
import subprocess
import time
from dataclasses import dataclass
from typing import Callable

from app.backup import BackupError, create_backup
from app.config import Settings
from app.models import active_users
from app.system_info import disk_usage, memory_usage, outbound_ip
from app.util import format_bytes
from app.xray_manager import (
    apply_configuration,
    load_reality_keys,
    read_active_config,
    render_config,
    restart_xray,
    validate_config,
    xray_status,
)


@dataclass
class ToolResult:
    ok: bool
    title: str
    output: str

    def as_dict(self) -> dict[str, object]:
        return {"ok": self.ok, "title": self.title, "output": self.output}


def _run_fixed(argv: list[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(  # noqa: S603 - fixed argv, never user input
            argv, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return f"{argv[0]} is not installed in this image."
    except (OSError, subprocess.SubprocessError) as exc:
        return f"Command failed: {exc}"
    return ((result.stdout or "") + (result.stderr or "")).strip() or "(no output)"


def tool_xray_status(settings: Settings) -> ToolResult:
    status = xray_status(settings)
    lines = [
        f"State           : {status.state}",
        f"Version         : {status.version}",
        f"PID             : {status.pid if status.pid else '-'}",
        f"Listening on    : 127.0.0.1:{settings.xray_port} -> {'yes' if status.listening else 'no'}",
        f"Restarts        : {status.restarts}",
        f"Last exit code  : {status.last_exit_code if status.last_exit_code is not None else '-'}",
    ]
    if status.error:
        lines.append(f"Note            : {status.error}")
    return ToolResult(status.running, "Xray status", "\n".join(lines))


def tool_xray_restart(settings: Settings) -> ToolResult:
    ok, detail = restart_xray(settings)
    return ToolResult(ok, "Restart Xray", detail)


def tool_validate_config(settings: Settings) -> ToolResult:
    keys = load_reality_keys(settings)
    if keys is None:
        return ToolResult(False, "Validate configuration", "REALITY keys are missing.")
    from app.xray_manager import ensure_ws_path

    config = render_config(settings, active_users(settings.db_path), keys, ensure_ws_path(settings))
    ok, output = validate_config(settings, config)
    active = read_active_config(settings)
    summary = [
        f"Candidate configuration: {'VALID' if ok else 'INVALID'}",
        f"Active config on disk  : {'present' if active else 'missing'}",
        "",
        output or "(no output)",
    ]
    return ToolResult(ok, "Validate configuration", "\n".join(summary))


def tool_resync(settings: Settings) -> ToolResult:
    result = apply_configuration(settings, active_users(settings.db_path), reason="manual resync")
    return ToolResult(result.ok, "Re-apply configuration", f"{result.method}: {result.message}")


def tool_listening_ports(settings: Settings) -> ToolResult:
    output = _run_fixed(["ss", "-tulpn"])
    return ToolResult(True, "Listening sockets", output)


def tool_dns_test(settings: Settings) -> ToolResult:
    targets = ["cloudflare.com", "github.com", settings.reality_server_name]
    lines = []
    ok = True
    for host in dict.fromkeys(targets):
        started = time.monotonic()
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
            addresses = sorted({info[4][0] for info in infos})[:4]
            elapsed = (time.monotonic() - started) * 1000
            lines.append(f"{host:<28} OK   {elapsed:6.1f} ms  {', '.join(addresses)}")
        except (socket.gaierror, OSError) as exc:
            ok = False
            lines.append(f"{host:<28} FAIL {exc}")
    return ToolResult(ok, "DNS resolution test", "\n".join(lines))


def tool_outbound_ip(settings: Settings) -> ToolResult:
    result = outbound_ip(settings, force=True)
    if result.get("error") and not result.get("ip"):
        return ToolResult(False, "Outbound public IP", f"Lookup failed: {result['error']}")
    note = (
        "\n\nNote: Railway's outbound address depends on your plan and settings. "
        "It is not guaranteed to be stable unless Static Outbound IP is enabled."
    )
    return ToolResult(True, "Outbound public IP", f"{result['ip']}{note}")


def tool_reality_reachability(settings: Settings) -> ToolResult:
    """Check that the REALITY destination is reachable and speaks TLS 1.3."""
    host, _, port = settings.reality_destination.rpartition(":")
    output = _run_fixed(
        [
            "openssl", "s_client", "-connect", f"{host}:{port}", "-servername",
            settings.reality_server_name, "-tls1_3", "-brief",
        ],
        timeout=12,
    )
    ok = "TLSv1.3" in output or "Protocol version: TLSv1.3" in output
    verdict = (
        "The destination negotiated TLS 1.3 — it is a usable REALITY target."
        if ok
        else "Could not confirm TLS 1.3. Pick a different REALITY_DESTINATION."
    )
    return ToolResult(ok, "REALITY destination check", f"{verdict}\n\n{output[:2000]}")


def tool_disk_usage(settings: Settings) -> ToolResult:
    usage = disk_usage(settings.data_dir)
    lines = [
        f"Volume path : {settings.data_dir}",
        f"Total       : {format_bytes(usage['total_bytes'])}",
        f"Used        : {format_bytes(usage['used_bytes'])} ({usage['percent']}%)",
        f"Free        : {format_bytes(usage['free_bytes'])}",
    ]
    return ToolResult(True, "Volume usage", "\n".join(lines))


def tool_memory_usage(settings: Settings) -> ToolResult:
    memory = memory_usage()
    lines = [
        f"Used   : {format_bytes(memory['used_bytes'])}",
        f"Limit  : {format_bytes(memory['total_bytes'])}",
        f"Percent: {memory['percent']}%",
    ]
    return ToolResult(True, "Memory usage", "\n".join(lines))


def tool_backup(settings: Settings) -> ToolResult:
    try:
        result = create_backup(settings, label="manual")
    except BackupError as exc:
        return ToolResult(False, "Database backup", str(exc))
    return ToolResult(
        True,
        "Database backup",
        json.dumps(result.as_dict(), indent=2)
        + "\n\nDownload it with:  railway ssh  ->  cat "
        + str(result.path),
    )


TOOL_ACTIONS: dict[str, tuple[str, Callable[[Settings], ToolResult]]] = {
    "xray_status": ("Show Xray status", tool_xray_status),
    "xray_restart": ("Restart Xray", tool_xray_restart),
    "validate_config": ("Validate configuration", tool_validate_config),
    "resync": ("Re-apply configuration", tool_resync),
    "listening_ports": ("Show listening ports", tool_listening_ports),
    "dns_test": ("DNS resolution test", tool_dns_test),
    "outbound_ip": ("Outbound public IP", tool_outbound_ip),
    "reality_check": ("REALITY destination check", tool_reality_reachability),
    "disk_usage": ("Volume usage", tool_disk_usage),
    "memory_usage": ("Memory usage", tool_memory_usage),
    "backup": ("Create database backup", tool_backup),
}


def run_tool(settings: Settings, action: str) -> ToolResult:
    entry = TOOL_ACTIONS.get(action)
    if entry is None:
        return ToolResult(False, "Unknown action", f"{action!r} is not an allowed action.")
    _, handler = entry
    try:
        return handler(settings)
    except Exception as exc:  # noqa: BLE001 - a tool must never 500 the panel
        return ToolResult(False, entry[0], f"{type(exc).__name__}: {exc}")
