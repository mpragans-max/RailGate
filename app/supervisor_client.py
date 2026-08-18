"""Client for the in-container process supervisor.

The admin API needs to restart Xray and read its state, but it must never be the
*parent* of Xray — otherwise restarting the web app would take the tunnel down.
The supervisor owns both processes and exposes a tiny newline-delimited JSON
protocol over a Unix socket, reachable only from inside the container.
"""

from __future__ import annotations

import json
import socket
from pathlib import Path

DEFAULT_TIMEOUT = 15.0
_MAX_RESPONSE = 1 << 20  # 1 MiB


class SupervisorUnavailable(RuntimeError):
    """The supervisor socket is missing or not answering."""


def send_command(socket_path: Path, payload: dict, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """Send one command and return the decoded reply.

    Raises :class:`SupervisorUnavailable` when the supervisor cannot be reached.
    """
    if not socket_path.exists():
        raise SupervisorUnavailable(
            f"Supervisor socket {socket_path} does not exist. "
            "Is RailGate running under scripts/supervisor.py?"
        )

    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(str(socket_path))
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\n" in chunk or total > _MAX_RESPONSE:
                break
        raw = b"".join(chunks).decode("utf-8", errors="replace").strip()
    except (OSError, socket.timeout) as exc:
        raise SupervisorUnavailable(f"Supervisor did not respond: {exc}") from exc
    finally:
        try:
            client.close()
        except OSError:
            pass

    if not raw:
        raise SupervisorUnavailable("Supervisor returned an empty response.")
    try:
        return json.loads(raw.splitlines()[0])
    except json.JSONDecodeError as exc:
        raise SupervisorUnavailable(f"Supervisor returned invalid JSON: {exc}") from exc


def is_available(socket_path: Path) -> bool:
    try:
        return bool(send_command(socket_path, {"cmd": "ping"}, timeout=3.0).get("ok"))
    except SupervisorUnavailable:
        return False


def status(socket_path: Path) -> dict:
    """Full supervisor status, or a structured error when unavailable."""
    try:
        return send_command(socket_path, {"cmd": "status"}, timeout=5.0)
    except SupervisorUnavailable as exc:
        return {"ok": False, "error": str(exc), "programs": {}}


def program_status(socket_path: Path, name: str) -> dict:
    return status(socket_path).get("programs", {}).get(name, {}) or {}


def restart_program(socket_path: Path, name: str, timeout: float = 40.0) -> dict:
    try:
        return send_command(socket_path, {"cmd": "restart", "program": name}, timeout=timeout)
    except SupervisorUnavailable as exc:
        return {"ok": False, "error": str(exc)}


def stop_program(socket_path: Path, name: str, timeout: float = 40.0) -> dict:
    try:
        return send_command(socket_path, {"cmd": "stop", "program": name}, timeout=timeout)
    except SupervisorUnavailable as exc:
        return {"ok": False, "error": str(exc)}


def start_program(socket_path: Path, name: str, timeout: float = 40.0) -> dict:
    try:
        return send_command(socket_path, {"cmd": "start", "program": name}, timeout=timeout)
    except SupervisorUnavailable as exc:
        return {"ok": False, "error": str(exc)}
