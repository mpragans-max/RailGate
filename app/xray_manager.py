"""Xray-core lifecycle: keys, configuration rendering, validation and apply.

Design rules enforced here:

* A configuration is **never** activated before ``xray run -test`` accepts it.
* The previous configuration is kept and restored automatically if the new one
  fails to start (rollback).
* Adding/removing accounts uses Xray's HandlerService API (``xray api adu/rmu``)
  so existing tunnels are not interrupted. A restart happens only when the
  *structure* of the config changed (ports, keys, SNI, transports).
* The REALITY private key is read here and written into the rendered config on
  disk. It is never returned to the web layer, the CLI or the logs.

Verified against Xray-core v26.3.27.
"""

from __future__ import annotations

import copy
import errno
import fcntl
import hashlib
import json
import os
import re
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Sequence

from app import supervisor_client
from app.config import Settings
from app.database import get_setting, set_setting
from app.models import VpnUser
from app.security import generate_ws_path
from app.util import parse_iso, utcnow

REALITY_INBOUND_TAG = "vless-reality"
WS_BACKEND_INBOUND_TAG = "vless-ws-backend"
SUPERVISOR_PROGRAM = "xray"

SETTING_WS_PATH = "ws_fallback_path"
SETTING_REALITY_PUBLIC_KEY = "reality_public_key"
SETTING_REALITY_SHORT_ID = "reality_short_id"
SETTING_LAST_APPLY = "last_config_apply"

_COMMAND_TIMEOUT = 30
_ADDED_PATTERN = re.compile(r"Added\s+(\d+)\s+user", re.IGNORECASE)
_REMOVED_PATTERN = re.compile(r"Removed\s+(\d+)\s+user", re.IGNORECASE)


class XrayError(RuntimeError):
    """Raised for unrecoverable Xray management problems."""


# --------------------------------------------------------------------------- #
# data containers
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RealityKeys:
    """REALITY material. ``private_key`` must never leave the server."""

    private_key: str
    public_key: str
    short_id: str

    def public_only(self) -> dict[str, str]:
        return {"public_key": self.public_key, "short_id": self.short_id}


@dataclass
class ApplyResult:
    ok: bool
    method: str = ""
    message: str = ""
    restarted: bool = False
    rolled_back: bool = False
    validation_output: str = ""
    structural_change: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "method": self.method,
            "message": self.message,
            "restarted": self.restarted,
            "rolled_back": self.rolled_back,
            "structural_change": self.structural_change,
            "validation_output": self.validation_output[-2000:],
        }


@dataclass
class XrayStatus:
    running: bool = False
    listening: bool = False
    pid: int | None = None
    started_at: datetime | None = None
    uptime_seconds: float | None = None
    restarts: int = 0
    last_exit_code: int | None = None
    version: str = "unknown"
    source: str = "supervisor"
    error: str = ""

    @property
    def state(self) -> str:
        if self.running and self.listening:
            return "running"
        if self.running:
            return "starting"
        return "stopped"

    def as_dict(self) -> dict[str, object]:
        return {
            "running": self.running,
            "listening": self.listening,
            "state": self.state,
            "pid": self.pid,
            "uptime_seconds": self.uptime_seconds,
            "restarts": self.restarts,
            "last_exit_code": self.last_exit_code,
            "version": self.version,
            "error": self.error,
        }


# --------------------------------------------------------------------------- #
# process helpers
# --------------------------------------------------------------------------- #
def _run(args: Sequence[str], timeout: int = _COMMAND_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        list(args),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def xray_version(settings: Settings) -> str:
    """First line of ``xray version``, or a readable error."""
    try:
        result = _run([str(settings.xray_bin), "version"], timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unavailable ({exc})"
    if result.returncode != 0:
        return "unavailable"
    first = (result.stdout or "").strip().splitlines()
    return first[0].strip() if first else "unknown"


def port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """True when a TCP connection can be established."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@contextmanager
def config_lock(settings: Settings, timeout: float = 30.0) -> Iterator[None]:
    """Cross-process lock so the CLI and the web app never race on apply."""
    settings.run_dir.mkdir(parents=True, exist_ok=True)
    lock_file = settings.apply_lock_path
    handle = open(lock_file, "a+")  # noqa: SIM115 - lifetime managed below
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EAGAIN):
                    raise
                if time.monotonic() >= deadline:
                    raise XrayError(
                        "Timed out waiting for the configuration lock. "
                        "Another apply is still running."
                    ) from exc
                time.sleep(0.2)
        yield
    finally:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        finally:
            handle.close()


# --------------------------------------------------------------------------- #
# REALITY key material
# --------------------------------------------------------------------------- #
def _parse_x25519_output(text: str) -> tuple[str, str]:
    """Parse ``xray x25519``.

    v26.3.27 prints::

        PrivateKey: <base64url>
        Password (PublicKey): <base64url>
        Hash32: <base64url>

    Older builds used ``Private key:`` / ``Public key:``; both are accepted.
    """
    private = public = ""
    for line in text.splitlines():
        if ":" not in line:
            continue
        label, _, value = line.partition(":")
        normalised = re.sub(r"[^a-z0-9]", "", label.lower())
        value = value.strip()
        if not value:
            continue
        if "privatekey" in normalised:
            private = value
        elif "publickey" in normalised or normalised.startswith("password"):
            public = value
    if not private or not public:
        raise XrayError(
            "Could not parse the output of `xray x25519`. "
            f"Unexpected format:\n{text.strip()[:400]}"
        )
    return private, public


def generate_reality_keypair(settings: Settings) -> tuple[str, str]:
    try:
        result = _run([str(settings.xray_bin), "x25519"], timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        raise XrayError(f"Could not run `{settings.xray_bin} x25519`: {exc}") from exc
    if result.returncode != 0:
        raise XrayError(f"`xray x25519` failed: {(result.stderr or result.stdout).strip()}")
    return _parse_x25519_output(result.stdout)


def _write_secret(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode), "w", encoding="utf-8") as handle:
        handle.write(value.strip() + "\n")
    os.replace(tmp, path)
    os.chmod(path, mode)


def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def load_reality_keys(settings: Settings) -> RealityKeys | None:
    private = _read_file(settings.reality_private_key_path)
    public = _read_file(settings.reality_public_key_path)
    short_id = _read_file(settings.reality_short_id_path)
    if private and public and short_id:
        return RealityKeys(private, public, short_id)
    return None


def ensure_reality_keys(settings: Settings, *, rotate: bool = False) -> RealityKeys:
    """Load persisted REALITY material, generating it on first boot.

    Idempotent: redeploying never regenerates keys while ``/data`` survives, so
    previously issued client links keep working.
    """
    existing = load_reality_keys(settings)
    if existing and not rotate:
        return existing

    private, public = generate_reality_keypair(settings)
    short_id = os.urandom(8).hex()

    _write_secret(settings.reality_private_key_path, private, 0o600)
    _write_secret(settings.reality_public_key_path, public, 0o644)
    _write_secret(settings.reality_short_id_path, short_id, 0o644)

    keys = RealityKeys(private, public, short_id)
    try:
        set_setting(settings.db_path, SETTING_REALITY_PUBLIC_KEY, public)
        set_setting(settings.db_path, SETTING_REALITY_SHORT_ID, short_id)
    except Exception:  # pragma: no cover - DB mirror is a convenience only
        pass
    return keys


def ensure_ws_path(settings: Settings) -> str:
    """Return the (persisted) randomised WebSocket fallback path."""
    if settings.ws_fallback_path_override:
        return settings.ws_fallback_path_override
    stored = get_setting(settings.db_path, SETTING_WS_PATH, "")
    if stored:
        return stored
    generated = generate_ws_path()
    set_setting(settings.db_path, SETTING_WS_PATH, generated)
    return generated


# --------------------------------------------------------------------------- #
# configuration rendering
# --------------------------------------------------------------------------- #
def _strip_comments(node):
    """Remove ``_comment`` keys so the rendered config stays clean."""
    if isinstance(node, dict):
        return {k: _strip_comments(v) for k, v in node.items() if not k.startswith("_")}
    if isinstance(node, list):
        return [_strip_comments(item) for item in node]
    return node


def load_template(settings: Settings) -> dict:
    path = settings.config_template_path
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise XrayError(f"Xray config template not found at {path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise XrayError(f"Xray config template {path} is not valid JSON: {exc}") from exc


def _find_inbound(config: dict, tag: str) -> dict | None:
    for inbound in config.get("inbounds", []):
        if inbound.get("tag") == tag:
            return inbound
    return None


def render_config(
    settings: Settings,
    users: Sequence[VpnUser],
    keys: RealityKeys,
    ws_path: str,
    template: dict | None = None,
) -> dict:
    """Build the complete Xray configuration for the given active accounts."""
    config = _strip_comments(copy.deepcopy(template or load_template(settings)))

    config.setdefault("log", {})["loglevel"] = settings.xray_log_level
    config.setdefault("api", {})["listen"] = settings.xray_api_address

    reality = _find_inbound(config, REALITY_INBOUND_TAG)
    if reality is None:
        raise XrayError(
            f"The config template has no inbound tagged {REALITY_INBOUND_TAG!r}."
        )
    reality["port"] = settings.xray_port
    reality["listen"] = "0.0.0.0"
    reality.setdefault("settings", {})["decryption"] = "none"
    reality["settings"]["clients"] = [
        {"id": user.uuid, "email": user.email, "flow": user.flow or "xtls-rprx-vision", "level": 0}
        for user in users
    ]
    stream = reality.setdefault("streamSettings", {})
    stream["network"] = "raw"
    stream["security"] = "reality"
    reality_settings = stream.setdefault("realitySettings", {})
    reality_settings["target"] = settings.reality_destination
    reality_settings["serverNames"] = [settings.reality_server_name]
    reality_settings["privateKey"] = keys.private_key
    reality_settings["shortIds"] = [keys.short_id]
    reality_settings.setdefault("show", False)
    reality_settings.setdefault("xver", 0)

    ws_backend = _find_inbound(config, WS_BACKEND_INBOUND_TAG)
    if settings.enable_ws_fallback:
        if ws_backend is None:
            raise XrayError(
                f"The config template has no inbound tagged {WS_BACKEND_INBOUND_TAG!r}."
            )
        ws_backend["port"] = settings.xray_ws_backend_port
        ws_backend["listen"] = "127.0.0.1"
        ws_backend.setdefault("settings", {})["decryption"] = "none"
        # No `flow`: XTLS Vision is invalid on a WebSocket transport.
        ws_backend["settings"]["clients"] = [
            {"id": user.uuid, "email": user.email, "level": 0} for user in users
        ]
    elif ws_backend is not None:
        config["inbounds"] = [ib for ib in config["inbounds"] if ib.get("tag") != WS_BACKEND_INBOUND_TAG]

    if not settings.block_bittorrent:
        rules = config.get("routing", {}).get("rules", [])
        config["routing"]["rules"] = [
            rule for rule in rules if "bittorrent" not in (rule.get("protocol") or [])
        ]

    return config


def structural_signature(config: dict) -> str:
    """Hash of everything except the client lists.

    Two configs with the same signature differ only in accounts, which can be
    applied through the runtime API without restarting Xray.
    """
    skeleton = copy.deepcopy(config)
    for inbound in skeleton.get("inbounds", []):
        if isinstance(inbound.get("settings"), dict):
            inbound["settings"]["clients"] = []
    return hashlib.sha256(
        json.dumps(skeleton, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def read_active_config(settings: Settings) -> dict | None:
    try:
        return json.loads(settings.xray_config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def validate_config(settings: Settings, config: dict) -> tuple[bool, str]:
    """Validate with the real Xray binary. Returns ``(ok, combined_output)``."""
    settings.generated_dir.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(
        prefix="candidate-", suffix=".json", dir=str(settings.generated_dir)
    )
    temp_path = Path(temp_name)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
        try:
            result = _run([str(settings.xray_bin), "run", "-test", "-c", str(temp_path)])
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Could not execute {settings.xray_bin}: {exc}"
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        return result.returncode == 0 and "Configuration OK" in output, output
    finally:
        temp_path.unlink(missing_ok=True)


def write_config_atomic(settings: Settings, config: dict) -> None:
    """Replace the active config atomically, keeping the previous copy."""
    target = settings.xray_config_path
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.exists():
        try:
            settings.xray_config_backup_path.write_text(
                target.read_text(encoding="utf-8"), encoding="utf-8"
            )
            os.chmod(settings.xray_config_backup_path, 0o600)
        except OSError:
            pass

    handle, temp_name = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=str(target.parent))
    temp_path = Path(temp_name)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(config, stream, indent=2)
        os.replace(temp_path, target)
        os.chmod(target, 0o600)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- #
# runtime user management (HandlerService API)
# --------------------------------------------------------------------------- #
def api_list_users(settings: Settings, tag: str) -> dict[str, dict[str, str]] | None:
    """``{email: {"id": ..., "flow": ...}}`` or ``None`` when unreachable."""
    try:
        result = _run(
            [str(settings.xray_bin), "api", "inbounduser",
             f"--server={settings.xray_api_address}", f"-tag={tag}"],
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    text = (result.stdout or "").strip()
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    users: dict[str, dict[str, str]] = {}
    for entry in payload.get("users") or []:
        email = entry.get("email") or ""
        account = entry.get("account") or {}
        if email:
            users[email] = {"id": account.get("id", ""), "flow": account.get("flow", "") or ""}
    return users


def _api_add_users(settings: Settings, inbound_stanzas: list[dict]) -> tuple[bool, str]:
    """``xray api adu``. The stanza must be a *full* inbound (port + listen)."""
    if not inbound_stanzas:
        return True, "nothing to add"
    expected = sum(len(stanza["settings"]["clients"]) for stanza in inbound_stanzas)
    if expected == 0:
        return True, "nothing to add"

    settings.generated_dir.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix="adu-", suffix=".json", dir=str(settings.generated_dir))
    temp_path = Path(temp_name)
    try:
        os.fchmod(handle, 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump({"inbounds": inbound_stanzas}, stream)
        try:
            result = _run(
                [str(settings.xray_bin), "api", "adu",
                 f"--server={settings.xray_api_address}", str(temp_path)],
                timeout=15,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return False, str(exc)
    finally:
        temp_path.unlink(missing_ok=True)

    output = ((result.stdout or "") + (result.stderr or "")).strip()
    # `xray api adu` exits 0 even when it adds nothing, so parse the summary.
    match = _ADDED_PATTERN.search(output)
    added = int(match.group(1)) if match else 0
    return added >= expected, output


def _api_remove_users(settings: Settings, tag: str, emails: Sequence[str]) -> tuple[bool, str]:
    if not emails:
        return True, "nothing to remove"
    try:
        result = _run(
            [str(settings.xray_bin), "api", "rmu",
             f"--server={settings.xray_api_address}", f"-tag={tag}", *emails],
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
    output = ((result.stdout or "") + (result.stderr or "")).strip()
    match = _REMOVED_PATTERN.search(output)
    removed = int(match.group(1)) if match else 0
    return removed >= len(emails), output


def _inbound_stanza(config: dict, tag: str, clients: list[dict]) -> dict | None:
    """Minimal but complete inbound stanza accepted by ``xray api adu``."""
    inbound = _find_inbound(config, tag)
    if inbound is None:
        return None
    return {
        "tag": tag,
        "port": inbound["port"],
        "listen": inbound.get("listen", "0.0.0.0"),
        "protocol": inbound.get("protocol", "vless"),
        "settings": {"clients": clients, "decryption": "none"},
    }


def sync_users_via_api(settings: Settings, config: dict) -> tuple[bool, str]:
    """Reconcile Xray's live account list with the rendered config."""
    messages: list[str] = []
    tags = [REALITY_INBOUND_TAG]
    if settings.enable_ws_fallback:
        tags.append(WS_BACKEND_INBOUND_TAG)

    for tag in tags:
        inbound = _find_inbound(config, tag)
        if inbound is None:
            continue
        desired = {
            client["email"]: {"id": client["id"], "flow": client.get("flow", "") or ""}
            for client in inbound["settings"]["clients"]
        }
        current = api_list_users(settings, tag)
        if current is None:
            return False, f"Xray API did not answer for inbound {tag!r}."

        # Anything whose UUID or flow changed must be removed before re-adding.
        stale = [
            email
            for email, account in current.items()
            if email not in desired or account != desired[email]
        ]
        ok, output = _api_remove_users(settings, tag, stale)
        if not ok:
            return False, f"Removing users from {tag!r} failed: {output}"
        if stale:
            messages.append(f"{tag}: removed {len(stale)}")

        remaining = {e: a for e, a in current.items() if e not in stale}
        additions = [
            {"id": account["id"], "email": email, "level": 0,
             **({"flow": account["flow"]} if account["flow"] else {})}
            for email, account in desired.items()
            if email not in remaining
        ]
        stanza = _inbound_stanza(config, tag, additions)
        if stanza is not None:
            ok, output = _api_add_users(settings, [stanza])
            if not ok:
                return False, f"Adding users to {tag!r} failed: {output}"
            if additions:
                messages.append(f"{tag}: added {len(additions)}")

    return True, "; ".join(messages) or "already in sync"


# --------------------------------------------------------------------------- #
# status & control
# --------------------------------------------------------------------------- #
def xray_status(settings: Settings) -> XrayStatus:
    """Combine supervisor state with a real TCP probe of the VPN port."""
    status = XrayStatus(version=xray_version(settings))
    status.listening = port_open("127.0.0.1", settings.xray_port)

    info = supervisor_client.status(settings.supervisor_socket_path)
    if info.get("ok"):
        program = (info.get("programs") or {}).get(SUPERVISOR_PROGRAM) or {}
        status.running = bool(program.get("running"))
        status.pid = program.get("pid")
        status.restarts = int(program.get("restarts") or 0)
        status.last_exit_code = program.get("last_exit_code")
        started = parse_iso(program.get("started_at"))
        status.started_at = started
        if started and status.running:
            status.uptime_seconds = max(0.0, (utcnow() - started).total_seconds())
    else:
        # No supervisor (unit tests, ad-hoc runs): trust the port probe.
        status.source = "probe"
        status.running = status.listening
        status.error = str(info.get("error") or "")
    return status


def wait_until_healthy(settings: Settings, timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open("127.0.0.1", settings.xray_port, timeout=1.0):
            return True
        time.sleep(0.5)
    return False


def restart_xray(settings: Settings, timeout: float = 40.0) -> tuple[bool, str]:
    """Ask the supervisor to restart Xray, then wait for the port to come back."""
    response = supervisor_client.restart_program(
        settings.supervisor_socket_path, SUPERVISOR_PROGRAM, timeout=timeout
    )
    if not response.get("ok"):
        return False, str(response.get("error") or "The supervisor refused the restart.")
    if not wait_until_healthy(settings, timeout=25.0):
        return False, (
            f"Xray restarted but is not accepting connections on port {settings.xray_port}."
        )
    return True, "Xray restarted."


# --------------------------------------------------------------------------- #
# the apply pipeline
# --------------------------------------------------------------------------- #
def apply_configuration(
    settings: Settings,
    users: Sequence[VpnUser],
    *,
    reason: str = "",
    force_restart: bool = False,
    allow_restart: bool = True,
) -> ApplyResult:
    """Render -> validate -> atomically replace -> apply -> verify -> rollback.

    The active configuration is only replaced once Xray itself has accepted the
    candidate, so an invalid render can never take the tunnel down.
    """
    with config_lock(settings):
        keys = ensure_reality_keys(settings)
        ws_path = ensure_ws_path(settings)
        config = render_config(settings, users, keys, ws_path)

        ok, output = validate_config(settings, config)
        if not ok:
            return ApplyResult(
                ok=False,
                method="validate",
                message=(
                    "Xray configuration validation failed; the previous "
                    "configuration remains active."
                ),
                validation_output=output,
            )

        previous = read_active_config(settings)
        structural = previous is None or structural_signature(previous) != structural_signature(config)

        write_config_atomic(settings, config)
        set_setting(settings.db_path, SETTING_LAST_APPLY, (reason or "apply"))

        status = xray_status(settings)
        if not status.running:
            return ApplyResult(
                ok=True,
                method="written",
                message="Configuration written. Xray is not running yet; it will use it on start.",
                structural_change=structural,
                validation_output=output,
            )

        if not structural and not force_restart:
            synced, detail = sync_users_via_api(settings, config)
            if synced:
                return ApplyResult(
                    ok=True,
                    method="api",
                    message=f"Accounts synchronised without restarting Xray ({detail}).",
                    validation_output=output,
                )
            if not allow_restart:
                return ApplyResult(
                    ok=False, method="api", message=detail, validation_output=output
                )
            # fall through to a restart

        if not allow_restart:
            return ApplyResult(
                ok=False,
                method="deferred",
                message="A restart is required but was not permitted by the caller.",
                structural_change=structural,
                validation_output=output,
            )

        restarted, detail = restart_xray(settings)
        if restarted:
            return ApplyResult(
                ok=True,
                method="restart",
                message=detail,
                restarted=True,
                structural_change=structural,
                validation_output=output,
            )

        # Rollback: put the previous configuration back and restart again.
        if previous is not None:
            write_config_atomic(settings, previous)
            rolled_back, rollback_detail = restart_xray(settings)
            return ApplyResult(
                ok=False,
                method="rollback",
                message=(
                    f"Xray failed to start with the new configuration ({detail}). "
                    + (
                        "The previous configuration was restored and is active again."
                        if rolled_back
                        else f"Rollback also failed: {rollback_detail}"
                    )
                ),
                restarted=True,
                rolled_back=True,
                structural_change=structural,
                validation_output=output,
            )

        return ApplyResult(
            ok=False,
            method="restart",
            message=f"Xray failed to start and there is no previous configuration to restore ({detail}).",
            restarted=True,
            structural_change=structural,
            validation_output=output,
        )
