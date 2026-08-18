#!/usr/bin/env python3
"""RailGate process supervisor (PID 1).

Deliberately small and purpose-built instead of systemd/supervisord:

* runs the startup self-test before anything else;
* owns both ``xray`` and ``admin-api`` so restarting one never kills the other;
* streams child output to stdout (for ``railway logs``) *and* to a size-capped
  file (for the dashboard's Logs page);
* exposes a Unix-socket control channel so the admin API can restart Xray;
* forwards SIGTERM/SIGINT and reaps children, so Railway deploys shut down
  cleanly instead of being killed.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.environ.get("APP_ROOT", "/opt/railgate"))

from app.bootstrap import run_bootstrap  # noqa: E402
from app.config import ConfigError, Settings, load_settings  # noqa: E402

XRAY = "xray"
ADMIN = "admin-api"

MAX_LOG_BYTES = 2 * 1024 * 1024
SHUTDOWN_GRACE_SECONDS = 12
ADMIN_CRASH_LIMIT = 5
ADMIN_CRASH_WINDOW = 120.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _log(message: str) -> None:
    print(f"[supervisor] {message}", flush=True)


class Program:
    """A supervised child process."""

    def __init__(
        self,
        name: str,
        argv: list[str],
        log_path: Path,
        cwd: str | None = None,
        env: dict[str, str] | None = None,
        critical: bool = False,
    ) -> None:
        self.name = name
        self.argv = argv
        self.log_path = log_path
        self.cwd = cwd
        self.env = env
        self.critical = critical

        self.process: subprocess.Popen | None = None
        self.desired_running = True
        self.started_at: str | None = None
        self.restarts = 0
        self.last_exit_code: int | None = None
        self.backoff = 1.0
        self.next_start_at = 0.0
        self.recent_crashes: list[float] = []
        self._lock = threading.RLock()

    # -- logging -------------------------------------------------------------
    def _rotate_if_needed(self) -> None:
        try:
            if self.log_path.exists() and self.log_path.stat().st_size > MAX_LOG_BYTES:
                backup = self.log_path.with_suffix(self.log_path.suffix + ".1")
                backup.unlink(missing_ok=True)
                self.log_path.rename(backup)
        except OSError:
            pass

    def _pump_output(self, stream) -> None:
        prefix = f"[{self.name}] "
        try:
            for raw in iter(stream.readline, b""):
                line = raw.decode("utf-8", errors="replace").rstrip("\n")
                print(prefix + line, flush=True)
                try:
                    self._rotate_if_needed()
                    self.log_path.parent.mkdir(parents=True, exist_ok=True)
                    with self.log_path.open("a", encoding="utf-8") as handle:
                        handle.write(f"{_now_iso()} {line}\n")
                except OSError:
                    pass
        except (ValueError, OSError):
            pass
        finally:
            try:
                stream.close()
            except OSError:
                pass

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> bool:
        with self._lock:
            if self.process is not None and self.process.poll() is None:
                return True
            self.desired_running = True
            try:
                self.process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                    self.argv,
                    cwd=self.cwd,
                    env=self.env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError as exc:
                _log(f"failed to start {self.name}: {exc}")
                self.process = None
                return False
            self.started_at = _now_iso()
            _log(f"started {self.name} (pid {self.process.pid})")
            threading.Thread(
                target=self._pump_output, args=(self.process.stdout,), daemon=True
            ).start()
            return True

    def stop(self, grace: float = SHUTDOWN_GRACE_SECONDS) -> None:
        with self._lock:
            self.desired_running = False
            process = self.process
        if process is None or process.poll() is not None:
            return
        _log(f"stopping {self.name} (pid {process.pid})")
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.terminate()
            except OSError:
                pass
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return
            time.sleep(0.2)
        _log(f"{self.name} ignored SIGTERM; sending SIGKILL")
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            pass

    def restart(self) -> bool:
        self.stop()
        with self._lock:
            self.backoff = 1.0
            self.next_start_at = 0.0
            self.restarts += 1
        return self.start()

    def is_running(self) -> bool:
        with self._lock:
            return self.process is not None and self.process.poll() is None

    def status(self) -> dict:
        with self._lock:
            running = self.process is not None and self.process.poll() is None
            return {
                "running": running,
                "desired_running": self.desired_running,
                "pid": self.process.pid if running and self.process else None,
                "started_at": self.started_at if running else None,
                "restarts": self.restarts,
                "last_exit_code": self.last_exit_code,
                "command": " ".join(self.argv),
            }

    def reap(self) -> bool:
        """Note an exit. Returns True when the process just died."""
        with self._lock:
            if self.process is None:
                return False
            code = self.process.poll()
            if code is None:
                return False
            self.last_exit_code = code
            self.process = None
            return True


class Supervisor:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.programs: dict[str, Program] = {}
        self.shutting_down = threading.Event()
        self.exit_code = 0
        self._socket: socket.socket | None = None

    # -- programs ------------------------------------------------------------
    def build_programs(self) -> None:
        settings = self.settings
        child_env = os.environ.copy()
        child_env.setdefault("PYTHONPATH", str(settings.app_root))
        child_env["PYTHONUNBUFFERED"] = "1"
        # The bootstrap password is generated once by the supervisor; make sure
        # the admin process inherits exactly the same value.
        child_env["ADMIN_PASSWORD"] = settings.admin_password
        child_env["ADMIN_SESSION_SECRET"] = settings.admin_session_secret

        self.programs[XRAY] = Program(
            name=XRAY,
            argv=[str(settings.xray_bin), "run", "-c", str(settings.xray_config_path)],
            log_path=settings.xray_log_path,
            cwd=str(settings.xray_data_dir),
            env=child_env,
        )
        self.programs[ADMIN] = Program(
            name=ADMIN,
            argv=[
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "0.0.0.0",
                "--port",
                str(settings.port),
                "--workers",
                "1",
                "--no-server-header",
                "--proxy-headers",
                "--forwarded-allow-ips",
                "*",
                "--log-level",
                settings.log_level.lower(),
            ],
            log_path=settings.admin_log_path,
            cwd=str(settings.app_root),
            env=child_env,
            critical=True,
        )

    # -- control socket ------------------------------------------------------
    def _handle_command(self, payload: dict) -> dict:
        command = str(payload.get("cmd", "")).lower()
        if command == "ping":
            return {"ok": True, "pong": True, "version": self.settings.app_version}
        if command == "status":
            return {
                "ok": True,
                "programs": {name: program.status() for name, program in self.programs.items()},
                "shutting_down": self.shutting_down.is_set(),
            }

        name = str(payload.get("program", ""))
        program = self.programs.get(name)
        if program is None:
            return {"ok": False, "error": f"Unknown program {name!r}."}
        if self.shutting_down.is_set():
            return {"ok": False, "error": "The supervisor is shutting down."}

        if command == "restart":
            return {"ok": program.restart(), "programs": {name: program.status()}}
        if command == "stop":
            program.stop()
            return {"ok": True, "programs": {name: program.status()}}
        if command == "start":
            return {"ok": program.start(), "programs": {name: program.status()}}
        return {"ok": False, "error": f"Unknown command {command!r}."}

    def _serve_control(self) -> None:
        path = self.settings.supervisor_socket_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                path.unlink()
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(str(path))
            os.chmod(path, 0o600)
            server.listen(8)
            server.settimeout(1.0)
        except OSError as exc:
            _log(f"control socket unavailable: {exc}")
            return

        self._socket = server
        _log(f"control socket listening on {path}")
        while not self.shutting_down.is_set():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(connection,), daemon=True).start()

        try:
            server.close()
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def _handle_client(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(60.0)
            data = b""
            while b"\n" not in data and len(data) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
            try:
                payload = json.loads(data.decode("utf-8", errors="replace").splitlines()[0])
                response = self._handle_command(payload if isinstance(payload, dict) else {})
            except (json.JSONDecodeError, IndexError):
                response = {"ok": False, "error": "Malformed request."}
            except Exception as exc:  # noqa: BLE001
                response = {"ok": False, "error": str(exc)}
            connection.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except OSError:
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    # -- signals -------------------------------------------------------------
    def install_signal_handlers(self) -> None:
        def handler(signum, _frame):
            if not self.shutting_down.is_set():
                _log(f"received signal {signum}; shutting down")
                self.shutting_down.set()

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGHUP, handler)

    # -- main loop -----------------------------------------------------------
    def run(self) -> int:
        self.install_signal_handlers()
        self.build_programs()
        threading.Thread(target=self._serve_control, daemon=True).start()

        for program in self.programs.values():
            program.start()

        while not self.shutting_down.is_set():
            time.sleep(0.5)
            now = time.monotonic()
            for program in self.programs.values():
                if program.reap():
                    code = program.last_exit_code
                    _log(f"{program.name} exited with code {code}")
                    if not program.desired_running or self.shutting_down.is_set():
                        continue
                    program.recent_crashes = [
                        t for t in program.recent_crashes if now - t < ADMIN_CRASH_WINDOW
                    ]
                    program.recent_crashes.append(now)
                    if program.critical and len(program.recent_crashes) >= ADMIN_CRASH_LIMIT:
                        _log(
                            f"{program.name} crashed {len(program.recent_crashes)} times in "
                            f"{int(ADMIN_CRASH_WINDOW)}s — giving up so the platform can redeploy."
                        )
                        self.exit_code = 1
                        self.shutting_down.set()
                        break
                    program.next_start_at = now + program.backoff
                    _log(f"restarting {program.name} in {program.backoff:.0f}s")
                    program.backoff = min(program.backoff * 2, 30.0)
                    program.restarts += 1
                elif (
                    program.desired_running
                    and not program.is_running()
                    and program.next_start_at
                    and now >= program.next_start_at
                ):
                    program.next_start_at = 0.0
                    program.start()
                elif program.is_running() and program.backoff > 1.0:
                    # Stable for a while: reset the backoff.
                    program.backoff = 1.0

        self.shutdown()
        return self.exit_code

    def shutdown(self) -> None:
        _log("stopping child processes")
        for name in (ADMIN, XRAY):
            program = self.programs.get(name)
            if program is not None:
                program.stop()
        try:
            self.settings.supervisor_socket_path.unlink(missing_ok=True)
        except OSError:
            pass
        _log("shutdown complete")


def main() -> int:
    banner = "RailGate supervisor starting"
    print(f"\n{'=' * 60}\n {banner}\n{'=' * 60}", flush=True)

    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"\nSTARTUP ABORTED — configuration error:\n\n{exc}\n", file=sys.stderr, flush=True)
        return 2

    print(
        f" {settings.app_name} v{settings.app_version} "
        f"(env={settings.app_env}, http port={settings.port}, xray port={settings.xray_port})",
        flush=True,
    )

    report = run_bootstrap(settings)
    print("\nStartup self-test:")
    print(report.render(), flush=True)
    if not report.ok:
        print(
            "\nSTARTUP ABORTED — the failing step above must be fixed before "
            "RailGate can serve traffic.\n",
            file=sys.stderr,
            flush=True,
        )
        return 1
    print()

    return Supervisor(settings).run()


if __name__ == "__main__":
    raise SystemExit(main())
