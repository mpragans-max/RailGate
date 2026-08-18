"""Startup sequence and self-test.

Run by the supervisor *before* any process is started, and re-runnable at any
time with ``python -m app.bootstrap``. Every step is idempotent: redeploying
must never change UUIDs, regenerate REALITY keys or reset the database as long
as the ``/data`` volume survives.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field

from app.config import ConfigError, Settings, load_settings
from app.database import init_db, database_status
from app.logstore import CATEGORY_SYSTEM, log_event
from app.models import active_users, list_users
from app.railway_info import detect_railway, resolve_public_endpoint
from app.system_info import volume_writable
from app.xray_manager import (
    XrayError,
    apply_configuration,
    ensure_reality_keys,
    ensure_ws_path,
    xray_version,
)

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"

_SYMBOLS = {STATUS_OK: "[ OK ]", STATUS_WARN: "[WARN]", STATUS_FAIL: "[FAIL]"}


@dataclass
class Step:
    name: str
    status: str
    detail: str = ""

    @property
    def failed(self) -> bool:
        return self.status == STATUS_FAIL


@dataclass
class BootstrapReport:
    steps: list[Step] = field(default_factory=list)

    def add(self, name: str, status: str, detail: str = "") -> Step:
        step = Step(name, status, detail)
        self.steps.append(step)
        return step

    @property
    def ok(self) -> bool:
        return not any(step.failed for step in self.steps)

    def render(self) -> str:
        width = max((len(step.name) for step in self.steps), default=10)
        lines = []
        for step in self.steps:
            line = f"  {_SYMBOLS[step.status]} {step.name.ljust(width)}"
            if step.detail:
                line += f"  {step.detail}"
            lines.append(line)
        return "\n".join(lines)

    def as_dict(self) -> dict[str, object]:
        return {
            "ok": self.ok,
            "steps": [{"name": s.name, "status": s.status, "detail": s.detail} for s in self.steps],
        }


def run_bootstrap(settings: Settings, *, quiet: bool = False) -> BootstrapReport:
    """Execute the full startup sequence. Never raises."""
    report = BootstrapReport()

    # 1. persistent storage -------------------------------------------------
    writable, error = volume_writable(settings.data_dir)
    if writable:
        report.add("persistent storage", STATUS_OK, str(settings.data_dir))
    else:
        report.add("persistent storage", STATUS_FAIL, error)
        return report

    try:
        for directory in settings.required_directories():
            directory.mkdir(parents=True, exist_ok=True)
        report.add("data directories", STATUS_OK, "created/verified")
    except OSError as exc:
        report.add("data directories", STATUS_FAIL, str(exc))
        return report

    # 2. database ------------------------------------------------------------
    try:
        applied = init_db(settings.db_path)
        status = database_status(settings.db_path)
        report.add(
            "database",
            STATUS_OK,
            f"schema v{status['schema_version']}"
            + (f", {applied} migration(s) applied" if applied else "")
            + f", {status['user_count']} account(s)",
        )
    except Exception as exc:  # noqa: BLE001
        report.add("database", STATUS_FAIL, str(exc))
        return report

    # 3. admin credentials ---------------------------------------------------
    if settings.admin_password_is_bootstrap:
        report.add("admin password", STATUS_WARN, "temporary bootstrap password (development mode)")
    else:
        report.add("admin password", STATUS_OK, f"user '{settings.admin_username}'")
    if settings.session_secret_is_ephemeral:
        report.add(
            "session secret",
            STATUS_WARN,
            "ADMIN_SESSION_SECRET is unset — logins reset on every redeploy",
        )
    else:
        report.add("session secret", STATUS_OK, "persistent")

    # 4/5. Xray binary -------------------------------------------------------
    if not settings.xray_bin.exists():
        report.add(
            "xray binary",
            STATUS_FAIL,
            f"{settings.xray_bin} not found. The Docker image installs it at /usr/local/bin/xray.",
        )
        return report
    version = xray_version(settings)
    if version.startswith("unavailable"):
        report.add("xray binary", STATUS_FAIL, version)
        return report
    report.add("xray binary", STATUS_OK, version)

    # 6. REALITY key material ------------------------------------------------
    try:
        existed = settings.reality_private_key_path.exists()
        keys = ensure_reality_keys(settings)
        report.add(
            "reality keys",
            STATUS_OK,
            ("reused existing" if existed else "generated") + f", short id {keys.short_id}",
        )
    except XrayError as exc:
        report.add("reality keys", STATUS_FAIL, str(exc))
        return report

    # 7. persisted settings --------------------------------------------------
    try:
        ws_path = ensure_ws_path(settings)
        report.add(
            "fallback path",
            STATUS_OK if settings.enable_ws_fallback else STATUS_WARN,
            ws_path if settings.enable_ws_fallback else "WebSocket fallback disabled",
        )
    except Exception as exc:  # noqa: BLE001
        report.add("fallback path", STATUS_WARN, str(exc))

    # 8. Railway environment -------------------------------------------------
    railway = detect_railway()
    endpoint = resolve_public_endpoint(settings, railway)
    if endpoint.available:
        report.add("railway tcp proxy", STATUS_OK, f"{endpoint.host}:{endpoint.port}")
    else:
        report.add(
            "railway tcp proxy",
            STATUS_WARN,
            "NOT CONFIGURED — the WebSocket fallback still works; "
            f"add a TCP Proxy to internal port {settings.xray_port}",
        )

    # 9/10. render + validate the configuration ------------------------------
    try:
        users = active_users(settings.db_path)
        result = apply_configuration(settings, users, reason="bootstrap")
        if result.ok:
            report.add(
                "xray configuration",
                STATUS_OK,
                f"{len(users)} active account(s), validated ({result.method})",
            )
        else:
            report.add("xray configuration", STATUS_FAIL, result.message + " " + result.validation_output[-300:])
            return report
    except Exception as exc:  # noqa: BLE001
        report.add("xray configuration", STATUS_FAIL, str(exc))
        return report

    try:
        log_event(
            settings.db_path,
            "info",
            CATEGORY_SYSTEM,
            f"RailGate {settings.app_version} bootstrap completed: "
            f"{len(list_users(settings.db_path))} account(s), Xray {version}.",
            echo=not quiet,
        )
    except Exception:  # pragma: no cover - logging must not break boot
        pass

    return report


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    as_json = "--json" in argv

    try:
        settings = load_settings()
    except ConfigError as exc:
        message = f"Configuration error:\n{exc}"
        if as_json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"\n{message}\n", file=sys.stderr)
        return 2

    report = run_bootstrap(settings, quiet=as_json)

    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print("\nRailGate startup self-test")
        print(report.render())
        print()
        if not report.ok:
            print("Startup aborted: fix the [FAIL] item above.\n", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
