"""Host/container metrics and the outbound IP lookup.

Everything here degrades to ``None``/``"unknown"`` instead of raising: the
dashboard is allowed to be incomplete, but it must never fail to render, and the
health endpoint must never depend on a third-party service.
"""

from __future__ import annotations

import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import Settings
from app.util import utcnow

CGROUP_ROOT = Path("/sys/fs/cgroup")

_PROCESS_START = time.monotonic()
_START_WALLCLOCK = utcnow()

_cpu_lock = threading.Lock()
_cpu_previous: tuple[float, float] | None = None  # (monotonic, cpu_usage_seconds)

_ip_lock = threading.Lock()
_ip_cache: dict[str, object] = {"value": "", "checked_at": 0.0, "error": ""}
_IP_CACHE_TTL = 600.0  # seconds


def app_uptime_seconds() -> float:
    return time.monotonic() - _PROCESS_START


def app_started_at():
    return _START_WALLCLOCK


def _read_int(path: Path) -> int | None:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _cgroup_cpu_usage_seconds() -> float | None:
    """Cumulative CPU seconds used by this container (cgroup v2, then v1)."""
    stat = CGROUP_ROOT / "cpu.stat"
    try:
        for line in stat.read_text(encoding="utf-8").splitlines():
            if line.startswith("usage_usec"):
                return int(line.split()[1]) / 1_000_000
    except (OSError, ValueError, IndexError):
        pass
    usage_ns = _read_int(CGROUP_ROOT / "cpuacct" / "cpuacct.usage")
    return usage_ns / 1_000_000_000 if usage_ns is not None else None


def _proc_cpu_usage_seconds() -> float | None:
    """Fallback: system-wide busy time from /proc/stat."""
    try:
        with open("/proc/stat", encoding="utf-8") as handle:
            parts = handle.readline().split()
        values = [float(v) for v in parts[1:]]
        ticks = 100.0
        idle = values[3] + (values[4] if len(values) > 4 else 0.0)
        return (sum(values) - idle) / ticks
    except (OSError, ValueError, IndexError):
        return None


def cpu_percent() -> float | None:
    """CPU usage since the previous call. The first call returns ``None``."""
    global _cpu_previous
    usage = _cgroup_cpu_usage_seconds()
    if usage is None:
        usage = _proc_cpu_usage_seconds()
    if usage is None:
        return None

    now = time.monotonic()
    with _cpu_lock:
        previous = _cpu_previous
        _cpu_previous = (now, usage)
    if previous is None:
        return None
    elapsed = now - previous[0]
    if elapsed <= 0.05:
        return None
    delta = max(0.0, usage - previous[1])
    return round(min(100.0, (delta / elapsed) * 100.0), 1)


def memory_usage() -> dict[str, object]:
    """Container memory usage, preferring cgroup limits over host totals."""
    current = _read_int(CGROUP_ROOT / "memory.current")
    limit_raw = (CGROUP_ROOT / "memory.max").read_text(encoding="utf-8").strip() if (
        CGROUP_ROOT / "memory.max"
    ).exists() else ""
    limit: int | None = None
    if limit_raw and limit_raw != "max":
        try:
            limit = int(limit_raw)
        except ValueError:
            limit = None

    if current is None:
        current = _read_int(CGROUP_ROOT / "memory" / "memory.usage_in_bytes")
    if limit is None:
        v1_limit = _read_int(CGROUP_ROOT / "memory" / "memory.limit_in_bytes")
        if v1_limit is not None and v1_limit < (1 << 62):
            limit = v1_limit

    if current is None or limit is None:
        total = available = None
        try:
            with open("/proc/meminfo", encoding="utf-8") as handle:
                for line in handle:
                    if line.startswith("MemTotal:"):
                        total = int(line.split()[1]) * 1024
                    elif line.startswith("MemAvailable:"):
                        available = int(line.split()[1]) * 1024
        except (OSError, ValueError, IndexError):
            pass
        if total is not None and available is not None:
            current = total - available
            limit = total

    if current is None or not limit:
        return {"used_bytes": None, "total_bytes": None, "percent": None}
    return {
        "used_bytes": current,
        "total_bytes": limit,
        "percent": round(current / limit * 100.0, 1) if limit else None,
    }


def disk_usage(path: Path) -> dict[str, object]:
    """Usage of the volume backing ``path``."""
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        return {"used_bytes": None, "total_bytes": None, "free_bytes": None, "percent": None}
    return {
        "used_bytes": usage.used,
        "total_bytes": usage.total,
        "free_bytes": usage.free,
        "percent": round(usage.used / usage.total * 100.0, 1) if usage.total else None,
    }


def volume_writable(path: Path) -> tuple[bool, str]:
    """Verify the data directory really accepts writes."""
    probe = path / ".railgate-write-test"
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, ""
    except OSError as exc:
        return False, (
            f"Persistent directory {path} is not writable ({exc}). "
            "On Railway: Service -> Settings -> Volumes -> attach a volume mounted at "
            f"{path}."
        )


def outbound_ip(settings: Settings, force: bool = False) -> dict[str, object]:
    """Look up the container's outbound public IP.

    Cached for ten minutes, short timeout, and a failure is reported as data
    rather than raised — health must never depend on this.
    """
    if not settings.outbound_ip_check_enabled:
        return {"ip": "", "error": "disabled", "checked_at": None, "cached": False}

    now = time.monotonic()
    with _ip_lock:
        age = now - float(_ip_cache["checked_at"] or 0.0)
        if not force and _ip_cache["value"] and age < _IP_CACHE_TTL:
            return {
                "ip": _ip_cache["value"],
                "error": "",
                "checked_at": _ip_cache["checked_at"],
                "cached": True,
            }

    value, error = "", ""
    try:
        import httpx

        response = httpx.get(
            settings.outbound_ip_check_url,
            timeout=httpx.Timeout(5.0, connect=3.0),
            follow_redirects=False,
            headers={"User-Agent": "RailGate/health"},
        )
        response.raise_for_status()
        candidate = response.text.strip().splitlines()[0].strip() if response.text.strip() else ""
        value = candidate[:64]
        if not value:
            error = "The IP service returned an empty response."
    except Exception as exc:  # noqa: BLE001 - any failure is non-fatal by design
        error = f"{type(exc).__name__}: {exc}"

    with _ip_lock:
        if value:
            _ip_cache.update({"value": value, "checked_at": now, "error": ""})
        else:
            _ip_cache["error"] = error
            _ip_cache["checked_at"] = now
        cached_value = _ip_cache["value"]

    return {"ip": value or cached_value, "error": error, "checked_at": now, "cached": False}


@dataclass
class SystemSnapshot:
    cpu_percent: float | None
    memory: dict[str, object]
    disk: dict[str, object]
    uptime_seconds: float

    def as_dict(self) -> dict[str, object]:
        return {
            "cpu_percent": self.cpu_percent,
            "memory": self.memory,
            "disk": self.disk,
            "uptime_seconds": self.uptime_seconds,
        }


def snapshot(settings: Settings) -> SystemSnapshot:
    return SystemSnapshot(
        cpu_percent=cpu_percent(),
        memory=memory_usage(),
        disk=disk_usage(settings.data_dir),
        uptime_seconds=app_uptime_seconds(),
    )
