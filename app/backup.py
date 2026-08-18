"""Backup and restore of everything that cannot be recreated.

A backup contains the SQLite database and the REALITY key material — lose those
and every issued client link becomes worthless. Logs, rendered configs and other
regenerable runtime files are deliberately excluded.
"""

from __future__ import annotations

import json
import sqlite3
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.config import Settings
from app.database import get_db
from app.util import to_iso, utcnow

MANIFEST_NAME = "manifest.json"
DB_NAME = "vpn.db"
KEY_FILES = ("reality-private-key", "reality-public-key", "short-id")
BACKUP_FORMAT_VERSION = 1


class BackupError(RuntimeError):
    """Raised when a backup or restore cannot be completed."""


@dataclass
class BackupResult:
    path: Path
    size_bytes: int
    created_at: datetime
    user_count: int

    def as_dict(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "filename": self.path.name,
            "size_bytes": self.size_bytes,
            "created_at": to_iso(self.created_at),
            "user_count": self.user_count,
        }


def _snapshot_database(db_path: Path, destination: Path) -> int:
    """Consistent copy of the DB using ``VACUUM INTO`` (no torn WAL state)."""
    if not db_path.exists():
        raise BackupError(f"There is no database at {db_path} to back up.")
    destination.unlink(missing_ok=True)
    try:
        with get_db(db_path) as conn:
            conn.execute("VACUUM INTO ?", (str(destination),))
            row = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
            return int(row["c"])
    except sqlite3.Error as exc:
        raise BackupError(f"Could not snapshot the database: {exc}") from exc


def create_backup(settings: Settings, label: str = "") -> BackupResult:
    """Write a ``.tar.gz`` into ``$DATA_DIR/backups`` and return its details."""
    settings.backups_dir.mkdir(parents=True, exist_ok=True)
    created = utcnow()
    stamp = created.strftime("%Y%m%d-%H%M%S")
    suffix = f"-{label}" if label else ""
    archive_path = settings.backups_dir / f"railgate-backup-{stamp}{suffix}.tar.gz"

    with tempfile.TemporaryDirectory(dir=str(settings.backups_dir)) as staging_name:
        staging = Path(staging_name)
        db_copy = staging / DB_NAME
        user_count = _snapshot_database(settings.db_path, db_copy)

        included_keys = []
        for name in KEY_FILES:
            source = settings.xray_data_dir / name
            if source.exists():
                (staging / name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
                included_keys.append(name)

        manifest = {
            "format_version": BACKUP_FORMAT_VERSION,
            "app_version": settings.app_version,
            "created_at": to_iso(created),
            "user_count": user_count,
            "includes": [DB_NAME, *included_keys],
            "reality_server_name": settings.reality_server_name,
            "reality_destination": settings.reality_destination,
            "xray_port": settings.xray_port,
        }
        (staging / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        try:
            with tarfile.open(archive_path, "w:gz") as archive:
                for item in sorted(staging.iterdir()):
                    archive.add(item, arcname=item.name)
        except OSError as exc:
            raise BackupError(f"Could not write the backup archive: {exc}") from exc

    try:
        archive_path.chmod(0o600)
        size = archive_path.stat().st_size
    except OSError as exc:  # pragma: no cover - defensive
        raise BackupError(f"Backup written but unreadable: {exc}") from exc

    return BackupResult(archive_path, size, created, user_count)


def list_backups(settings: Settings) -> list[dict[str, object]]:
    if not settings.backups_dir.exists():
        return []
    entries = []
    for path in sorted(settings.backups_dir.glob("railgate-backup-*.tar.gz"), reverse=True):
        try:
            stat = path.stat()
        except OSError:
            continue
        entries.append(
            {
                "filename": path.name,
                "path": str(path),
                "size_bytes": stat.st_size,
                "modified_at": to_iso(datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)),
            }
        )
    return entries


def inspect_backup(archive_path: Path) -> dict[str, object]:
    """Read a backup's manifest without touching live data."""
    if not archive_path.exists():
        raise BackupError(f"Backup file {archive_path} does not exist.")
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = archive.extractfile(MANIFEST_NAME)
            if member is None:
                raise BackupError("The archive has no manifest.json — it is not a RailGate backup.")
            return json.loads(member.read().decode("utf-8"))
    except (tarfile.TarError, OSError, json.JSONDecodeError, KeyError) as exc:
        raise BackupError(f"Could not read {archive_path}: {exc}") from exc


def _safe_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """Reject path traversal, absolute paths, links and unexpected files."""
    allowed = {MANIFEST_NAME, DB_NAME, *KEY_FILES}
    members = []
    for member in archive.getmembers():
        if not member.isfile():
            raise BackupError(f"Archive entry {member.name!r} is not a regular file.")
        name = Path(member.name).name
        if member.name != name or name not in allowed:
            raise BackupError(f"Archive entry {member.name!r} is not an expected backup file.")
        members.append(member)
    return members


def restore_backup(settings: Settings, archive_path: Path, *, confirm: bool = False) -> dict[str, object]:
    """Restore a backup over the live data.

    Refuses to run without ``confirm=True``. A safety backup of the current
    state is taken first, so a mistaken restore is itself recoverable.
    """
    manifest = inspect_backup(archive_path)
    if not confirm:
        raise BackupError(
            "Restore would overwrite the live database and REALITY keys. "
            "Re-run with explicit confirmation (`vpnctl restore <file> --confirm`)."
        )

    safety: BackupResult | None = None
    if settings.db_path.exists():
        try:
            safety = create_backup(settings, label="pre-restore")
        except BackupError:
            safety = None

    restored: list[str] = []
    try:
        with tarfile.open(archive_path, "r:gz") as archive:
            members = _safe_members(archive)
            with tempfile.TemporaryDirectory(dir=str(settings.data_dir)) as staging_name:
                staging = Path(staging_name)
                for member in members:
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        continue
                    (staging / Path(member.name).name).write_bytes(extracted.read())

                db_source = staging / DB_NAME
                if db_source.exists():
                    for suffix in ("-wal", "-shm"):
                        Path(str(settings.db_path) + suffix).unlink(missing_ok=True)
                    settings.db_path.write_bytes(db_source.read_bytes())
                    settings.db_path.chmod(0o600)
                    restored.append(DB_NAME)

                settings.xray_data_dir.mkdir(parents=True, exist_ok=True)
                for name in KEY_FILES:
                    source = staging / name
                    if not source.exists():
                        continue
                    target = settings.xray_data_dir / name
                    target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
                    target.chmod(0o600 if name == "reality-private-key" else 0o644)
                    restored.append(name)
    except (tarfile.TarError, OSError) as exc:
        raise BackupError(f"Restore failed: {exc}") from exc

    return {
        "restored": restored,
        "manifest": manifest,
        "safety_backup": str(safety.path) if safety else "",
    }
