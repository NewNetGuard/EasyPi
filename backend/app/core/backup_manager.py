from __future__ import annotations

import os
import re
import shutil
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Iterable, List

from app.core.paths import get_easypi_root

BACKUP_NAME_RE = re.compile(r"^backup_[0-9]{8}_[0-9]{4}\.tar\.gz$")
CRON_FIELD_RE = re.compile(r"^[0-9*/,-]+$")
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_SIZE = 10 * 1024 * 1024 * 1024


class BackupManager:
    """Manage system backups."""

    def __init__(self, default_destination: str = "data/backups") -> None:
        self.repo_root = get_easypi_root()
        self.destination = (self.repo_root / default_destination).resolve()
        self.destination.mkdir(parents=True, exist_ok=True)

    def create_backup(self, targets: list[str], destination: str | None = None) -> str:
        if not targets:
            raise ValueError("No targets provided for backup.")

        dest = self._resolve_destination(destination)
        dest.mkdir(parents=True, exist_ok=True)

        resolved_targets = self._validate_targets(targets)
        total_size = sum(self._path_size(target) for target in resolved_targets)
        self._ensure_disk_space(dest, total_size)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        archive_path = dest / f"backup_{timestamp}.tar.gz"

        try:
            with tarfile.open(archive_path, "w:gz") as archive:
                for target in resolved_targets:
                    archive.add(target, arcname=target.name)
        except (OSError, tarfile.TarError) as exc:
            archive_path.unlink(missing_ok=True)
            raise RuntimeError(f"Failed to create backup: {exc}") from exc

        return str(archive_path)

    def list_backups(self, destination: str | None = None) -> list[dict]:
        dest = self._resolve_destination(destination)
        if not dest.exists():
            return []

        backups: list[dict] = []
        for file in dest.glob("backup_*.tar.gz"):
            try:
                stat = file.stat()
            except OSError:
                continue
            backups.append(
                {
                    "name": file.name,
                    "path": str(file),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                }
            )
        backups.sort(key=lambda item: item["modified"], reverse=True)
        return backups

    def restore_backup(self, filename: str, destination: str | None = None) -> str:
        dest = self._resolve_destination(destination)
        if Path(filename).name != filename or not BACKUP_NAME_RE.fullmatch(filename):
            raise ValueError("Invalid backup filename")
        archive_path = dest / filename
        try:
            archive_path.lstat()
        except FileNotFoundError:
            raise FileNotFoundError(f"Backup archive not found: {archive_path}")
        if not archive_path.is_file() or archive_path.is_symlink():
            raise ValueError("Backup archive must be a regular file")

        restore_root = (
            self.repo_root / "data" / "restored" / filename.removesuffix(".tar.gz")
        )
        restore_root.mkdir(parents=True, mode=0o700, exist_ok=False)

        try:
            with tarfile.open(archive_path, "r:gz") as archive:
                members = archive.getmembers()
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise ValueError("Backup archive has too many members")
                if sum(max(member.size, 0) for member in members) > MAX_ARCHIVE_SIZE:
                    raise ValueError("Backup archive is too large")
                for member in members:
                    self._restore_member(archive, member, restore_root)
        except (OSError, tarfile.TarError) as exc:
            raise RuntimeError(f"Failed to restore backup: {exc}") from exc

        return str(restore_root)

    def schedule_backup(self, cron: str) -> None:
        cron = cron.strip()
        fields = cron.split()
        if len(fields) != 5 or any(
            not CRON_FIELD_RE.fullmatch(field) for field in fields
        ):
            raise ValueError("Cron must contain five numeric schedule fields")

        script_path = self.repo_root / "scripts" / "backup" / "create_backup.sh"
        if not script_path.exists():
            raise FileNotFoundError(f"Backup script not found: {script_path}")

        command = f"{cron} bash {script_path} >/dev/null 2>&1"

        try:
            current = subprocess.run(
                ["crontab", "-l"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        except FileNotFoundError as exc:
            raise RuntimeError("crontab command not available.") from exc

        existing = current.stdout if current.returncode == 0 else ""
        if "no crontab for" in current.stderr.lower():
            existing = ""

        if command in existing:
            return

        new_entries = existing.rstrip()
        if new_entries:
            new_entries += "\n"
        new_entries += "# EasyPi backup job\n" + command + "\n"

        result = subprocess.run(
            ["crontab", "-"],
            input=new_entries,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to install cron job.")

    def _resolve_destination(self, destination: str | None) -> Path:
        if destination:
            path = Path(destination)
            if not path.is_absolute():
                path = (self.repo_root / path).resolve()
            else:
                path = path.resolve()
            if os.path.commonpath((str(self.destination), str(path))) != str(
                self.destination
            ):
                raise ValueError("Backup destination must stay under data/backups")
            return path
        return self.destination

    def _validate_targets(self, targets: Iterable[str]) -> List[Path]:
        resolved: List[Path] = []
        for target in targets:
            path = Path(target).expanduser()
            if not path.is_absolute():
                path = (self.repo_root / path).resolve()
            else:
                path = path.resolve()
            if os.path.commonpath((str(self.repo_root), str(path))) != str(
                self.repo_root
            ):
                raise ValueError("Backup targets must stay inside the EasyPi root")
            if not path.exists():
                raise FileNotFoundError(f"Backup target not found: {path}")
            resolved.append(path)
        return resolved

    def _restore_member(
        self,
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
        restore_root: Path,
    ) -> None:
        raw_name = member.name
        while raw_name.startswith("./"):
            raw_name = raw_name[2:]
        rel = PurePosixPath(raw_name)
        if (
            not raw_name
            or member.name.startswith("/")
            or ".." in rel.parts
            or member.issym()
            or member.islnk()
            or member.isdev()
            or not (member.isdir() or member.isfile())
        ):
            raise ValueError(f"Unsafe backup member: {member.name}")

        target = restore_root.joinpath(*rel.parts)
        target.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        if member.isdir():
            target.mkdir(mode=0o700, exist_ok=True)
            return

        source = archive.extractfile(member)
        if source is None:
            raise ValueError(f"Cannot read backup member: {member.name}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(target, flags, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
        finally:
            os.close(fd)
            source.close()

    def _path_size(self, path: Path) -> int:
        if path.is_file():
            return path.stat().st_size
        total = 0
        for child in path.rglob("*"):
            if child.is_file():
                try:
                    total += child.stat().st_size
                except OSError:
                    continue
        return total

    def _ensure_disk_space(self, destination: Path, required_bytes: int) -> None:
        usage = shutil.disk_usage(destination)
        if usage.free < required_bytes:
            raise OSError("Not enough disk space to create backup.")


__all__ = ["BackupManager"]
