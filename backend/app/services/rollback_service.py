from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException

from app.core.paths import get_data_dir, get_easypi_root, get_scripts_dir
from app.schemas.rollback import (
    RollbackActionResponse,
    RollbackCreateRequest,
    RollbackListResponse,
    RollbackSnapshotRecord,
    RollbackSummary,
)


_SNAPSHOT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
_RESTORE_ARCHIVE_RE = re.compile(
    r"^(?:config|full|pre-restore)-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}"
    r"(?:-\d{2})?\.(?:tar\.gz|epibak)$"
)
_RESTORE_RESULT_STATUSES = {"running", "success", "failed", "failed-rolled-back"}


class _RollbackOperationBusy(Exception):
    """Raised when another process already owns the rollback operation lease."""


class _RollbackOperationLease:
    """Secure inter-process lease held for the complete rollback operation."""

    def __init__(self, path: Path, operation: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        self.fd = os.open(path, flags, 0o600)
        self._unlock = lambda: None
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(self.fd, 0o600)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode):
                raise RuntimeError("Rollback operation lock is not a regular file")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise RuntimeError("Rollback operation lock has an unexpected owner")

            if os.name == "nt":
                import msvcrt

                if info.st_size == 0:
                    os.write(self.fd, b"\0")
                    os.fsync(self.fd)
                os.lseek(self.fd, 0, os.SEEK_SET)
                try:
                    msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise _RollbackOperationBusy from exc
                self._unlock = lambda: msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                try:
                    fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise _RollbackOperationBusy from exc
                self._unlock = lambda: fcntl.flock(self.fd, fcntl.LOCK_UN)

            payload = json.dumps(
                {
                    "pid": os.getpid(),
                    "operation": operation,
                    "started_at": int(time.time()),
                }
            ).encode("utf-8")
            os.ftruncate(self.fd, 0)
            os.lseek(self.fd, 0, os.SEEK_SET)
            os.write(self.fd, payload)
            os.fsync(self.fd)
        except Exception:
            os.close(self.fd)
            self.fd = -1
            raise

    def close(self) -> None:
        if self.fd < 0:
            return
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            self._unlock()
        finally:
            os.close(self.fd)
            self.fd = -1


class RollbackService:
    """Manage safe config snapshots and restoration."""

    def __init__(
        self,
        *,
        metadata_dir: Path | None = None,
        scripts_dir: Path | None = None,
        backup_dir: Path | None = None,
        restore_status_file: Path | None = None,
    ) -> None:
        self.root_dir = get_easypi_root()
        self.metadata_dir = metadata_dir or (get_data_dir() / "rollback")
        self.scripts_dir = scripts_dir or (get_scripts_dir() / "backup")
        self.backup_dir = backup_dir or (self.root_dir / "backups")
        self.runner = get_scripts_dir() / "runner"
        self.restore_status_file = restore_status_file or Path(
            "/var/lib/easypi/restore-status/latest.json"
        )
        self.metadata_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        try:
            self.metadata_dir.chmod(0o750)
            self.backup_dir.chmod(0o750)
        except OSError:
            pass
        self.operation_lock_path = self.metadata_dir / ".operation.lock"

    def list_snapshots(self, limit: int = 50) -> RollbackListResponse:
        self._reconcile_restore_results()
        safe_limit = max(1, min(limit, 200))
        snapshots = sorted(
            self._load_all_snapshots(),
            key=lambda record: self._parse_iso(record.created_at),
            reverse=True,
        )[:safe_limit]
        summary = RollbackSummary()
        for snapshot in snapshots:
            summary.total += 1
            if snapshot.status == "ready":
                summary.ready += 1
            elif snapshot.status in {"creating", "restoring"}:
                summary.active += 1
            else:
                summary.failed += 1

        return RollbackListResponse(
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            snapshots=snapshots,
        )

    def get_snapshot(self, snapshot_id: str) -> RollbackSnapshotRecord:
        self._reconcile_restore_results()
        return self._get_snapshot(snapshot_id)

    async def create_snapshot(self, payload: RollbackCreateRequest) -> RollbackActionResponse:
        lease = self._acquire_operation_lease("create")
        snapshot_id: str | None = None
        scheduled = False
        try:
            snapshot_id = self._new_snapshot_id()
            created_at = datetime.now(timezone.utc).isoformat()
            record = RollbackSnapshotRecord(
                snapshot_id=snapshot_id,
                name=payload.name or "Manual safe snapshot",
                reason=payload.reason,
                status="creating",
                created_at=created_at,
                updated_at=created_at,
            )
            self._save_snapshot(record)
            asyncio.create_task(self._run_create_snapshot(snapshot_id, lease))
            scheduled = True
        except Exception:
            if snapshot_id:
                self._metadata_path(snapshot_id).unlink(missing_ok=True)
            raise
        finally:
            if not scheduled:
                lease.close()
        return RollbackActionResponse(
            snapshot_id=snapshot_id,
            status="started",
            message=f"Safe snapshot '{record.name}' started",
        )

    async def restore_snapshot(self, snapshot_id: str) -> RollbackActionResponse:
        lease = self._acquire_operation_lease("restore")
        scheduled = False
        try:
            self._reconcile_restore_results()
            record = self._get_snapshot(snapshot_id)
            if record.status in {"creating", "restoring"}:
                raise HTTPException(status_code=400, detail="Snapshot is still busy")
            if not record.archive_path:
                raise HTTPException(status_code=404, detail="Snapshot archive path is missing")

            archive_path = os.path.realpath(record.archive_path)
            real_backup_dir = os.path.realpath(str(self.backup_dir))
            if not archive_path.startswith(real_backup_dir + os.sep):
                raise HTTPException(status_code=403, detail="Invalid snapshot archive path")

            if not os.path.isfile(archive_path) or os.path.islink(record.archive_path):
                raise HTTPException(status_code=404, detail="Snapshot archive not found on disk")

            record.status = "restoring"
            record.updated_at = datetime.now(timezone.utc).isoformat()
            record.error_message = None
            self._save_snapshot(record)
            try:
                asyncio.create_task(self._run_restore_snapshot(snapshot_id, archive_path, lease))
            except Exception:
                record.status = "ready"
                record.updated_at = datetime.now(timezone.utc).isoformat()
                record.error_message = "Failed to schedule snapshot restore"
                self._save_snapshot(record)
                raise
            scheduled = True
        finally:
            if not scheduled:
                lease.close()
        return RollbackActionResponse(
            snapshot_id=snapshot_id,
            status="started",
            message=f"Restore of '{record.name}' started",
        )

    def delete_snapshot(self, snapshot_id: str) -> RollbackActionResponse:
        lease = self._acquire_operation_lease("delete")
        try:
            record = self._get_snapshot(snapshot_id)
            if record.status in {"creating", "restoring"}:
                raise HTTPException(status_code=400, detail="Snapshot is busy and cannot be deleted")

            if record.archive_path:
                archive_path = os.path.realpath(record.archive_path)
                real_backup_dir = os.path.realpath(str(self.backup_dir))
                if not archive_path.startswith(real_backup_dir + os.sep):
                    raise HTTPException(status_code=403, detail="Invalid snapshot archive path")
                if os.path.islink(record.archive_path):
                    raise HTTPException(status_code=403, detail="Snapshot archive must not be a symbolic link")
                if os.path.exists(archive_path):
                    try:
                        result = subprocess.run(
                            [
                                "sudo", "-n", str(self.runner), "backup/backup_file.sh",
                                "delete", os.path.basename(archive_path),
                            ],
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=False,
                        )
                    except (OSError, subprocess.TimeoutExpired) as exc:
                        raise HTTPException(
                            status_code=500,
                            detail="Snapshot archive deletion failed; metadata was preserved",
                        ) from exc
                    if result.returncode != 0 or os.path.exists(archive_path):
                        raise HTTPException(
                            status_code=500,
                            detail="Snapshot archive deletion failed; metadata was preserved",
                        )

            self._metadata_path(snapshot_id).unlink(missing_ok=True)
            return RollbackActionResponse(
                snapshot_id=snapshot_id,
                status="deleted",
                message=f"Snapshot '{record.name}' deleted",
            )
        finally:
            lease.close()

    def prepare_download(self, snapshot_id: str) -> tuple[str, str]:
        lease = self._acquire_operation_lease("download")
        temp_file: str | None = None
        try:
            record = self._get_snapshot(snapshot_id)
            if not record.archive_path:
                raise HTTPException(status_code=404, detail="Snapshot archive path is missing")

            archive_path = os.path.realpath(record.archive_path)
            real_backup_dir = os.path.realpath(str(self.backup_dir))
            if not archive_path.startswith(real_backup_dir + os.sep):
                raise HTTPException(status_code=403, detail="Invalid snapshot archive path")

            if not os.path.isfile(archive_path) or os.path.islink(record.archive_path):
                raise HTTPException(status_code=404, detail="Snapshot archive not found on disk")

            filename = os.path.basename(archive_path)
            suffix = f"_{filename}" if filename else ".tar.gz"
            source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            source_fd = os.open(archive_path, source_flags)
            with os.fdopen(source_fd, "rb") as source, tempfile.NamedTemporaryFile(
                prefix=f"rollback_{snapshot_id}_",
                suffix=suffix,
                delete=False,
            ) as tmp:
                temp_file = tmp.name
                source_info = os.fstat(source.fileno())
                if not stat.S_ISREG(source_info.st_mode) or (
                    os.name != "nt" and source_info.st_mode & 0o022
                ):
                    raise HTTPException(status_code=403, detail="Snapshot archive permissions are unsafe")
                shutil.copyfileobj(source, tmp)
                tmp.flush()
                os.fsync(tmp.fileno())
                if hasattr(os, "fchmod"):
                    os.fchmod(tmp.fileno(), 0o600)
                else:
                    os.chmod(temp_file, 0o600)
        except Exception as exc:
            if temp_file:
                try:
                    os.unlink(temp_file)
                except OSError:
                    pass
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(status_code=500, detail=f"Failed to prepare snapshot archive: {exc}") from exc
        finally:
            lease.close()
        return temp_file, filename

    async def _run_create_snapshot(self, snapshot_id: str, lease: _RollbackOperationLease) -> None:
        record: RollbackSnapshotRecord | None = None
        try:
            record = self._get_snapshot(snapshot_id)
            script_path = self.scripts_dir / "create_config_backup.sh"
            process = await asyncio.create_subprocess_exec(
                "sudo", "-n", str(self.runner), f"backup/{script_path.name}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")
            if process.returncode != 0:
                combined = "\n".join(part for part in [output.strip(), error_output.strip()] if part.strip())
                raise RuntimeError(combined or f"Script exited with code {process.returncode}")

            archive_path = self._extract_backup_file(output, error_output)
            if not archive_path:
                raise RuntimeError("Could not determine created snapshot archive")

            real_path = os.path.realpath(archive_path)
            real_backup_dir = os.path.realpath(str(self.backup_dir))
            if not real_path.startswith(real_backup_dir + os.sep):
                raise RuntimeError("Created snapshot archive path is outside the backup directory")

            if not os.path.isfile(real_path):
                raise RuntimeError("Created snapshot archive was not found on disk")

            record.status = "ready"
            record.archive_path = real_path
            record.size_bytes = os.path.getsize(real_path)
            record.updated_at = datetime.now(timezone.utc).isoformat()
            record.error_message = None
            self._save_snapshot(record)
        except Exception as exc:
            if record is not None:
                record.status = "failed"
                record.updated_at = datetime.now(timezone.utc).isoformat()
                record.error_message = str(exc)[:1024]
                self._save_snapshot(record)
        finally:
            lease.close()

    async def _run_restore_snapshot(
        self,
        snapshot_id: str,
        archive_path: str,
        lease: _RollbackOperationLease,
    ) -> None:
        record: RollbackSnapshotRecord | None = None
        try:
            record = self._get_snapshot(snapshot_id)
            script_path = self.scripts_dir / "restore_config_backup.sh"
            process = await asyncio.create_subprocess_exec(
                "sudo", "-n", str(self.runner), f"backup/{script_path.name}",
                archive_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")
            combined = "\n".join(part for part in [output.strip(), error_output.strip()] if part.strip())

            if process.returncode != 0 or "RESTORE_SCHEDULED=easypi-restore.service" not in output:
                raise RuntimeError(combined or f"Restore exited with code {process.returncode}")

            record.status = "restoring"
            record.updated_at = datetime.now(timezone.utc).isoformat()
            record.last_restore_status = "running"
            record.error_message = None
            self._save_snapshot(record)
        except Exception as exc:
            if record is not None:
                record.status = "restore-failed"
                record.updated_at = datetime.now(timezone.utc).isoformat()
                record.last_restore_status = "failed"
                record.error_message = str(exc)[:1024]
                self._save_snapshot(record)
        finally:
            lease.close()

    def _acquire_operation_lease(self, operation: str) -> _RollbackOperationLease:
        try:
            return _RollbackOperationLease(self.operation_lock_path, operation)
        except _RollbackOperationBusy as exc:
            raise HTTPException(
                status_code=409,
                detail="Another Rollback Center operation is already running",
            ) from exc

    def _load_all_snapshots(self) -> list[RollbackSnapshotRecord]:
        records: list[RollbackSnapshotRecord] = []
        for path in self.metadata_dir.glob("*.json"):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
                records.append(RollbackSnapshotRecord.model_validate(payload))
            except Exception:
                continue
        return records

    def _read_restore_result(self) -> dict[str, str] | None:
        path = self.restore_status_file
        try:
            details = path.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size > 4096
                or details.st_mode & 0o022
                or (os.name == "posix" and details.st_uid != 0)
            ):
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None
        archive = payload.get("archive")
        status_value = payload.get("status")
        updated_at = payload.get("updated_at")
        if (
            not isinstance(archive, str)
            or not _RESTORE_ARCHIVE_RE.fullmatch(archive)
            or status_value not in _RESTORE_RESULT_STATUSES
            or not isinstance(updated_at, str)
        ):
            return None
        try:
            datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
        except ValueError:
            return None
        return {"archive": archive, "status": status_value, "updated_at": updated_at}

    @staticmethod
    def _restore_unit_active() -> bool:
        if os.name == "nt" or shutil.which("systemctl") is None:
            return False
        try:
            result = subprocess.run(
                ["systemctl", "is-active", "--quiet", "easypi-restore.service"],
                capture_output=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def _reconcile_restore_results(self) -> None:
        restoring = [
            record for record in self._load_all_snapshots() if record.status == "restoring"
        ]
        if not restoring:
            return

        result = self._read_restore_result()
        unit_active: bool | None = None
        for record in restoring:
            archive_name = os.path.basename(record.archive_path or "")
            matching = result if result and result["archive"] == archive_name else None
            status_value = matching["status"] if matching else None
            if status_value == "success":
                record.status = "ready"
                record.updated_at = matching["updated_at"]
                record.last_restored_at = matching["updated_at"]
                record.last_restore_status = "success"
                record.error_message = None
                self._save_snapshot(record)
                continue
            if status_value in {"failed", "failed-rolled-back"}:
                record.status = "restore-failed"
                record.updated_at = matching["updated_at"]
                record.last_restore_status = status_value
                record.error_message = (
                    "Restore failed and the pre-restore snapshot was reapplied"
                    if status_value == "failed-rolled-back"
                    else "Restore failed; inspect easypi-restore.service logs"
                )
                self._save_snapshot(record)
                continue

            if unit_active is None:
                unit_active = self._restore_unit_active()
            if unit_active:
                continue
            record.status = "restore-failed"
            record.updated_at = datetime.now(timezone.utc).isoformat()
            record.last_restore_status = "interrupted"
            record.error_message = "Restore did not publish a final result"
            self._save_snapshot(record)

    def _get_snapshot(self, snapshot_id: str) -> RollbackSnapshotRecord:
        path = self._metadata_path(snapshot_id)
        if not path.exists():
            raise HTTPException(status_code=404, detail="Snapshot not found")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            return RollbackSnapshotRecord.model_validate(payload)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Snapshot metadata is unreadable: {exc}") from exc

    def _save_snapshot(self, record: RollbackSnapshotRecord) -> None:
        path = self._metadata_path(record.snapshot_id)
        payload = json.dumps(record.model_dump(mode="json"), ensure_ascii=True, indent=2)
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{record.snapshot_id}.",
            suffix=".tmp",
            dir=self.metadata_dir,
        )
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o640)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
            os.chmod(path, 0o640)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temp_name)
            except FileNotFoundError:
                pass

    def _metadata_path(self, snapshot_id: str) -> Path:
        if not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise HTTPException(status_code=400, detail="Invalid snapshot identifier")
        return self.metadata_dir / f"{snapshot_id}.json"

    def _new_snapshot_id(self) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        return f"rollback-{stamp}"

    def _extract_backup_file(self, stdout_text: str, stderr_text: str) -> str | None:
        for text in (stdout_text, stderr_text):
            for line in text.splitlines():
                if line.startswith("BACKUP_FILE="):
                    return line.split("=", 1)[1].strip()
        return None

    def _parse_iso(self, value: str) -> float:
        try:
            return datetime.fromisoformat(value).timestamp()
        except ValueError:
            return 0.0


rollback_service = RollbackService()
