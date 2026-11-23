"""
Backup Service

Handles backup creation, restoration, and management.
All operations use sudo and shell scripts for security.
"""

import asyncio
import json
import logging
import os
import re
import stat
import subprocess
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.db.session import SessionLocal
from app.models.backup import BackupJob, BackupStatus, BackupType
from app.schemas.backup import BackupResponse, BackupRestoreStatusResponse
from fastapi import HTTPException
from sqlalchemy.orm import Session

from config import ROOT_DIR

logger = logging.getLogger(__name__)

BACKUP_DIR = str(ROOT_DIR / "backups")
SCRIPTS_DIR = str(ROOT_DIR / "scripts" / "backup")
RUNNER_PATH = str(ROOT_DIR / "scripts" / "runner")
RECOVERY_EXPORT_DIR = Path(BACKUP_DIR) / "recovery"
RECOVERY_IMPORT_DIR = ROOT_DIR / "data" / "backup-key-imports"
BACKUP_IMPORT_DIR = ROOT_DIR / "data" / "backup-archive-imports"
RECOVERY_PACKAGE_SUFFIX = ".epikey"
RESTORE_STATUS_FILE = Path("/var/lib/easypi/restore-status/latest.json")
RESTORE_RESULT_STATUSES = {"running", "success", "failed-rolled-back", "failed"}
BACKUP_ARCHIVE_NAME_RE = re.compile(
    r"^(?:config|full|pre-restore)-\d{4}-\d{2}-\d{2}-\d{2}-\d{2}"
    r"(?:-\d{2})?\.(?:epibak|tar\.gz)$"
)
RECOVERY_PACKAGE_NAME_RE = re.compile(
    r"^(?P<prefix>recovery-key|import)-"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"\.epikey$"
)
RECOVERY_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

# Track running backup processes for cancellation
_running_processes: Dict[int, asyncio.subprocess.Process] = {}
_running_tasks: Dict[int, asyncio.Task[None]] = {}
_cancellation_requests: set[int] = set()


class BackupService:
    """Service for managing backups"""

    def __init__(self):
        self._ensure_backup_dir()

    def _ensure_backup_dir(self):
        """Ensure backup directory exists"""
        try:
            Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True)
            # chmod is handled by the service setup
        except Exception as e:
            logger.error(f"Failed to create backup directory: {e}")

    def _format_size(self, size_bytes: int) -> str:
        """Format size in bytes to human readable"""
        if size_bytes == 0:
            return "0 B"

        units = ["B", "KB", "MB", "GB", "TB"]
        unit_index = 0
        size = float(size_bytes)

        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1

        return f"{size:.1f} {units[unit_index]}"

    @staticmethod
    def reconcile_interrupted_backups(
        message: str = "Interrupted by backend restart",
    ) -> int:
        """Fail stale RUNNING records before this process accepts new work."""

        db: Session = SessionLocal()
        try:
            jobs = (
                db.query(BackupJob)
                .filter(BackupJob.status == BackupStatus.RUNNING)
                .all()
            )
            for job in jobs:
                job.status = BackupStatus.FAILED
                job.error_message = message
            if jobs:
                db.commit()
                logger.warning("Marked %s interrupted backup job(s) as failed", len(jobs))
            return len(jobs)
        finally:
            db.close()

    async def shutdown(self) -> None:
        """Stop tracked backup children before the API process exits."""

        tasks = [task for task in _running_tasks.values() if not task.done()]
        for task in tasks:
            # A user-requested cancellation may already be unwinding the task.
            # A second cancellation at that point could interrupt its child-process
            # cleanup, so only inject CancelledError once.
            if task.cancelling() == 0:
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Keep a second line of defence for a task that failed while terminating
        # its sudo child. Never declare shutdown cleanup complete while a tracked
        # helper is still alive.
        processes = [
            (backup_id, process)
            for backup_id, process in _running_processes.items()
            if process.returncode is None
        ]
        if processes:
            results = await asyncio.gather(
                *(
                    self._terminate_backup_process(process)
                    for _backup_id, process in processes
                ),
                return_exceptions=True,
            )
            for (backup_id, process), result in zip(processes, results):
                if isinstance(result, BaseException):
                    logger.error(
                        "Could not confirm backup child termination during shutdown: %s",
                        result,
                    )
                elif process.returncode is not None:
                    _running_processes.pop(backup_id, None)
        self.reconcile_interrupted_backups("Interrupted by backend shutdown")

    @staticmethod
    async def _terminate_backup_process(
        process: asyncio.subprocess.Process,
    ) -> None:
        """Terminate one backup helper and wait until the OS confirms its exit."""

        if process.returncode is not None:
            return
        try:
            process.terminate()
        except ProcessLookupError:
            # The process may have exited between returncode and terminate().
            pass

        try:
            await asyncio.wait_for(process.wait(), timeout=4.0)
            return
        except asyncio.TimeoutError:
            pass

        try:
            process.kill()
        except ProcessLookupError:
            pass
        await asyncio.wait_for(process.wait(), timeout=4.0)

    @staticmethod
    def resolve_backup_archive_path(file_path: str) -> Path:
        """Return one direct, trusted EasyPi backup archive without following links."""

        candidate = Path(file_path)
        if not candidate.is_absolute() or not BACKUP_ARCHIVE_NAME_RE.fullmatch(
            candidate.name
        ):
            raise ValueError("Invalid backup archive path")
        try:
            backup_root_path = Path(BACKUP_DIR)
            root_details = backup_root_path.lstat()
            details = candidate.lstat()
        except OSError as exc:
            raise FileNotFoundError("Backup archive was not found") from exc
        if (
            candidate.parent != backup_root_path
            or backup_root_path.is_symlink()
            or not stat.S_ISDIR(root_details.st_mode)
            or candidate.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or (
                os.name == "posix"
                and (
                    root_details.st_uid != 0
                    or root_details.st_mode & 0o022
                    or details.st_uid != 0
                    or details.st_mode & 0o022
                )
            )
        ):
            raise ValueError("Backup archive ownership, permissions, or path are unsafe")
        try:
            backup_root = backup_root_path.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
        except OSError as exc:
            raise FileNotFoundError("Backup archive was not found") from exc
        if resolved.parent != backup_root:
            raise ValueError("Backup archive ownership, permissions, or path are unsafe")
        return resolved

    def get_all_backups(self, db: Session) -> List[BackupResponse]:
        """Get all backups from database"""
        self._reconcile_backup_archives(db)
        backups = db.query(BackupJob).order_by(BackupJob.created_at.desc()).all()

        result = []
        for backup in backups:
            result.append(
                BackupResponse(
                    id=backup.id,
                    name=backup.name,
                    type=backup.type.value,
                    size=self._format_size(backup.size_bytes),
                    size_bytes=backup.size_bytes,
                    created_at=backup.created_at,
                    status=backup.status.value,
                    error_message=backup.error_message,
                )
            )

        return result

    def _reconcile_backup_archives(self, db: Session) -> None:
        """Register trusted archives left by an interrupted import."""

        known_paths = {
            str(path)
            for (path,) in db.query(BackupJob.file_path)
            .filter(BackupJob.file_path.isnot(None))
            .all()
        }
        added = False
        for candidate in sorted(Path(BACKUP_DIR).glob("*.epibak")):
            try:
                trusted = self.resolve_backup_archive_path(str(candidate))
            except (FileNotFoundError, ValueError):
                continue
            if str(trusted) in known_paths:
                continue
            backup_type = (
                BackupType.CONFIG
                if trusted.name.startswith("config-")
                else BackupType.FULL
            )
            db.add(
                BackupJob(
                    name=f"Imported {trusted.name}",
                    type=backup_type,
                    status=BackupStatus.COMPLETED,
                    file_path=str(trusted),
                    size_bytes=trusted.stat().st_size,
                )
            )
            known_paths.add(str(trusted))
            added = True
        if added:
            db.commit()

    @staticmethod
    def new_backup_import_path() -> Path:
        BACKUP_IMPORT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        details = BACKUP_IMPORT_DIR.lstat()
        if (
            BACKUP_IMPORT_DIR.is_symlink()
            or not stat.S_ISDIR(details.st_mode)
            or (os.name == "posix" and details.st_uid != os.geteuid())
        ):
            raise HTTPException(status_code=500, detail="Backup import directory is unsafe")
        os.chmod(BACKUP_IMPORT_DIR, 0o700)
        return BACKUP_IMPORT_DIR / f"import-{uuid.uuid4()}.epibak"

    async def import_backup_archive(self, upload_name: str, archive_name: str) -> Path:
        if not re.fullmatch(
            r"import-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[.]epibak",
            upload_name,
        ) or not BACKUP_ARCHIVE_NAME_RE.fullmatch(archive_name) or not archive_name.endswith(".epibak"):
            raise HTTPException(status_code=400, detail="Invalid backup archive name")
        process = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            RUNNER_PATH,
            "backup/import_archive.sh",
            upload_name,
            archive_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace")
            if "already exists" in detail:
                raise HTTPException(status_code=409, detail="Backup archive already exists")
            if "another backup or restore" in detail:
                raise HTTPException(status_code=409, detail="Another backup or restore is running")
            raise HTTPException(status_code=400, detail="Backup archive failed validation")
        markers = [
            line.split("=", 1)[1].strip()
            for line in stdout.decode("utf-8", errors="replace").splitlines()
            if line.startswith("BACKUP_FILE=")
        ]
        if len(markers) != 1:
            raise HTTPException(status_code=500, detail="Backup import returned an invalid response")
        try:
            return self.resolve_backup_archive_path(markers[0])
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(status_code=500, detail="Imported backup failed path validation") from exc

    @staticmethod
    def get_restore_status() -> BackupRestoreStatusResponse:
        """Read the small root-owned status record produced by detached restore."""

        path = RESTORE_STATUS_FILE
        try:
            link_details = path.lstat()
        except FileNotFoundError:
            return BackupRestoreStatusResponse(status="idle")
        except OSError as exc:
            logger.warning("Could not inspect restore status: %s", exc)
            raise HTTPException(
                status_code=503, detail="Restore status is unavailable"
            ) from exc

        if path.is_symlink() or not stat.S_ISREG(link_details.st_mode):
            raise HTTPException(status_code=503, detail="Restore status is unavailable")

        fd = -1
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(path, flags)
            details = os.fstat(fd)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_size > 4096
                or (
                    os.name == "posix"
                    and (details.st_uid != 0 or details.st_mode & 0o022)
                )
            ):
                raise ValueError("unsafe restore status file")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(4097)
            if len(raw) > 4096:
                raise ValueError("oversized restore status file")
            payload = json.loads(raw.decode("utf-8"))
            archive = payload.get("archive")
            status_value = payload.get("status")
            updated_at = payload.get("updated_at")
            if (
                not isinstance(archive, str)
                or not BACKUP_ARCHIVE_NAME_RE.fullmatch(archive)
                or status_value not in RESTORE_RESULT_STATUSES
                or not isinstance(updated_at, str)
            ):
                raise ValueError("invalid restore status payload")
            parsed_updated_at = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            if parsed_updated_at.tzinfo is None:
                raise ValueError("restore status timestamp has no timezone")
            return BackupRestoreStatusResponse(
                status=status_value,
                archive=archive,
                updated_at=parsed_updated_at,
            )
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as exc:
            logger.warning("Rejected restore status record: %s", exc)
            raise HTTPException(
                status_code=503, detail="Restore status is unavailable"
            ) from exc
        finally:
            if fd >= 0:
                os.close(fd)

    async def create_backup(
        self, backup_type: str, name: Optional[str], db: Session
    ) -> Dict[str, Any]:
        """Create a new backup"""
        # Validate type
        if backup_type not in ["full", "config"]:
            raise HTTPException(status_code=400, detail="Invalid backup type")

        # Generate default name if not provided
        if not name:
            type_names = {"full": "Full System Backup", "config": "Config Files Backup"}
            name = type_names[backup_type]

        # Create backup job in database
        backup_job = BackupJob(
            name=name, type=BackupType(backup_type), status=BackupStatus.RUNNING
        )
        db.add(backup_job)
        db.commit()
        db.refresh(backup_job)

        # Keep the task reachable so cancellation and graceful shutdown can
        # terminate the privileged child instead of merely changing the DB row.
        task = asyncio.create_task(
            self._run_backup_script(backup_job.id, backup_type)
        )
        _running_tasks[backup_job.id] = task
        task.add_done_callback(
            lambda _task, backup_id=backup_job.id: _running_tasks.pop(backup_id, None)
        )

        return {
            "id": backup_job.id,
            "status": "started",
            "message": f"Backup '{name}' started",
        }

    async def _run_backup_script(self, backup_id: int, backup_type: str):
        """Run backup script in background"""
        script_name = f"create_{backup_type}_backup.sh"
        script_path = os.path.join(SCRIPTS_DIR, script_name)
        process: asyncio.subprocess.Process | None = None

        # Use fresh DB session for background task (Dependency session may be closed)
        db: Session = SessionLocal()
        try:
            logger.info(f"Starting backup {backup_id}, script: {script_path}")

            # Run backup script with sudo
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-n",
                RUNNER_PATH,
                f"backup/{script_name}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Track process for potential cancellation
            _running_processes[backup_id] = process

            stdout, stderr = await process.communicate()

            # Remove from tracking
            _running_processes.pop(backup_id, None)

            # Decode output
            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")

            logger.info(f"Backup {backup_id} script output: {output}")
            if error_output:
                logger.warning(f"Backup {backup_id} stderr: {error_output}")

            if process.returncode == 0:
                markers = [
                    line.split("=", 1)[1].strip()
                    for line in output.splitlines()
                    if line.startswith("BACKUP_FILE=")
                ]
                if len(markers) != 1 or not markers[0]:
                    raise RuntimeError(
                        "Backup helper returned an invalid archive marker"
                    )

                try:
                    trusted_file = self.resolve_backup_archive_path(markers[0])
                except (FileNotFoundError, ValueError) as exc:
                    raise RuntimeError("Created backup failed path validation") from exc
                size_bytes = trusted_file.stat().st_size

                backup_job = (
                    db.query(BackupJob)
                    .filter(BackupJob.id == backup_id)
                    .first()
                )
                if backup_job:
                    backup_job.status = BackupStatus.COMPLETED
                    backup_job.file_path = str(trusted_file)
                    backup_job.size_bytes = size_bytes
                    db.commit()

                logger.info(
                    "Backup %s completed successfully: %s, size: %s",
                    backup_id,
                    trusted_file,
                    size_bytes,
                )
            else:
                raise Exception(
                    error_output or f"Script exited with code {process.returncode}"
                )

        except asyncio.CancelledError:
            termination_error: BaseException | None = None
            if process is not None and process.returncode is None:
                try:
                    await self._terminate_backup_process(process)
                except BaseException as exc:
                    termination_error = exc

            reason = (
                "Cancelled by user"
                if backup_id in _cancellation_requests
                else "Interrupted by backend shutdown"
            )
            if termination_error is not None:
                reason = f"{reason}; child process termination was not confirmed"
            backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()
            if backup_job:
                backup_job.status = BackupStatus.FAILED
                backup_job.error_message = reason
                db.commit()
            logger.info("Backup %s stopped: %s", backup_id, reason)
            if termination_error is not None:
                raise RuntimeError(
                    "Backup child process termination could not be confirmed"
                ) from termination_error
            raise
        except Exception as e:
            logger.error(f"Backup {backup_id} failed: {e}")

            # Remove from tracking
            _running_processes.pop(backup_id, None)

            # Update backup job with error
            backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()
            if backup_job:
                backup_job.status = BackupStatus.FAILED
                backup_job.error_message = str(e)[:1024]
                db.commit()
        finally:
            # Retain a live child in the process registry so shutdown can make a
            # final termination attempt and callers cannot receive false success.
            if process is None or process.returncode is not None:
                _running_processes.pop(backup_id, None)
            _cancellation_requests.discard(backup_id)
            db.close()

    async def restore_backup(self, backup_id: int, db: Session) -> Dict[str, str]:
        """Restore from backup"""
        backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()

        if not backup_job:
            raise HTTPException(status_code=404, detail="Backup not found")

        if backup_job.status != BackupStatus.COMPLETED:
            raise HTTPException(status_code=400, detail="Backup is not completed")

        if not backup_job.file_path:
            raise HTTPException(status_code=404, detail="Backup file path not set")

        try:
            real_path = str(self.resolve_backup_archive_path(backup_job.file_path))
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Backup file not found")
        except ValueError as exc:
            raise HTTPException(status_code=403, detail="Invalid backup file path") from exc

        # Both config and full archives share one scope-aware, validated
        # restore engine. There is intentionally no restore_full_backup.sh.
        script_name = "restore_config_backup.sh"
        script_path = os.path.join(SCRIPTS_DIR, script_name)

        try:
            # The root script only schedules the detached systemd restore and
            # returns quickly. Await that handshake so the API never reports a
            # false "started" result when sudo, runner, or systemd-run failed.
            await self._run_restore_script(script_path, real_path)
            return {
                "status": "started",
                "message": f"Restore of '{backup_job.name}' started",
            }
        except Exception as e:
            logger.error(f"Failed to start restore: {e}")
            raise HTTPException(
                status_code=500,
                detail="Restore could not be scheduled; inspect the EasyPi service logs",
            ) from e

    async def _run_restore_script(self, script_path: str, backup_file: str):
        """Run restore script in background"""
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-n",
                RUNNER_PATH,
                f"backup/{Path(script_path).name}",
                backup_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await process.communicate()

            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")
            if (
                process.returncode == 0
                and "RESTORE_SCHEDULED=easypi-restore.service" in output
            ):
                logger.info("Restore job scheduled from %s", backup_file)
                return
            detail = (error_output or output).strip()
            logger.error(
                "Restore could not be scheduled (rc=%s): %s",
                process.returncode,
                detail,
            )
            raise RuntimeError(
                detail[:1024]
                or f"Restore scheduler exited with code {process.returncode}"
            )
        except Exception as e:
            logger.error(f"Restore error: {e}")
            raise

    def delete_backup(self, backup_id: int, db: Session) -> Dict[str, str]:
        """Delete backup"""
        backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()

        if not backup_job:
            raise HTTPException(status_code=404, detail="Backup not found")

        # Delete file if exists
        if backup_job.file_path and os.path.lexists(backup_job.file_path):
            try:
                real_path = str(self.resolve_backup_archive_path(backup_job.file_path))
            except FileNotFoundError:
                real_path = ""
            except ValueError as exc:
                raise HTTPException(
                    status_code=403, detail="Invalid backup file path"
                ) from exc

            if real_path:
                try:
                    result = subprocess.run(
                        [
                            "sudo",
                            "-n",
                            RUNNER_PATH,
                            "backup/backup_file.sh",
                            "delete",
                            os.path.basename(real_path),
                        ],
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    if result.returncode != 0 or os.path.lexists(real_path):
                        raise RuntimeError("Privileged backup deletion did not complete")
                    logger.info(f"Deleted backup file: {real_path}")
                except (OSError, RuntimeError, subprocess.TimeoutExpired) as e:
                    logger.error(f"Failed to delete backup file: {e}")
                    raise HTTPException(
                        status_code=500,
                        detail="Backup file deletion failed; its record was preserved",
                    ) from e

        # Delete database record
        db.delete(backup_job)
        db.commit()

        return {"status": "deleted", "message": f"Backup '{backup_job.name}' deleted"}

    def get_backup_status(self, backup_id: int, db: Session) -> Dict[str, Any]:
        """Get backup status"""
        backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()

        if not backup_job:
            raise HTTPException(status_code=404, detail="Backup not found")

        return {
            "id": backup_job.id,
            "status": backup_job.status.value,
            "progress": 100 if backup_job.status == BackupStatus.COMPLETED else 0,
            "error_message": backup_job.error_message,
        }

    async def cancel_backup(self, backup_id: int, db: Session) -> Dict[str, str]:
        """Cancel a running backup"""
        backup_job = db.query(BackupJob).filter(BackupJob.id == backup_id).first()

        if not backup_job:
            raise HTTPException(status_code=404, detail="Backup not found")

        if backup_job.status != BackupStatus.RUNNING:
            raise HTTPException(status_code=400, detail="Backup is not running")

        task = _running_tasks.get(backup_id)
        if task is None or task.done():
            raise HTTPException(
                status_code=409,
                detail=(
                    "This backend process no longer tracks the backup; refresh its "
                    "status instead of assuming it was cancelled"
                ),
            )

        _cancellation_requests.add(backup_id)
        if not task.cancel():
            raise HTTPException(
                status_code=409,
                detail="Backup finished before cancellation could be requested",
            )
        try:
            results = await asyncio.wait_for(
                asyncio.gather(task, return_exceptions=True),
                timeout=10.0,
            )
        except asyncio.TimeoutError as exc:
            logger.error("Timed out terminating backup %s", backup_id)
            raise HTTPException(
                status_code=500,
                detail="Backup cancellation could not be confirmed",
            ) from exc

        task_result = results[0]
        process = _running_processes.get(backup_id)
        if (
            isinstance(task_result, BaseException)
            and not isinstance(task_result, asyncio.CancelledError)
        ) or (process is not None and process.returncode is None):
            logger.error(
                "Backup %s cancellation ended without confirmed child termination",
                backup_id,
            )
            raise HTTPException(
                status_code=500,
                detail="Backup cancellation could not be confirmed",
            )

        # Update status in database
        backup_job.status = BackupStatus.FAILED
        backup_job.error_message = "Cancelled by user"
        db.commit()

        logger.info(f"Backup {backup_id} cancelled by user")
        return {
            "status": "cancelled",
            "message": f"Backup '{backup_job.name}' cancelled",
        }

    async def _run_recovery_key_action(
        self,
        action: str,
        package_name: str,
        package_passphrase: str | None = None,
    ) -> str:
        if action not in {"export", "import", "delete"}:
            raise ValueError("invalid recovery-key action")
        match = RECOVERY_PACKAGE_NAME_RE.fullmatch(package_name)
        expected_prefix = "import" if action == "import" else "recovery-key"
        if match is None or match.group("prefix") != expected_prefix:
            raise ValueError("invalid recovery-key package name")
        if action == "delete" and package_passphrase is not None:
            raise ValueError("recovery-key deletion does not accept a passphrase")
        if action != "delete" and package_passphrase is None:
            raise ValueError("recovery-key action requires a passphrase")

        process = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            RUNNER_PATH,
            "backup/recovery_key.sh",
            action,
            package_name,
            stdin=(
                asyncio.subprocess.DEVNULL
                if package_passphrase is None
                else asyncio.subprocess.PIPE
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            secret_input = (
                None
                if package_passphrase is None
                else package_passphrase.encode("utf-8") + b"\n"
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(secret_input),
                timeout=45.0,
            )
        except asyncio.TimeoutError as exc:
            process.kill()
            await process.wait()
            raise HTTPException(
                status_code=504,
                detail="Recovery-key operation timed out",
            ) from exc
        if process.returncode != 0:
            detail = stderr.decode("utf-8", errors="replace").strip()
            logger.warning("Recovery-key %s failed: %s", action, detail[:500])
            raise HTTPException(
                status_code=400 if action == "import" else 500,
                detail=(
                    "Recovery-key package could not be processed"
                    if action == "import"
                    else "Recovery-key operation failed"
                ),
            )
        return stdout.decode("utf-8", errors="replace")

    async def export_recovery_key(self, package_passphrase: str) -> Path:
        package_name = f"recovery-key-{uuid.uuid4()}{RECOVERY_PACKAGE_SUFFIX}"
        try:
            await self._run_recovery_key_action(
                "export", package_name, package_passphrase
            )
            candidate = RECOVERY_EXPORT_DIR / package_name
            resolved = candidate.resolve(strict=True)
            export_root = RECOVERY_EXPORT_DIR.resolve(strict=True)
            details = candidate.lstat()
            if (
                resolved.parent != export_root
                or candidate.is_symlink()
                or not stat.S_ISREG(details.st_mode)
                or (os.name == "posix" and details.st_uid != 0)
                or (os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o640)
            ):
                raise HTTPException(
                    status_code=500,
                    detail="Recovery-key export path failed validation",
                )
            return resolved
        except Exception:
            await self.cleanup_recovery_export(package_name)
            raise

    async def import_recovery_key(
        self,
        package_name: str,
        package_passphrase: str,
    ) -> tuple[str, bool]:
        output = await self._run_recovery_key_action(
            "import", package_name, package_passphrase
        )
        fingerprints = [
            line.split("=", 1)[1]
            for line in output.splitlines()
            if line.startswith("RECOVERY_KEY_FINGERPRINT=")
        ]
        states = [
            line.split("=", 1)[1]
            for line in output.splitlines()
            if line.startswith("RECOVERY_KEY_IMPORTED=")
        ]
        if (
            len(fingerprints) != 1
            or not RECOVERY_FINGERPRINT_RE.fullmatch(fingerprints[0])
            or len(states) != 1
            or states[0] not in {"YES", "ALREADY_PRESENT"}
        ):
            logger.error("Recovery-key helper returned an invalid success response")
            raise HTTPException(
                status_code=500,
                detail="Recovery-key operation returned an invalid response",
            )
        return fingerprints[0], states[0] == "YES"

    async def cleanup_recovery_export(self, package_name: str) -> None:
        """Remove an exported key through the root-owned runner boundary."""

        try:
            await self._run_recovery_key_action("delete", package_name)
        except Exception as exc:
            logger.error("Could not remove recovery-key export %s: %s", package_name, exc)

    @staticmethod
    def new_recovery_import_path() -> Path:
        RECOVERY_IMPORT_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
        if RECOVERY_IMPORT_DIR.is_symlink() or not RECOVERY_IMPORT_DIR.is_dir():
            raise HTTPException(
                status_code=500,
                detail="Recovery-key import directory is unsafe",
            )
        os.chmod(RECOVERY_IMPORT_DIR, 0o700)
        return RECOVERY_IMPORT_DIR / f"import-{uuid.uuid4()}{RECOVERY_PACKAGE_SUFFIX}"
