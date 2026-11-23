from __future__ import annotations

import json
import logging
import os
import re
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy.orm import Session

from app.core.paths import get_data_dir, get_privileged_logs_dir
from app.core.installer import ALLOWED_INSTALL_SCRIPTS, JOB_ID_RE
from app.models.backup import BackupJob, BackupStatus
from app.schemas.jobs import JobRecord, JobsResponse, JobSummary
from app.services.operation_event_service import OperationEventService
from app.services.rollback_service import RollbackService

logger = logging.getLogger(__name__)

_INSTALLER_FINISHED_RE = re.compile(r"finished \(exit=(\d+)\)")
_PROGRESS_RE = re.compile(r"(\d{1,3}(?:\.\d+)?)%")
_QUEUED_GRACE_SECONDS = 120
_MAX_INSTALLER_JOB_BYTES = 64 * 1024


@dataclass
class _DatedJob:
    sort_ts: float
    record: JobRecord


class JobsService:
    def __init__(
        self,
        installer_dir: Path | None = None,
        logs_dir: Path | None = None,
        rollback_service: RollbackService | None = None,
        operation_event_service: OperationEventService | None = None,
    ) -> None:
        self.installer_dir = installer_dir or (get_data_dir() / "installer")
        self.logs_dir = logs_dir or get_privileged_logs_dir()
        self.rollback_service = rollback_service or RollbackService()
        self.operation_event_service = operation_event_service or OperationEventService()

    def list_jobs(self, db: Session, limit: int = 40) -> JobsResponse:
        safe_limit = max(1, min(limit, 200))
        combined = [
            *self._collect_installer_jobs(limit=safe_limit),
            *self._collect_backup_jobs(db, limit=safe_limit),
            *self._collect_rollback_jobs(limit=safe_limit),
            *self._collect_operation_jobs(limit=safe_limit),
        ]
        combined.sort(key=lambda item: item.sort_ts, reverse=True)
        jobs = [item.record for item in combined[:safe_limit]]
        summary = self._build_summary(jobs)

        return JobsResponse(
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=summary,
            jobs=jobs,
        )

    def _collect_installer_jobs(self, limit: int) -> list[_DatedJob]:
        if not self.installer_dir.exists():
            return []

        candidates: list[tuple[float, Path]] = []
        for job_path in self.installer_dir.glob("*.json"):
            if not JOB_ID_RE.fullmatch(job_path.stem):
                continue
            try:
                info = job_path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                continue
            if info.st_size > _MAX_INSTALLER_JOB_BYTES:
                continue
            candidates.append((info.st_mtime, job_path))

        dated_jobs: list[_DatedJob] = []
        for job_mtime, job_path in sorted(candidates, reverse=True)[:limit]:
            job_id = job_path.stem
            payload = self._read_job_payload(job_path)
            if not payload:
                continue

            script = str(payload.get("script") or "").strip()
            args = [str(arg) for arg in payload.get("args") or []]
            title, subtitle, route = self._describe_installer_job(script, args)

            started_ts = self._coerce_timestamp(payload.get("created_at_epoch")) or job_mtime
            log_path = self.logs_dir / f"installer-{job_id}.log"
            log_mtime = self._regular_file_mtime(log_path)
            updated_ts = max(started_ts, log_mtime or started_ts)
            log_tail = self._read_log_tail(log_path, max_bytes=8192)
            status, progress, message = self._derive_installer_status(started_ts, log_path, log_tail)

            dated_jobs.append(
                _DatedJob(
                    sort_ts=started_ts,
                    record=JobRecord(
                        job_id=job_id,
                        source="installer",
                        status=status,
                        title=title,
                        subtitle=subtitle,
                        route=route,
                        started_at=self._isoformat(started_ts),
                        updated_at=self._isoformat(updated_ts),
                        progress=progress,
                        message=message,
                    ),
                )
            )

        return dated_jobs

    def _collect_backup_jobs(self, db: Session, limit: int) -> list[_DatedJob]:
        backups = (
            db.query(BackupJob)
            .order_by(BackupJob.created_at.desc(), BackupJob.id.desc())
            .limit(limit)
            .all()
        )
        dated_jobs: list[_DatedJob] = []

        for backup in backups:
            started_dt = self._normalize_datetime(getattr(backup, "created_at", None))
            started_ts = started_dt.timestamp()
            status = self._map_backup_status(backup)
            message = self._build_backup_message(backup, status)
            progress = 100 if status == "success" else None

            dated_jobs.append(
                _DatedJob(
                    sort_ts=started_ts,
                    record=JobRecord(
                        job_id=f"backup-{backup.id}",
                        source="backup",
                        status=status,
                        title=str(getattr(backup, "name", "") or f"Backup #{backup.id}"),
                        subtitle=f"System Backup · {getattr(getattr(backup, 'type', None), 'value', getattr(backup, 'type', 'unknown'))}",
                        route="/backup",
                        started_at=started_dt.isoformat(),
                        updated_at=started_dt.isoformat(),
                        progress=progress,
                        message=message,
                    ),
                )
            )

        return dated_jobs

    def _collect_rollback_jobs(self, limit: int) -> list[_DatedJob]:
        snapshots = self.rollback_service.list_snapshots(limit=limit).snapshots
        dated_jobs: list[_DatedJob] = []

        for snapshot in snapshots:
            started_ts = self._parse_iso_timestamp(snapshot.created_at)
            updated_ts = self._parse_iso_timestamp(snapshot.updated_at) or started_ts
            status = self._map_rollback_status(snapshot.status)
            message = self._build_rollback_message(snapshot.status, snapshot.reason, snapshot.error_message)
            progress = 100 if status == "success" else None

            dated_jobs.append(
                _DatedJob(
                    sort_ts=updated_ts or started_ts,
                    record=JobRecord(
                        job_id=snapshot.snapshot_id,
                        source="rollback",
                        status=status,
                        title=snapshot.name,
                        subtitle="Rollback Center · Safe snapshot",
                        route="/rollback",
                        started_at=snapshot.created_at,
                        updated_at=snapshot.updated_at,
                        progress=progress,
                        message=message,
                    ),
                )
            )

        return dated_jobs

    def _collect_operation_jobs(self, limit: int) -> list[_DatedJob]:
        events = self.operation_event_service.list_events(limit=limit)
        dated_jobs: list[_DatedJob] = []

        for event in events:
            started_ts = self._parse_iso_timestamp(event.started_at)
            updated_ts = self._parse_iso_timestamp(event.updated_at) or started_ts
            dated_jobs.append(
                _DatedJob(
                    sort_ts=updated_ts or started_ts,
                    record=JobRecord(
                        job_id=event.event_id,
                        source="action",
                        status=self._map_operation_status(event.status),
                        title=event.title,
                        subtitle=event.subtitle,
                        route=event.route,
                        started_at=event.started_at or None,
                        updated_at=event.updated_at or None,
                        message=self._build_operation_message(event.status),
                    ),
                )
            )

        return dated_jobs

    def _derive_installer_status(
        self,
        started_ts: float,
        log_path: Path,
        log_tail: str,
    ) -> tuple[str, int | None, str]:
        progress = self._parse_progress(log_tail)
        finished = _INSTALLER_FINISHED_RE.search(log_tail)

        if finished:
            exit_code = int(finished.group(1))
            if exit_code == 0:
                return "success", 100, "Job finished successfully"
            return "failed", progress, "Job failed; open the related section for details"

        if self._regular_file_mtime(log_path) is not None:
            return "running", progress, "Job is running"

        age_seconds = max(0.0, datetime.now(timezone.utc).timestamp() - started_ts)
        if age_seconds <= _QUEUED_GRACE_SECONDS:
            return "queued", progress, "Waiting for installer job to start"
        return "unknown", progress, "Job was created but no installer log has been written yet"

    def _build_summary(self, jobs: Iterable[JobRecord]) -> JobSummary:
        summary = JobSummary()
        for job in jobs:
            summary.total += 1
            if job.status == "running":
                summary.running += 1
            elif job.status == "queued":
                summary.queued += 1
            elif job.status == "success":
                summary.success += 1
            elif job.status == "failed":
                summary.failed += 1
            elif job.status == "cancelled":
                summary.cancelled += 1
            else:
                summary.unknown += 1
        return summary

    def _read_job_payload(self, job_path: Path) -> dict[str, Any] | None:
        try:
            raw = json.loads(
                self._read_regular_bytes(job_path, _MAX_INSTALLER_JOB_BYTES).decode("utf-8")
            )
        except Exception as exc:
            logger.warning(
                "Failed to read installer job payload %s: %s",
                job_path.name,
                type(exc).__name__,
            )
            return None

        if not isinstance(raw, dict):
            logger.warning("Installer job payload %s is not an object", job_path.name)
            return None
        script = raw.get("script")
        args = raw.get("args") or []
        if script not in ALLOWED_INSTALL_SCRIPTS:
            logger.warning("Installer job payload %s names an unknown action", job_path.name)
            return None
        if (
            not isinstance(args, list)
            or len(args) > 64
            or any(not isinstance(arg, str) or len(arg) > 4096 for arg in args)
        ):
            logger.warning("Installer job payload %s has invalid arguments", job_path.name)
            return None
        return raw

    def _read_log_tail(self, log_path: Path, max_bytes: int = 8192) -> str:
        try:
            before = log_path.lstat()
            if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
                return ""
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(log_path, flags)
            with os.fdopen(fd, "rb") as handle:
                info = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                ):
                    return ""
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                safe_max_bytes = max(1, min(int(max_bytes), 64 * 1024))
                handle.seek(max(0, size - safe_max_bytes))
                data = handle.read(safe_max_bytes)
            return data.decode("utf-8", errors="replace").strip()
        except FileNotFoundError:
            return ""
        except Exception as exc:
            logger.warning("Failed to read job log %s: %s", log_path.name, type(exc).__name__)
            return ""

    def _read_regular_bytes(self, path: Path, max_bytes: int) -> bytes:
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            raise ValueError("unsafe file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
                or info.st_size > max_bytes
            ):
                raise ValueError("unsafe file")
            chunks: list[bytes] = []
            remaining = max_bytes + 1
            while remaining > 0:
                chunk = os.read(fd, min(remaining, 64 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
            if len(data) > max_bytes:
                raise ValueError("file too large")
            return data
        finally:
            os.close(fd)

    def _regular_file_mtime(self, path: Path) -> float | None:
        try:
            info = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            return None
        return info.st_mtime

    def _describe_installer_job(self, script: str, args: list[str]) -> tuple[str, str, str | None]:
        action = args[0] if args else ""
        if script == "services/ai.sh":
            if action == "install":
                return "Install Ollama Runtime", "AI Chat · Local model runtime", "/ai"
            if action == "uninstall":
                return "Uninstall Ollama Runtime", "AI Chat · Local model runtime", "/ai"
            if action == "service":
                return "Enable Ollama Service", "AI Chat · Local model runtime", "/ai"
            return "AI Runtime Task", "AI Chat · Installer job", "/ai"

        if script == "services/tailscale.sh":
            if action == "install":
                return "Install Tailscale", "Remote Access · Tailscale runtime", "/remote-access"
            if action == "uninstall":
                return "Uninstall Tailscale", "Remote Access · Tailscale runtime", "/remote-access"
            return "Tailscale Task", "Remote Access · Installer job", "/remote-access"

        if script == "services/wireguard.sh":
            if action == "install":
                return "Install WireGuard", "VPN · WireGuard runtime", "/vpn"
            if action == "uninstall":
                return "Uninstall WireGuard", "VPN · WireGuard runtime", "/vpn"
            return "WireGuard Task", "VPN · Installer job", "/vpn"

        if script == "security/update_system.sh":
            if action == "upgrade":
                return "Update System Packages", "Security · Package maintenance", "/security"
            return "Security Maintenance Job", "Security · Installer job", "/security"

        return "Installer Job", "Background installer task", None

    def _map_backup_status(self, backup: BackupJob) -> str:
        raw_status = str(getattr(getattr(backup, "status", None), "value", getattr(backup, "status", "unknown")) or "unknown").lower()
        error_message = str(getattr(backup, "error_message", "") or "").lower()
        if raw_status == BackupStatus.RUNNING.value:
            return "running"
        if raw_status == BackupStatus.COMPLETED.value:
            return "success"
        if raw_status == BackupStatus.FAILED.value and "cancel" in error_message:
            return "cancelled"
        if raw_status == BackupStatus.FAILED.value:
            return "failed"
        return "unknown"

    def _build_backup_message(self, backup: BackupJob, status: str) -> str:
        if status == "running":
            return "Backup is still running"
        if status == "success":
            return "Backup archive is ready"
        if status == "cancelled":
            return "Backup was cancelled"
        if status == "failed":
            return "Backup failed; open Backup for details"
        return "Backup status is unknown"

    def _map_rollback_status(self, raw_status: str) -> str:
        status = str(raw_status or "unknown").lower()
        if status == "creating":
            return "queued"
        if status == "restoring":
            return "running"
        if status == "ready":
            return "success"
        if status in {"failed", "restore-failed"}:
            return "failed"
        return "unknown"

    def _map_operation_status(self, raw_status: str) -> str:
        status = str(raw_status or "unknown").lower()
        if status in {"queued", "running", "success", "failed", "cancelled", "unknown"}:
            return status
        if status == "error":
            return "failed"
        return "unknown"

    def _build_rollback_message(self, raw_status: str, reason: str | None, error_message: str | None) -> str:
        status = str(raw_status or "unknown").lower()
        if status == "creating":
            return "Creating safe snapshot"
        if status == "restoring":
            return "Restoring safe snapshot"
        if status == "ready":
            return "Safe snapshot is ready"
        if status in {"failed", "restore-failed"}:
            return "Safe snapshot operation failed; open Rollback Center for details"
        return "Safe snapshot status is unknown"

    def _build_operation_message(self, raw_status: str) -> str:
        status = self._map_operation_status(raw_status)
        if status == "success":
            return "Operation completed successfully"
        if status == "failed":
            return "Operation failed; open the related section for details"
        if status == "cancelled":
            return "Operation was cancelled"
        if status == "running":
            return "Operation is running"
        if status == "queued":
            return "Operation is queued"
        return "Operation status is unknown"

    def _parse_progress(self, log_text: str) -> int | None:
        if not log_text:
            return None
        matches = _PROGRESS_RE.findall(log_text)
        if not matches:
            return None
        try:
            value = float(matches[-1])
        except ValueError:
            return None
        return int(round(max(0.0, min(100.0, value))))

    def _last_meaningful_line(self, log_text: str) -> str:
        if not log_text:
            return ""
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        for line in reversed(lines):
            if _INSTALLER_FINISHED_RE.search(line):
                continue
            return line
        return ""

    def _coerce_timestamp(self, value: Any) -> float | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            parsed = float(value)
        else:
            try:
                parsed = float(str(value))
            except (TypeError, ValueError):
                return None
        now = datetime.now(timezone.utc).timestamp()
        if not 946684800 <= parsed <= now + 86400:
            return None
        return parsed

    def _normalize_datetime(self, value: Any) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return datetime.now(timezone.utc)

    def _isoformat(self, timestamp: float) -> str:
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()

    def _parse_iso_timestamp(self, value: str | None) -> float:
        if not value:
            return 0.0
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
        except ValueError:
            return 0.0
