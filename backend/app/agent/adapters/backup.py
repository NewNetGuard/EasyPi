"""Backup fact adapter for agent modules."""

from __future__ import annotations

import os
from typing import Any, Callable

from app.db.session import SessionLocal
from app.models.backup import BackupJob


class BackupAdapter:
    """Expose read-only backup state for agent modules."""

    def __init__(
        self,
        service: Any | None = None,
        *,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        if service is None:
            from app.services.backup_service import BackupService

            service = BackupService()
        self.service = service
        self.session_factory = session_factory or SessionLocal

    async def list_backups(self) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            backups = self.service.get_all_backups(db)
            job_details = {
                int(job.id): job
                for job in db.query(BackupJob).all()
            }
            normalized: list[dict[str, Any]] = []
            for backup in backups:
                if hasattr(backup, "model_dump"):
                    payload = backup.model_dump(mode="json")
                elif isinstance(backup, dict):
                    payload = dict(backup)
                else:
                    continue
                job = job_details.get(int(payload.get("id") or 0))
                file_path = str(getattr(job, "file_path", "") or "").strip() if job is not None else ""
                payload["file_path"] = file_path or None
                payload["file_exists"] = bool(file_path and os.path.exists(file_path))
                normalized.append(payload)
            return normalized
        finally:
            db.close()

    async def create_backup(self, *, backup_type: str = "full", name: str | None = None) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.create_backup(backup_type=backup_type, name=name, db=db)
            if hasattr(result, "model_dump"):
                return result.model_dump(mode="json")
            if isinstance(result, dict):
                return dict(result)
            return {"success": False, "message": "The backup service did not confirm that a job started."}
        finally:
            db.close()

    async def cancel_latest_running_backup(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            backups = self.service.get_all_backups(db)
            running_backup = None
            for backup in backups:
                status = str(getattr(backup, "status", "") or (backup.get("status") if isinstance(backup, dict) else ""))
                if status == "running":
                    running_backup = backup
                    break
            if running_backup is None:
                return {"success": False, "message": "No running backup job was found."}
            backup_id = int(getattr(running_backup, "id", 0) or (running_backup.get("id") if isinstance(running_backup, dict) else 0))
            result = await self.service.cancel_backup(backup_id, db)
            return dict(result) if isinstance(result, dict) else {
                "success": False,
                "message": "The backup service did not confirm that the job was cancelled.",
            }
        finally:
            db.close()
