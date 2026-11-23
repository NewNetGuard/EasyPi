"""Read-only adapters for Jobs, Notifications, and Rollback diagnostics."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from app.db.session import SessionLocal


def _dump(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        return dict(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return dict(value)
    return {}


class OperationsAdapter:
    """Expose operational-center state without adding mutation capabilities."""

    def __init__(
        self,
        *,
        jobs_service: Any | None = None,
        inbox_service: Any | None = None,
        rollback_service: Any | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        if jobs_service is None:
            from app.services.jobs_service import JobsService

            jobs_service = JobsService()
        if inbox_service is None:
            from app.services.inbox_service import InboxService

            inbox_service = InboxService(jobs_service=jobs_service)
        if rollback_service is None:
            from app.services.rollback_service import RollbackService

            rollback_service = RollbackService()

        self.jobs_service = jobs_service
        self.inbox_service = inbox_service
        self.rollback_service = rollback_service
        self.session_factory = session_factory or SessionLocal

    async def get_jobs(self, *, limit: int = 50) -> dict[str, Any]:
        db = self.session_factory()
        try:
            return _dump(self.jobs_service.list_jobs(db, limit=limit))
        finally:
            db.close()

    async def get_notifications(self, *, limit: int = 80) -> dict[str, Any]:
        db = self.session_factory()
        try:
            return _dump(self.inbox_service.list_items(db, limit=limit))
        finally:
            db.close()

    async def get_snapshots(self, *, limit: int = 50) -> dict[str, Any]:
        payload = _dump(self.rollback_service.list_snapshots(limit=limit))
        snapshots = payload.get("snapshots") or []
        for item in snapshots:
            if not isinstance(item, dict):
                continue
            archive_path = str(item.get("archive_path") or "").strip()
            if archive_path:
                path = Path(archive_path)
                item["archive_exists"] = path.is_file() and not path.is_symlink()
                item["archive_readable"] = bool(item["archive_exists"] and os.access(path, os.R_OK))
        return payload
