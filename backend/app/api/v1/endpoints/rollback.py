from __future__ import annotations

import os
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends
from fastapi.responses import FileResponse

from app.api.deps import require_admin
from app.models.user import User
from app.schemas.rollback import RollbackActionResponse, RollbackCreateRequest, RollbackListResponse
from app.services.rollback_service import rollback_service
from app.services.operation_event_service import OperationEventService


router = APIRouter(prefix="/rollback", tags=["rollback"])
operation_event_service = OperationEventService()


def _record_rollback_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/rollback",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        pass


@router.get("/snapshots", response_model=RollbackListResponse)
def list_rollback_snapshots(
    limit: int = 50,
    _admin: User = Depends(require_admin),
) -> RollbackListResponse:
    return rollback_service.list_snapshots(limit=limit)


@router.post("/snapshots", response_model=RollbackActionResponse)
async def create_rollback_snapshot(
    payload: RollbackCreateRequest,
    _admin: User = Depends(require_admin),
) -> RollbackActionResponse:
    return await rollback_service.create_snapshot(payload)


@router.post("/snapshots/{snapshot_id}/restore", response_model=RollbackActionResponse)
async def restore_rollback_snapshot(
    snapshot_id: str,
    _admin: User = Depends(require_admin),
) -> RollbackActionResponse:
    return await rollback_service.restore_snapshot(snapshot_id)


@router.delete("/snapshots/{snapshot_id}", response_model=RollbackActionResponse)
def delete_rollback_snapshot(
    snapshot_id: str,
    _admin: User = Depends(require_admin),
) -> RollbackActionResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = rollback_service.delete_snapshot(snapshot_id)
        _record_rollback_event(
            action_id="rollback.delete",
            title="Delete safe snapshot",
            subtitle=f"Rollback - {snapshot_id}",
            status="success",
            message=result.message,
            started_at=started_at,
        )
        return result
    except Exception as exc:
        detail = getattr(exc, "detail", str(exc))
        _record_rollback_event(
            action_id="rollback.delete",
            title="Delete safe snapshot",
            subtitle=f"Rollback - {snapshot_id}",
            status="failed",
            message=str(detail),
            started_at=started_at,
        )
        raise


@router.get("/snapshots/{snapshot_id}/download")
def download_rollback_snapshot(
    snapshot_id: str,
    background_tasks: BackgroundTasks,
    _admin: User = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        temp_file, filename = rollback_service.prepare_download(snapshot_id)
        background_tasks.add_task(_cleanup_temp_file, temp_file)
        _record_rollback_event(
            action_id="rollback.download",
            title="Download safe snapshot",
            subtitle=f"Rollback - {snapshot_id}",
            status="success",
            message=f"Prepared snapshot download: {filename}",
            started_at=started_at,
        )
        return FileResponse(path=temp_file, filename=filename, media_type="application/gzip")
    except Exception as exc:
        detail = getattr(exc, "detail", str(exc))
        _record_rollback_event(
            action_id="rollback.download",
            title="Download safe snapshot",
            subtitle=f"Rollback - {snapshot_id}",
            status="failed",
            message=str(detail),
            started_at=started_at,
        )
        raise


def _cleanup_temp_file(file_path: str) -> None:
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass
