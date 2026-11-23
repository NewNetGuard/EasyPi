"""Per-camera status and health endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.v1.endpoints.camera_helpers import (
    check_camera_online as _check_camera_online,
    get_camera_or_404 as _get_camera_or_404,
    get_storage_info as _get_storage_info,
)
from app.db.session import get_db
from app.models.user import User
from app.schemas.camera import CameraHealth, CameraHealthChecks, CameraStatus
from app.services.recording_service import recording_service

router = APIRouter(prefix="/cameras", tags=["cameras"])


@router.get("/{camera_id}/status", response_model=CameraStatus)
async def get_camera_status(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> CameraStatus:
    """Get camera recording status."""
    camera = _get_camera_or_404(db, camera_id)

    is_online = _check_camera_online(camera.ip, camera.port)
    rec_status = await recording_service.get_recording_status(camera_id)
    is_recording = bool(rec_status.get("recording")) or camera.status == "recording"

    health = CameraHealth(
        status="healthy" if is_online else "unhealthy",
        checks=CameraHealthChecks(
            network="ok" if is_online else "error",
            rtspStream="ok" if is_online else "error",
            recordingService="inactive",
            diskSpace="ok",
            lastFrame=camera.last_seen.isoformat() if camera.last_seen else "",
        ),
    )

    return CameraStatus(
        cameraId=camera_id,
        recording=is_recording,
        since=rec_status.get("started_at") if is_recording else None,
        status="active" if is_recording else "inactive",
        lastFrame=camera.last_seen.isoformat() if camera.last_seen else None,
        health=health,
    )


@router.get("/{camera_id}/health", response_model=CameraHealth)
def get_camera_health(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> CameraHealth:
    """Get camera health status."""
    camera = _get_camera_or_404(db, camera_id)
    is_online = _check_camera_online(camera.ip, camera.port)
    storage = _get_storage_info()

    disk_status = "ok"
    if storage.percent > 90:
        disk_status = "critical"
    elif storage.percent > 80:
        disk_status = "warning"

    return CameraHealth(
        status="healthy" if is_online else "unhealthy",
        checks=CameraHealthChecks(
            network="ok" if is_online else "error",
            rtspStream="ok" if is_online else "error",
            recordingService="active" if camera.status == "recording" else "inactive",
            diskSpace=disk_status,
            lastFrame=camera.last_seen.isoformat() if camera.last_seen else "",
        ),
    )
