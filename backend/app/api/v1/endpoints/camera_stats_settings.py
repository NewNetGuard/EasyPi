"""Camera statistics and settings endpoints."""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_helpers import (
    get_storage_info as _get_storage_info,
    load_camera_settings as _load_settings,
    save_camera_settings as _save_settings,
)
from app.api.v1.endpoints.camera_operation_events import record_camera_event as _record_camera_event
from app.db.session import get_db
from app.models.camera import Camera
from app.models.user import User
from app.schemas.camera import CameraSettings, CameraStats, EventsToday, RecordingsInfo
from app.services.recording_service import recording_service

logger = logging.getLogger("easypi")
router = APIRouter(prefix="/cameras", tags=["cameras"])


@router.get("/stats", response_model=CameraStats)
def get_camera_stats(
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> CameraStats:
    """Get camera statistics."""
    result = db.execute(select(Camera))
    cameras = result.scalars().all()

    total = len(cameras)
    online = sum(1 for camera in cameras if camera.status in ("online", "recording"))
    offline = sum(1 for camera in cameras if camera.status == "offline")
    recording = sum(1 for camera in cameras if camera.status == "recording")

    raw_recordings = recording_service.get_all_recordings()
    today = datetime.now().date().isoformat()
    today_count = sum(
        1 for item in raw_recordings if str(item.get("created_at", ""))[:10] == today
    )
    recordings_size = sum(int(item.get("size", 0)) for item in raw_recordings)

    return CameraStats(
        totalCameras=total,
        online=online,
        offline=offline,
        recording=recording,
        storage=_get_storage_info(),
        recordings=RecordingsInfo(
            total=len(raw_recordings),
            today=today_count,
            size=recording_service._format_size(recordings_size),
        ),
        eventsToday=EventsToday(),
    )


@router.get("/settings", response_model=CameraSettings)
def get_settings(_user: User = Depends(get_current_user)) -> CameraSettings:
    """Get camera settings."""
    return _load_settings()


@router.patch("/settings", response_model=CameraSettings)
def update_settings(
    settings: CameraSettings,
    _admin: User = Depends(require_admin),
) -> CameraSettings:
    """Update camera settings."""
    _save_settings(settings)
    logger.info("Camera settings updated")
    _record_camera_event(
        action_id="camera.settings.update",
        title="Update camera settings",
        subtitle="IP Cameras · Settings",
        status="success",
        message="Camera settings updated",
    )
    return settings
