"""Service control endpoints for camera recordings."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_operation_events import record_camera_event as _record_camera_event
from app.api.v1.endpoints.camera_helpers import (
    check_camera_online as _check_camera_online,
    get_camera_or_404 as _get_camera_or_404,
    get_go2rtc_rtsp_url,
)
from app.db.session import get_db
from app.models.user import User
from app.services.recording_service import recording_service

logger = logging.getLogger("easypi")
router = APIRouter(tags=["cameras"])


@router.post(
    "/{camera_id}/service/start",
    status_code=status.HTTP_200_OK,
    summary="Start recording",
    description="Start FFmpeg recording for a camera. Records RTSP stream to MP4 files.",
)
async def start_recording(
    camera_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Start recording for a camera using FFmpeg."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = _get_camera_or_404(db, camera_id)
    try:
        if not _check_camera_online(camera.ip, camera.port):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Camera is offline")

        result = await recording_service.start_recording(
            camera_id=camera.id,
            camera_name=camera.name,
            rtsp_url=get_go2rtc_rtsp_url(camera.name, camera.id),
        )

        if not result.get("success"):
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Failed to start recording"),
            )

        camera.status = "recording"
        camera.last_seen = datetime.now(timezone.utc)
        db.commit()

        logger.info("Recording started for camera: %s", camera.name)
        response = {
            "status": "recording",
            "message": f"Recording started for {camera.name}",
        }
        _record_camera_event(
            action_id="camera.recording.start",
            title="Start camera recording",
            subtitle=f"IP Cameras · {camera.name}",
            status="success",
            message=response["message"],
            started_at=started_at,
        )
        return response
    except HTTPException as exc:
        _record_camera_event(
            action_id="camera.recording.start",
            title="Start camera recording",
            subtitle=f"IP Cameras · {camera.name}",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.post(
    "/{camera_id}/service/stop",
    status_code=status.HTTP_200_OK,
    summary="Stop recording",
    description="Stop FFmpeg recording for a camera.",
)
async def stop_recording(
    camera_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Stop recording for a camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = _get_camera_or_404(db, camera_id)

    result = await recording_service.stop_recording(camera_id)
    if not result.get("success"):
        logger.warning("Stop recording issue: %s", result.get("error"))

    camera.status = "online" if _check_camera_online(camera.ip, camera.port) else "offline"
    db.commit()

    logger.info("Recording stopped for camera: %s", camera.name)
    response = {"status": camera.status, "message": f"Recording stopped for {camera.name}"}
    _record_camera_event(
        action_id="camera.recording.stop",
        title="Stop camera recording",
        subtitle=f"IP Cameras · {camera.name}",
        status="success" if result.get("success", False) else "failed",
        message=result.get("error") or response["message"],
        started_at=started_at,
    )
    return response


@router.post(
    "/{camera_id}/service/restart",
    status_code=status.HTTP_200_OK,
    summary="Restart recording",
    description="Restart FFmpeg recording for a camera.",
)
async def restart_recording(
    camera_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Restart recording for a camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = _get_camera_or_404(db, camera_id)
    try:
        if not _check_camera_online(camera.ip, camera.port):
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Camera is offline")

        await recording_service.stop_recording(camera_id)
        result = await recording_service.start_recording(
            camera_id=camera.id,
            camera_name=camera.name,
            rtsp_url=get_go2rtc_rtsp_url(camera.name, camera.id),
        )

        if not result.get("success"):
            camera.status = "error"
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=result.get("error", "Failed to restart recording"),
            )

        camera.status = "recording"
        camera.last_seen = datetime.now(timezone.utc)
        db.commit()

        logger.info("Recording restarted for camera: %s", camera.name)
        response = {"status": "recording", "message": f"Recording restarted for {camera.name}"}
        _record_camera_event(
            action_id="camera.recording.restart",
            title="Restart camera recording",
            subtitle=f"IP Cameras · {camera.name}",
            status="success",
            message=response["message"],
            started_at=started_at,
        )
        return response
    except HTTPException as exc:
        _record_camera_event(
            action_id="camera.recording.restart",
            title="Restart camera recording",
            subtitle=f"IP Cameras · {camera.name}",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.get(
    "/{camera_id}/service/status",
    status_code=status.HTTP_200_OK,
    summary="Get recording status",
    description="Get current FFmpeg recording status for a camera.",
)
async def get_recording_status(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    """Get recording status for a camera."""
    camera = _get_camera_or_404(db, camera_id)
    status_payload = await recording_service.get_recording_status(camera_id)
    return {
        "camera_id": camera_id,
        "camera_name": camera.name,
        "recording": bool(status_payload.get("recording")),
        "status": status_payload.get("status", "stopped"),
        "started_at": status_payload.get("started_at"),
        "restart_count": status_payload.get("restart_count", 0),
    }
