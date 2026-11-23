"""Events and FFmpeg-related camera endpoints."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_operation_events import record_camera_event as _record_camera_event
from app.db.session import get_db
from app.models.user import User
from app.schemas.camera import CameraEvent
from app.services.recording_service import recording_service
from app.api.v1.endpoints.camera_helpers import get_camera_or_404 as _get_camera_or_404

router = APIRouter(tags=["cameras"])


@router.get("/events", response_model=list[CameraEvent])
def list_all_events(_user: User = Depends(get_current_user)) -> list[CameraEvent]:
    """List all camera events."""
    return []


@router.post("/events/clear", status_code=status.HTTP_200_OK)
def clear_all_events(_admin: User = Depends(require_admin)) -> dict:
    """Clear all events."""
    _record_camera_event(
        action_id="camera.events.clear-all",
        title="Clear all camera events",
        subtitle="IP Cameras · Events",
        status="success",
        message="Cleared all camera events",
    )
    return {"message": "All events cleared"}


@router.get("/{camera_id}/events", response_model=list[CameraEvent])
def list_camera_events(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[CameraEvent]:
    """List events for a specific camera."""
    _get_camera_or_404(db, camera_id)
    return []


@router.post("/{camera_id}/events/clear", status_code=status.HTTP_200_OK)
def clear_camera_events(
    camera_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Clear events for a specific camera."""
    camera = _get_camera_or_404(db, camera_id)
    _record_camera_event(
        action_id="camera.events.clear",
        title="Clear camera events",
        subtitle="IP Cameras · Events",
        status="success",
        message=f"Cleared events for {camera.name}",
    )
    return {"message": f"Events cleared for {camera.name}"}


@router.get(
    "/ffmpeg/status",
    summary="Check FFmpeg status",
    description="Check if FFmpeg is installed and get version info.",
)
async def get_ffmpeg_status(_user: User = Depends(get_current_user)) -> dict:
    """Check FFmpeg installation status."""
    available = recording_service.ffmpeg_available
    result = {
        "installed": available,
        "version": None,
    }

    if available:
        try:
            process = await asyncio.create_subprocess_exec(
                "ffmpeg",
                "-version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            if stdout:
                result["version"] = stdout.decode().split("\n")[0]
        except Exception:
            pass

    return result


@router.post(
    "/ffmpeg/install",
    summary="Install FFmpeg",
    description="Attempt to install FFmpeg using system package manager.",
)
async def install_ffmpeg(_admin: User = Depends(require_admin)) -> dict:
    """Install FFmpeg on the system."""
    result = await recording_service.ensure_ffmpeg_installed()

    if not result.get("success"):
        _record_camera_event(
            action_id="camera.ffmpeg.install",
            title="Install FFmpeg",
            subtitle="IP Cameras · FFmpeg",
            status="failed",
            message=result.get("error", "Failed to install FFmpeg"),
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result.get("error", "Failed to install FFmpeg"),
        )

    _record_camera_event(
        action_id="camera.ffmpeg.install",
        title="Install FFmpeg",
        subtitle="IP Cameras · FFmpeg",
        status="success",
        message=result.get("message", "FFmpeg installed successfully"),
    )
    return result
