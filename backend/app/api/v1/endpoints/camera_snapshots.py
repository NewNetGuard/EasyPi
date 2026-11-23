"""Snapshot-related camera endpoints."""
from __future__ import annotations

from datetime import datetime, timezone
import os
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_helpers import (
    check_camera_online as _check_camera_online,
    get_camera_or_404 as _get_camera_or_404,
    get_go2rtc_rtsp_url,
)
from app.api.v1.endpoints.camera_operation_events import record_camera_event
from app.db.session import get_db
from app.models.user import User
from app.schemas.camera import SnapshotDeleteResponse, SnapshotInfo, SnapshotListResponse
from app.services.recording_service import recording_service
from app.services.snapshot_service import snapshot_service

router = APIRouter(tags=["cameras"])


async def capture_camera_snapshot(camera) -> Response:
    """Capture one camera frame without exposing camera credentials or RTSP details."""
    if not _check_camera_online(camera.ip, camera.port, timeout=2.0):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Camera '{camera.name}' is offline ({camera.ip}:{camera.port} not responding)",
        )

    success, jpeg_bytes, error = await snapshot_service.capture_snapshot(
        get_go2rtc_rtsp_url(camera.name, camera.id)
    )

    if not success:
        if "FFmpeg not found" in error:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=error)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Failed to capture snapshot: {error}",
        )

    return Response(
        content=jpeg_bytes,
        media_type="image/jpeg",
        headers={
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
            "Expires": "0",
            "X-Content-Type-Options": "nosniff",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )


@router.get(
    "/{camera_id}/snapshot",
    summary="Capture snapshot",
    description="Capture a single frame from the camera using FFmpeg. Returns JPEG image.",
)
async def get_snapshot(
    camera_id: str,
    request: Request,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Get a snapshot from the camera."""
    del request
    camera = _get_camera_or_404(db, camera_id)
    return await capture_camera_snapshot(camera)


@router.get(
    "/snapshots",
    summary="List all snapshots",
    description="Get a list of all captured snapshots.",
    response_model=SnapshotListResponse,
    tags=["Snapshots"],
)
async def list_snapshots(
    camera_name: Optional[str] = Query(None, description="Filter by camera name"),
    _user: User = Depends(get_current_user),
) -> SnapshotListResponse:
    """List all captured snapshots."""
    snapshots = recording_service.list_snapshots(camera_name=camera_name)
    storage = recording_service.get_snapshots_storage_info()

    snapshot_infos = [
        SnapshotInfo(
            id=snap["id"],
            camera_id=None,
            camera_name=snap["camera_name"],
            filename=snap["filename"],
            size=snap["size"],
            created_at=snap["created_at"],
            url=f"/api/v1/cameras/snapshots/{snap['filename']}",
        )
        for snap in snapshots
    ]

    return SnapshotListResponse(
        snapshots=snapshot_infos,
        total_count=len(snapshot_infos),
        total_size=storage.get("total_size", 0),
    )


@router.get(
    "/snapshots/storage",
    summary="Get snapshots storage info",
    description="Get storage statistics for snapshots.",
    tags=["Snapshots"],
)
async def get_snapshots_storage(_user: User = Depends(get_current_user)) -> dict:
    """Get storage information for snapshots directory."""
    storage = recording_service.get_snapshots_storage_info()
    return {key: value for key, value in storage.items() if key != "path"}


@router.get(
    "/snapshots/{filename}",
    summary="Get snapshot by filename",
    description="Download a specific snapshot image.",
    tags=["Snapshots"],
)
async def get_snapshot_file(
    filename: str,
    _user: User = Depends(get_current_user),
):
    """Get a specific snapshot by filename."""
    opened = recording_service.open_snapshot_by_filename(filename)
    if opened is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Snapshot '{filename}' not found",
        )

    fd, details = opened
    try:
        signature = os.read(fd, 8)
        os.lseek(fd, 0, os.SEEK_SET)
        if signature.startswith(b"\xff\xd8"):
            media_type = "image/jpeg"
        elif signature == b"\x89PNG\r\n\x1a\n":
            media_type = "image/png"
        else:
            raise OSError("Snapshot format is invalid")
    except OSError as exc:
        os.close(fd)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Snapshot not found",
        ) from exc

    def stream_file():
        with os.fdopen(fd, "rb", closefd=True) as handle:
            while chunk := handle.read(1024 * 1024):
                yield chunk

    return StreamingResponse(
        stream_file(),
        media_type=media_type,
        headers={
            "Content-Length": str(details.st_size),
            "Cache-Control": "private, no-store",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )


@router.delete(
    "/snapshots/{filename}",
    summary="Delete snapshot",
    description="Delete a specific snapshot.",
    tags=["Snapshots"],
)
async def delete_snapshot(
    filename: str,
    _admin: User = Depends(require_admin),
) -> dict:
    """Delete a specific snapshot by filename."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = recording_service.delete_snapshot(filename)
    if not result.get("success"):
        record_camera_event(
            action_id="camera.snapshot.delete",
            title="Delete snapshot",
            subtitle=f"IP Cameras - {filename}",
            status="failed",
            message=result.get("error", "Failed to delete snapshot"),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("error", "Failed to delete snapshot"),
        )
    record_camera_event(
        action_id="camera.snapshot.delete",
        title="Delete snapshot",
        subtitle=f"IP Cameras - {filename}",
        status="success",
        message=result.get("message", "Snapshot deleted"),
        started_at=started_at,
    )
    return result


@router.delete(
    "/snapshots",
    summary="Delete snapshots by camera",
    description="Delete all snapshots for a specific camera.",
    response_model=SnapshotDeleteResponse,
    tags=["Snapshots"],
)
async def delete_camera_snapshots(
    camera_name: str = Query(..., description="Camera name to delete snapshots for"),
    _admin: User = Depends(require_admin),
) -> SnapshotDeleteResponse:
    """Delete all snapshots for a specific camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = recording_service.delete_snapshots_by_camera(camera_name)
    record_camera_event(
        action_id="camera.snapshot.delete-by-camera",
        title="Delete camera snapshots",
        subtitle=f"IP Cameras - {camera_name}",
        status="success" if result.get("success", False) else "failed",
        message=f"Deleted {result.get('deleted_count', 0)} snapshots for camera '{camera_name}'",
        started_at=started_at,
    )
    return SnapshotDeleteResponse(
        success=result.get("success", False),
        deleted_count=result.get("deleted_count", 0),
        freed_bytes=result.get("freed_bytes", 0),
        message=f"Deleted {result.get('deleted_count', 0)} snapshots for camera '{camera_name}'",
    )


@router.post(
    "/snapshots/cleanup",
    summary="Cleanup old snapshots",
    description="Delete snapshots older than specified days.",
    response_model=SnapshotDeleteResponse,
    tags=["Snapshots"],
)
async def cleanup_snapshots(
    max_age_days: int = Query(default=7, ge=1, le=365, description="Max age in days"),
    _admin: User = Depends(require_admin),
) -> SnapshotDeleteResponse:
    """Delete snapshots older than max_age_days."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = recording_service.cleanup_old_snapshots(max_age_days)
    record_camera_event(
        action_id="camera.snapshot.cleanup",
        title="Cleanup old snapshots",
        subtitle="IP Cameras - Snapshots",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", ""),
        started_at=started_at,
    )
    return SnapshotDeleteResponse(
        success=result.get("success", False),
        deleted_count=result.get("deleted_count", 0),
        freed_bytes=result.get("freed_bytes", 0),
        message=result.get("message", ""),
    )
