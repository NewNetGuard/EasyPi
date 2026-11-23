"""Recording-related camera endpoints."""
from __future__ import annotations

import hashlib
import os
import re
from datetime import datetime as dt, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_operation_events import record_camera_event as _record_camera_event
from app.core.safe_storage import open_regular_beneath, unlink_regular_beneath
from app.db.session import get_db
from app.models.camera import Camera
from app.models.user import User
from app.schemas.camera import Recording
from app.services.recording_service import recording_service

router = APIRouter(tags=["cameras"])

_RECORDING_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_BYTE_RANGE_RE = re.compile(
    r"^bytes=(?P<start>[0-9]{0,20})-(?P<end>[0-9]{0,20})$",
    re.IGNORECASE,
)


def _find_recording_path(recording_id: str) -> Optional[Path]:
    """Resolve one opaque recording id through the service's safe inventory."""

    if not _RECORDING_ID_RE.fullmatch(recording_id):
        return None
    for recording in recording_service.get_all_recordings():
        path_text = str(recording.get("path") or "")
        if hashlib.sha256(path_text.encode()).hexdigest()[:16] != recording_id:
            continue
        candidate = recording_service._safe_recording_file(Path(path_text), ".mp4")
        if candidate is not None:
            return candidate
    return None


def _open_recording(path: Path) -> tuple[int, int]:
    """Open a recording through directory descriptors pinned below storage."""

    root = recording_service.recordings_path.resolve(strict=True)
    relative = path.relative_to(root)
    fd, details = open_regular_beneath(root, relative, suffixes={".mp4"})
    return fd, details.st_size


def _delete_recording_file(path: Path) -> None:
    root = recording_service.recordings_path.resolve(strict=True)
    relative = path.relative_to(root)
    unlink_regular_beneath(root, relative, suffixes={".mp4"})


def _range_error(file_size: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_416_RANGE_NOT_SATISFIABLE,
        detail="Range not satisfiable",
        headers={"Content-Range": f"bytes */{file_size}"},
    )


def _parse_byte_range(value: str, file_size: int) -> tuple[int, int]:
    """Parse one RFC 7233 byte range, including a suffix range."""

    match = _BYTE_RANGE_RE.fullmatch(value.strip()) if len(value) <= 128 else None
    if match is None or file_size <= 0:
        raise _range_error(file_size)

    raw_start = match.group("start")
    raw_end = match.group("end")
    if not raw_start and not raw_end:
        raise _range_error(file_size)

    if not raw_start:
        suffix_length = int(raw_end)
        if suffix_length <= 0:
            raise _range_error(file_size)
        return max(file_size - suffix_length, 0), file_size - 1

    start = int(raw_start)
    end = int(raw_end) if raw_end else file_size - 1
    if start >= file_size or end < start:
        raise _range_error(file_size)
    return start, min(end, file_size - 1)


def _iter_open_file(fd: int, start: int, content_length: int):
    """Yield a bounded region and always release the already-open descriptor."""

    with os.fdopen(fd, "rb", closefd=True) as file_handle:
        file_handle.seek(start)
        remaining = content_length
        while remaining > 0:
            data = file_handle.read(min(1024 * 1024, remaining))
            if not data:
                break
            remaining -= len(data)
            yield data


def _build_camera_lookup(db: Session) -> dict[str, Camera]:
    cameras_list = db.query(Camera).all()
    cameras_dict: dict[str, Camera] = {}
    for cam in cameras_list:
        cameras_dict[cam.id] = cam
        short_id = cam.id[:8] if len(cam.id) > 8 else cam.id
        cameras_dict[f"{cam.name}_{short_id}"] = cam
    return cameras_dict


def _resolve_camera(cameras_dict: dict[str, Camera], camera_folder: str) -> Optional[Camera]:
    camera = cameras_dict.get(camera_folder)
    if camera:
        return camera

    for cam in cameras_dict.values():
        if camera_folder.startswith(cam.name):
            return cam

    return None


def _build_recording_model(rec: dict, camera: Optional[Camera]) -> Recording:
    filename = rec.get("filename", "")
    try:
        parts = filename.replace(".mp4", "").split("_")
        if len(parts) >= 3:
            date_str = parts[-2]
            time_str = parts[-1]
            start_dt = dt.strptime(f"{date_str}_{time_str}", "%Y%m%d_%H%M%S")
            duration_estimate = max(60, rec.get("size", 0) // 50000)
            end_dt = start_dt + timedelta(seconds=duration_estimate)
        else:
            start_dt = dt.fromisoformat(rec.get("created_at", dt.now().isoformat()))
            duration_estimate = 60
            end_dt = start_dt + timedelta(seconds=duration_estimate)
    except Exception:
        start_dt = dt.now()
        duration_estimate = 60
        end_dt = start_dt + timedelta(seconds=duration_estimate)

    rec_id = hashlib.sha256(rec.get("path", "").encode()).hexdigest()[:16]
    camera_folder = rec.get("camera", "")

    return Recording(
        id=rec_id,
        cameraId=camera.id if camera else "unknown",
        cameraName=camera.name if camera else camera_folder,
        startTime=start_dt.isoformat(),
        endTime=end_dt.isoformat(),
        duration=duration_estimate,
        fileSize=rec.get("size", 0),
        hasMotion=False,
        locked=recording_service.is_protected(rec_id),
        thumbnail=None,
        events=[],
    )


@router.get("/recordings", response_model=list[Recording])
def list_recordings(
    cameraId: Optional[str] = None,
    date: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[Recording]:
    """List recordings from filesystem."""
    raw_recordings = recording_service.get_all_recordings()
    cameras_dict = _build_camera_lookup(db)
    recordings: list[Recording] = []

    for rec in raw_recordings:
        camera_folder = rec.get("camera", "")
        camera = _resolve_camera(cameras_dict, camera_folder)
        if cameraId and camera and camera.id != cameraId:
            continue
        if date and rec.get("date") != date:
            continue
        recordings.append(_build_recording_model(rec, camera))

    return recordings[offset:offset + limit]


# NOTE: static /recordings/<word> routes must be declared before the
# /recordings/{recording_id} path-parameter route, or they get shadowed.
@router.get("/recordings/storage")
def recordings_storage(_user: User = Depends(get_current_user)) -> dict:
    """Disk + recordings usage and whether auto-cleanup is near (drives the banner)."""
    return recording_service.storage_status()


# This static path must stay above DELETE /recordings/{recording_id}.
@router.delete(
    "/recordings/cleanup",
    summary="Cleanup old recordings",
    description="Delete recordings older than specified days.",
)
async def cleanup_recordings(
    max_age_days: int = Query(default=30, ge=1, le=365),
    _admin: User = Depends(require_admin),
) -> dict:
    """Delete recordings older than max_age_days."""
    result = await recording_service.cleanup_old_recordings(max_age_days)
    success = bool(result.get("success", True))
    deleted_count = result.get("deleted_count", 0)
    _record_camera_event(
        action_id="camera.recordings.cleanup",
        title="Cleanup old recordings",
        subtitle="IP Cameras · Recordings",
        status="success" if success else "failed",
        message=result.get(
            "message",
            f"Cleanup finished, deleted {deleted_count} recording(s) older than {max_age_days} days",
        ),
    )
    return result


@router.post("/recordings/{recording_id}/protect", status_code=status.HTTP_204_NO_CONTENT)
def protect_recording(recording_id: str, _admin: User = Depends(require_admin)):
    """Lock a recording so the storage guard/retention never auto-delete it."""
    if _find_recording_path(recording_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording not found",
        )
    if not recording_service.set_protected(recording_id, True):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recording protection state could not be saved",
        )


@router.delete("/recordings/{recording_id}/protect", status_code=status.HTTP_204_NO_CONTENT)
def unprotect_recording(recording_id: str, _admin: User = Depends(require_admin)):
    """Unlock a recording so it can be auto-cleaned again."""
    if not _RECORDING_ID_RE.fullmatch(recording_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording not found",
        )
    if not recording_service.set_protected(recording_id, False):
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Recording protection state could not be saved",
        )


@router.get("/recordings/{recording_id}", response_model=Recording)
def get_recording(
    recording_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> Recording:
    """Get recording by ID."""
    raw_recordings = recording_service.get_all_recordings()
    cameras_dict = _build_camera_lookup(db)

    for rec in raw_recordings:
        rec_id = hashlib.sha256(rec.get("path", "").encode()).hexdigest()[:16]
        if rec_id == recording_id:
            camera = _resolve_camera(cameras_dict, rec.get("camera", ""))
            return _build_recording_model(rec, camera)

    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")


@router.get("/recordings/{recording_id}/stream")
async def stream_recording(
    recording_id: str,
    request: Request,
    _user: User = Depends(get_current_user),
):
    """Stream recording video file with range support."""
    file_path = _find_recording_path(recording_id)
    if file_path is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording file not found",
        )
    try:
        fd, file_size = _open_recording(file_path)
    except OSError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording file not found",
        ) from exc
    range_header = request.headers.get("range")

    if range_header:
        try:
            start, end = _parse_byte_range(range_header, file_size)
        except HTTPException:
            os.close(fd)
            raise
        content_length = end - start + 1

        return StreamingResponse(
            _iter_open_file(fd, start, content_length),
            status_code=206,
            media_type="video/mp4",
            headers={
                "Content-Range": f"bytes {start}-{end}/{file_size}",
                "Accept-Ranges": "bytes",
                "Content-Length": str(content_length),
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
                "Cross-Origin-Resource-Policy": "same-origin",
            },
        )

    return StreamingResponse(
        _iter_open_file(fd, 0, file_size),
        media_type="video/mp4",
        headers={
            "Accept-Ranges": "bytes",
            "Content-Length": str(file_size),
            "Cache-Control": "private, no-store",
            "X-Content-Type-Options": "nosniff",
            "Cross-Origin-Resource-Policy": "same-origin",
        },
    )


@router.delete("/recordings/{recording_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_recording(
    recording_id: str,
    _admin: User = Depends(require_admin),
):
    """Delete a recording."""
    file_path = _find_recording_path(recording_id)
    if file_path is not None:
        try:
            _delete_recording_file(file_path)
        except FileNotFoundError:
            file_path = None
        except OSError:
            file_path = None
        else:
            recording_service.set_protected(recording_id, False)  # drop any lock
            _record_camera_event(
                action_id="camera.recording.delete",
                title="Delete recording",
                subtitle="IP Cameras · Recordings",
                status="success",
                message=f"Deleted recording {file_path.name}",
            )
            return

    _record_camera_event(
        action_id="camera.recording.delete",
        title="Delete recording",
        subtitle="IP Cameras · Recordings",
        status="failed",
        message=f"Recording {recording_id} not found",
    )
    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Recording not found")
