"""Camera CRUD entity endpoints."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_operation_events import record_camera_event
from app.api.v1.endpoints.camera_helpers import (
    check_camera_online as _check_camera_online,
    get_camera_or_404 as _get_camera_or_404,
    get_camera_status_cached as _get_camera_status_cached,
    sync_go2rtc_config,
)
from app.core.encryption import encrypt_password
from app.db.session import get_db
from app.models.camera import Camera
from app.models.user import User
from app.schemas.camera import CameraCreate, CameraResponse, CameraUpdate
from app.services.recording_service import recording_service

logger = logging.getLogger("easypi")
router = APIRouter(prefix="/cameras", tags=["cameras"])


@router.get("", response_model=list[CameraResponse])
def list_cameras(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[dict]:
    """List all cameras."""
    offset = (page - 1) * size
    result = db.execute(select(Camera).offset(offset).limit(size))
    cameras = result.scalars().all()

    response = []
    for camera in cameras:
        is_online = _get_camera_status_cached(camera.id, camera.ip, camera.port)
        if is_online and camera.status == "offline":
            camera.status = "online"
            camera.last_seen = datetime.now(timezone.utc)
            db.commit()
        elif not is_online and camera.status in ("online", "recording"):
            camera.status = "offline"
            db.commit()
        response.append(camera.to_response())

    return response


@router.post("", response_model=CameraResponse, status_code=status.HTTP_201_CREATED)
def create_camera(
    payload: CameraCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Add a new camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = Camera(
        id=str(uuid.uuid4()),
        name=payload.name,
        ip=payload.ip,
        port=payload.port,
        username=payload.username,
        password=encrypt_password(payload.password) if payload.password else "",
        rtsp_path=payload.rtspPath,
        brand=payload.brand,
        model=payload.model,
        location=payload.location,
        status="offline",
        ptz_username=payload.ptzUsername or None,
        ptz_secret=encrypt_password(payload.ptzPassword) if payload.ptzPassword else None,
        onvif_port=payload.onvifPort,
    )
    db.add(camera)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        record_camera_event(
            action_id="camera.create",
            title="Add camera",
            subtitle=f"IP Cameras - {payload.name}",
            status="failed",
            message="Camera with this name already exists",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Camera with this name already exists",
        ) from exc
    db.refresh(camera)

    if _check_camera_online(camera.ip, camera.port):
        camera.status = "online"
        camera.last_seen = datetime.now(timezone.utc)
        db.commit()

    sync_go2rtc_config(db)
    logger.info("Camera created: %s (%s)", camera.name, camera.ip)
    record_camera_event(
        action_id="camera.create",
        title="Add camera",
        subtitle=f"IP Cameras - {camera.name}",
        status="success",
        message=f"Camera added: {camera.name}",
        started_at=started_at,
    )
    return camera.to_response()


@router.get("/{camera_id}", response_model=CameraResponse)
def get_camera(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> dict:
    """Get camera by ID."""
    camera = _get_camera_or_404(db, camera_id)
    return camera.to_response()


@router.patch("/{camera_id}", response_model=CameraResponse)
def update_camera(
    camera_id: str,
    payload: CameraUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict:
    """Update camera settings."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = _get_camera_or_404(db, camera_id)
    update_data = payload.model_dump(exclude_unset=True)
    field_map = {
        "rtspPath": "rtsp_path",
        "ptzUsername": "ptz_username",
        "ptzPassword": "ptz_secret",
        "onvifPort": "onvif_port",
    }

    for key, value in update_data.items():
        db_key = field_map.get(key, key)
        if hasattr(camera, db_key):
            if db_key in ("password", "ptz_secret") and value:
                value = encrypt_password(value)
            setattr(camera, db_key, value)

    camera.updated_at = datetime.now(timezone.utc)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        record_camera_event(
            action_id="camera.update",
            title="Update camera",
            subtitle=f"IP Cameras - {camera.name}",
            status="failed",
            message="Camera with this name already exists",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Camera with this name already exists",
        ) from exc

    db.refresh(camera)
    sync_go2rtc_config(db)
    logger.info("Camera updated: %s", camera.name)
    record_camera_event(
        action_id="camera.update",
        title="Update camera",
        subtitle=f"IP Cameras - {camera.name}",
        status="success",
        message=f"Camera updated: {camera.name}",
        started_at=started_at,
    )
    return camera.to_response()


@router.delete("/{camera_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_camera(
    camera_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Delete a camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    camera = _get_camera_or_404(db, camera_id)
    name = camera.name
    await recording_service.stop_recording(camera_id)
    db.delete(camera)
    db.commit()
    sync_go2rtc_config(db)
    logger.info("Camera deleted: %s", name)
    record_camera_event(
        action_id="camera.delete",
        title="Delete camera",
        subtitle=f"IP Cameras - {name}",
        status="success",
        message=f"Camera deleted: {name}",
        started_at=started_at,
    )
