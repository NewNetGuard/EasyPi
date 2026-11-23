"""Camera discovery and brand metadata endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status
from pydantic import BaseModel, Field, field_validator

from app.api.deps import get_current_user, require_admin
from app.api.v1.endpoints.camera_discovery import (
    detect_camera_stream,
    get_camera_brands_payload,
)
from app.api.v1.endpoints.camera_operation_events import record_camera_event
from app.models.user import User

logger = logging.getLogger("easypi")
router = APIRouter(prefix="/cameras", tags=["cameras"])


class CameraDetectRequest(BaseModel):
    ip: str = Field(min_length=2, max_length=45)
    port: int = Field(default=554, ge=1, le=65535)
    username: str = Field(default="admin", max_length=64)
    password: str = Field(min_length=1, max_length=127)
    brand: str | None = Field(default=None, max_length=100)
    preferredPath: str | None = Field(default=None, min_length=1, max_length=255)

    @field_validator("preferredPath")
    @classmethod
    def validate_preferred_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value.startswith("/"):
            raise ValueError("preferredPath must start with '/'")
        if "\r" in value or "\n" in value:
            raise ValueError("preferredPath must not contain line breaks")
        return value


@router.get(
    "/brands",
    status_code=status.HTTP_200_OK,
    summary="Get supported camera brands",
    description="Returns list of supported camera brands with default settings",
)
def get_camera_brands(_user: User = Depends(get_current_user)) -> dict:
    """Get list of supported camera brands with their default settings."""
    return get_camera_brands_payload()


@router.post(
    "/detect",
    status_code=status.HTTP_200_OK,
    summary="Auto-detect camera RTSP path",
    description="Try common RTSP paths to find working stream",
)
async def detect_camera(
    payload: CameraDetectRequest,
    _admin: User = Depends(require_admin),
) -> dict:
    """Auto-detect working RTSP path for a camera."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await detect_camera_stream(
        ip=payload.ip,
        port=payload.port,
        username=payload.username,
        password=payload.password,
        brand=payload.brand,
        preferred_path=payload.preferredPath,
        logger=logger,
    )
    record_camera_event(
        action_id="camera.detect",
        title="Detect camera stream",
        subtitle=f"IP Cameras - {payload.ip}",
        status="success" if result.get("success") else "failed",
        message=result.get("error") or result.get("message") or "Camera detection finished",
        started_at=started_at,
    )
    return result
