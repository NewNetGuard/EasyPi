"""Live streaming endpoints for cameras."""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.api.v1.endpoints.camera_helpers import (
    get_camera_or_404 as _get_camera_or_404,
    normalize_stream_name as _normalize_stream_name,
    sync_go2rtc_config,
)
from app.core.go2rtc_client import go2rtc_http_auth
from app.db.session import get_db
from app.models.user import User

logger = logging.getLogger("easypi")
router = APIRouter(tags=["cameras"])


async def _ensure_go2rtc_stream(client: httpx.AsyncClient, go2rtc_url: str, stream_name: str, rtsp_url: str, db: Session) -> None:
    async def _load_streams() -> dict:
        streams_response = await client.get(f"{go2rtc_url}/api/streams")
        if streams_response.status_code != 200:
            return {}
        return streams_response.json() or {}

    async def _add_stream(current_rtsp_url: str) -> None:
        if "#transport=tcp" not in current_rtsp_url:
            current_rtsp_url = f"{current_rtsp_url}#transport=tcp"
        patch_response = await client.patch(
            f"{go2rtc_url}/api/config",
            json={"streams": {stream_name: current_rtsp_url}},
        )
        if patch_response.status_code != 200:
            logger.warning("Failed to add camera stream: HTTP %s", patch_response.status_code)

    streams = await _load_streams()
    if stream_name not in streams:
        await _add_stream(rtsp_url)
        streams = await _load_streams()

    if stream_name not in streams:
        logger.warning("go2rtc stream missing after PATCH; running sync_go2rtc_config")
        sync_go2rtc_config(db)
        streams = await _load_streams()

    if stream_name not in streams:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Live stream not available in go2rtc (stream not found)",
        )


@router.get("/{camera_id}/stream-url")
async def get_stream_url(
    camera_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    """Prepare a camera and return its revocable live-media WebSocket."""
    camera = _get_camera_or_404(db, camera_id)
    rtsp_url = camera.get_rtsp_url()
    stream_name = _normalize_stream_name(camera.name, camera.id)
    go2rtc_url = os.getenv("EASYPI_GO2RTC_API_URL", "http://127.0.0.1:1984")

    try:
        async with httpx.AsyncClient(timeout=10.0, auth=go2rtc_http_auth()) as client:
            await _ensure_go2rtc_stream(client, go2rtc_url, stream_name, rtsp_url, db)

        return {
            "transport": "mse-websocket",
            "websocketPath": f"/ws/cameras/{camera.id}/live",
        }
    except httpx.RequestError as exc:
        logger.error("go2rtc connection error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="go2rtc service unavailable",
        )
