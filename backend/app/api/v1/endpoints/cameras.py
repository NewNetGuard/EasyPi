"""IP Cameras management API endpoints."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.camera_helpers import sync_go2rtc_config
from app.api.v1.endpoints.camera_management import router as management_router
from app.api.v1.endpoints.camera_events_ffmpeg import router as events_ffmpeg_router
from app.api.v1.endpoints.camera_live import router as live_router
from app.api.v1.endpoints.camera_recordings import router as recordings_router
from app.api.v1.endpoints.camera_service_control import router as service_control_router
from app.api.v1.endpoints.camera_snapshots import router as snapshots_router
from app.api.v1.endpoints.camera_ptz import router as ptz_router

router = APIRouter(tags=["cameras"])
# Sub-routers that expose static /cameras/<word> paths (recordings, events,
# snapshots, …) MUST be registered before the management router: its greedy
# GET /cameras/{camera_id} otherwise shadows them (a request to
# /cameras/recordings was matched as camera_id="recordings" -> 404, so the
# recordings/events/snapshots lists silently disappeared from the UI).
router.include_router(recordings_router, prefix="/cameras")
router.include_router(events_ffmpeg_router, prefix="/cameras")
router.include_router(service_control_router, prefix="/cameras")
router.include_router(snapshots_router, prefix="/cameras")
router.include_router(live_router, prefix="/cameras")
router.include_router(ptz_router, prefix="/cameras")
router.include_router(management_router)

__all__ = ["router", "sync_go2rtc_config"]
