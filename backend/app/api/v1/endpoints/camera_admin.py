"""Administrative camera router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.camera_discovery_admin import router as discovery_admin_router
from app.api.v1.endpoints.camera_stats_settings import router as stats_settings_router

router = APIRouter()
router.include_router(stats_settings_router)
router.include_router(discovery_admin_router)
