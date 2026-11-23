"""Camera CRUD router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.camera_entities import router as entities_router
from app.api.v1.endpoints.camera_status import router as status_router

router = APIRouter()
router.include_router(entities_router)
router.include_router(status_router)
