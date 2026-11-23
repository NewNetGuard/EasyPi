"""Camera management router aggregator."""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1.endpoints.camera_admin import router as admin_router
from app.api.v1.endpoints.camera_crud import router as crud_router

router = APIRouter()
router.include_router(admin_router)
router.include_router(crud_router)
