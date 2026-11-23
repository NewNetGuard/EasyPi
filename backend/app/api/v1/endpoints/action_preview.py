from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.action_preview import ActionPreviewRequest, ActionPreviewResponse
from app.services.action_preview_service import action_preview_service


router = APIRouter(prefix="/action-preview", tags=["action-preview"])


@router.post("", response_model=ActionPreviewResponse)
def get_action_preview(
    payload: ActionPreviewRequest,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> ActionPreviewResponse:
    try:
        return action_preview_service.build_preview(payload, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
