from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.schemas.inbox import InboxResponse
from app.services.inbox_service import InboxService


router = APIRouter(tags=["inbox"])
inbox_service = InboxService()


@router.get("/inbox", response_model=InboxResponse)
def list_notification_inbox(
    limit: int = 60,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> InboxResponse:
    return inbox_service.list_items(db, limit=limit)
