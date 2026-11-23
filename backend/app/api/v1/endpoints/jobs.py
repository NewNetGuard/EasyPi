from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.schemas.jobs import JobsResponse
from app.services.jobs_service import JobsService

router = APIRouter(prefix="/jobs", tags=["jobs"])

jobs_service = JobsService()


@router.get("", response_model=JobsResponse)
def list_jobs(
    limit: int = Query(default=40, ge=1, le=200),
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
) -> JobsResponse:
    return jobs_service.list_jobs(db=db, limit=limit)
