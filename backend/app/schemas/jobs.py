from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


JobSource = Literal["installer", "backup", "rollback", "action"]
JobStatus = Literal["queued", "running", "success", "failed", "cancelled", "unknown"]


class JobSummary(BaseModel):
    total: int = 0
    running: int = 0
    queued: int = 0
    success: int = 0
    failed: int = 0
    cancelled: int = 0
    unknown: int = 0


class JobRecord(BaseModel):
    job_id: str
    source: JobSource
    status: JobStatus
    title: str
    subtitle: str | None = None
    route: str | None = None
    started_at: str | None = None
    updated_at: str | None = None
    progress: int | None = None
    message: str | None = None


class JobsResponse(BaseModel):
    generated_at: str
    summary: JobSummary
    jobs: list[JobRecord] = Field(default_factory=list)
