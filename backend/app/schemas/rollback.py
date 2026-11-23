from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator


RollbackStatus = Literal["creating", "ready", "failed", "restoring", "restore-failed"]

_SAFE_NAME_RE = re.compile(r"^[\w\s-]+$")
_SAFE_REASON_RE = re.compile(r"^[^<>\x00-\x1f]+$")


class RollbackCreateRequest(BaseModel):
    name: str | None = Field(default=None, max_length=120)
    reason: str | None = Field(default=None, max_length=300)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            return None
        if not _SAFE_NAME_RE.match(trimmed):
            raise ValueError("Only letters, numbers, spaces, underscores, and dashes are allowed")
        return trimmed

    @field_validator("reason")
    @classmethod
    def validate_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        trimmed = value.strip()
        if not trimmed:
            return None
        if not _SAFE_REASON_RE.match(trimmed):
            raise ValueError("Reason contains invalid characters")
        return trimmed


class RollbackActionResponse(BaseModel):
    snapshot_id: str
    status: str
    message: str


class RollbackSnapshotRecord(BaseModel):
    snapshot_id: str
    name: str
    reason: str | None = None
    status: RollbackStatus
    created_at: str
    updated_at: str
    archive_path: str | None = None
    size_bytes: int | None = None
    error_message: str | None = None
    last_restored_at: str | None = None
    last_restore_status: str | None = None


class RollbackSummary(BaseModel):
    total: int = 0
    ready: int = 0
    active: int = 0
    failed: int = 0


class RollbackListResponse(BaseModel):
    generated_at: str
    summary: RollbackSummary
    snapshots: list[RollbackSnapshotRecord] = Field(default_factory=list)
