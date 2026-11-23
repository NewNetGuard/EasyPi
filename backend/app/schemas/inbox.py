from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


InboxSource = Literal["jobs", "security", "push", "watchdog"]
InboxSeverity = Literal["critical", "warning", "success", "info"]


class InboxSummary(BaseModel):
    total: int = 0
    action_required: int = 0
    critical: int = 0
    warning: int = 0
    success: int = 0
    info: int = 0
    jobs: int = 0
    security: int = 0
    push: int = 0
    watchdog: int = 0


class InboxItem(BaseModel):
    event_id: str
    source: InboxSource
    severity: InboxSeverity
    title: str
    message: str
    timestamp: str | None = None
    route: str | None = None
    source_label: str | None = None


class InboxResponse(BaseModel):
    generated_at: str
    summary: InboxSummary
    items: list[InboxItem] = Field(default_factory=list)
