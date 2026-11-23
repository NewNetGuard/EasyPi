from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


ActionPreviewId = Literal[
    "backup.restore",
    "backup.delete",
    "backup.cancel",
    "rollback.restore",
    "rollback.delete",
    "security.fix_firewall",
    "security.fix_ssh_root_login",
    "security.fix_password_auth",
    "security.fix_filesystem_readonly",
    "security.fix_outdated_packages",
    "dns.deploy",
    "wireguard.install",
    "wireguard.reset",
    "wireguard.uninstall",
    "remote-access.install",
    "remote-access.uninstall",
]
ActionPreviewRisk = Literal["low", "medium", "high", "critical"]


class ActionPreviewRequest(BaseModel):
    action_id: ActionPreviewId
    target_id: str = Field(..., min_length=1, max_length=120)


class ActionPreviewResponse(BaseModel):
    action_id: ActionPreviewId
    title: str
    target_label: str | None = None
    summary: str
    risk_level: ActionPreviewRisk
    destructive: bool = False
    requires_confirmation: bool = True
    affects: list[str] = Field(default_factory=list)
    service_impact: list[str] = Field(default_factory=list)
    rollback_available: bool = False
    rollback_hint: str | None = None
    recommended_checks: list[str] = Field(default_factory=list)
