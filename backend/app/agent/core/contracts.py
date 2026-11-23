"""Shared contracts for the EasyPi agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

TargetType = Literal["auto", "device", "domain", "service"]
ConfidenceLevel = Literal["high", "medium", "low"]
FactSeverity = Literal["info", "warning", "critical"]
CategoryType = Literal["device", "domain", "service", "unknown"]
ActionStyle = Literal["primary", "secondary", "danger"]
CheckStatus = Literal["ok", "warning", "failed", "skipped"]
SourceStatus = Literal["ok", "partial", "unavailable", "stale", "conflict"]


@dataclass(slots=True)
class AgentRequest:
    """Normalized request passed through the agent pipeline."""

    question: str
    target_type: TargetType = "auto"
    target: str | None = None
    route: str | None = None
    tab: str | None = None
    entity_type: str | None = None
    entity_id: str | None = None
    # Populated only by the authenticated backend boundary.  It is deliberately
    # absent from the public request schema so clients cannot select a tenant.
    actor_user_id: int | None = None


@dataclass(slots=True)
class AgentContext:
    """Normalized request context shared across the agent pipeline."""

    question: str
    question_lower: str
    target: str | None
    target_lower: str
    route: str | None
    route_lower: str
    tab: str | None
    tab_lower: str
    entity_type: str | None
    entity_type_lower: str
    entity_id: str | None
    target_type: TargetType


@dataclass(slots=True)
class AgentFact:
    """A single fact exposed to the user."""

    label: str
    value: str
    severity: FactSeverity = "info"

    def to_dict(self) -> dict[str, str]:
        return {
            "label": self.label,
            "value": self.value,
            "severity": self.severity,
        }


@dataclass(slots=True)
class AgentCheck:
    """A normalized diagnostic check entry."""

    check_id: str
    label: str
    status: CheckStatus
    details: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "check_id": self.check_id,
            "label": self.label,
            "status": self.status,
            "details": self.details,
        }


@dataclass(slots=True)
class AgentFinding:
    """A machine-readable finding produced by a reasoning step."""

    code: str
    summary: str
    severity: FactSeverity = "info"
    details: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "code": self.code,
            "summary": self.summary,
            "severity": self.severity,
            "details": self.details,
        }


@dataclass(slots=True)
class AgentAction:
    """A concrete remediation or control action suggested by the agent."""

    action_id: str
    label: str
    description: str
    style: ActionStyle = "secondary"
    requires_confirmation: bool = True
    confirmation_text: str | None = None
    confirmation_token: str | None = None
    parameters: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "label": self.label,
            "description": self.description,
            "style": self.style,
            "requires_confirmation": self.requires_confirmation,
            "confirmation_text": self.confirmation_text,
            "confirmation_token": self.confirmation_token,
            "parameters": dict(self.parameters),
        }


@dataclass(slots=True)
class AgentResponse:
    """Unified response returned by agent modules."""

    category: CategoryType
    target: str
    matched: bool
    title: str
    summary: str
    confidence: ConfidenceLevel
    section: str | None = None
    subsection: str | None = None
    module: str | None = None
    source_status: SourceStatus = "ok"
    source_errors: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    facts: list[AgentFact] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    reason_chain: list[str] = field(default_factory=list)
    actions: list[AgentAction] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "target": self.target,
            "matched": self.matched,
            "title": self.title,
            "summary": self.summary,
            "confidence": self.confidence,
            "section": self.section,
            "subsection": self.subsection,
            "module": self.module,
            "source_status": self.source_status,
            "source_errors": list(self.source_errors),
            "checks_run": list(self.checks_run),
            "facts": [fact.to_dict() for fact in self.facts],
            "recommendations": list(self.recommendations),
            "reason_chain": list(self.reason_chain),
            "actions": [action.to_dict() for action in self.actions],
        }


@dataclass(slots=True)
class AgentActionResult:
    """Outcome of an agent action execution."""

    action_id: str
    success: bool
    message: str
    data: dict[str, object] = field(default_factory=dict)
    follow_up: AgentResponse | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "action_id": self.action_id,
            "success": self.success,
            "message": self.message,
            "data": dict(self.data),
            "follow_up": self.follow_up.to_dict() if self.follow_up is not None else None,
        }
