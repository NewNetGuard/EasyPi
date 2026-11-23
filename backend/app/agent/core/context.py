"""Context helpers for the EasyPi agent."""

from __future__ import annotations

from app.agent.core.contracts import AgentContext, AgentRequest
from app.agent.core.sanitization import normalize_agent_request


def build_agent_context(request: AgentRequest) -> AgentContext:
    """Build normalized routing context from a raw agent request."""

    normalized = normalize_agent_request(request)

    question = str(normalized.question or "").strip()
    target = str(normalized.target or "").strip() or None
    route = str(normalized.route or "").strip() or None
    tab = str(normalized.tab or "").strip() or None
    entity_type = str(normalized.entity_type or "").strip() or None
    entity_id = str(normalized.entity_id or "").strip() or None

    return AgentContext(
        question=question,
        question_lower=question.lower(),
        target=target,
        target_lower=(target or "").lower(),
        route=route,
        route_lower=(route or "").lower(),
        tab=tab,
        tab_lower=(tab or "").lower(),
        entity_type=entity_type,
        entity_type_lower=(entity_type or "").lower(),
        entity_id=entity_id,
        target_type=normalized.target_type,
    )
