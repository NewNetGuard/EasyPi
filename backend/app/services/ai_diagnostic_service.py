"""Compatibility wrapper for the EasyPi diagnostics agent."""

from __future__ import annotations

from typing import Any, Callable
from datetime import datetime

from app.agent.core.contracts import AgentRequest
from app.agent.core.gateway import AgentGateway, build_default_agent_gateway
from app.agent.core.sanitization import normalize_agent_request, validate_action_id


class AIDiagnosticService:
    """Expose the agent through the legacy diagnostics service interface."""

    def __init__(
        self,
        netprotection: Any | None = None,
        tailscale: Any | None = None,
        threat_monitor: Any | None = None,
        now_provider: Callable[[], datetime] | None = None,
    ) -> None:
        self.gateway: AgentGateway = build_default_agent_gateway(
            netprotection=netprotection,
            tailscale=tailscale,
            threat_monitor=threat_monitor,
            now_provider=now_provider,
        )

    async def explain(
        self,
        question: str,
        target_type: str = "auto",
        target: str | None = None,
        route: str | None = None,
        tab: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        actor_user_id: int | None = None,
    ) -> dict[str, Any]:
        request = AgentRequest(
            question=str(question or "").strip(),
            target_type=target_type,
            target=target,
            route=route,
            tab=tab,
            entity_type=entity_type,
            entity_id=entity_id,
            actor_user_id=actor_user_id,
        )
        response = await self.gateway.explain(normalize_agent_request(request))
        return response.to_dict()

    async def execute_action(
        self,
        action_id: str,
        *,
        parameters: dict[str, Any] | None = None,
        confirmation_token: str | None = None,
        question: str | None = None,
        target_type: str = "auto",
        target: str | None = None,
        route: str | None = None,
        tab: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        actor_user_id: int | None = None,
    ) -> dict[str, Any]:
        follow_up_request = None
        if question:
            follow_up_request = AgentRequest(
                question=str(question or "").strip(),
                target_type=target_type,
                target=target,
                route=route,
                tab=tab,
                entity_type=entity_type,
                entity_id=entity_id,
                actor_user_id=actor_user_id,
            )
        result = await self.gateway.execute_action(
            validate_action_id(action_id),
            parameters=parameters,
            confirmation_token=confirmation_token,
            actor_user_id=actor_user_id,
            follow_up_request=normalize_agent_request(follow_up_request) if follow_up_request is not None else None,
        )
        return result.to_dict()

    async def run_probe(
        self,
        probe_id: str,
        *,
        parameters: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
    ) -> dict[str, Any]:
        normalized_parameters = dict(parameters or {})
        if probe_id == "personal_dns.tenancy":
            normalized_parameters["actor_user_id"] = actor_user_id
        return await self.gateway.run_probe(
            validate_action_id(probe_id),
            parameters=normalized_parameters,
        )


__all__ = ["AIDiagnosticService"]
