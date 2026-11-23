"""Module contracts for the EasyPi agent."""

from __future__ import annotations

from typing import Protocol

from app.agent.core.contracts import AgentRequest, AgentResponse


class AgentModule(Protocol):
    """Contract implemented by every agent module."""

    name: str

    def score(self, request: AgentRequest) -> int:
        """Return a routing score for the incoming request."""

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        """Return an explanation or None when the module cannot answer."""

