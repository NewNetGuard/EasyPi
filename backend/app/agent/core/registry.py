"""Module registry for the EasyPi agent."""

from __future__ import annotations

from collections.abc import Iterable

from app.agent.core.module import AgentModule


class AgentRegistry:
    """Keeps a stable ordered collection of agent modules."""

    def __init__(self, modules: Iterable[AgentModule] | None = None) -> None:
        self._modules: list[AgentModule] = list(modules or [])

    def register(self, module: AgentModule) -> None:
        self._modules.append(module)

    def all(self) -> tuple[AgentModule, ...]:
        return tuple(self._modules)

