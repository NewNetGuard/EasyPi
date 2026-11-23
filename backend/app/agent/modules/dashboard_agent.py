"""Canonical dashboard agent module."""

from app.agent.modules.dashboard_reasoning_agent import DashboardReasoningAgent


class DashboardAgent(DashboardReasoningAgent):
    """Compatibility wrapper that exposes the canonical dashboard agent name."""

    name = "dashboard_agent"
