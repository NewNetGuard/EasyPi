"""Canonical monitoring agent module."""

from app.agent.modules.dashboard_monitoring_agent import DashboardMonitoringAgent


class MonitoringAgent(DashboardMonitoringAgent):
    """Compatibility wrapper that exposes the canonical monitoring agent name."""

    name = "monitoring_agent"
