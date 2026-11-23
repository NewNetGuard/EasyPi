"""Cross-section reasoning for Remote Access, Tailscale, and dashboard services."""

from __future__ import annotations

from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class RemoteDashboardServicesReasoningAgent:
    """Explain whether Remote Access is isolated or part of a wider dashboard service issue."""

    name = "remote_dashboard_services_reasoning_agent"
    _REMOTE_WORDS = ("remote access", "tailscale", "tailnet", "subnet router", "peer", "funnel")
    _DASHBOARD_WORDS = ("dashboard", "services", "service status", "cards")

    def __init__(self, service_status: ServiceStatusAdapter, monitoring: MonitoringAdapter) -> None:
        self.service_status = service_status
        self.monitoring = monitoring

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        target = (request.target or "").lower()
        route = (request.route or "").lower()
        has_remote = any(word in question or word in target or word in route for word in self._REMOTE_WORDS)
        has_dashboard = any(word in question or word in target or word in route for word in self._DASHBOARD_WORDS)
        if has_remote and has_dashboard:
            return 160
        return 0

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        tailscale_status = await self.service_status.get_tailscale_status()
        metrics = await self.monitoring.get_service_metrics()
        stats = await self.monitoring.get_system_stats()

        tailscale_state = self._status_value(tailscale_status)
        if tailscale_state == "unknown" and not metrics and not stats:
            return AgentResponse(
                category="service", target="remote-dashboard-services", matched=True,
                title="Cross-section diagnostics for Remote Access and dashboard services",
                summary="Remote Access and dashboard service data are insufficient or unavailable.",
                confidence="low", section="dashboard", subsection="cross-section", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["Neither remote status nor monitoring returned authoritative evidence."],
                recommendations=["Restore the status sources before deciding whether the problem is isolated."],
            )
        stopped_services = [metric for metric in metrics if not bool(metric.get("running"))]
        top_service = self._top_service(metrics)
        cpu = float((stats.get("cpu") or {}).get("usage") or 0)

        facts = [
            AgentFact(
                "Tailscale status",
                tailscale_state,
                "info" if tailscale_state in {"connected", "running"} else "warning",
            ),
            AgentFact("Stopped services", str(len(stopped_services)), "warning" if stopped_services else "info"),
            AgentFact("CPU usage", f"{cpu:.1f}%", "warning" if cpu >= 85 else "info"),
        ]
        if top_service is not None:
            facts.append(AgentFact("Top service", top_service))

        if tailscale_state not in {"connected", "running"} and stopped_services:
            summary = "Remote Access is failing alongside broader service degradation visible on the dashboard."
            confidence = "high"
            reason_chain = [
                f"Tailscale currently reports '{tailscale_state}'.",
                "Dashboard service metrics also show stopped services.",
                "This looks broader than an isolated Remote Access login problem.",
            ]
            recommendations = [
                "Open Dashboard or Services first, then return to Remote Access after service health is stable.",
            ]
        elif tailscale_state not in {"connected", "running"}:
            summary = "The current problem looks isolated to Remote Access and Tailscale."
            confidence = "high"
            reason_chain = [
                f"Tailscale currently reports '{tailscale_state}'.",
                "Dashboard service metrics do not show a wider service outage.",
            ]
            recommendations = [
                "Focus on Tailscale login, node status, and advertised route settings next.",
            ]
        elif stopped_services:
            summary = "Remote Access looks healthy, but the dashboard still shows service degradation elsewhere."
            confidence = "high"
            reason_chain = [
                f"Tailscale currently reports '{tailscale_state}'.",
                "Dashboard service metrics still show stopped services.",
            ]
            recommendations = [
                "Treat this as a broader dashboard or service issue, not a Remote Access outage.",
            ]
        else:
            summary = "Remote Access and dashboard service health look consistent right now."
            confidence = "medium"
            reason_chain = [
                "Tailscale status and dashboard service metrics were inspected together.",
                "No shared service-health root cause was detected.",
            ]
            recommendations = [
                "Ask a narrower question about Remote Access or a specific dashboard card if one area still looks wrong.",
            ]

        return AgentResponse(
            category="service",
            target="remote-dashboard-services",
            matched=True,
            title="Cross-section diagnostics for Remote Access and dashboard services",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="cross-section",
            module=self.name,
            checks_run=["tailscale_status", "service_metrics", "system_stats"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _status_value(self, status: object) -> str:
        raw = getattr(status, "status", None)
        value = getattr(raw, "value", raw)
        return str(value or "unknown").strip().lower()

    def _top_service(self, services: list[dict[str, object]]) -> str | None:
        ranked = sorted(
            services,
            key=lambda item: (float(item.get("cpu") or 0), float(item.get("ram") or 0)),
            reverse=True,
        )
        if not ranked:
            return None
        top = ranked[0]
        return f"{top.get('name')} (CPU {float(top.get('cpu') or 0):.1f}%)"
