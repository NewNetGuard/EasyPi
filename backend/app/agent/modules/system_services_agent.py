"""System service diagnostics for the EasyPi agent."""

from __future__ import annotations

from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class SystemServicesAgent:
    """Explain shared service health for EasyPi core services."""

    name = "system_services_agent"
    _NETPROTECTION_KEYWORDS = (
        "netprotection",
        "net protection",
        "guard service",
        "dns protection",
        "dns engine",
        "transparent dns",
        "protection service",
    )
    _THREAT_KEYWORDS = (
        "threat monitor",
        "threat monitoring",
        "threat detection",
        "ssh monitor",
        "security monitor",
    )
    _ROUTES = ("guard", "security", "dashboard", "monitor")

    def __init__(self, adapter: ServiceStatusAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if request.target_type == "service":
            score += 35

        if self._matches_netprotection(question, target):
            score += 100

        if self._matches_threat_monitor(question, target):
            score += 120

        if any(token in route for token in self._ROUTES):
            score += 20

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        target = (request.target or "").lower()

        if self._matches_netprotection(question, target):
            return await self._explain_netprotection()

        if self._matches_threat_monitor(question, target):
            return await self._explain_threat_monitor()

        return None

    async def _explain_netprotection(self) -> AgentResponse:
        status = await self.adapter.get_netprotection_status()
        if not status:
            return AgentResponse(
                category="service", target="netprotection", matched=True,
                title="NetProtection status unavailable",
                summary="NetProtection status is missing or unavailable, so its runtime state is unknown.",
                confidence="low", section="guard-security", subsection="service-status", module=self.name,
                checks_run=["netprotection_status"],
                facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Inspect the NetProtection status endpoint before starting or restarting the service."],
            )
        running = bool(status.get("running"))
        service_status = str(status.get("service_status") or "unknown").lower()
        available = bool(status.get("available"))
        conflict = running and (service_status in {"failed", "inactive", "stopped"} or not available)
        facts = [
            AgentFact("Service", "NetProtection"),
            AgentFact("Running", self._yes_no(running), "info" if running else "critical"),
            AgentFact("Systemd status", str(status.get("service_status") or "unknown")),
            AgentFact("Transparent DNS", self._yes_no(bool(status.get("transparent_dns")))),
            AgentFact("Available", self._yes_no(bool(status.get("available")))),
        ]
        return AgentResponse(
            category="service",
            target="netprotection",
            matched=True,
            title="NetProtection diagnostics",
            summary=(
                "NetProtection status is conflicting and degraded: the running flag disagrees with systemd/runtime availability."
                if conflict
                else "NetProtection is running and DNS protection is enabled."
                if running
                else "NetProtection is not running locally."
            ),
            confidence="low" if conflict else "high",
            section="guard-security",
            subsection="service-status",
            module=self.name,
            checks_run=["netprotection_status"],
            facts=facts,
            reason_chain=[
                "The local NetProtection status endpoint was queried.",
                "Running state and DNS protection flags were inspected.",
            ],
            recommendations=[
                "Check the DNS service state and systemd status if protection should be active.",
                "Review Transparent DNS settings if devices are bypassing EasyPi DNS.",
            ],
        )

    async def _explain_threat_monitor(self) -> AgentResponse:
        status = await self.adapter.get_threat_monitor_status()
        if not status:
            return AgentResponse(
                category="service", target="threat-monitoring", matched=True,
                title="Threat monitoring status unavailable",
                summary="Threat monitoring status is unavailable, so its current state is unknown.",
                confidence="low", section="security", subsection="security-monitor", module=self.name,
                checks_run=["threat_monitor_status"], facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Inspect the threat-monitor status source before changing service state."],
            )
        enabled = bool(status.get("enabled"))
        threshold_known = status.get("ssh_threshold") is not None
        facts = [
            AgentFact("Service", "Threat monitoring"),
            AgentFact("Enabled", self._yes_no(enabled), "info" if enabled else "warning"),
            AgentFact("SSH threshold", str(status.get("ssh_threshold", "Unknown"))),
            AgentFact("Auto ban", self._yes_no(bool(status.get("auto_ban")))),
            AgentFact("Tracked threats", str(status.get("threats_count", 0))),
        ]
        return AgentResponse(
            category="service",
            target="threat-monitoring",
            matched=True,
            title="Threat monitoring diagnostics",
            summary=(
                "Threat monitoring is enabled, but collection health is only partially confirmed."
                if enabled and not threshold_known
                else "Threat monitoring is enabled and collecting local threat signals."
                if enabled and threshold_known
                else "Threat monitoring is currently disabled."
            ),
            confidence="high" if threshold_known or not enabled else "low",
            section="security",
            subsection="security-monitor",
            module=self.name,
            source_status="ok" if threshold_known or not enabled else "partial",
            checks_run=["threat_monitor_status"],
            facts=facts,
            reason_chain=[
                "The local threat monitoring service status was queried.",
                "Monitoring configuration and current threat counters were inspected.",
            ],
            recommendations=[
                "Enable monitoring if you want local SSH and port-scan detection.",
                "Review threat history if the service is enabled but you expect more signals.",
            ],
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _matches_netprotection(self, question: str, target: str) -> bool:
        if any(keyword in question or keyword in target for keyword in self._NETPROTECTION_KEYWORDS):
            return True
        haystack = f"{question} {target}"
        return "guard" in haystack and "service" in haystack

    def _matches_threat_monitor(self, question: str, target: str) -> bool:
        return any(keyword in question or keyword in target for keyword in self._THREAT_KEYWORDS)
