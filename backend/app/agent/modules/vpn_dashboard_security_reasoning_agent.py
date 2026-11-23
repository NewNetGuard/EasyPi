"""Cross-section reasoning for VPN, dashboard health, and security findings."""

from __future__ import annotations

from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class VPNDashboardSecurityReasoningAgent:
    """Explain whether VPN problems are isolated or part of a wider security issue."""

    name = "vpn_dashboard_security_reasoning_agent"
    _VPN_WORDS = ("vpn", "wireguard", "handshake", "peer", "tunnel")
    _DASHBOARD_WORDS = ("dashboard", "health", "card", "service", "overall")
    _SECURITY_WORDS = ("security", "firewall", "scan", "hardening", "fix")

    def __init__(
        self,
        wireguard: WireGuardAdapter,
        security: SecurityAdapter,
        monitoring: MonitoringAdapter,
    ) -> None:
        self.wireguard = wireguard
        self.security = security
        self.monitoring = monitoring

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        target = (request.target or "").lower()
        route = (request.route or "").lower()
        haystack = f"{question} {target} {route}"
        hits = sum(
            1
            for keywords in (self._VPN_WORDS, self._DASHBOARD_WORDS, self._SECURITY_WORDS)
            if any(keyword in haystack for keyword in keywords)
        )
        return 160 if hits >= 2 else 0

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        wireguard = await self.wireguard.get_status()
        latest_scan = self.security.get_latest_scan() or {}
        metrics = await self.monitoring.get_service_metrics()

        if not wireguard and not latest_scan and not metrics:
            return AgentResponse(
                category="service", target="vpn-dashboard-security", matched=True,
                title="Cross-section diagnostics for VPN, dashboard health, and security",
                summary="VPN, dashboard, and security data are insufficient or unavailable.",
                confidence="low", section="dashboard", subsection="cross-section", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["All three cross-section sources returned empty state."],
                recommendations=["Restore the status sources before inferring consistency or causality."],
            )

        installed = bool(wireguard.get("installed"))
        running = bool(wireguard.get("running"))
        peers = wireguard.get("peers") or []
        critical_findings = list(latest_scan.get("critical") or [])
        warning_findings = list(latest_scan.get("warnings") or [])
        security_issue_ids = {str(item.get("id") or "") for item in (critical_findings + warning_findings)}
        stopped_services = [metric for metric in metrics if not bool(metric.get("running"))]

        facts = [
            AgentFact("WireGuard installed", self._yes_no(installed)),
            AgentFact("WireGuard running", self._yes_no(running), "info" if running else "warning"),
            AgentFact("Configured peers", str(len(peers))),
            AgentFact(
                "Critical security findings",
                str(len(critical_findings)),
                "critical" if critical_findings else "info",
            ),
            AgentFact("Stopped services", str(len(stopped_services)), "warning" if stopped_services else "info"),
        ]

        if installed and not running and "firewall_inactive" in security_issue_ids:
            summary = "WireGuard is down while Security independently reports an inactive firewall; these are concurrent problems with no established causal link."
            confidence = "high"
            reason_chain = [
                "WireGuard is installed but not running.",
                "The latest security scan still reports a firewall-related finding.",
                "The available facts do not show that the inactive firewall caused WireGuard startup to fail.",
            ]
            recommendations = [
                "Investigate WireGuard startup and the firewall finding separately, then re-check both states.",
            ]
        elif installed and not running and critical_findings:
            summary = "VPN is down and System Security still reports critical findings."
            confidence = "high"
            reason_chain = [
                "WireGuard is installed but not running.",
                "System Security still reports critical findings.",
            ]
            recommendations = [
                "Clear critical security findings before treating the VPN issue as isolated.",
            ]
        elif installed and not running:
            summary = "The current problem looks isolated to the VPN service rather than a wider security incident."
            confidence = "high"
            reason_chain = [
                "WireGuard is installed but not running.",
                "The latest security scan does not show a matching critical issue that clearly explains the VPN failure.",
            ]
            recommendations = [
                "Restart WireGuard and inspect peer or endpoint configuration next.",
            ]
        elif running and critical_findings:
            summary = "VPN is currently running, but dashboard and security health still show broader issues."
            confidence = "high"
            reason_chain = [
                "WireGuard is running.",
                "System Security still reports critical findings.",
                "That means the dashboard warning is broader than WireGuard itself.",
            ]
            recommendations = [
                "Open Security next, because the VPN service is not the primary root cause right now.",
            ]
        else:
            summary = "VPN, dashboard health, and security findings look internally consistent right now."
            confidence = "medium"
            reason_chain = [
                "WireGuard status, dashboard service metrics, and latest security findings were inspected together.",
                "No shared VPN or security root cause was detected.",
            ]
            recommendations = [
                "Ask a narrower question about VPN peers, dashboard health, or a specific security finding if needed.",
            ]

        return AgentResponse(
            category="service",
            target="vpn-dashboard-security",
            matched=True,
            title="Cross-section diagnostics for VPN, dashboard health, and security",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="cross-section",
            module=self.name,
            checks_run=["wireguard_status", "latest_security_scan", "service_metrics"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
