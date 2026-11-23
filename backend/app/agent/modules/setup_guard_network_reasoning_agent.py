"""Cross-section reasoning for Setup, Guard Security, and Network Activity."""

from __future__ import annotations

from app.agent.adapters.netprotection import NetProtectionAdapter
from app.agent.adapters.network_activity import NetworkActivityAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class SetupGuardNetworkReasoningAgent:
    """Explain shared DNS and visibility issues across Setup, Guard, and Network Activity."""

    name = "setup_guard_network_reasoning_agent"
    _DOMAIN_KEYWORDS = {
        "setup": ("setup", "permissions", "sudo", "system dns", "pi dns", "resolver"),
        "guard": ("guard", "netprotection", "dns protection", "parental", "quarantine"),
        "network": ("network activity", "queries", "traffic", "top talkers", "blocked domains"),
    }
    _ROUTES = ("setup", "guard", "network-activity", "dashboard")

    def __init__(
        self,
        setup: SetupAdapter,
        netprotection: NetProtectionAdapter,
        network_activity: NetworkActivityAdapter,
    ) -> None:
        self.setup = setup
        self.netprotection = netprotection
        self.network_activity = network_activity

    def score(self, request: AgentRequest) -> int:
        domains = self._matched_domains(request)
        if len(domains) >= 2:
            return 165
        question = request.question.lower()
        route = (request.route or "").lower()
        if "after setup" in question and any(token in route for token in self._ROUTES):
            return 145
        return 0

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        permissions = await self.setup.get_permissions_status()
        dns_status = await self.setup.get_dns_status()
        netprotection_status = await self.netprotection.get_status()
        activity_status = await self.network_activity.get_status()
        activity_stats = await self.network_activity.get_stats()
        active_devices = await self.network_activity.get_devices(active_only=True)

        if not any((permissions, dns_status, netprotection_status, activity_status, activity_stats, active_devices)):
            return AgentResponse(
                category="service", target="setup-guard-network-activity", matched=True,
                title="Cross-section diagnostics for Setup, Guard Security, and Network Activity",
                summary="Setup, Guard Security, and Network Activity data are unavailable, so no shared cause can be established.",
                confidence="low", section="dashboard", subsection="cross-section", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["All cross-section sources returned empty state."],
                recommendations=["Restore the status and activity sources before troubleshooting."],
            )

        permissions_ok = bool(permissions.get("permissions_ok"))
        needs_relogin = bool(permissions.get("needs_relogin"))
        current_dns = dns_status.get("current_dns") or []
        ignore_dhcp_dns = bool(dns_status.get("ignore_dhcp_dns"))
        netprotection_running = bool(netprotection_status.get("running"))
        activity_running = bool(activity_status.get("running"))
        total_queries = int(activity_stats.get("totalQueries") or 0)
        blocked_queries = int(activity_stats.get("blockedQueries") or 0)

        facts = [
            AgentFact("Permissions OK", self._yes_no(permissions_ok), "info" if permissions_ok else "warning"),
            AgentFact("Needs relogin", self._yes_no(needs_relogin), "warning" if needs_relogin else "info"),
            AgentFact("Current DNS", ", ".join(str(value) for value in current_dns) or "Unknown"),
            AgentFact("Ignore DHCP DNS", self._yes_no(ignore_dhcp_dns), "info" if ignore_dhcp_dns else "warning"),
            AgentFact(
                "NetProtection running",
                self._yes_no(netprotection_running),
                "info" if netprotection_running else "critical",
            ),
            AgentFact(
                "Network Activity running",
                self._yes_no(activity_running),
                "info" if activity_running else "warning",
            ),
            AgentFact("Active devices", str(len(active_devices))),
            AgentFact("Total queries", str(total_queries), "warning" if total_queries == 0 else "info"),
            AgentFact("Blocked queries", str(blocked_queries)),
        ]

        if not permissions_ok:
            summary = "Setup permissions are incomplete, and that can break both Guard Security and Network Activity."
            confidence = "high"
            reason_chain = [
                "Setup permission status still reports missing group membership, sudo state, or a relogin requirement.",
                "Guard Security depends on privileged local DNS control.",
                "Network Activity depends on the same local telemetry and DNS visibility path.",
            ]
            recommendations = [
                "Finish the Setup permissions flow first, then restart the backend or relogin before debugging Guard or Network Activity.",
            ]
        elif (not current_dns or not ignore_dhcp_dns) and (not netprotection_running or total_queries == 0):
            summary = "Setup DNS is not pinned cleanly, so Guard Security and Network Activity can lose consistent DNS visibility."
            confidence = "high"
            reason_chain = [
                "Setup DNS currently has missing resolver data or still allows DHCP DNS changes.",
                "Guard Security depends on stable local DNS control.",
                "Network Activity currently shows little or no usable DNS traffic.",
            ]
            recommendations = [
                "Pin Setup DNS cleanly before debugging Guard rules or Network Activity graphs.",
            ]
        elif not netprotection_running and (not activity_running or total_queries == 0):
            summary = "Guard Security is not running, and Network Activity has no reliable traffic data because the protection path is down."
            confidence = "high"
            reason_chain = [
                "Setup basics look healthy enough for local diagnostics.",
                "NetProtection is not running.",
                "Network Activity is stopped or has no current DNS query data.",
            ]
            recommendations = [
                "Restore Guard Security first, then re-check whether Network Activity starts seeing traffic again.",
            ]
        elif not activity_running or total_queries == 0:
            summary = "Guard Security looks available, but Network Activity is not collecting usable traffic data."
            confidence = "high"
            reason_chain = [
                "Setup permissions and DNS look healthy.",
                "NetProtection is running.",
                "Network Activity is stopped or currently empty.",
            ]
            recommendations = [
                "Focus on Network Activity collection, query log freshness, and device visibility next.",
            ]
        else:
            summary = "Setup, Guard Security, and Network Activity look consistent right now."
            confidence = "medium"
            reason_chain = [
                "Cross-section diagnostics inspected Setup, Guard Security, and Network Activity together.",
                "No shared DNS or visibility root cause was detected.",
            ]
            recommendations = [
                "Ask a narrower question about Setup, Guard Security, or Network Activity for a deeper explanation.",
            ]

        return AgentResponse(
            category="service",
            target="setup-guard-network-activity",
            matched=True,
            title="Cross-section diagnostics for Setup, Guard Security, and Network Activity",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="cross-section",
            module=self.name,
            checks_run=[
                "permissions_status",
                "system_dns_status",
                "netprotection_status",
                "network_activity_status",
                "network_activity_stats",
            ],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _matched_domains(self, request: AgentRequest) -> set[str]:
        question = request.question.lower()
        target = (request.target or "").lower()
        route = (request.route or "").lower()
        haystack = f"{question} {target} {route}"
        matched: set[str] = set()
        for name, keywords in self._DOMAIN_KEYWORDS.items():
            if any(keyword in haystack for keyword in keywords):
                matched.add(name)
        return matched

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
