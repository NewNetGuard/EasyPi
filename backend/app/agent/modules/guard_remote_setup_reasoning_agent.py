"""Cross-section reasoning for Guard Security, Remote Access, and Setup."""

from __future__ import annotations

from app.agent.adapters.netprotection import NetProtectionAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class GuardRemoteSetupReasoningAgent:
    """Explain shared failure patterns across Guard Security, Remote Access, and Setup."""

    name = "guard_remote_setup_reasoning_agent"
    _DOMAIN_KEYWORDS = {
        "guard": ("guard", "netprotection", "dns protection", "transparent dns", "parental", "quarantine"),
        "remote": ("remote access", "tailscale", "tailnet", "subnet router", "funnel"),
        "setup": ("setup", "permissions", "sudo", "relogin", "system dns", "pi dns"),
    }
    _ROUTES = ("guard", "remote-access", "setup", "dashboard")

    def __init__(
        self,
        netprotection: NetProtectionAdapter,
        service_status: ServiceStatusAdapter,
        setup: SetupAdapter,
    ) -> None:
        self.netprotection = netprotection
        self.service_status = service_status
        self.setup = setup

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

        permissions, dns_status, netprotection_status, tailscale_status = await self._collect_state()
        if not any((permissions, dns_status, netprotection_status)) and self._tailscale_status_value(tailscale_status) == "unknown":
            return AgentResponse(
                category="service", target="guard-remote-setup", matched=True,
                title="Cross-section diagnostics for Guard Security, Remote Access, and Setup",
                summary="Setup, Guard Security, and Remote Access data are insufficient or unavailable.",
                confidence="low", section="dashboard", subsection="cross-section", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["All cross-section sources returned unknown or empty state."],
                recommendations=["Restore the underlying status sources before diagnosing a shared cause."],
            )
        permissions_ok = bool(permissions.get("permissions_ok"))
        needs_relogin = bool(permissions.get("needs_relogin"))
        dns_servers = dns_status.get("current_dns") or []
        ignore_dhcp_dns = bool(dns_status.get("ignore_dhcp_dns"))
        netprotection_running = bool(netprotection_status.get("running"))
        tailscale_state = self._tailscale_status_value(tailscale_status)

        facts = [
            AgentFact("Permissions OK", self._yes_no(permissions_ok), "info" if permissions_ok else "warning"),
            AgentFact("Needs relogin", self._yes_no(needs_relogin), "warning" if needs_relogin else "info"),
            AgentFact("Current DNS", ", ".join(str(item) for item in dns_servers) or "Unknown"),
            AgentFact("Ignore DHCP DNS", self._yes_no(ignore_dhcp_dns), "info" if ignore_dhcp_dns else "warning"),
            AgentFact("NetProtection running", self._yes_no(netprotection_running), "info" if netprotection_running else "critical"),
            AgentFact("Tailscale status", tailscale_state, "info" if tailscale_state in {"running", "connected"} else "warning"),
        ]

        if not permissions_ok:
            summary = "Setup permissions are incomplete, and that can affect both Guard Security and Remote Access."
            confidence = "high"
            reason_chain = [
                "Setup permission status shows missing group membership or sudo state.",
                "Guard Security and Remote Access both depend on privileged local operations.",
            ]
            if needs_relogin:
                reason_chain.append("The user still needs a relogin or service restart to pick up new group membership.")
            if not netprotection_running:
                reason_chain.append("NetProtection is not currently running.")
            if tailscale_state not in {"running", "connected"}:
                reason_chain.append(f"Tailscale currently reports '{tailscale_state}'.")
            recommendations = [
                "Complete Setup permissions first, then restart the backend or relogin before debugging services.",
                "After permissions are healthy, re-check Guard Security and Remote Access separately.",
            ]
        elif not dns_servers or not ignore_dhcp_dns:
            summary = "Setup DNS state is not pinned cleanly, so Guard-related behavior can become inconsistent."
            confidence = "high"
            reason_chain = [
                "Setup DNS settings were inspected alongside Guard Security and Remote Access state.",
                "The Pi DNS configuration is missing active DNS servers or is still accepting DHCP DNS changes.",
            ]
            if not netprotection_running:
                reason_chain.append("NetProtection is also not running, which amplifies DNS instability.")
            recommendations = [
                "Review Setup DNS so the Pi resolver stays consistent before debugging Guard policies.",
                "If devices still bypass EasyPi DNS, verify gateway or resolver configuration per device.",
            ]
        elif not netprotection_running and tailscale_state not in {"running", "connected"}:
            summary = "Guard Security and Remote Access both show issues, but Setup basics look healthy."
            confidence = "high"
            reason_chain = [
                "Setup permissions and DNS look healthy.",
                "NetProtection is not running.",
                f"Tailscale currently reports '{tailscale_state}'.",
                "This points to service-level problems rather than Setup itself.",
            ]
            recommendations = [
                "Inspect Guard Security and Remote Access as separate service failures.",
                "Check service logs and start-state for NetProtection and Tailscale.",
            ]
        elif not netprotection_running:
            summary = "The shared problem is isolated to Guard Security. Setup and Remote Access look healthy."
            confidence = "high"
            reason_chain = [
                "Setup permissions and DNS look healthy.",
                f"Tailscale currently reports '{tailscale_state}'.",
                "NetProtection is the only failing subsystem in this cross-section check.",
            ]
            recommendations = [
                "Focus on Guard Security service state, DNS engine health, and policy runtime.",
            ]
        elif tailscale_state not in {"running", "connected"}:
            summary = "The shared problem is isolated to Remote Access. Setup and Guard Security look healthy."
            confidence = "high"
            reason_chain = [
                "Setup permissions and DNS look healthy.",
                "NetProtection is running.",
                f"Tailscale currently reports '{tailscale_state}'.",
            ]
            recommendations = [
                "Focus on Remote Access login, service state, and advertised route configuration.",
            ]
        else:
            summary = "Setup, Guard Security, and Remote Access look consistent right now."
            confidence = "medium"
            reason_chain = [
                "Cross-section diagnostics inspected Setup, Guard Security, and Remote Access together.",
                "No shared root-cause pattern was detected.",
            ]
            recommendations = [
                "Ask a narrower question about Guard Security, Remote Access, or Setup if one area still feels wrong.",
            ]

        return AgentResponse(
            category="service",
            target="guard-remote-setup",
            matched=True,
            title="Cross-section diagnostics for Guard Security, Remote Access, and Setup",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="cross-section",
            module=self.name,
            checks_run=["permissions_status", "system_dns_status", "netprotection_status", "tailscale_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    async def _collect_state(self) -> tuple[dict, dict, dict, object]:
        permissions = await self.setup.get_permissions_status()
        dns_status = await self.setup.get_dns_status()
        netprotection_status = await self.netprotection.get_status()
        tailscale_status = await self.service_status.get_tailscale_status()
        return permissions, dns_status, netprotection_status, tailscale_status

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

    def _tailscale_status_value(self, status: object) -> str:
        raw = getattr(status, "status", None)
        value = getattr(raw, "value", raw)
        return str(value or "unknown").strip().lower()

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
