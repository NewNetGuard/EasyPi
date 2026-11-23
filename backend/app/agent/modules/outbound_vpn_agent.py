"""Outbound VPN (Privacy -> Internet Encryption) agent module.

Explains the OUTBOUND VPN client: EasyPi routing the network out through a
commercial VPN (WireGuard/OpenVPN), whole-network or per-device, with a
kill-switch. Distinct from WireGuardAgent, which covers the INBOUND WireGuard
*server* (remote access into the home).
"""

from __future__ import annotations

from app.agent.adapters.outbound_vpn import OutboundVpnAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class OutboundVpnAgent:
    """Explain the outbound VPN client / Internet Encryption state."""

    name = "outbound_vpn_agent"
    # Outbound-specific vocabulary — keeps this distinct from the inbound WG server.
    _KEYWORDS = (
        "internet encryption", "internet-encryption", "outbound", "mullvad", "proton",
        "nordvpn", "openvpn", "kill switch", "killswitch", "wg-out", "encrypt my traffic",
        "hide from isp", "route through vpn", "provider vpn",
    )
    _ROUTES = ("internet-encryption", "internet_encryption")

    def __init__(self, adapter: OutboundVpnAdapter) -> None:
        self.adapter = adapter

    def _hit(self, request: AgentRequest) -> bool:
        q = request.question.lower()
        t = (request.target or "").lower()
        r = (request.route or "").lower()
        return (
            any(tok in r for tok in self._ROUTES)
            or "internet encryption" in q or "internet encryption" in t
            or any(k in q or k in t for k in self._KEYWORDS)
        )

    def score(self, request: AgentRequest) -> int:
        q = request.question.lower()
        t = (request.target or "").lower()
        r = (request.route or "").lower()
        score = 0
        if any(tok in r for tok in self._ROUTES):
            score += 120
        if "internet encryption" in q or "internet encryption" in t:
            score += 120
        if any(k in q or k in t for k in self._KEYWORDS):
            score += 80
        # Generic "vpn"/"tunnel" is weak here so the inbound WireGuard server agent
        # keeps bare "vpn" questions; we win only with outbound context.
        if ("vpn" in q or "tunnel" in q) and self._hit(request):
            score += 30
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if not self._hit(request):
            return None

        status = await self.adapter.get_status()
        if not status:
            return AgentResponse(
                category="service", target="outbound_vpn", matched=True,
                title="Internet Encryption status unavailable",
                summary="Outbound VPN status is unavailable, so configuration and connection state are unknown.",
                confidence="low", section="internet-encryption", subsection="outbound_vpn", module=self.name,
                checks_run=["outbound_vpn_status"], facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Restore the outbound VPN status source before changing routing."],
            )
        configured = bool(status.get("configured"))
        running = bool(status.get("running"))
        engine = str(status.get("engine") or "").lower()
        engine_label = {"openvpn": "OpenVPN", "wireguard": "WireGuard", "outline": "Outline/static"}.get(
            engine,
            engine or "Unknown",
        )
        scope = str(status.get("scope") or "all")
        endpoint = str(status.get("endpoint") or "")
        killswitch = bool(status.get("killswitch"))
        device_list = status.get("device_list") or []
        online = status.get("online_targets")
        rx = status.get("rx_bytes") or 0
        tx = status.get("tx_bytes") or 0

        facts = [
            AgentFact("Configured", self._yes_no(configured), "info" if configured else "warning"),
            AgentFact("Enabled", self._yes_no(running), "info" if running else "warning"),
        ]
        if configured:
            facts.append(AgentFact("Engine", engine_label))
            facts.append(AgentFact("Scope", "Whole network" if scope == "all" else "Selected devices"))
        if running:
            facts.append(AgentFact("Endpoint", endpoint or "Unknown"))
            facts.append(AgentFact("Kill-switch", "On" if killswitch else "Off", "info" if killswitch else "warning"))
            if scope == "selected":
                facts.append(AgentFact("Devices routed", f"{online if online is not None else 0} of {len(device_list)}"))
            if engine != "openvpn":
                facts.append(AgentFact("Transfer", f"↓ {self._bytes(rx)} · ↑ {self._bytes(tx)}"))

        # ── narrative by state ────────────────────────────────────────────────
        connection_evidence = bool(status.get("latest_handshake") or endpoint or int(rx or 0) or int(tx or 0))
        if running and not connection_evidence:
            summary = "The outbound VPN runtime flag is on, but endpoint, handshake, and traffic evidence are missing; connection health is unconfirmed."
            reason_chain = [
                "The runtime reports a running tunnel.",
                "No endpoint, handshake, or transfer evidence confirms that traffic is actually using it.",
            ]
            recommendations = ["Verify the live tunnel interface and provider endpoint before relying on encrypted routing."]
        elif not configured:
            summary = (
                "Internet Encryption is not set up — no VPN provider config has been imported, so your traffic "
                "still goes out through your ISP in the clear (from the ISP's view of which sites you reach)."
            )
            reason_chain = [
                "The outbound VPN client status was queried.",
                "No WireGuard or OpenVPN provider config is stored.",
            ]
            recommendations = [
                "On the Internet Encryption page, paste a WireGuard .conf or OpenVPN .ovpn from a provider (Mullvad/Proton).",
                "Then choose the scope (whole network or selected devices) and press Enable.",
            ]
        elif not running:
            summary = (
                f"A {engine_label} config is imported but the tunnel is OFF — traffic is not being routed through the VPN yet."
            )
            reason_chain = [
                "The outbound VPN client status was queried.",
                f"A {engine_label} config is stored, but the tunnel interface is not up.",
            ]
            recommendations = [
                "Press Enable on the Internet Encryption page to bring the tunnel up.",
                "If it fails to come up, re-check the provider config (endpoint reachable, keys correct).",
            ]
        elif scope == "selected" and (online or 0) == 0:
            summary = (
                "The tunnel is up but routing is set to selected devices and none of them are currently online, "
                "so nothing is being routed through the VPN right now."
            )
            reason_chain = [
                "The outbound VPN client is running with per-device scope.",
                "No targeted device currently resolves to an online IP (ARP).",
            ]
            recommendations = [
                "Confirm the selected devices are on the network, or switch the scope to whole network.",
            ]
        elif not killswitch:
            summary = (
                f"Traffic is encrypted through {endpoint or 'the VPN'} ({engine_label}), but the kill-switch is OFF — "
                "if the tunnel drops, traffic could leak to your ISP in the clear."
            )
            reason_chain = [
                "The outbound VPN tunnel is up and routing traffic.",
                "The kill-switch firewall rule is not currently present.",
            ]
            recommendations = [
                "Disable and re-enable from the Internet Encryption page to reinstall the kill-switch.",
            ]
        else:
            where = "your whole network is" if scope == "all" else f"{online} device(s) are"
            summary = (
                f"Internet Encryption is healthy — {where} routed out through {endpoint or 'the VPN'} "
                f"({engine_label}) with the kill-switch on. Your ISP sees only the encrypted tunnel."
            )
            reason_chain = [
                "The outbound VPN tunnel is up.",
                f"Routing scope is '{scope}' and the kill-switch is active.",
            ]
            recommendations = [
                "No action needed. To verify, check a routed device's public IP — it should show the VPN server's location.",
            ]

        return AgentResponse(
            category="service",
            target="outbound_vpn",
            matched=True,
            title="Internet Encryption (outbound VPN) diagnostics",
            summary=summary,
            confidence="medium" if running and not connection_evidence else "high",
            section="internet-encryption",
            subsection="outbound_vpn",
            module=self.name,
            checks_run=["outbound_vpn_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _bytes(self, n: int) -> str:
        try:
            n = int(n)
        except Exception:
            return "0 B"
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024:
                return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
            n /= 1024.0
        return f"{n:.1f} PB"
