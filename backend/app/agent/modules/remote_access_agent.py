"""Remote access agent module."""

from __future__ import annotations

from app.agent.adapters.remote_access import RemoteAccessAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class RemoteAccessAgent:
    """Explain remote access questions using local Tailscale status."""

    name = "remote_access_agent"
    _KEYWORDS = (
        "tailscale",
        "tailnet",
        "remote access",
        "remote",
        "subnet router",
        "funnel",
        "peer",
        "advertised route",
        "lan unreachable",
        "tailnet",
    )
    _ROUTES = ("remote", "tailscale")

    def __init__(self, adapter: RemoteAccessAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if request.target_type == "service":
            score += 40

        if any(keyword in question for keyword in self._KEYWORDS):
            score += 90

        if "tailscale" in target or "remote access" in target:
            score += 90

        if any(token in route for token in self._ROUTES):
            score += 30

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        target = (request.target or "").lower()
        if not self._matches_remote_access(question, target):
            return None

        try:
            state = await self.adapter.get_remote_access_state()
        except Exception as exc:
            return AgentResponse(
                category="service",
                target="tailscale",
                matched=True,
                title="Remote Access source unavailable",
                summary=f"Remote Access status is unavailable because its source returned {type(exc).__name__}: {exc}.",
                confidence="low",
                section="remote-access",
                subsection="tailscale",
                module=self.name,
                checks_run=["tailscale_status"],
                facts=[AgentFact("Source failure", str(exc), "warning")],
                reason_chain=["The source timeout/failure was preserved instead of becoming an unknown healthy state."],
                recommendations=["Check tailscaled and retry the status request."],
            )
        status = state.get("status")
        local_networks = self._normalize_networks(state.get("local_networks") or [])
        status_value = self._status_value(status)
        peers = getattr(status, "peers", []) or []
        online_peers = [peer for peer in peers if bool(getattr(peer, "online", False))]
        advertised_routes = list(getattr(status, "advertised_routes", []) or [])
        is_subnet_router = bool(getattr(status, "is_subnet_router", False))
        facts = [
            AgentFact("Service", "Tailscale"),
            AgentFact("Status", status_value, "info" if status_value == "connected" else "warning"),
            AgentFact("Hostname", str(getattr(status, "hostname", None) or "Unknown")),
            AgentFact("Tailnet", str(getattr(status, "tailnet_name", None) or "Unknown")),
            AgentFact("Known peers", str(len(peers))),
            AgentFact("Connected peers", str(len(online_peers))),
            AgentFact("Online peers", str(len(online_peers))),
            AgentFact("Subnet router", self._yes_no(is_subnet_router)),
            AgentFact("Advertised routes", str(len(advertised_routes))),
            AgentFact("Local networks", str(len(local_networks))),
        ]
        dns_name = str(getattr(status, "dns_name", None) or "").strip()
        if dns_name:
            facts.append(AgentFact("DNS name", dns_name))
        if advertised_routes:
            facts.append(AgentFact("Primary route", str(advertised_routes[0])))
        if local_networks:
            first_network = local_networks[0]
            facts.append(AgentFact("Primary local network", str(first_network.get("networkRange") or first_network.get("ip") or "Unknown")))

        if "funnel" in question or "funnel" in target:
            return self._funnel_response(status_value, dns_name, facts)
        if any(token in question or token in target for token in ("subnet router", "advertised route", "route", "lan unreachable", "local network")):
            return self._subnet_router_response(status_value, is_subnet_router, advertised_routes, local_networks, facts)
        if "peer" in question or "peer" in target or "tailnet" in question:
            return self._peer_response(status_value, peers, online_peers, facts, request)

        if status_value == "connected":
            return AgentResponse(
                category="service",
                target="tailscale",
                matched=True,
                title="Tailscale diagnostics",
                summary="Tailscale is connected and remote access looks healthy.",
                confidence="high",
                section="remote-access",
                subsection="tailscale",
                module=self.name,
                checks_run=["tailscale_status"],
                facts=facts,
                reason_chain=[
                    "The Tailscale service returned a connected state.",
                    "The current tailnet, route, and peer information are available locally.",
                ],
                recommendations=[
                    "If a specific device still cannot connect, inspect peer routing, subnet router state, and local network discovery.",
                ],
            )

        if status_value == "needs_login":
            summary = "Tailscale is installed but not logged in — remote access stays inactive until you authenticate."
            recommendations = [
                "Open the Remote Access page and complete the Tailscale login to activate the tunnel.",
                "After login, this EasyPi becomes reachable from your other Tailscale devices anywhere.",
            ]
        elif status_value == "stopped":
            summary = "Tailscale is installed but not running — remote access is currently down."
            recommendations = [
                "Start Tailscale from the Remote Access page, then verify it shows connected.",
                "If it does not stay up, check the tailscaled service logs.",
            ]
        elif status_value == "not_installed":
            summary = "Remote access (Tailscale) is not set up yet — you cannot reach this EasyPi from outside your home network."
            recommendations = [
                "Install Tailscale from the Remote Access page to reach EasyPi from anywhere, safely, without opening router ports.",
                "After install, log in and this device joins your private tailnet.",
            ]
        else:
            summary = "Tailscale status could not be confirmed."
            recommendations = [
                "Open the Remote Access page and check the tailscaled service logs for details.",
            ]

        return AgentResponse(
            category="service",
            target="tailscale",
            matched=True,
            title="Tailscale diagnostics",
            summary=summary,
            confidence="high" if status_value in {"needs_login", "stopped", "not_installed"} else "medium",
            section="remote-access",
            subsection="tailscale",
            module=self.name,
            source_status="unavailable" if status_value == "unknown" else "ok",
            checks_run=["tailscale_status"],
            facts=facts,
            reason_chain=[
                "The local Tailscale runtime state was read from the service.",
                f"The reported status is {status_value}.",
            ],
            recommendations=recommendations,
        )

    def _status_value(self, status: object) -> str:
        raw = getattr(status, "status", None)
        if raw is None:
            return "unknown"
        value = getattr(raw, "value", raw)
        return str(value or "unknown").strip().lower()

    def _matches_remote_access(self, question: str, target: str) -> bool:
        haystacks = (question, target)
        return any(keyword in haystack for haystack in haystacks for keyword in self._KEYWORDS)

    def _funnel_response(self, status_value: str, dns_name: str, facts: list[AgentFact]) -> AgentResponse:
        if status_value not in {"connected", "running"}:
            summary = "Funnel cannot be trusted while Tailscale is not connected."
            confidence = "high"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                f"The reported status is {status_value}, so inbound Funnel reachability cannot be confirmed.",
            ]
        elif dns_name:
            summary = "Tailscale is connected, but the current backend does not persist a dedicated Funnel enabled flag."
            confidence = "medium"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                "A DNS name is available, but Funnel state is not stored as a dedicated local fact in the current backend surface.",
            ]
        else:
            summary = "Tailscale is connected, but no DNS name is available for Funnel-style access."
            confidence = "medium"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                "No DNS name was returned, so Funnel address generation cannot be confirmed.",
            ]
        return AgentResponse(
            category="service",
            target="tailscale",
            matched=True,
            title="Tailscale funnel diagnostics",
            summary=summary,
            confidence=confidence,
            section="remote-access",
            subsection="funnel",
            module=self.name,
            checks_run=["tailscale_status", "local_networks"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Use the Remote Access page to enable or disable Funnel explicitly if you need internet-facing access.",
                "Keep remote access behind Tailscale only unless Funnel is intentionally enabled.",
            ],
        )

    def _subnet_router_response(
        self,
        status_value: str,
        is_subnet_router: bool,
        advertised_routes: list[object],
        local_networks: list[dict[str, object]],
        facts: list[AgentFact],
    ) -> AgentResponse:
        if status_value not in {"connected", "running"}:
            summary = "Subnet routing cannot work because Tailscale is not connected."
            confidence = "high"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                f"The reported status is {status_value}, so advertised subnet routes are not active.",
            ]
        elif not is_subnet_router or not advertised_routes:
            summary = "Tailscale is connected, but subnet router mode is not actively advertising any LAN routes."
            confidence = "high"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                "No advertised subnet routes were found in the current runtime status.",
            ]
        elif not local_networks:
            summary = "Subnet routing is enabled, but no local network inventory was returned for LAN reachability checks."
            confidence = "medium"
            reason_chain = [
                "The Tailscale runtime reports subnet router mode and advertised routes.",
                "The local network inventory is empty, so LAN reachability cannot be fully explained.",
            ]
        else:
            summary = "Subnet router mode looks active, and advertised LAN routes are present."
            confidence = "high"
            reason_chain = [
                "The Tailscale runtime reports connected state.",
                "Advertised routes and local network inventory are both available.",
            ]
        return AgentResponse(
            category="service",
            target="tailscale",
            matched=True,
            title="Subnet router diagnostics",
            summary=summary,
            confidence=confidence,
            section="remote-access",
            subsection="subnet-router",
            module=self.name,
            checks_run=["tailscale_status", "local_networks"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Advertise LAN routes from Remote Access if remote peers should reach local devices.",
                "Verify local subnet detection if the route is present but LAN devices are still unreachable.",
            ],
        )

    def _peer_response(
        self,
        status_value: str,
        peers: list[object],
        online_peers: list[object],
        facts: list[AgentFact],
        request: AgentRequest,
    ) -> AgentResponse:
        selected_peer = self._find_peer(str(request.target or request.question), peers)
        if selected_peer is not None:
            facts.append(AgentFact("Selected peer", str(getattr(selected_peer, "hostname", None) or getattr(selected_peer, "dns_name", None) or "Unknown")))
            facts.append(AgentFact("Selected peer online", self._yes_no(bool(getattr(selected_peer, "online", False))), "info" if bool(getattr(selected_peer, "online", False)) else "warning"))
        if status_value not in {"connected", "running"}:
            summary = "Peer state cannot be trusted because Tailscale is not connected."
            confidence = "high"
            reason_chain = [
                "The local Tailscale runtime state was read from the service.",
                f"The reported status is {status_value}, so peer connectivity is not currently active.",
            ]
        elif selected_peer is not None and not bool(getattr(selected_peer, "online", False)):
            summary = "The selected peer exists in the tailnet but is currently offline."
            confidence = "high"
            reason_chain = [
                "Tailnet peer data were read from the local runtime status.",
                "The selected peer is known but currently not online.",
            ]
        elif not peers:
            summary = "No tailnet peers are currently visible from local Tailscale status."
            confidence = "medium"
            reason_chain = [
                "Tailnet peer data were read from the local runtime status.",
                "The current runtime did not return any peer entries.",
            ]
        elif not online_peers:
            summary = "Tailnet peers are known, but none of them are currently online."
            confidence = "high"
            reason_chain = [
                "Tailnet peer data were read from the local runtime status.",
                "All currently known peers are offline.",
            ]
        else:
            summary = "Tailnet peers are visible, and at least one peer is currently online."
            confidence = "medium"
            reason_chain = [
                "Tailnet peer data were read from the local runtime status.",
                "At least one peer is currently online.",
            ]
        return AgentResponse(
            category="service",
            target="tailscale",
            matched=True,
            title="Tailnet peer diagnostics",
            summary=summary,
            confidence=confidence,
            section="remote-access",
            subsection="peers",
            module=self.name,
            checks_run=["tailscale_status", "local_networks"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Check the target peer's own Tailscale state if this EasyPi peer view looks healthy but that device still cannot connect.",
                "Use subnet router diagnostics if peers connect to EasyPi but cannot reach the LAN behind it.",
            ],
        )

    def _normalize_networks(self, networks: list[object]) -> list[dict[str, object]]:
        normalized: list[dict[str, object]] = []
        for network in networks:
            if hasattr(network, "model_dump"):
                normalized.append(network.model_dump(mode="json"))
                continue
            if isinstance(network, dict):
                normalized.append(dict(network))
                continue
            normalized.append(
                {
                    "interface": getattr(network, "interface", None),
                    "ip": getattr(network, "ip", None),
                    "netmask": getattr(network, "netmask", None),
                    "networkRange": getattr(network, "networkRange", None),
                }
            )
        return normalized

    def _find_peer(self, value: str, peers: list[object]) -> object | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        for peer in peers:
            hostname = str(getattr(peer, "hostname", None) or "").strip().lower()
            dns_name = str(getattr(peer, "dns_name", None) or "").strip().lower()
            if normalized in {hostname, dns_name}:
                return peer
            if hostname and hostname in normalized:
                return peer
            if dns_name and dns_name in normalized:
                return peer
        return None

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
