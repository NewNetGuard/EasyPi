"""WireGuard VPN agent module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class WireGuardAgent:
    """Explain WireGuard VPN state."""

    name = "wireguard_agent"
    _KEYWORDS = ("wireguard", "vpn", "peer", "handshake", "qr", "endpoint", "wg")
    _ROUTES = ("vpn", "wireguard")

    def __init__(self, adapter: WireGuardAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if "wireguard" in question or "wireguard" in target or "vpn" in question or "vpn" in target:
            score += 110
        elif any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 70
        if any(keyword in question for keyword in ("qr", "config", "handshake", "endpoint")):
            score += 45
        if any(token in route for token in self._ROUTES):
            score += 60
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if (
            "wireguard" not in question
            and "wireguard" not in target
            and "vpn" not in question
            and "vpn" not in target
            and not any(keyword in question or keyword in target for keyword in self._KEYWORDS)
            and not any(token in route for token in self._ROUTES)
        ):
            return None

        status = await self.adapter.get_status()
        if not status:
            return AgentResponse(
                category="service", target="wireguard", matched=True,
                title="WireGuard status unavailable",
                summary="WireGuard source data are unavailable, so installation and runtime state are unknown.",
                confidence="low", section="vpn", subsection="wireguard", module=self.name,
                checks_run=["wireguard_status"], facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Restore the WireGuard status source before changing VPN state."],
            )
        installed = bool(status.get("installed"))
        running = bool(status.get("running"))
        peers = status.get("peers") or []
        selected_peer = self._find_peer(str(request.target or request.question), peers)
        peers_without_handshake = sum(1 for peer in peers if not self._is_recent_handshake(peer.get("latest_handshake")))
        facts = [
            AgentFact("Installed", self._yes_no(installed), "info" if installed else "warning"),
            AgentFact("Running", self._yes_no(running), "info" if running else "critical"),
            AgentFact("Port", str(status.get("port") or "Unknown")),
            AgentFact("Endpoint", str(status.get("endpoint") or "Unknown")),
            AgentFact("Peers", str(len(peers))),
        ]
        if peers:
            facts.append(
                AgentFact(
                    "Peers without handshake",
                    str(peers_without_handshake),
                    "warning" if peers_without_handshake else "info",
                )
            )
            latest_handshake = max((str(peer.get("latest_handshake") or "") for peer in peers), default="")
            if latest_handshake:
                facts.append(AgentFact("Latest handshake", latest_handshake))
        if selected_peer is not None:
            facts.append(AgentFact("Selected peer", str(selected_peer.get("name") or "Unknown")))
            facts.append(
                AgentFact(
                    "Selected peer handshake",
                    str(selected_peer.get("latest_handshake") or "Missing"),
                    "warning" if not selected_peer.get("latest_handshake") else "info",
                )
            )

        if ("config" in question or "qr" in question) and selected_peer is not None:
            artifacts = self.adapter.get_peer_artifacts(str(selected_peer.get("name") or ""))
            facts.append(AgentFact("Config exists", self._yes_no(bool(artifacts.get("config_exists")))))
            facts.append(AgentFact("QR exists", self._yes_no(bool(artifacts.get("qr_exists")))))
            if "qr" in question and not bool(artifacts.get("qr_exists")):
                summary = f"WireGuard peer '{selected_peer.get('name')}' does not currently have a generated QR artifact."
                confidence = "high"
                reason_chain = [
                    "The selected peer exists in local WireGuard status.",
                    "The local peer artifact path was checked for the QR export file.",
                ]
                recommendations = [
                    "Recreate the peer or inspect the clients directory if the QR export should already exist.",
                ]
            elif "config" in question and not bool(artifacts.get("config_exists")):
                summary = f"WireGuard peer '{selected_peer.get('name')}' does not currently have a downloadable client config file."
                confidence = "high"
                reason_chain = [
                    "The selected peer exists in local WireGuard status.",
                    "The local peer artifact path was checked for the config export file.",
                ]
                recommendations = [
                    "Recreate the peer or inspect the clients directory if the config export should already exist.",
                ]
            else:
                summary = f"WireGuard peer '{selected_peer.get('name')}' has local client artifacts available."
                confidence = "high"
                reason_chain = [
                    "The selected peer exists in local WireGuard status.",
                    "The local clients directory contains the requested peer artifact files.",
                ]
                recommendations = [
                    "Download the config or QR from the VPN page if you need to onboard that client now.",
                ]
            return AgentResponse(
                category="service",
                target="wireguard",
                matched=True,
                title="WireGuard client artifact diagnostics",
                summary=summary,
                confidence=confidence,
                section="vpn",
                subsection="wireguard",
                module=self.name,
                checks_run=["wireguard_status", "wireguard_peer_artifacts"],
                facts=facts,
                reason_chain=reason_chain,
                recommendations=recommendations,
            )

        if ("endpoint" in question or "public ip" in question) and not status.get("endpoint"):
            return AgentResponse(
                category="service",
                target="wireguard",
                matched=True,
                title="WireGuard endpoint diagnostics",
                summary="WireGuard is missing a configured public endpoint.",
                confidence="high",
                section="vpn",
                subsection="wireguard",
                module=self.name,
                checks_run=["wireguard_status"],
                facts=facts,
                reason_chain=[
                    "Local WireGuard status was queried.",
                    "No endpoint value is currently stored in server status.",
                ],
                recommendations=[
                    "Configure the public endpoint and port before expecting external clients to connect.",
                ],
            )

        if selected_peer is not None and not selected_peer.get("latest_handshake"):
            summary = f"WireGuard peer '{selected_peer.get('name')}' has no recent handshake."
            confidence = "high"
            reason_chain = [
                "The selected peer exists in local WireGuard status.",
                "The peer currently lacks a recent handshake timestamp.",
            ]
            recommendations = [
                "Check the peer config, server endpoint, and whether the client has actually started WireGuard.",
            ]
            return AgentResponse(
                category="service",
                target="wireguard",
                matched=True,
                title="WireGuard peer diagnostics",
                summary=summary,
                confidence=confidence,
                section="vpn",
                subsection="wireguard",
                module=self.name,
                checks_run=["wireguard_status"],
                facts=facts,
                reason_chain=reason_chain,
                recommendations=recommendations,
            )

        if not installed:
            summary = "WireGuard VPN is not installed yet — you have no private tunnel into your home network."
            confidence = "high"
            reason_chain = [
                "The WireGuard status command was queried.",
                "It reported that WireGuard is not installed.",
            ]
            recommendations = [
                "Install WireGuard from the VPN page to enable secure remote access to your home network.",
                "After installing, add a peer to generate a client config/QR for your phone or laptop.",
            ]
        elif not running:
            summary = "WireGuard is installed but not running — the VPN tunnel is currently down."
            confidence = "high"
            reason_chain = [
                "The WireGuard status command was queried.",
                "The service is installed but currently stopped.",
            ]
            recommendations = [
                "Restart WireGuard from the VPN page (service wg-quick@wg0) to bring the tunnel back up.",
                "If it will not start, verify the server endpoint/port and check the service logs.",
            ]
        elif not peers:
            summary = "WireGuard is running, but no peers are configured yet — there are no clients to connect."
            confidence = "high"
            reason_chain = [
                "The WireGuard service is running.",
                "No peers are present in the server configuration.",
            ]
            recommendations = [
                "Add a peer from the VPN page, then import the generated config/QR on your device.",
            ]
        elif peers_without_handshake == len(peers):
            summary = f"WireGuard is running with {len(peers)} peer(s), but none has a recent handshake — no client is currently connected."
            confidence = "high"
            reason_chain = [
                "The WireGuard service is running.",
                "All configured peers currently lack a recent handshake timestamp.",
            ]
            recommendations = [
                "Confirm the server's public endpoint/port is reachable (router UDP port-forward).",
                "On the client, check the config is imported and the tunnel is switched on.",
            ]
        else:
            connected = len(peers) - peers_without_handshake
            summary = f"WireGuard is running and healthy — {connected} of {len(peers)} peer(s) recently connected."
            confidence = "high"
            reason_chain = [
                "The WireGuard service is running.",
                f"{connected} of {len(peers)} peers have a recent handshake.",
            ]
            recommendations = [
                "No action needed — the VPN is up and clients are connecting.",
                "If one client cannot connect, inspect that peer's config and handshake counter.",
            ]

        return AgentResponse(
            category="service",
            target="wireguard",
            matched=True,
            title="WireGuard diagnostics",
            summary=summary,
            confidence=confidence,
            section="vpn",
            subsection="wireguard",
            module=self.name,
            checks_run=["wireguard_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _is_recent_handshake(self, value: object) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return False
        parsed = parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
        return parsed >= datetime.now(timezone.utc) - timedelta(days=7)

    def _find_peer(self, value: str, peers: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        for peer in peers:
            name = str(peer.get("name") or "").strip().lower()
            public_key = str(peer.get("public_key") or "").strip().lower()
            if normalized in {name, public_key}:
                return peer
            if name and name in normalized:
                return peer
        return None
