"""Knowledge and diagnostics for Privacy -> Stealth.

Stealth is EasyPi's outbound anti-censorship tunnel. Chameleon carries selected
LAN traffic over authenticated TLS/HTTP/2 to a user-owned VPS. This module
describes only the Stealth section and its Chameleon transport.

This agent is deliberately read-only. It explains the live state and directs
the user to the matching Client, Server, or Profile control without exposing
stored passwords or private keys.
"""

from __future__ import annotations

from app.agent.adapters.stealth import StealthAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class StealthAgent:
    """Explain Stealth setup, deployment, identity, routing, and runtime health."""

    name = "stealth_agent"
    _KEYWORDS = (
        "stealth", "chameleon", "reality", "anti-censorship", "anti censorship",
        "censorship", "dpi", "deep packet", "obfuscation", "obfs", "shield",
        "ip shield", "domain https", "duckdns", "bypass censorship", "roskomnadzor",
        "tspu", "gfw", "цензур", "хамелеон", "стелс", "тспу", "обход блокиров",
    )
    _ROUTES = ("stealth",)

    _DIAGNOSTIC_WORDS = (
        "error", "failed", "failure", "unavailable", "not connected",
        "doesn't connect", "cannot connect", "broken", "health", "why is stealth not",
        "why is chameleon not", "почему стелс не", "почему хамелеон не", "ошиб",
        "не подключ", "не работает", "недоступ",
    )
    _DOMAIN_WORDS = (
        "domain", "duckdns", "sni", "host header", "let's encrypt", "letsencrypt",
        "certificate", "cert", "renew", "token", "domain https", "домен", "сертификат",
        "токен", "обновлен",
    )
    _DEPLOYMENT_WORDS = (
        "deploy", "deployment", "ssh", "vps", "host key", "fingerprint", "ed25519",
        "password", "server tab", "install server", "развер", "сервер", "парол",
        "отпечаток", "ключ ssh",
    )
    _ROUTING_WORDS = (
        "scope", "selected device", "whole network", "routing", "route", "kill-switch",
        "killswitch", "leak", "dns", "quic", "udp/443", "device", "маршрут", "устройств",
        "утеч", "вся сеть", "выбран",
    )
    _PROFILE_WORDS = (
        "profile", "browser", "chrome", "fingerprint", "tls", "http/2", "h2",
        "mobile", "desktop", "behavior", "window_update", "ack", "профил", "браузер",
        "хром", "отпечаток",
    )
    _LIFECYCLE_WORDS = (
        "reboot", "restart", "stop server", "uninstall", "remove server", "server logs",
        "reset profile", "перезагруз", "останов", "удалить сервер", "логи", "сброс",
    )

    def __init__(self, adapter: StealthAdapter) -> None:
        self.adapter = adapter

    def _hit(self, request: AgentRequest) -> bool:
        q = request.question.lower()
        t = (request.target or "").lower()
        r = (request.route or "").lower()
        return (
            any(tok in r for tok in self._ROUTES)
            or "stealth" in q or "stealth" in t
            or any(k in q or k in t for k in self._KEYWORDS)
        )

    def score(self, request: AgentRequest) -> int:
        q = request.question.lower()
        t = (request.target or "").lower()
        r = (request.route or "").lower()
        score = 0
        if any(tok in r for tok in self._ROUTES):
            score += 120
        if "stealth" in q or "stealth" in t or "chameleon" in q or "chameleon" in t:
            score += 120
        if any(k in q or k in t for k in self._KEYWORDS):
            score += 80
        if ("vpn" in q or "tunnel" in q) and self._hit(request):
            score += 30
        return score

    @staticmethod
    def _contains(text: str, words: tuple[str, ...]) -> bool:
        return any(word in text for word in words)

    def _topic(self, request: AgentRequest) -> str:
        tab = str(request.tab or "").strip().lower()
        if tab == "client":
            return "routing"
        if tab == "server":
            return "deployment"
        if tab == "profile":
            return "profile"
        text = " ".join(
            value for value in (
                request.question.lower(),
                (request.target or "").lower(),
                (request.tab or "").lower(),
            ) if value
        )
        if self._contains(text, self._DIAGNOSTIC_WORDS):
            return "diagnostics"
        if self._contains(text, self._DOMAIN_WORDS):
            return "domain"
        if self._contains(text, self._DEPLOYMENT_WORDS):
            return "deployment"
        if self._contains(text, self._ROUTING_WORDS):
            return "routing"
        if self._contains(text, self._PROFILE_WORDS):
            return "profile"
        if self._contains(text, self._LIFECYCLE_WORDS):
            return "lifecycle"
        return "diagnostics"

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if not self._hit(request):
            return None

        status = await self.adapter.get_status()
        if not status:
            return AgentResponse(
                category="service", target="stealth", matched=True,
                title="Stealth status unavailable",
                summary="Stealth runtime status is unavailable, so configuration and connection state are unknown.",
                confidence="low", section="stealth", subsection="diagnostics", module=self.name,
                checks_run=["stealth_status"], facts=[AgentFact("Source data", "Unavailable", "warning")],
                recommendations=["Restore the Stealth status source before changing tunnel state."],
            )
        topic = self._topic(request)

        configured = bool(status.get("configured"))
        has_keys = bool(status.get("has_psk")) and bool(status.get("reality_public"))
        ssh_host = str(status.get("ssh_host") or "")
        has_ssh_auth = bool(
            status.get("has_password")
            or status.get("ssh_key_installed")
            or status.get("ssh_key_verified")
        )
        host_key_trusted = bool(status.get("ssh_host_key_trusted"))
        ssh_key_verified = bool(status.get("ssh_key_verified"))
        ip_shield_deployed = bool(status.get("ip_shield_deployed"))
        domain = str(status.get("domain") or "")
        domain_tls_deployed = bool(status.get("domain_tls_deployed"))
        acme_accepted = bool(status.get("acme_terms_accepted"))

        enabled = bool(status.get("enabled"))
        running = bool(status.get("running"))
        connected = bool(status.get("connected"))
        health_error = str(status.get("health_error") or "")
        failure_code = str(status.get("failure_code") or "")
        health_hint = str(status.get("health_hint") or "")
        scope = str(status.get("scope") or "all")
        killswitch = bool(status.get("killswitch"))
        dns_protected = bool(status.get("dns_protected", status.get("dns_protection")))
        block_quic = bool(status.get("block_quic", False))
        quic_blocked = bool(status.get("quic_blocked"))
        online = status.get("online_targets")
        device_list = status.get("device_list") or []
        fingerprint = str(status.get("fingerprint") or "")
        behavior = str(status.get("behavior") or "")
        shield = str(status.get("shield") or status.get("shield_preset") or "")
        rx = status.get("bytes_recv") or 0
        tx = status.get("bytes_sent") or 0

        facts = [
            AgentFact("Client configured", self._yes_no(configured and has_keys), "info" if configured and has_keys else "warning"),
            AgentFact("IP Shield deployed", self._yes_no(ip_shield_deployed), "info" if ip_shield_deployed else "warning"),
            AgentFact("Domain HTTPS", domain if domain_tls_deployed else "Not active"),
            AgentFact("Enabled", self._yes_no(enabled and running), "info" if enabled and running else "warning"),
        ]
        if ssh_host:
            ssh_identity = "Trusted" if host_key_trusted else "Not trusted"
            ssh_auth = "Verified Ed25519 key" if ssh_key_verified else ("Credential available" if has_ssh_auth else "Missing")
            facts.extend([
                AgentFact("SSH server identity", ssh_identity, "info" if host_key_trusted else "warning"),
                AgentFact("SSH authentication", ssh_auth, "info" if has_ssh_auth else "warning"),
            ])
        if running:
            facts.extend([
                AgentFact("Connected to server", self._yes_no(connected), "info" if connected else "critical"),
                AgentFact("Scope", "Whole network" if scope == "all" else "Selected devices"),
                AgentFact("Kill-switch", "On" if killswitch else "Off", "info" if killswitch else "critical"),
                AgentFact("DNS protected", self._yes_no(dns_protected), "info" if dns_protected else "warning"),
            ])
            if block_quic:
                facts.append(AgentFact("QUIC leakage blocked", self._yes_no(quic_blocked), "info" if quic_blocked else "warning"))
        if connected:
            identity = domain if domain_tls_deployed and domain else (shield or "IP Shield")
            facts.append(AgentFact("Active TLS identity", identity))
            if fingerprint:
                facts.append(AgentFact("TLS/HTTP2 profile", fingerprint))
            if behavior:
                facts.append(AgentFact("Behavior mode", behavior))
            if scope == "selected":
                facts.append(AgentFact("Devices routed", f"{online if online is not None else 0} of {len(device_list)}"))
            facts.append(AgentFact("Transfer", f"↓ {self._bytes(rx)} · ↑ {self._bytes(tx)}"))

        summary, reason_chain, recommendations = self._answer(
            topic=topic,
            configured=configured,
            has_keys=has_keys,
            ssh_host=ssh_host,
            has_ssh_auth=has_ssh_auth,
            host_key_trusted=host_key_trusted,
            ssh_key_verified=ssh_key_verified,
            ip_shield_deployed=ip_shield_deployed,
            domain=domain,
            domain_tls_deployed=domain_tls_deployed,
            acme_accepted=acme_accepted,
            enabled=enabled,
            running=running,
            connected=connected,
            health_error=health_error,
            failure_code=failure_code,
            health_hint=health_hint,
            scope=scope,
            killswitch=killswitch,
            dns_protected=dns_protected,
            block_quic=block_quic,
            quic_blocked=quic_blocked,
            online=online,
            fingerprint=fingerprint,
            behavior=behavior,
        )

        return AgentResponse(
            category="service",
            target="stealth",
            matched=True,
            title="Stealth anti-censorship transport",
            summary=summary,
            confidence="high" if status else "low",
            section="stealth",
            subsection=topic,
            module=self.name,
            checks_run=["stealth_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _answer(self, *, topic: str, **state: object) -> tuple[str, list[str], list[str]]:
        if topic == "domain":
            domain = str(state["domain"] or "")
            if state["domain_tls_deployed"]:
                return (
                    f"Domain HTTPS is active for {domain}. The Stealth transport uses the trusted domain certificate, TLS SNI, "
                    "and HTTP Host for this name. The certificate is time-limited, but the VPS renewal service renews "
                    "it automatically and restarts the Stealth server only when needed.",
                    [
                        "The domain was validated through HTTP on the VPS; no DuckDNS token was required.",
                        "EasyPi verified the domain certificate and HTTP/2 before switching the live client.",
                    ],
                    [
                        "No routine renewal action is required.",
                        "Remove domain is safe: EasyPi first verifies and switches back to IP Shield, then removes the saved identity.",
                    ],
                )
            if domain:
                missing = []
                if not state["acme_accepted"]:
                    missing.append("Let's Encrypt agreement")
                if not state["ip_shield_deployed"]:
                    missing.append("initial Deploy & Start")
                detail = ", ".join(missing) if missing else "Configure Domain & TLS has not completed"
                return (
                    f"Domain HTTPS is saved but not active: {detail}. Stealth can continue working through IP Shield while this optional step is incomplete.",
                    [
                        "A domain is optional; IP Shield is the supported fallback.",
                        "Domain mode becomes active only after DNS, certificate, SNI, HTTP/2, and client connectivity are verified.",
                    ],
                    ["Point the domain to the VPS, complete the missing items on Server, then press Configure Domain & TLS once."],
                )
            return (
                "Stealth is fully supported without a domain. IP Shield uses a trusted certificate for the VPS public IP, so encryption and server authentication remain active. A DuckDNS domain is optional; it adds a normal hostname, SNI, and Host identity but does not make the tunnel invisible.",
                [
                    "No DuckDNS domain is stored, and Stealth never requests its token.",
                    "A single VPS remains visible as one network destination in either mode.",
                ],
                ["Keep IP Shield for the simplest setup, or add Domain HTTPS later if you want hostname/SNI semantics."],
            )

        if topic == "deployment":
            if not state["ssh_host"]:
                return (
                    "The Stealth exit server has not been configured. Deployment is a one-click workflow, but EasyPi first needs the public IPv4 address and SSH login for a VPS outside the censored network.",
                    ["No VPS SSH host is saved."],
                    ["On Server, enter the VPS SSH details and press Check SSH."],
                )
            if not state["host_key_trusted"]:
                return (
                    "EasyPi has not trusted this VPS SSH identity yet. It intentionally refuses deployment until you compare the displayed SHA-256 fingerprint with the VPS provider and approve it.",
                    ["SSH host-key pinning prevents silently connecting to an impersonated server."],
                    ["Press Check SSH, compare the fingerprint with the provider console, then trust it only if it matches."],
                )
            if not state["has_ssh_auth"]:
                return (
                    "The VPS identity is trusted, but no usable SSH credential is available.",
                    ["Deployment requires either the initial password or the EasyPi-managed Ed25519 key."],
                    ["Enter the VPS password once; EasyPi will install and verify a device-specific Ed25519 key, then remove the stored password."],
                )
            if not state["ip_shield_deployed"]:
                return (
                    "The secure SSH connection is ready, but the Stealth server and its IP Shield certificate have not been deployed yet.",
                    [
                        "Deploy & Start uploads the server, installs the service, obtains the trusted IP certificate, and verifies HTTP/2.",
                        "Deployment operations are serialized so two clicks cannot modify the VPS in parallel.",
                    ],
                    ["Accept the Let's Encrypt agreement and press Deploy & Start once."],
                )
            auth = "a verified Ed25519 key; the initial password has been removed" if state["ssh_key_verified"] else "the saved SSH credential"
            return (
                f"The Stealth server and IP Shield are deployed. EasyPi now administers the VPS with {auth}. Stored credentials are protected by the host system and TPM2 when available.",
                ["The trusted VPS identity and IP Shield deployment are recorded locally."],
                ["Use Server logs for diagnostics; Stop Server pauses it, while Remove from server uninstalls the service and its folder."],
            )

        if topic == "routing":
            scope_text = "the whole LAN" if state["scope"] == "all" else f"{state['online'] or 0} selected online device(s)"
            if not state["running"]:
                return (
                    f"Stealth is not running, so it currently routes none of {scope_text} through the protected transport.",
                    ["Saved scope takes effect when Stealth is enabled."],
                    ["Choose Whole network or Selected devices on Client, save routing, then enable Stealth."],
                )
            missing = []
            if not state["killswitch"]:
                missing.append("kill-switch")
            if not state["dns_protected"]:
                missing.append("DNS routing")
            if state["block_quic"] and not state["quic_blocked"]:
                missing.append("QUIC blocking")
            if missing:
                return (
                    f"Stealth is running for {scope_text}, but these leak protections are missing: {', '.join(missing)}.",
                    ["The live firewall/routing state does not match the saved protection settings."],
                    ["Disable and re-enable Stealth to rebuild its routing and firewall rules."],
                )
            return (
                f"Stealth routes {scope_text} through the protected transport. The kill-switch and DNS protection are active"
                + (", and UDP/443 is blocked so applications fall back to tunnelled TCP" if state["block_quic"] else "")
                + ". Selected devices are tracked by MAC address, so the scope follows DHCP address changes; the EasyPi panel remains reachable.",
                ["Runtime routing and leak-protection rules match the saved scope."],
                ["No routing action is needed."],
            )

        if topic == "profile":
            profile = str(state["fingerprint"] or "the selected browser profile")
            behavior = str(state["behavior"] or "adaptive")
            return (
                f"Stealth presents a browser-like TLS/HTTP/2 transport profile ({profile}) with {behavior} behavior. Mobile, desktop, and auto modes select the appropriate profile; Chrome-like HTTP/2 flow control avoids the earlier reactive WINDOW_UPDATE signature. This is best-effort camouflage, not a claim of undetectability.",
                [
                    "The encrypted inner traffic is carried inside authenticated TLS/HTTP/2 on TCP/443.",
                    "Tests confirmed stable transport and browser-like flow control, while one VPS still remains one visible endpoint.",
                ],
                ["Keep the working profile unless a new capture shows a specific measurable fingerprint."],
            )

        if topic == "lifecycle":
            return (
                "Enable and Disable control the local Stealth routing. Stop Server pauses the Stealth service on the VPS, Remove from server uninstalls it, Server logs reads diagnostics, and Reset learned profile removes only the locally learned behavior profile. Enabled strict routing is restored after an EasyPi reboot; protected devices remain offline until Chameleon reconnects or an administrator explicitly disables it.",
                ["Lifecycle controls are separated so a local disable does not accidentally uninstall the exit server."],
                ["Use the least destructive control that matches the intended result."],
            )

        if topic == "diagnostics" and state["enabled"] and state["running"]:
            if not state["connected"]:
                leak_state = "active" if state["killswitch"] and state["dns_protected"] else "missing or off"
                return (
                    f"Stealth is running but not connected; local kill-switch/DNS leak protection is {leak_state}.",
                    ["Runtime connection and leak-protection flags were evaluated directly."],
                    ["Restore the carrier connection and re-enable protection rules if they are missing."],
                )
            if state["killswitch"] and state["dns_protected"] and (not state["block_quic"] or state["quic_blocked"]):
                return (
                    "Stealth is healthy and connected; kill-switch and DNS protection are active.",
                    ["The live runtime reports an established carrier connection and active leak protection."],
                    ["No action is required."],
                )

        if not state["configured"] or not state["has_keys"]:
            return (
                "Stealth is not configured yet. It needs a client endpoint, PSK, and identity key before the server can be deployed.",
                ["The Client configuration or generated keys are incomplete."],
                ["On Client, generate both keys, enter the VPS address, and save the client."],
            )
        if not state["ssh_host"]:
            return (
                "The client is configured, but no VPS exit server is saved.",
                ["Stealth needs a user-controlled VPS outside the censored network."],
                ["Open Server and enter the VPS SSH details."],
            )
        if not state["ip_shield_deployed"]:
            return (
                "The client is configured, but the Stealth server and trusted IP Shield identity are not deployed.",
                ["Stealth will not enable without a verified server certificate."],
                ["Complete Check SSH / fingerprint trust, then run Deploy & Start."],
            )
        if not state["enabled"] or not state["running"]:
            return (
                "Stealth is configured and its exit server is deployed, but local routing is off.",
                ["The saved configuration remains available; no selected traffic is currently tunnelled."],
                ["Press Enable when you want the saved routing scope to use Stealth."],
            )
        if not state["connected"]:
            title = state["health_error"] or state["failure_code"] or "the server connection has not completed"
            recommendation = state["health_hint"] or "Open Server logs, check VPS reachability on TCP/443, and run Deploy & Start if needed."
            return (
                f"Stealth is enabled locally but not connected: {title}. The kill-switch should keep protected devices from leaking directly while recovery is required.",
                [f"Runtime failure code: {state['failure_code'] or 'not reported'}."],
                [str(recommendation)],
            )
        if state["scope"] == "selected" and int(state["online"] or 0) == 0:
            return (
                "Stealth is connected, but none of the selected devices is currently online, so no device traffic is entering the tunnel.",
                ["Selected-device scope resolves devices by their saved MAC addresses."],
                ["Bring a selected device online, select a different device, or switch to Whole network."],
            )
        if not state["killswitch"] or not state["dns_protected"] or (state["block_quic"] and not state["quic_blocked"]):
            return (
                "The tunnel is connected, but one or more local leak-protection rules are missing.",
                ["Runtime protection state is incomplete even though the carrier connection is up."],
                ["Disable and re-enable Stealth to rebuild the firewall and routing state."],
            )
        identity = str(state["domain"] or "IP Shield") if state["domain_tls_deployed"] else "IP Shield"
        return (
            f"Stealth is healthy and connected through {identity}. The saved routing scope, kill-switch, DNS protection, and browser-like transport profile are active. This is a strong best-effort anti-DPI transport; a network observer can still see the single VPS endpoint and no mode guarantees invisibility.",
            ["Client, server identity, carrier connection, and leak protections all report healthy."],
            ["No action is required."],
        )

    @staticmethod
    def _yes_no(value: bool) -> str:
        return "Yes" if value else "No"

    @staticmethod
    def _bytes(n: object) -> str:
        try:
            value = int(n)
        except Exception:
            value = 0
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if value < 1024:
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} PB"
