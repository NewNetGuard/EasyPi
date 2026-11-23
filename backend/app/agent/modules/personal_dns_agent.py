"""Personal DNS diagnostics module."""

from __future__ import annotations

import re

from app.agent.adapters.personal_dns import PersonalDNSAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class PersonalDNSAgent:
    """Explain Personal DNS deployment and reachability state."""

    name = "personal_dns_agent"
    _KEYWORDS = (
        "personal dns",
        "encrypted dns",
        "dns deploy",
        "dns deployment",
        "doh",
        "dot",
        "dns server",
        "vps dns",
        "dns cleanup",
        "personal dns certificate",
        "dns certificate",
        "doh certificate",
        "dot certificate",
        "dns tls",
        "certbot",
        "upstream",
        "resolver",
        "public dns",
        "firewall",
    )
    _ROUTES = ("personal-dns",)
    _IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def __init__(self, adapter: PersonalDNSAdapter, netprotection=None) -> None:
        self.adapter = adapter
        self.netprotection = netprotection

    async def _local_dns_response(self) -> AgentResponse:
        """Report the LOCAL NetProtection DNS server (the 'Local NetProtection'
        card in the Personal DNS section) — used when there is no remote VPS
        deployment, which is the common case."""
        status = await self.netprotection.get_status()
        ds = await self.netprotection.get_dashboard_stats()
        running = bool(status.get("running"))
        protection_enabled = bool(status.get("protection_enabled"))
        transparent = bool(status.get("transparent_dns"))
        facts = [
            AgentFact("Local DNS server", "Running" if running else "Stopped", "info" if running else "critical"),
            AgentFact("Blocklist domains", str(ds.get("blocked_domains") or 0)),
            AgentFact("Total queries", str(ds.get("total_queries") or 0)),
            AgentFact("Blocked queries", str(ds.get("blocked_today") or 0)),
            AgentFact("Block rate", "%.1f%%" % float(ds.get("block_percentage") or 0)),
            AgentFact("Transparent DNS", self._yes_no(transparent)),
            AgentFact("VPS deployment", "None"),
        ]
        if running and protection_enabled and float(ds.get("block_percentage") or 0) > 0:
            summary = "The local Personal DNS server (NetProtection) is running and filtering queries."
            confidence = "high"
            reason_chain = [
                "No remote VPS deployment record was found.",
                "The local NetProtection DNS server status and statistics were inspected.",
                "The local resolver is running and serving filtered DNS.",
            ]
            recommendations = [
                "Point your router or devices at this EasyPi as their DNS server to use it.",
                "Optionally deploy Personal DNS to a VPS for encrypted remote access.",
            ]
        elif running:
            summary = "The local Personal DNS service is running, but filtering is disabled or unconfirmed by current counters."
            confidence = "medium"
            reason_chain = [
                "The local NetProtection process reports as running.",
                "Protection is disabled or current counters do not show filtering evidence.",
            ]
            recommendations = ["Enable protection and verify fresh blocked-query counters before calling filtering active."]
        else:
            summary = "The local Personal DNS server (NetProtection) is not running."
            confidence = "high"
            reason_chain = [
                "No remote VPS deployment record was found.",
                "The local NetProtection DNS server reports as stopped.",
            ]
            recommendations = [
                "Start NetProtection from Guard Security to serve local DNS.",
            ]
        return AgentResponse(
            category="service",
            target="personal-dns",
            matched=True,
            title="Personal DNS diagnostics",
            summary=summary,
            confidence=confidence,
            section="personal-dns",
            subsection="local-server",
            module=self.name,
            checks_run=["netprotection_status", "dashboard_stats"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 125
        if any(token in route for token in self._ROUTES):
            score += 80
        if self._extract_ip(request.target or request.question):
            score += 35
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        try:
            deploy = self.adapter.get_latest_deploy(user_id=request.actor_user_id)
        except Exception as exc:
            return AgentResponse(
                category="service",
                target="personal-dns",
                matched=True,
                title="Personal DNS source unavailable",
                summary="Personal DNS deployment state cannot be confirmed because its source failed.",
                confidence="low",
                section="personal-dns",
                subsection="deployment",
                module=self.name,
                source_status="unavailable",
                source_errors=[f"{type(exc).__name__}: {exc}"],
                facts=[AgentFact("Source failure", f"{type(exc).__name__}: {exc}", "warning")],
                reason_chain=["The deployment source failed before tenant-scoped state could be loaded."],
                recommendations=["Restore the Personal DNS deployment source and retry."],
            )
        target_ip = self._extract_ip(request.target or request.question)
        if target_ip and deploy is None:
            deploy = {
                "vps_ip": target_ip,
                "status": "unknown",
                "domain": None,
                "wireguard_installed": False,
                "warnings": [],
                "recommendations": [],
            }

        dns_certificate_request = self._is_dns_certificate_request(question, target)

        if deploy is None:
            # No remote VPS deployment — report the LOCAL NetProtection DNS
            # server (what the section's main card shows) instead of nothing.
            if self.netprotection is not None:
                return await self._local_dns_response()
            return AgentResponse(
                category="service",
                target="personal-dns",
                matched=True,
                title="Personal DNS diagnostics",
                summary="EasyPi does not have a saved Personal DNS deployment yet.",
                confidence="high",
                section="personal-dns",
                subsection="deployment",
                module=self.name,
                checks_run=["dns_deploy_history"],
                facts=[],
                reason_chain=[
                    "The local Personal DNS deployment history was checked.",
                    "No saved deployment record was found.",
                ],
                recommendations=[
                    "Deploy a Personal DNS server to a VPS before checking reachability.",
                ],
            )

        vps_ip = str(deploy.get("vps_ip") or deploy.get("dns_ipv4") or target_ip or "").strip()
        remote_status = await self.adapter.get_remote_status(vps_ip) if vps_ip else {}
        facts = [
            AgentFact("VPS IP", vps_ip or "Unknown"),
            AgentFact("Deployment status", str(deploy.get("status") or "unknown")),
            AgentFact("Domain", str(deploy.get("domain") or "Not configured")),
            AgentFact("WireGuard included", self._yes_no(bool(deploy.get("wireguard_installed")))),
        ]
        inspect_method = getattr(self.adapter, "inspect_deployment_log", None)
        log_flags = (
            inspect_method(deploy)
            if callable(inspect_method)
            else {
                "mentions_certificate": False,
                "mentions_upstream": False,
                "mentions_cleanup": False,
                "mentions_firewall": False,
            }
        )

        if deploy.get("deployment_date"):
            facts.append(AgentFact("Deployment date", str(deploy.get("deployment_date"))))
        if deploy.get("doh_url"):
            facts.append(AgentFact("DoH URL", str(deploy.get("doh_url"))))
        if deploy.get("dot_address"):
            facts.append(AgentFact("DoT endpoint", str(deploy.get("dot_address"))))
        if deploy.get("admin_url"):
            facts.append(AgentFact("Admin panel", str(deploy.get("admin_url"))))
        reachable_raw = remote_status.get("reachable") if remote_status else None
        if reachable_raw is None and remote_status:
            if "is_online" in remote_status:
                reachable_raw = remote_status.get("is_online")
            elif str(remote_status.get("status") or "").lower() in {"online", "reachable", "healthy"}:
                reachable_raw = True
        admin_raw = remote_status.get("admin_panel") if remote_status and "admin_panel" in remote_status else None
        dns_raw = remote_status.get("dns_port") if remote_status and "dns_port" in remote_status else None
        if remote_status:
            facts.extend(
                [
                    AgentFact("VPS reachable", self._yes_no(bool(reachable_raw)) if reachable_raw is not None else "Unknown", "info" if reachable_raw else "warning"),
                    AgentFact("Admin port", self._yes_no(bool(admin_raw)) if admin_raw is not None else "Unknown", "info" if admin_raw else "warning"),
                    AgentFact("DNS port", self._yes_no(bool(dns_raw)) if dns_raw is not None else "Unknown", "info" if dns_raw else "warning"),
                ]
            )
        if log_flags["mentions_certificate"]:
            facts.append(AgentFact("Certificate activity", "Detected in deployment log"))
        if log_flags["mentions_upstream"]:
            facts.append(AgentFact("Upstream DNS activity", "Detected in deployment log"))
        if log_flags["mentions_firewall"]:
            facts.append(AgentFact("Firewall activity", "Detected in deployment log"))

        deploy_status = str(deploy.get("status") or "unknown").lower()
        reachable = bool(reachable_raw) if reachable_raw is not None else None
        admin_panel = bool(admin_raw) if admin_raw is not None else None
        dns_port = bool(dns_raw) if dns_raw is not None else None

        if dns_certificate_request and not log_flags["mentions_certificate"]:
            summary = "Personal DNS certificate validity was not checked, so a certificate-specific failure cannot be confirmed or excluded."
            confidence = "low"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log does not contain certificate-related entries.",
            ]
        elif dns_certificate_request and log_flags["mentions_certificate"]:
            summary = "The latest Personal DNS deployment log points to certificate or TLS activity as part of the current issue."
            confidence = "high" if deploy_status == "failed" else "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log contains certificate or TLS-related entries.",
            ]
        elif ("upstream" in question or "resolver" in question) and not log_flags["mentions_upstream"]:
            summary = "The saved Personal DNS deployment data do not show an upstream DNS-specific failure."
            confidence = "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log does not contain upstream DNS-related entries.",
            ]
        elif ("upstream" in question or "resolver" in question) and log_flags["mentions_upstream"]:
            summary = "The latest Personal DNS deployment log points to an upstream DNS or resolver issue."
            confidence = "high" if deploy_status == "failed" else "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log contains upstream DNS or resolver-related entries.",
            ]
        elif "cleanup" in question and not log_flags["mentions_cleanup"]:
            summary = "The saved Personal DNS deployment data do not show a cleanup-specific failure."
            confidence = "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log does not contain cleanup-related entries.",
            ]
        elif "cleanup" in question and log_flags["mentions_cleanup"]:
            summary = "The latest Personal DNS deployment log points to cleanup activity as part of the current issue."
            confidence = "high" if deploy_status == "failed" else "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log contains cleanup-related entries.",
            ]
        elif ("firewall" in question or "public dns" in question or "resolve" in question) and log_flags["mentions_firewall"]:
            summary = "The latest Personal DNS deployment log points to firewall or exposed-port configuration as part of the current issue."
            confidence = "high" if not reachable else "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The saved deployment log contains firewall or listener-related entries.",
            ]
        elif deploy_status == "failed":
            summary = "The latest Personal DNS deployment is marked as failed."
            confidence = "high"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "Its saved deployment status is 'failed'.",
            ]
        elif remote_status and reachable and admin_panel is False and dns_port is False:
            summary = "The Personal DNS host is reachable, but both the admin and DNS service ports are unavailable."
            confidence = "high"
            reason_chain = [
                "The host-level reachability check succeeded.",
                "Both service-specific port checks failed.",
            ]
        elif remote_status and reachable is False:
            summary = "A Personal DNS deployment exists, but the VPS is not reachable right now."
            confidence = "high"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "A remote status check could not reach the VPS admin or DNS ports.",
            ]
        elif remote_status and admin_panel and not dns_port:
            summary = "The Personal DNS VPS is reachable, but the DNS port is not responding."
            confidence = "high"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The admin panel responds, but DNS port reachability failed.",
            ]
        elif remote_status and dns_port and not admin_panel:
            summary = "The DNS service responds, but the Personal DNS admin panel is not reachable."
            confidence = "high"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The DNS port responds, but the admin panel check failed.",
            ]
        elif remote_status and reachable:
            summary = "Personal DNS deployment looks reachable from EasyPi."
            confidence = "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "The remote VPS status check reached at least one service port.",
            ]
        else:
            summary = "Personal DNS deployment history was found, but remote reachability could not be confirmed."
            confidence = "medium"
            reason_chain = [
                "The latest deployment record was loaded from local history.",
                "No fresh reachability details were available for the VPS.",
            ]

        recommendations = [
            "Open Personal DNS to inspect the latest deployment record and VPS details.",
            "If reachability failed, verify the VPS firewall, Docker container state, and exposed ports.",
        ]
        if not deploy.get("domain"):
            recommendations.append("Add a domain if you want DoH or DoT endpoints instead of raw IP-only access.")

        return AgentResponse(
            category="service",
            target=vps_ip or "personal-dns",
            matched=True,
            title="Personal DNS diagnostics",
            summary=summary,
            confidence=confidence,
            section="personal-dns",
            subsection="deployment",
            module=self.name,
            checks_run=["dns_deploy_history", "dns_remote_status"] if remote_status else ["dns_deploy_history"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _extract_ip(self, value: str) -> str | None:
        match = self._IP_RE.search(str(value or ""))
        if not match:
            return None
        return match.group(0)

    def _is_dns_certificate_request(self, question: str, target: str) -> bool:
        combined = f"{question} {target}".strip()
        return any(
            token in combined
            for token in (
                "personal dns certificate",
                "dns certificate",
                "doh certificate",
                "dot certificate",
                "dns tls",
                "certbot",
            )
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
