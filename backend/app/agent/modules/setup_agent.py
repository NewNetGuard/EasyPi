"""Setup and settings agent module."""

from __future__ import annotations

from app.agent.adapters.setup import SetupAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class SetupAgent:
    """Explain setup, permissions, and basic settings state."""

    name = "setup_agent"
    _HTTPS_CERT_KEYWORDS = (
        "certificate",
        "cert",
        "ssl",
        "https",
        "tls",
        "self-signed",
        "self signed",
        "browser warning",
        "secure connection",
        "nginx certificate",
        "web certificate",
        "panel certificate",
    )
    _DNS_CERT_CONTEXT = (
        "personal dns",
        "encrypted dns",
        "doh",
        "dot",
        "dns tls",
        "dns certificate",
        "dns cert",
        "vps dns",
        "resolver",
    )
    _PERMISSION_KEYWORDS = ("permission", "permissions", "sudo", "group", "relogin", "easypi group")
    _DNS_KEYWORDS = ("system dns", "pi dns", "resolver", "nameserver")
    _TIME_KEYWORDS = ("timezone", "time zone", "clock")
    _UPDATE_KEYWORDS = ("update", "upgrade", "restart services", "restart backend", "restart easypi")
    _GENERAL_KEYWORDS = ("setup", "system info", "hostname", "easypi installed")
    _ROUTES = ("setup", "settings")

    def __init__(self, adapter: SetupAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if self._is_web_certificate_request(question, target):
            score += 180
        if self._matches_any(question, target, self._PERMISSION_KEYWORDS):
            score += 95
        if self._is_dns_setup_request(question, target, route):
            score += 90
        if self._matches_any(question, target, self._TIME_KEYWORDS):
            score += 80
        if self._matches_any(question, target, self._UPDATE_KEYWORDS):
            score += 85
        if self._matches_any(question, target, self._GENERAL_KEYWORDS):
            score += 60
        if any(token in route for token in self._ROUTES):
            score += 25
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        target = (request.target or "").lower()
        route = (request.route or "").lower()

        if self._is_web_certificate_request(question, target):
            return await self._https_certificate_response(question=question)
        if self._matches_any(question, target, self._PERMISSION_KEYWORDS):
            return await self._permissions_response()
        if self._is_dns_setup_request(question, target, route):
            return await self._dns_response()
        if self._matches_any(question, target, self._TIME_KEYWORDS):
            return await self._timezone_response()
        if self._matches_any(question, target, self._UPDATE_KEYWORDS):
            return await self._update_response(question=question)
        if self._matches_any(question, target, self._GENERAL_KEYWORDS) or any(token in route for token in self._ROUTES):
            return await self._overview_response()
        return None

    async def _permissions_response(self) -> AgentResponse:
        status = await self.adapter.get_permissions_status()
        if not status:
            return self._unavailable_response("setup-permissions", "Setup permissions diagnostics", "Permission status")
        permissions_ok = bool(status.get("permissions_ok"))
        needs_relogin = bool(status.get("needs_relogin"))
        facts = [
            AgentFact("Current user", str(status.get("current_user") or "Unknown")),
            AgentFact("EasyPi group exists", self._yes_no(bool(status.get("group_exists")))),
            AgentFact("User in EasyPi group", self._yes_no(bool(status.get("in_easypi_group")))),
            AgentFact("Sudo configured", self._yes_no(bool(status.get("sudo_configured")))),
            AgentFact("Needs relogin", self._yes_no(needs_relogin), "warning" if needs_relogin else "info"),
        ]

        if bool(status.get("is_development")):
            summary = "EasyPi is running in development mode, so Linux permission checks are not required here."
            confidence = "high"
            reason_chain = [
                "The setup status endpoint reported development mode.",
                "Linux group and sudo configuration are not enforced in this mode.",
            ]
        elif permissions_ok:
            summary = "EasyPi permissions look healthy."
            confidence = "high"
            reason_chain = [
                "The permissions status endpoint was queried.",
                "Group membership and sudo configuration both look correct.",
            ]
        elif needs_relogin:
            summary = "The user was added to the EasyPi group, but the current session still needs a restart or relogin."
            confidence = "high"
            reason_chain = [
                "The permissions status endpoint was queried.",
                "The user exists in the EasyPi group file, but the active session does not have the group yet.",
            ]
        else:
            summary = "EasyPi setup permissions are incomplete."
            confidence = "high"
            reason_chain = [
                "The permissions status endpoint was queried.",
                "Required group membership or sudo configuration is still missing.",
            ]

        if bool(status.get("is_development")):
            recommendations = ["No Linux permissions remediation is required in development mode."]
        elif permissions_ok:
            recommendations = [
                "No permissions remediation is required.",
                "Keep the EasyPi sudo policy root-owned and use only the reviewed privileged runner.",
            ]
        elif needs_relogin:
            recommendations = [
                "Restart the EasyPi services or relogin so the active session receives the EasyPi group.",
            ]
        elif not bool(status.get("sudo_configured")):
            recommendations = [
                "Restore the root-owned EasyPi sudo policy from the local console or rerun the installer.",
                "The agent cannot safely bootstrap its own root permissions.",
            ]
        else:
            recommendations = [
                "Run the permissions setup flow to repair the EasyPi group membership.",
            ]

        return AgentResponse(
            category="service",
            target="setup-permissions",
            matched=True,
            title="Setup permissions diagnostics",
            summary=summary,
            confidence=confidence,
            section="setup",
            subsection="permissions",
            module=self.name,
            checks_run=["permissions_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    async def _dns_response(self) -> AgentResponse:
        status = await self.adapter.get_dns_status()
        current_dns = status.get("current_dns") or []
        facts = [
            AgentFact("Current DNS", ", ".join(str(value) for value in current_dns) or "Unknown"),
            AgentFact("Connection", str(status.get("connection_name") or "Unknown")),
            AgentFact("Ignore DHCP DNS", self._yes_no(bool(status.get("ignore_dhcp_dns")))),
        ]
        summary = "EasyPi system DNS settings were loaded successfully."
        reason_chain = [
            "The Pi DNS status endpoint was queried.",
            "Current resolver entries and NetworkManager settings were inspected.",
        ]
        if not current_dns:
            summary = "EasyPi could not find active DNS servers for the Pi itself."
            reason_chain.append("No nameserver entries were found in the current DNS status.")
        elif not bool(status.get("ignore_dhcp_dns")):
            summary = "System DNS is not pinned because DHCP is still allowed to overwrite the configured resolver."
            reason_chain.append("Ignore-DHCP DNS is disabled for the active connection.")

        return AgentResponse(
            category="service",
            target="system-dns",
            matched=True,
            title="System DNS diagnostics",
            summary=summary,
            confidence="high" if current_dns else "medium",
            section="setup",
            subsection="dns",
            module=self.name,
            checks_run=["system_dns_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "If the Pi should ignore DHCP DNS, keep that setting enabled in Setup.",
                "Review resolver settings if upstream DNS changes unexpectedly.",
            ],
        )

    async def _https_certificate_response(self, *, question: str) -> AgentResponse:
        state = await self.adapter.get_https_certificate_state()
        cert_exists = bool(state.get("cert_exists"))
        key_exists = bool(state.get("key_exists"))
        certificate_kind = str(state.get("certificate_kind") or "unknown")
        cert_size = int(state.get("cert_size") or 0)
        key_size = int(state.get("key_size") or 0)
        facts = [
            AgentFact("Certificate path", str(state.get("cert_path") or "Unknown")),
            AgentFact("Private key path", str(state.get("key_path") or "Unknown")),
            AgentFact("Certificate file present", self._yes_no(cert_exists), "info" if cert_exists else "warning"),
            AgentFact("Private key present", self._yes_no(key_exists), "info" if key_exists else "warning"),
            AgentFact("Certificate kind", certificate_kind),
        ]
        if cert_exists:
            facts.append(AgentFact("Certificate file size", f"{cert_size} bytes"))
        if key_exists:
            facts.append(AgentFact("Private key size", f"{key_size} bytes"))

        if cert_exists and key_exists and (cert_size < 256 or key_size < 256):
            summary = "EasyPi HTTPS files are present but too small to be validated as a certificate and key; they may be corrupt."
            confidence = "low"
            reason_chain = [
                "The configured certificate and key paths both exist.",
                "Their file sizes are implausibly small, so presence alone does not establish validity.",
            ]
        elif cert_exists and key_exists and certificate_kind == "public-ca":
            summary = "EasyPi is configured with a public-CA HTTPS certificate; the reported browser warning needs a separate validity or hostname check."
            confidence = "medium"
            reason_chain = [
                "The certificate metadata identifies a public-CA certificate.",
                "File presence does not validate its hostname, chain, or expiry.",
            ]
        elif cert_exists and key_exists and certificate_kind == "self-signed" and any(token in question for token in ("warning", "browser", "self-signed", "self signed")):
            summary = "EasyPi web HTTPS certificate files exist, and browser warnings are expected because the current certificate is self-signed."
            confidence = "high"
            reason_chain = [
                "The local EasyPi HTTPS certificate paths were inspected.",
                "Both the self-signed certificate file and the private key are present.",
                "Browsers still warn because the current certificate is self-signed rather than trusted by a public CA.",
            ]
        elif cert_exists and key_exists:
            summary = "EasyPi web HTTPS certificate files exist locally."
            confidence = "high"
            reason_chain = [
                "The local EasyPi HTTPS certificate paths were inspected.",
                "Both the certificate file and the private key are present at the expected EasyPi locations.",
            ]
        else:
            summary = "EasyPi web HTTPS certificate setup is incomplete because the certificate file or private key is missing."
            confidence = "high"
            reason_chain = [
                "The local EasyPi HTTPS certificate paths were inspected.",
                "At least one required file is missing from the expected EasyPi certificate locations.",
            ]

        if certificate_kind == "public-ca" and cert_exists and key_exists:
            recommendations = [
                "Validate the certificate hostname, validity dates, and chain against the URL shown in the browser.",
                "Do not replace a public-CA certificate with a self-signed certificate to address a hostname or chain warning.",
            ]
        elif not cert_exists or not key_exists:
            recommendations = [
                "Restore the missing certificate or private-key file, then validate the resulting HTTPS configuration.",
            ]
        else:
            recommendations = [
                "Keep using the self-signed certificate only for local access, or install a trusted certificate if browser warnings should disappear.",
            ]

        return AgentResponse(
            category="service",
            target="easypi-https-certificate",
            matched=True,
            title="EasyPi HTTPS certificate diagnostics",
            summary=summary,
            confidence=confidence,
            section="setup",
            subsection="https",
            module=self.name,
            checks_run=["https_certificate_state"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    async def _timezone_response(self) -> AgentResponse:
        timezone_info = await self.adapter.get_timezone()
        if not timezone_info.get("timezone"):
            return self._unavailable_response("timezone", "Timezone diagnostics", "Timezone")
        timezone_value = str(timezone_info.get("timezone") or "Unknown")
        return AgentResponse(
            category="service",
            target="timezone",
            matched=True,
            title="Timezone diagnostics",
            summary=f"EasyPi is currently configured for timezone '{timezone_value}'.",
            confidence="high",
            section="settings",
            subsection="general",
            module=self.name,
            checks_run=["timezone_status"],
            facts=[
                AgentFact("Timezone", timezone_value),
                AgentFact("Development mode", self._yes_no(bool(timezone_info.get("is_development")))),
            ],
            reason_chain=[
                "The timezone setting was queried from the system settings endpoint.",
            ],
            recommendations=[
                "Change the timezone in Settings if system time should follow a different region.",
            ],
        )

    async def _update_response(self, *, question: str) -> AgentResponse:
        permissions = await self.adapter.get_permissions_status()
        system_info = await self.adapter.get_system_info()
        installed = bool(system_info.get("easypi_installed"))
        permissions_ok = bool(permissions.get("permissions_ok"))
        needs_relogin = bool(permissions.get("needs_relogin"))
        facts = [
            AgentFact("EasyPi installed", self._yes_no(installed), "info" if installed else "warning"),
            AgentFact("Current user", str(system_info.get("current_user") or permissions.get("current_user") or "Unknown")),
            AgentFact("Permissions OK", self._yes_no(permissions_ok), "info" if permissions_ok else "warning"),
            AgentFact("Needs relogin", self._yes_no(needs_relogin), "warning" if needs_relogin else "info"),
        ]

        if not installed:
            summary = "EasyPi update and restart flows are only available on an installed EasyPi node."
            confidence = "high"
            reason_chain = [
                "The setup adapter inspected local system installation facts.",
                "This node does not report an installed EasyPi deployment.",
            ]
        elif needs_relogin:
            summary = "EasyPi service restart or update actions may fail until the current session picks up the required group membership."
            confidence = "high"
            reason_chain = [
                "The setup adapter inspected local permission state.",
                "The account still needs a relogin or backend restart to pick up the EasyPi group in the active session.",
            ]
        elif not permissions_ok:
            summary = "EasyPi is installed, but setup permissions are incomplete for safe restart or update actions."
            confidence = "high"
            reason_chain = [
                "The setup adapter inspected local system installation facts.",
                "The node is installed, but current permission checks are still incomplete.",
            ]
        elif "restart" in question:
            summary = "EasyPi restart capability looks available from the current setup state."
            confidence = "medium"
            reason_chain = [
                "The setup adapter inspected local system installation and permission facts.",
                "EasyPi is installed and current permission checks look healthy enough for restart operations.",
            ]
        else:
            summary = "EasyPi update capability looks available from the current setup state."
            confidence = "medium"
            reason_chain = [
                "The setup adapter inspected local system installation and permission facts.",
                "EasyPi is installed and current permission checks look healthy enough for update operations.",
            ]

        return AgentResponse(
            category="service",
            target="setup-update",
            matched=True,
            title="Setup update and restart diagnostics",
            summary=summary,
            confidence=confidence,
            section="setup",
            subsection="maintenance",
            module=self.name,
            checks_run=["system_info", "permissions_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Complete Setup permissions before running update or restart operations from EasyPi.",
                "Use the Setup maintenance controls only after the current session has picked up the required group membership.",
            ],
        )

    async def _overview_response(self) -> AgentResponse:
        permissions = await self.adapter.get_permissions_status()
        system_info = await self.adapter.get_system_info()
        if not permissions and not system_info:
            return self._unavailable_response("setup", "Setup overview diagnostics", "Setup overview")
        facts = [
            AgentFact("Hostname", str(system_info.get("hostname") or "Unknown")),
            AgentFact("OS", str(system_info.get("os") or "Unknown")),
            AgentFact("Current user", str(system_info.get("current_user") or "Unknown")),
            AgentFact("EasyPi installed", self._yes_no(bool(system_info.get("easypi_installed")))),
            AgentFact("Permissions OK", self._yes_no(bool(permissions.get("permissions_ok")))),
        ]
        return AgentResponse(
            category="service",
            target="setup",
            matched=True,
            title="Setup overview diagnostics",
            summary="EasyPi setup and basic system information were collected successfully.",
            confidence="medium",
            section="setup",
            subsection="overview",
            module=self.name,
            checks_run=["system_info", "permissions_status"],
            facts=facts,
            reason_chain=[
                "The setup overview uses local system information and permission status.",
            ],
            recommendations=[
                "Ask a more specific question about permissions, DNS, or timezone for a deeper explanation.",
            ],
        )

    def _matches_any(self, question: str, target: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword in question or keyword in target for keyword in keywords)

    def _is_dns_setup_request(self, question: str, target: str, route: str) -> bool:
        if self._matches_any(question, target, self._DNS_KEYWORDS):
            return True
        return ("dns" in question or "dns" in target) and any(token in route for token in self._ROUTES)

    def _is_web_certificate_request(self, question: str, target: str) -> bool:
        if not self._matches_any(question, target, self._HTTPS_CERT_KEYWORDS):
            return False
        return not self._matches_any(question, target, self._DNS_CERT_CONTEXT)

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _unavailable_response(self, target: str, title: str, source: str) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=target,
            matched=True,
            title=title,
            summary=f"{source} data are unavailable, so the current state is unknown.",
            confidence="low",
            section="setup",
            subsection="overview",
            module=self.name,
            checks_run=[],
            facts=[AgentFact("Source data", "Unavailable", "warning")],
            reason_chain=[f"The {source.lower()} source returned no authoritative payload."],
            recommendations=["Check the Setup backend source and retry."],
        )
