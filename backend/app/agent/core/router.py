"""Request router for the EasyPi agent."""

from __future__ import annotations

from app.agent.core.context import build_agent_context
from app.agent.core.contracts import AgentContext
from app.agent.core.contracts import AgentRequest
from app.agent.core.module import AgentModule
from app.agent.core.registry import AgentRegistry


class AgentRouter:
    """Select the best module for a given request."""

    _ROUTE_HINTS: dict[str, dict[str, int]] = {
        "dashboard": {
            "dashboard_agent": 60,
            "dashboard_incident_agent": 35,
            "monitoring_agent": 30,
            "remote_dashboard_services_reasoning_agent": 25,
            "vpn_dashboard_security_reasoning_agent": 20,
        },
        "guard-security": {
            "netprotection_agent": 120,
            "guard_remote_setup_reasoning_agent": 45,
            "setup_guard_network_reasoning_agent": 30,
        },
        "personal-dns": {
            "personal_dns_agent": 80,
        },
        "ip-cameras": {
            "cameras_agent": 80,
            "camera_backup_cloud_reasoning_agent": 35,
        },
        "cloud": {
            "cloud_agent": 80,
            "camera_backup_cloud_reasoning_agent": 35,
        },
        "settings": {
            "settings_agent": 80,
            "users_security_settings_reasoning_agent": 50,
            "users_agent": 30,
        },
        "setup": {
            "setup_agent": 80,
            "setup_guard_network_reasoning_agent": 50,
            "guard_remote_setup_reasoning_agent": 45,
        },
        "remote-access": {
            "remote_access_agent": 80,
            "remote_dashboard_services_reasoning_agent": 95,
        },
        "network-activity": {
            "network_activity_agent": 80,
            "setup_guard_network_reasoning_agent": 40,
        },
        "network-toolkit": {
            "network_toolkit_agent": 80,
        },
        "security": {
            "security_agent": 80,
            "users_security_settings_reasoning_agent": 45,
            "vpn_dashboard_security_reasoning_agent": 35,
        },
        "system-backup": {
            "backup_agent": 80,
            "camera_backup_cloud_reasoning_agent": 40,
        },
        "jobs": {
            "jobs_agent": 120,
        },
        "rollback": {
            "rollback_agent": 120,
            "backup_agent": 25,
        },
        "users": {
            "users_agent": 80,
            "users_auth_reasoning_agent": 55,
            "users_security_settings_reasoning_agent": 45,
        },
        "vpn": {
            "wireguard_agent": 80,
            "vpn_dashboard_security_reasoning_agent": 55,
        },
        "internet-encryption": {
            "outbound_vpn_agent": 120,
        },
        "stealth": {
            # Explicit Stealth page context must outrank the generic EasyPi web
            # certificate helper for Domain HTTPS / Let's Encrypt questions.
            "stealth_agent": 160,
        },
        "marketplace": {
            "marketplace_agent": 120,
        },
        "monitoring": {
            "monitoring_agent": 80,
            "dashboard_agent": 40,
        },
        "notifications": {
            "notifications_agent": 120,
            "dashboard_incident_agent": 45,
            "security_agent": 35,
            "settings_agent": 20,
        },
        "file-manager": {
            "files_agent": 80,
        },
        "terminal": {
            "terminal_agent": 80,
        },
        "help": {
            "help_agent": 80,
        },
        "ai-chat": {
            "ai_runtime_agent": 80,
            "claude_provider_agent": 55,
        },
        "claude": {
            "claude_provider_agent": 80,
            "ai_runtime_agent": 45,
        },
    }
    _TAB_HINTS: dict[str, dict[str, int]] = {
        "notifications": {"settings_agent": 40},
        "security": {
            "settings_agent": 30,
            "security_agent": 20,
            "users_security_settings_reasoning_agent": 35,
        },
        "user": {"settings_agent": 35, "users_agent": 25},
        "general": {"settings_agent": 35, "setup_agent": 20},
        "dns": {"setup_agent": 35, "personal_dns_agent": 25, "netprotection_agent": 20},
        "dashboard": {"dashboard_agent": 35, "netprotection_agent": 20},
    }
    _GUARD_SECURITY_TABS = {
        "dashboard",
        "ad-tracker",
        "nrd",
        "shadow-mode",
        "heuristics",
        "parental",
        "schedules",
        "devices",
        "ad-blocking",
        "lists",
        "firewall",
        "query-log",
        "security",
        "statistics",
        "dns",
        "advanced",
    }
    _ENTITY_HINTS: dict[str, dict[str, int]] = {
        "camera": {"cameras_agent": 45, "camera_backup_cloud_reasoning_agent": 25},
        "backup": {"backup_agent": 45, "camera_backup_cloud_reasoning_agent": 25},
        "user": {
            "users_agent": 45,
            "users_auth_reasoning_agent": 25,
            "users_security_settings_reasoning_agent": 25,
        },
        "domain": {"netprotection_agent": 35, "personal_dns_agent": 20},
        "device": {"netprotection_agent": 30, "network_activity_agent": 25},
        "service": {"security_agent": 20, "remote_access_agent": 20, "wireguard_agent": 20},
    }
    _TARGET_TYPE_HINTS: dict[str, dict[str, int]] = {
        "device": {"netprotection_agent": 25, "network_activity_agent": 20},
        "domain": {"netprotection_agent": 25, "personal_dns_agent": 20},
        "service": {"security_agent": 15, "remote_access_agent": 15, "wireguard_agent": 15},
    }
    _INCIDENT_WORDS = (
        "incident",
        "main problem",
        "biggest problem",
        "where should i start",
        "across sections",
        "what happened",
        "whole system",
        "which dashboard card should i open first",
    )
    _DASHBOARD_SERVICE_WORDS = ("services are red", "dashboard", "services", "remote access")
    _VPN_SECURITY_WORDS = ("dashboard", "security", "tunnel", "access")
    _GUARD_REMOTE_SETUP_WORDS = ("guard", "remote access", "setup")
    _SETUP_GUARD_NETWORK_WORDS = ("setup", "guard", "network activity")
    _HELP_WORDS = (
        "help",
        "support",
        "guide",
        "faq",
        "documentation",
        "docs",
        "read next",
        "what next",
        "where next",
        "where should i start",
        "error code",
        "how to",
        "how do i",
    )
    _WEB_CERT_WORDS = (
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
    _DNS_CERT_WORDS = (
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

    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry

    def select(self, request: AgentRequest) -> AgentModule | None:
        context = build_agent_context(request)
        best_module: AgentModule | None = None
        best_key: tuple[int, int, int, int] | None = None

        for index, module in enumerate(self.registry.all()):
            base_score = int(module.score(request) or 0)
            if base_score <= 0:
                continue

            affinity = self._affinity(module.name, context)
            combined_score = base_score + affinity
            score_key = (combined_score, affinity, base_score, -index)

            if best_key is None or score_key > best_key:
                best_key = score_key
                best_module = module

        return best_module

    def _affinity(self, module_name: str, context: AgentContext) -> int:
        affinity = 0
        route_family = self._route_family(context.route_lower)
        normalized_route = route_family.replace("-", "_")
        module_name_lower = str(module_name or "").strip().lower()

        if route_family:
            affinity += self._ROUTE_HINTS.get(route_family, {}).get(module_name_lower, 0)
            if normalized_route and normalized_route in module_name_lower:
                affinity += 15

        if context.tab_lower:
            affinity += self._TAB_HINTS.get(context.tab_lower, {}).get(module_name_lower, 0)

        if context.entity_type_lower:
            affinity += self._ENTITY_HINTS.get(context.entity_type_lower, {}).get(module_name_lower, 0)

        affinity += self._TARGET_TYPE_HINTS.get(context.target_type, {}).get(module_name_lower, 0)

        question = context.question_lower
        if route_family == "dashboard":
            if any(token in question for token in self._INCIDENT_WORDS):
                if module_name_lower == "dashboard_incident_agent":
                    affinity += 35
            elif module_name_lower == "dashboard_agent":
                affinity += 20
            if all(token in question for token in self._GUARD_REMOTE_SETUP_WORDS):
                if module_name_lower == "guard_remote_setup_reasoning_agent":
                    affinity += 90
            if all(token in question for token in self._SETUP_GUARD_NETWORK_WORDS):
                if module_name_lower == "setup_guard_network_reasoning_agent":
                    affinity += 90
            if any(token in question for token in ("vpn", "wireguard")) and "security" in question:
                if module_name_lower == "vpn_dashboard_security_reasoning_agent":
                    affinity += 90
        if route_family == "remote-access":
            if all(token in question for token in self._DASHBOARD_SERVICE_WORDS):
                if module_name_lower == "remote_dashboard_services_reasoning_agent":
                    affinity += 70
        if route_family == "vpn":
            if any(token in question for token in self._VPN_SECURITY_WORDS):
                if module_name_lower == "vpn_dashboard_security_reasoning_agent":
                    affinity += 25
        if route_family == "guard-security" and module_name_lower == "netprotection_agent":
            if context.tab_lower in self._GUARD_SECURITY_TABS:
                affinity += 80
            if any(token in question for token in ("rewrite", "profile", "schedule", "query log", "shadow", "upstream", "encrypted dns")):
                affinity += 20
        if "threat monitoring" in question or "security monitor" in question:
            if module_name_lower == "system_services_agent":
                affinity += 60
        if any(token in question for token in self._HELP_WORDS):
            if module_name_lower == "help_agent":
                affinity += 110
        if self._is_web_certificate_request(question):
            if module_name_lower == "setup_agent":
                affinity += 75

        return affinity

    def _route_family(self, route: str) -> str:
        value = str(route or "").strip().strip("/").lower()
        if not value:
            return ""
        return value.split("/", 1)[0]

    def _is_web_certificate_request(self, question: str) -> bool:
        if not any(token in question for token in self._WEB_CERT_WORDS):
            return False
        return not any(token in question for token in self._DNS_CERT_WORDS)
