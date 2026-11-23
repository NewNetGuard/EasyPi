"""Full dashboard incident reasoning module."""

from __future__ import annotations

import asyncio

from app.agent.adapters.backup import BackupAdapter
from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.cloud import CloudAdapter
from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class DashboardIncidentAgent:
    """Explain the main incident visible across the dashboard."""

    name = "dashboard_incident_agent"
    _INCIDENT_WORDS = (
        "incident",
        "everything",
        "whole system",
        "whole dashboard",
        "what happened",
        "main problem",
        "biggest problem",
        "what should i open first",
        "which dashboard card should i open first",
        "across sections",
        "where should i start",
    )
    _HEALTH_WORDS = ("dashboard", "overall", "summary", "status", "health", "problem", "issue", "broken")
    _ROUTES = ("dashboard",)
    _STORAGE_ERROR_WORDS = ("space", "disk", "storage", "full", "capacity", "no space", "quota")

    def __init__(
        self,
        monitoring: MonitoringAdapter,
        service_status: ServiceStatusAdapter,
        backup: BackupAdapter,
        cameras: CamerasAdapter,
        wireguard: WireGuardAdapter,
        security: SecurityAdapter,
        setup: SetupAdapter,
        cloud: CloudAdapter,
        users_auth: UsersAuthAdapter,
    ) -> None:
        self.monitoring = monitoring
        self.service_status = service_status
        self.backup = backup
        self.cameras = cameras
        self.wireguard = wireguard
        self.security = security
        self.setup = setup
        self.cloud = cloud
        self.users_auth = users_auth

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()

        score = 0
        if any(keyword in question or keyword in target for keyword in self._INCIDENT_WORDS):
            score += 175
        elif any(token in route for token in self._ROUTES) and any(word in question for word in self._HEALTH_WORDS):
            score += 105
        elif "dashboard" in question and any(word in question for word in ("what", "why", "broken", "problem", "issue")):
            score += 100
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        (
            stats,
            services,
            netprotection,
            tailscale,
            wireguard,
            cameras,
            backups,
            permissions,
            dns_status,
            users,
        ) = await asyncio.gather(
            self.monitoring.get_system_stats(),
            self.monitoring.get_service_metrics(),
            self.service_status.get_netprotection_status(),
            self.service_status.get_tailscale_status(),
            self.wireguard.get_status(),
            self.cameras.list_cameras(),
            self.backup.list_backups(),
            self.setup.get_permissions_status(),
            self.setup.get_dns_status(),
            self.users_auth.list_users(),
        )

        latest_scan = self.security.get_latest_scan() or {}
        cloud_stats = self.cloud.get_storage_stats()
        recordings = self.cameras.get_all_recordings()

        if (
            not any((stats, services, netprotection, wireguard, cameras, backups, permissions, dns_status, users, latest_scan, cloud_stats, recordings))
            and self._status_value(tailscale) == "unknown"
        ):
            return AgentResponse(
                category="service", target="dashboard", matched=True, title="Dashboard incident summary",
                summary="Dashboard incident data are insufficient because all sources are unavailable or unknown.",
                confidence="low", section="dashboard", subsection="incidents", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["No source returned authoritative evidence for an incident diagnosis."],
                recommendations=["Restore dashboard sources and retry before choosing a remediation."],
            )

        cpu = float((stats.get("cpu") or {}).get("usage") or 0)
        stopped_services = sum(1 for service in services if not bool(service.get("running")))
        netprotection_running = bool(netprotection.get("running"))
        tailscale_status = self._status_value(tailscale)
        wireguard_installed = bool(wireguard.get("installed"))
        wireguard_running = bool(wireguard.get("running"))
        offline_cameras = [camera for camera in cameras if str(camera.get("status") or "").lower() in {"offline", "error"}]
        failed_backup = next((item for item in backups if str(item.get("status") or "").lower() == "failed"), None)
        cloud_percent = float(cloud_stats.get("percent") or 0)
        critical_security = len(latest_scan.get("critical") or [])
        active_admins = [
            user for user in users if bool(user.get("is_active")) and str(user.get("role") or "").lower() == "admin"
        ]
        permissions_ok = bool(permissions.get("permissions_ok"))
        dns_configured = bool(dns_status.get("current_dns"))
        dns_locked = bool(dns_status.get("ignore_dhcp_dns"))

        facts = [
            AgentFact("CPU usage", f"{cpu:.1f}%", "warning" if cpu >= 85 else "info"),
            AgentFact("Stopped services", str(stopped_services), "warning" if stopped_services else "info"),
            AgentFact("NetProtection", "Running" if netprotection_running else "Stopped", "info" if netprotection_running else "critical"),
            AgentFact("Tailscale", tailscale_status, "info" if tailscale_status in {"connected", "running"} else "warning"),
            AgentFact("WireGuard", "Running" if wireguard_running else ("Stopped" if wireguard_installed else "Not installed")),
            AgentFact("Offline cameras", str(len(offline_cameras)), "warning" if offline_cameras else "info"),
            AgentFact("Saved recordings", str(len(recordings))),
            AgentFact("Failed backups", "1" if failed_backup else "0", "warning" if failed_backup else "info"),
            AgentFact("Cloud usage", f"{cloud_percent:.1f}%", "warning" if cloud_percent >= 90 else "info"),
            AgentFact("Critical security findings", str(critical_security), "critical" if critical_security else "info"),
            AgentFact("Setup permissions", "Healthy" if permissions_ok else "Incomplete", "info" if permissions_ok else "critical"),
            AgentFact("Setup DNS", "Pinned" if dns_configured and dns_locked else "Incomplete", "warning" if not (dns_configured and dns_locked) else "info"),
            AgentFact("Active admins", str(len(active_admins)), "warning" if not active_admins and users else "info"),
        ]

        incidents: list[dict[str, object]] = []
        if not permissions_ok:
            incidents.append(
                {
                    "severity": 100,
                    "summary": "Setup permissions are incomplete and can block multiple backend actions across EasyPi.",
                    "reason": "Setup currently reports missing group membership, sudo state, or relogin completion.",
                    "recommendations": [
                        "Open Setup first and finish the permissions flow before debugging other backend-heavy sections.",
                    ],
                }
            )
        if permissions_ok and (not dns_configured or not dns_locked) and not netprotection_running:
            incidents.append(
                {
                    "severity": 92,
                    "summary": "Guard Security is degraded while EasyPi DNS setup still looks incomplete.",
                    "reason": "System DNS is not fully pinned to EasyPi, and NetProtection is not running.",
                    "recommendations": [
                        "Open Setup and verify system DNS before debugging Guard Security rules.",
                    ],
                }
            )
        if netprotection_running is False and tailscale_status not in {"connected", "running"}:
            incidents.append(
                {
                    "severity": 88,
                    "summary": "Both Guard Security and Remote Access are degraded at the same time.",
                    "reason": "NetProtection is stopped and Tailscale is not in a connected or running state.",
                    "recommendations": [
                        "Open Guard Security and Remote Access next, because both network-control surfaces are degraded.",
                    ],
                }
            )
        if critical_security:
            incidents.append(
                {
                    "severity": 82,
                    "summary": "System Security still reports critical findings.",
                    "reason": f"The latest saved security scan still contains {critical_security} critical findings.",
                    "recommendations": [
                        "Open Security after the highest operational incident and clear critical findings first.",
                    ],
                }
            )
        if failed_backup is not None and self._contains_storage_error(str(failed_backup.get("error_message") or "")) and cloud_percent >= 90:
            incidents.append(
                {
                    "severity": 78,
                    "summary": "Storage pressure is showing up in backups while cloud capacity is already high.",
                    "reason": "The latest failed backup mentions storage pressure, and cloud usage is near the critical threshold.",
                    "recommendations": [
                        "Open System Backup and Cloud together to reduce capacity pressure before retrying jobs.",
                    ],
                }
            )
        elif failed_backup is not None:
            incidents.append(
                {
                    "severity": 70,
                    "summary": f"The latest backup job '{failed_backup.get('name')}' failed.",
                    "reason": "Backup history contains a failed job even though it does not clearly look like a shared capacity issue.",
                    "recommendations": [
                        "Open System Backup and inspect the latest error message directly.",
                    ],
                }
            )
        if offline_cameras:
            incidents.append(
                {
                    "severity": 68,
                    "summary": f"{len(offline_cameras)} camera(s) are currently offline.",
                    "reason": "The local camera inventory reports one or more offline or error states.",
                    "recommendations": [
                        "Open IP Cameras and verify power, network reachability, and stream credentials.",
                    ],
                }
            )
        if cpu >= 85 or stopped_services:
            incidents.append(
                {
                    "severity": 64,
                    "summary": "Host load or stopped services are degrading the overall dashboard health.",
                    "reason": f"CPU usage is {cpu:.1f}% and {stopped_services} monitored service(s) are stopped.",
                    "recommendations": [
                        "Open Monitoring and Services to identify the busiest or stopped processes first.",
                    ],
                }
            )
        if wireguard_installed and not wireguard_running:
            incidents.append(
                {
                    "severity": 52,
                    "summary": "WireGuard is installed but not currently running.",
                    "reason": "The local VPN service exists, but its runtime state is stopped.",
                    "recommendations": [
                        "Open VPN if WireGuard access is expected right now.",
                    ],
                }
            )
        if users and not active_admins:
            incidents.append(
                {
                    "severity": 60,
                    "summary": "No active admin account is available right now.",
                    "reason": "Existing users were found, but none of them is an active admin.",
                    "recommendations": [
                        "Restore admin access before making more identity or security changes.",
                    ],
                }
            )

        incidents.sort(key=lambda item: int(item["severity"]), reverse=True)

        checks_run = [
            "system_stats",
            "service_metrics",
            "netprotection_status",
            "tailscale_status",
            "wireguard_status",
            "camera_inventory",
            "backup_history",
            "cloud_storage_stats",
            "setup_permissions",
            "setup_dns_status",
            "users",
            "latest_security_scan",
        ]

        if incidents:
            top = incidents[0]
            supporting = [str(item["summary"]) for item in incidents[1:3]]
            recommendations = list(top["recommendations"])
            recommendations.append("Open dashboard cards from highest severity to lowest instead of debugging everything at once.")
            return AgentResponse(
                category="service",
                target="dashboard",
                matched=True,
                title="Dashboard incident summary",
                summary=str(top["summary"]),
                confidence="high",
                section="dashboard",
                subsection="incidents",
                module=self.name,
                checks_run=checks_run,
                facts=facts,
                reason_chain=[
                    "Full dashboard incident reasoning collected facts from setup, monitoring, services, security, cloud, backup, cameras, VPN, and users.",
                    str(top["reason"]),
                    *supporting,
                ],
                recommendations=recommendations,
            )

        return AgentResponse(
            category="service",
            target="dashboard",
            matched=True,
            title="Dashboard incident summary",
            summary="No major dashboard-wide incident was detected from the current local facts.",
            confidence="medium",
            section="dashboard",
            subsection="incidents",
            module=self.name,
            checks_run=checks_run,
            facts=facts,
            reason_chain=[
                "Full dashboard incident reasoning collected facts from setup, monitoring, services, security, cloud, backup, cameras, VPN, and users.",
                "The current data do not point to a single dominant cross-section incident.",
            ],
            recommendations=[
                "Ask a narrower question about the section that looks suspicious if you need a deeper explanation.",
            ],
        )

    def _status_value(self, status: object) -> str:
        raw = getattr(status, "status", None)
        if raw is None:
            return "unknown"
        value = getattr(raw, "value", raw)
        return str(value or "unknown").strip().lower()

    def _contains_storage_error(self, value: str) -> bool:
        text = str(value or "").strip().lower()
        return any(token in text for token in self._STORAGE_ERROR_WORDS)
