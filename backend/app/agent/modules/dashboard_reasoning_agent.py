"""Dashboard cross-section reasoning module."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from app.agent.adapters.backup import BackupAdapter
from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class DashboardReasoningAgent:
    """Explain cross-section health on the dashboard."""

    name = "dashboard_reasoning_agent"
    _KEYWORDS = (
        "dashboard",
        "overall health",
        "overall status",
        "what is wrong",
        "what changed",
        "red card",
        "summary",
        "health summary",
        "status summary",
    )
    _HEALTH_WORDS = ("health", "status", "problem", "issue", "wrong", "broken", "summary")
    _METRIC_WORDS = ("cpu", "ram", "memory", "disk", "temperature", "uptime")
    _ROUTES = ("dashboard",)

    def __init__(
        self,
        monitoring: MonitoringAdapter,
        service_status: ServiceStatusAdapter,
        backup: BackupAdapter,
        cameras: CamerasAdapter,
        wireguard: WireGuardAdapter,
        security: SecurityAdapter,
    ) -> None:
        self.monitoring = monitoring
        self.service_status = service_status
        self.backup = backup
        self.cameras = cameras
        self.wireguard = wireguard
        self.security = security

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if self._requested_widget(question, target, (request.tab or "").lower()) is not None:
            score += 170
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 140
        elif any(token in route for token in self._ROUTES) and any(word in question for word in self._HEALTH_WORDS):
            score += 125
        elif "dashboard" in route and "dashboard" in question:
            score += 120
        elif any(token in route for token in self._ROUTES):
            # The frontend's generic suggestions still carry dashboard context.
            # Keep them with the cross-section dashboard responder instead of
            # treating an unspecified question as a monitoring-metric request.
            score += 45
        if any(word in question for word in self._METRIC_WORDS):
            score -= 50
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if self.score(request) <= 0:
            return None
        if "dashboard" not in question and "dashboard" not in target and "dashboard" not in route and not any(word in question for word in self._HEALTH_WORDS):
            return None

        widget = self._requested_widget(question, target, (request.tab or "").lower())
        if widget is not None:
            return await self._widget_response(widget)

        results = await asyncio.gather(
            self.monitoring.get_system_stats(),
            self.monitoring.get_service_metrics(),
            self.service_status.get_netprotection_status(),
            self.service_status.get_tailscale_status(),
            self.wireguard.get_status(),
            self.cameras.list_cameras(),
            self.backup.list_backups(),
            return_exceptions=True,
        )
        source_names = ("monitoring", "service metrics", "NetProtection", "Tailscale", "WireGuard", "cameras", "backups")
        failures = [f"{name}: {type(value).__name__}: {value}" for name, value in zip(source_names, results) if isinstance(value, Exception)]
        stats = {} if isinstance(results[0], Exception) else results[0]
        services = [] if isinstance(results[1], Exception) else results[1]
        netprotection = {} if isinstance(results[2], Exception) else results[2]
        tailscale = None if isinstance(results[3], Exception) else results[3]
        wireguard = {} if isinstance(results[4], Exception) else results[4]
        cameras = [] if isinstance(results[5], Exception) else results[5]
        backups = [] if isinstance(results[6], Exception) else results[6]
        try:
            scan = self.security.get_latest_scan() or {}
        except Exception as exc:
            scan = {}
            failures.append(f"security: {type(exc).__name__}: {exc}")

        tailscale_value = str(getattr(tailscale, "status", "unknown") or "unknown").lower()
        if not failures and not any((stats, services, netprotection, wireguard, cameras, backups, scan)) and tailscale_value == "unknown":
            return AgentResponse(
                category="service", target="dashboard", matched=True, title="Dashboard health summary",
                summary="Dashboard source data are unavailable, so overall health is unknown.", confidence="low",
                section="dashboard", subsection="overview", module=self.name, checks_run=[],
                facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["No dashboard source returned authoritative health evidence."],
                recommendations=["Restore dashboard data sources and retry."],
            )

        issues: list[str] = []
        facts: list[AgentFact] = []

        cpu = float((stats.get("cpu") or {}).get("usage") or 0)
        if cpu >= 85:
            issues.append(f"CPU usage is elevated at {cpu:.1f}%")
        facts.append(AgentFact("CPU usage", f"{cpu:.1f}%"))

        stopped_services = sum(1 for service in services if not bool(service.get("running")))
        facts.append(AgentFact("Stopped services", str(stopped_services), "warning" if stopped_services else "info"))
        if stopped_services:
            issues.append(f"{stopped_services} monitored services are stopped")

        if not bool(netprotection.get("running")):
            issues.append("NetProtection is not running")
            facts.append(AgentFact("NetProtection", "Stopped", "critical"))
        else:
            facts.append(AgentFact("NetProtection", "Running"))

        tailscale_status = tailscale_value
        # "not_installed"/"unknown" means the optional feature was never set up —
        # that is not a dashboard "issue". Only flag a tunnel that was configured
        # but is currently broken (needs login, stopped, or errored).
        tailscale_broken = tailscale_status in {"needs_login", "stopped", "error"}
        facts.append(AgentFact("Tailscale", tailscale_status, "warning" if tailscale_broken else "info"))
        if tailscale_broken:
            issues.append(f"Tailscale is set up but not connected ({tailscale_status})")

        if bool(wireguard.get("installed")) and not bool(wireguard.get("running")):
            issues.append("WireGuard is installed but not running")
            facts.append(AgentFact("WireGuard", "Stopped", "warning"))

        offline_cameras = sum(1 for camera in cameras if str(camera.get("status") or "").lower() in {"offline", "error"})
        facts.append(AgentFact("Offline cameras", str(offline_cameras), "warning" if offline_cameras else "info"))
        if offline_cameras:
            issues.append(f"{offline_cameras} cameras are offline")

        failed_backups = [item for item in backups if str(item.get("status")) == "failed"]
        latest_failed_backup = next((item for item in failed_backups if not self._record_is_stale(item)), None)
        historical_failed_backup = next((item for item in failed_backups if self._record_is_stale(item)), None)
        facts.append(
            AgentFact(
                "Failed backups",
                "1" if latest_failed_backup else "0",
                "warning" if latest_failed_backup else "info",
            )
        )
        if latest_failed_backup is not None:
            issues.append(f"Latest backup '{latest_failed_backup.get('name')}' failed")
        elif historical_failed_backup is not None:
            facts.append(AgentFact("Historical backup failure", str(historical_failed_backup.get("created_at") or "Old"), "warning"))

        critical_security = len(scan.get("critical") or [])
        facts.append(AgentFact("Critical security findings", str(critical_security), "critical" if critical_security else "info"))
        if critical_security:
            issues.append(f"{critical_security} critical security findings are active")

        unavailable_labels: set[str] = set()
        if isinstance(results[0], Exception):
            unavailable_labels.add("CPU usage")
        if isinstance(results[1], Exception):
            unavailable_labels.add("Stopped services")
        if isinstance(results[2], Exception):
            unavailable_labels.add("NetProtection")
        if isinstance(results[3], Exception):
            unavailable_labels.add("Tailscale")
        if isinstance(results[5], Exception):
            unavailable_labels.add("Offline cameras")
        if isinstance(results[6], Exception):
            unavailable_labels.add("Failed backups")
        if any(failure.startswith("security:") for failure in failures):
            unavailable_labels.add("Critical security findings")
        facts = [fact for fact in facts if fact.label not in unavailable_labels]

        for failure in failures:
            facts.append(AgentFact("Source failure", failure, "warning"))

        if failures:
            summary = f"Dashboard data are partial because a monitoring or service source failed: {failures[0]}."
            confidence = "low"
            reason_chain = ["Available dashboard sources were retained.", *failures]
        elif issues:
            summary = "Dashboard shows active issues across multiple EasyPi sections."
            confidence = "high"
            reason_chain = [
                "Dashboard diagnostics collected facts from monitoring, services, security, backup, cameras, and VPN.",
                *issues[:4],
            ]
        else:
            summary = "Dashboard cross-section health looks stable right now."
            confidence = "medium"
            reason_chain = [
                "Dashboard diagnostics collected facts from monitoring, services, security, backup, cameras, and VPN.",
                "No major cross-section issue was detected.",
            ]

        return AgentResponse(
            category="service",
            target="dashboard",
            matched=True,
            title="Dashboard health summary",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="overview",
            module=self.name,
            checks_run=[
                "system_stats",
                "service_metrics",
                "netprotection_status",
                "tailscale_status",
                "wireguard_status",
                "camera_inventory",
                "backup_history",
                "latest_security_scan",
            ],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open the section behind the most severe issue first instead of debugging everything at once.",
                "Ask a narrower question about security, backup, cameras, VPN, or monitoring for a deeper explanation.",
            ],
        )

    async def _widget_response(self, widget: str) -> AgentResponse:
        if widget == "security":
            return self._security_widget_response()
        if widget == "backup":
            return await self._backup_widget_response()
        if widget == "cameras":
            return await self._cameras_widget_response()
        if widget == "remote-access":
            return await self._remote_widget_response()
        if widget == "vpn":
            return await self._vpn_widget_response()
        if widget == "guard-security":
            return await self._guard_widget_response()
        return await self._monitoring_widget_response()

    def _security_widget_response(self) -> AgentResponse:
        scan = self.security.get_latest_scan() or {}
        if not scan:
            return AgentResponse(
                category="service", target="dashboard-security-card", matched=True,
                title="Dashboard security card diagnostics",
                summary="The dashboard security card state is unknown because no saved scan is available.",
                confidence="low", section="dashboard", subsection="security-card", module=self.name,
                checks_run=[], facts=[AgentFact("Saved scan", "Unavailable", "warning")],
                reason_chain=["No authoritative saved security scan was returned."],
                recommendations=["Run a security scan explicitly from System Security, then refresh the dashboard."],
            )
        critical = len(scan.get("critical") or [])
        warnings = len(scan.get("warnings") or [])
        facts = [
            AgentFact("Critical findings", str(critical), "critical" if critical else "info"),
            AgentFact("Warnings", str(warnings), "warning" if warnings else "info"),
        ]
        if scan.get("last_scan"):
            facts.append(AgentFact("Last scan", str(scan.get("last_scan"))))
        if critical:
            summary = "The dashboard security card is red because critical findings are still active."
            confidence = "high"
        elif warnings:
            summary = "The dashboard security card is warning-level because non-critical findings remain."
            confidence = "high"
        else:
            summary = "The dashboard security card should look healthy from the current saved scan."
            confidence = "medium"
        return AgentResponse(
            category="service",
            target="dashboard-security-card",
            matched=True,
            title="Dashboard security card diagnostics",
            summary=summary,
            confidence=confidence,
            section="dashboard",
            subsection="security-card",
            module=self.name,
            checks_run=["latest_security_scan"],
            facts=facts,
            reason_chain=[
                "The latest saved security scan result was inspected for the dashboard card.",
                "Critical and warning findings were mapped to the dashboard security widget state.",
            ],
            recommendations=[
                "Open Security to inspect the finding behind the current dashboard card state.",
            ],
        )

    async def _backup_widget_response(self) -> AgentResponse:
        backups = await self.backup.list_backups()
        failed = [item for item in backups if str(item.get("status") or "").lower() == "failed"]
        running = [item for item in backups if str(item.get("status") or "").lower() == "running"]
        facts = [
            AgentFact("Backup jobs", str(len(backups))),
            AgentFact("Failed backups", str(len(failed)), "warning" if failed else "info"),
            AgentFact("Running backups", str(len(running))),
        ]
        if failed:
            facts.append(AgentFact("Latest failed backup", str(failed[0].get("name") or "Unknown"), "warning"))
        summary = "The dashboard backup card is red because a recent backup job failed." if failed else "The dashboard backup card does not show a failed backup from current history."
        return AgentResponse(
            category="service",
            target="dashboard-backup-card",
            matched=True,
            title="Dashboard backup card diagnostics",
            summary=summary,
            confidence="high" if failed else "medium",
            section="dashboard",
            subsection="backup-card",
            module=self.name,
            checks_run=["backup_history"],
            facts=facts,
            reason_chain=[
                "Recent backup history was inspected for the dashboard backup card.",
                "Failed and running jobs were counted from the saved backup list.",
            ],
            recommendations=[
                "Open System Backup to inspect the latest failed job and retry only after the root cause is clear.",
            ],
        )

    async def _cameras_widget_response(self) -> AgentResponse:
        cameras = await self.cameras.list_cameras()
        offline = [camera for camera in cameras if str(camera.get("status") or "").lower() in {"offline", "error"}]
        facts = [
            AgentFact("Total cameras", str(len(cameras))),
            AgentFact("Offline cameras", str(len(offline)), "warning" if offline else "info"),
        ]
        if offline:
            facts.append(AgentFact("First offline camera", str(offline[0].get("name") or "Unknown"), "warning"))
        summary = "The dashboard cameras card is warning-level because one or more cameras are offline." if offline else "The dashboard cameras card looks healthy from the current camera inventory."
        return AgentResponse(
            category="service",
            target="dashboard-cameras-card",
            matched=True,
            title="Dashboard cameras card diagnostics",
            summary=summary,
            confidence="high" if offline else "medium",
            section="dashboard",
            subsection="cameras-card",
            module=self.name,
            checks_run=["camera_inventory"],
            facts=facts,
            reason_chain=[
                "The current camera inventory was inspected for the dashboard card state.",
                "Offline and error camera states were counted locally.",
            ],
            recommendations=[
                "Open IP Cameras and inspect connectivity, credentials, and stream health for the offline camera first.",
            ],
        )

    async def _remote_widget_response(self) -> AgentResponse:
        tailscale = await self.service_status.get_tailscale_status()
        status = self._status_value(tailscale)
        peers = getattr(tailscale, "peers", []) or []
        facts = [
            AgentFact("Tailscale status", status, "info" if status in {"connected", "running"} else "warning"),
            AgentFact("Connected peers", str(len(peers))),
        ]
        summary = (
            "The dashboard remote access card is red because Tailscale is not connected."
            if status not in {"connected", "running"}
            else "The dashboard remote access card looks healthy from current Tailscale runtime state."
        )
        return AgentResponse(
            category="service",
            target="dashboard-remote-access-card",
            matched=True,
            title="Dashboard remote access card diagnostics",
            summary=summary,
            confidence="high",
            section="dashboard",
            subsection="remote-access-card",
            module=self.name,
            checks_run=["tailscale_status"],
            facts=facts,
            reason_chain=[
                "The local Tailscale runtime state was inspected for the dashboard card.",
                f"The current Tailscale status is {status}.",
            ],
            recommendations=[
                "Open Remote Access to restore login or runtime health if remote access should be available now.",
            ],
        )

    async def _vpn_widget_response(self) -> AgentResponse:
        wireguard = await self.wireguard.get_status()
        installed = bool(wireguard.get("installed"))
        running = bool(wireguard.get("running"))
        facts = [
            AgentFact("Installed", "Yes" if installed else "No"),
            AgentFact("Running", "Yes" if running else "No", "info" if running else "warning"),
            AgentFact("Peers", str(len(wireguard.get("peers") or []))),
        ]
        summary = (
            "The dashboard VPN card is red because WireGuard is installed but not running."
            if installed and not running
            else "The dashboard VPN card does not show a runtime problem from current WireGuard status."
        )
        return AgentResponse(
            category="service",
            target="dashboard-vpn-card",
            matched=True,
            title="Dashboard VPN card diagnostics",
            summary=summary,
            confidence="high" if installed else "medium",
            section="dashboard",
            subsection="vpn-card",
            module=self.name,
            checks_run=["wireguard_status"],
            facts=facts,
            reason_chain=[
                "Local WireGuard status was inspected for the dashboard card.",
                "Install and runtime state were mapped to the dashboard VPN health view.",
            ],
            recommendations=[
                "Open VPN and inspect server status, peers, and endpoint configuration if the card is still red.",
            ],
        )

    async def _guard_widget_response(self) -> AgentResponse:
        status = await self.service_status.get_netprotection_status()
        running = bool(status.get("running"))
        facts = [
            AgentFact("NetProtection", "Running" if running else "Stopped", "info" if running else "critical"),
            AgentFact("Transparent DNS", "Yes" if bool(status.get("transparent_dns")) else "No"),
            AgentFact("Systemd status", str(status.get("service_status") or "unknown")),
        ]
        summary = (
            "The dashboard Guard card is red because NetProtection is not running."
            if not running
            else "The dashboard Guard card looks healthy from the current NetProtection service state."
        )
        return AgentResponse(
            category="service",
            target="dashboard-guard-card",
            matched=True,
            title="Dashboard Guard card diagnostics",
            summary=summary,
            confidence="high",
            section="dashboard",
            subsection="guard-card",
            module=self.name,
            checks_run=["netprotection_status"],
            facts=facts,
            reason_chain=[
                "The local NetProtection status endpoint was queried for the dashboard card.",
                "Running state and DNS protection flags were inspected.",
            ],
            recommendations=[
                "Open Guard Security if protection should be active but the dashboard still shows a red card.",
            ],
        )

    async def _monitoring_widget_response(self) -> AgentResponse:
        stats, services = await asyncio.gather(
            self.monitoring.get_system_stats(),
            self.monitoring.get_service_metrics(),
        )
        cpu = float((stats.get("cpu") or {}).get("usage") or 0)
        ram_used = float((stats.get("ram") or {}).get("used") or 0)
        ram_total = float((stats.get("ram") or {}).get("total") or 0)
        ram_percent = round((ram_used / ram_total) * 100, 1) if ram_total else 0.0
        stopped_services = sum(1 for service in services if not bool(service.get("running")))
        facts = [
            AgentFact("CPU usage", f"{cpu:.1f}%", "warning" if cpu >= 85 else "info"),
            AgentFact("RAM usage", f"{ram_percent:.1f}%", "warning" if ram_percent >= 90 else "info"),
            AgentFact("Stopped services", str(stopped_services), "warning" if stopped_services else "info"),
        ]
        if cpu >= 85:
            summary = "The dashboard monitoring card is red because CPU usage is elevated."
        elif ram_percent >= 90:
            summary = "The dashboard monitoring card is red because RAM usage is critically high."
        elif stopped_services:
            summary = "The dashboard monitoring card is warning-level because some monitored services are stopped."
        else:
            summary = "The dashboard monitoring card looks healthy from the current monitoring snapshot."
        return AgentResponse(
            category="service",
            target="dashboard-monitoring-card",
            matched=True,
            title="Dashboard monitoring card diagnostics",
            summary=summary,
            confidence="high" if cpu >= 85 or ram_percent >= 90 or stopped_services else "medium",
            section="dashboard",
            subsection="monitoring-card",
            module=self.name,
            checks_run=["system_stats", "service_metrics"],
            facts=facts,
            reason_chain=[
                "The current monitoring snapshot was collected for the dashboard card.",
                "CPU, RAM, and stopped-service counts were mapped to dashboard widget severity.",
            ],
            recommendations=[
                "Open Monitoring if the system-health widget stays red or spikes repeat over time.",
            ],
        )

    def _requested_widget(self, question: str, target: str, tab: str) -> str | None:
        haystack = f"{question} {target} {tab}"
        if not any(token in haystack for token in ("card", "widget", "tile")):
            return None
        if any(token in haystack for token in ("security", "scan", "hardening")):
            return "security"
        if any(token in haystack for token in ("backup", "archive")):
            return "backup"
        if any(token in haystack for token in ("camera", "cameras", "recording")):
            return "cameras"
        if any(token in haystack for token in ("remote access", "tailscale", "tailnet")):
            return "remote-access"
        if any(token in haystack for token in ("vpn", "wireguard")):
            return "vpn"
        if any(token in haystack for token in ("guard", "netprotection", "dns protection")):
            return "guard-security"
        if any(token in haystack for token in ("monitoring", "cpu", "ram", "memory", "disk", "temperature")):
            return "monitoring"
        return None

    def _status_value(self, status: object) -> str:
        raw = getattr(status, "status", None)
        if raw is None:
            return "unknown"
        value = getattr(raw, "value", raw)
        return str(value or "unknown").strip().lower()

    def _record_is_stale(self, record: dict[str, object]) -> bool:
        raw = str(record.get("created_at") or "").strip()
        if not raw:
            return False
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).days > 7
        except ValueError:
            return False
