"""Dashboard and monitoring agent module."""

from __future__ import annotations

import asyncio

from app.agent.adapters.monitoring import MonitoringAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class DashboardMonitoringAgent:
    """Explain dashboard and system monitoring state."""

    name = "dashboard_monitoring_agent"
    _PAGE_KEYWORDS = ("dashboard", "monitoring")
    _METRIC_KEYWORDS = (
        "cpu",
        "ram",
        "memory",
        "disk",
        "temperature",
        "uptime",
        "database health",
        "redis health",
        "dependency health",
        "dependencies health",
    )
    _HISTORY_KEYWORDS = ("yesterday", "persistent", "transient", "since yesterday")
    _SERVICE_CAUSE_KEYWORDS = ("which service caused", "top service", "hottest service")
    _EXCLUDED_KEYWORDS = ("threat monitor", "threat monitoring", "security monitor", "ssh monitor")
    _ROUTES = ("dashboard", "monitoring")

    def __init__(self, adapter: MonitoringAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if self._matches_request(question, target, route):
            score += 100
        if any(token in route for token in self._ROUTES) and not self._is_excluded(question, target):
            score += 35
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not self._matches_request(question, target, route):
            return None

        stats_result, services_result = await asyncio.gather(
            self.adapter.get_system_stats(),
            self.adapter.get_service_metrics(),
            return_exceptions=True,
        )
        failures = [value for value in (stats_result, services_result) if isinstance(value, BaseException)]
        stats = {} if isinstance(stats_result, BaseException) else stats_result
        services = [] if isinstance(services_result, BaseException) else services_result
        if failures:
            failure = failures[0]
            facts = [AgentFact("Source failure", f"{type(failure).__name__}: {failure}", "warning")]
            if services:
                facts.append(AgentFact("Service metrics available", str(len(services))))
            return AgentResponse(
                category="service",
                target="system-monitoring",
                matched=True,
                title="Partial monitoring diagnostics",
                summary=f"Monitoring data are partial because a source returned {type(failure).__name__}: {failure}.",
                confidence="low",
                section="monitoring",
                subsection="system-health",
                module=self.name,
                checks_run=["system_stats", "service_metrics"],
                facts=facts,
                reason_chain=["Available sources were preserved when one monitoring dependency failed."],
                recommendations=["Retry the failed monitoring source before making a current-health decision."],
            )
        if not stats and not services:
            return AgentResponse(
                category="service",
                target="system-monitoring",
                matched=True,
                title="Monitoring data unavailable",
                summary="Monitoring data are unavailable, so CPU, RAM, disk, and temperature health is unknown.",
                confidence="low",
                section="monitoring",
                subsection="system-health",
                module=self.name,
                checks_run=["system_stats", "service_metrics"],
                facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["Empty source fallbacks were not interpreted as healthy zero values."],
                recommendations=["Inspect the monitoring service and retry after it returns a complete snapshot."],
            )

        cpu = float((stats.get("cpu") or {}).get("usage") or 0)
        ram_used = float((stats.get("ram") or {}).get("used") or 0)
        ram_total = float((stats.get("ram") or {}).get("total") or 0)
        ram_percent = round((ram_used / ram_total) * 100, 1) if ram_total else 0.0
        disks = stats.get("disk") or []
        hottest_disk = self._worst_disk(disks)
        temp = (stats.get("temp") or {}).get("celsius")
        stopped_services = [service for service in services if not bool(service.get("running"))]
        top_service = self._top_service(services)

        facts = [
            AgentFact("CPU usage", f"{cpu:.1f}%"),
            AgentFact("RAM usage", f"{ram_percent:.1f}%"),
            AgentFact("Stopped services", str(len(stopped_services)), "warning" if stopped_services else "info"),
        ]
        if hottest_disk is not None:
            facts.append(
                AgentFact(
                    "Highest disk usage",
                    f"{hottest_disk['mount']} {hottest_disk['percent']:.1f}%",
                    "warning" if hottest_disk["percent"] >= 85 else "info",
                )
            )
        if temp is not None:
            facts.append(
                AgentFact("Temperature", f"{float(temp):.1f} C", "warning" if float(temp) >= 80 else "info")
            )
        if top_service is not None:
            facts.append(AgentFact("Top service", top_service))
        if stats.get("timestamp"):
            facts.append(AgentFact("Collected at", str(stats.get("timestamp"))))

        if any(keyword in question for keyword in self._HISTORY_KEYWORDS):
            summary = "The current monitoring snapshot can identify hot services, but this agent adapter does not yet keep a full historical time-series for persistence analysis."
            confidence = "medium"
            reason_chain = [
                "The local monitoring snapshot was collected.",
                "Current metrics can identify the hottest service now, but not confirm whether the issue is transient or persistent since yesterday.",
            ]
            return AgentResponse(
                category="service",
                target="system-monitoring",
                matched=True,
                title="Dashboard and monitoring diagnostics",
                summary=summary,
                confidence=confidence,
                section="monitoring",
                subsection="system-health",
                module=self.name,
                checks_run=["system_stats", "service_metrics"],
                facts=facts,
                reason_chain=reason_chain,
                recommendations=[
                    "Use the current snapshot to identify the hottest service now.",
                    "Add or inspect longer-term monitoring retention if persistence over time must be explained automatically.",
                ],
            )
        if any(keyword in question for keyword in self._SERVICE_CAUSE_KEYWORDS) and top_service is not None:
            summary = f"The current monitoring snapshot points to {top_service} as the hottest service right now."
            confidence = "high"
            reason_chain = [
                "The local monitoring snapshot was collected.",
                "Current service metrics were ranked by CPU and RAM usage.",
            ]
            return AgentResponse(
                category="service",
                target="system-monitoring",
                matched=True,
                title="Dashboard and monitoring diagnostics",
                summary=summary,
                confidence=confidence,
                section="monitoring",
                subsection="system-health",
                module=self.name,
                checks_run=["system_stats", "service_metrics"],
                facts=facts,
                reason_chain=reason_chain,
                recommendations=[
                    "Inspect the reported top service first if the current spike is still active.",
                    "Use longer-term monitoring retention if you need historical causality across earlier time windows.",
                ],
            )

        issues: list[str] = []
        recommendations: list[str] = []
        if cpu >= 85:
            issues.append(f"CPU usage is elevated at {cpu:.1f}%")
            top_cpu = max((float(service.get("cpu") or 0) for service in services), default=0.0)
            if top_cpu >= max(20.0, cpu * 0.5):
                recommendations.append(
                    f"Inspect the top service ({top_service or 'the highest-CPU process'}); only restart it after confirming it accounts for the host CPU spike."
                )
            else:
                recommendations.append(
                    "The monitored EasyPi services do not explain the host-wide CPU spike; inspect the full process list before restarting any EasyPi service."
                )
            recommendations.append("Confirm the spike persists across fresh samples before taking action.")
        if ram_percent >= 90:
            issues.append(f"RAM usage is critically high at {ram_percent:.1f}%")
            top_ram_service = self._top_service_by(services, "ram")
            recommendations = recommendations + [
                f"Inspect the heaviest RAM service ({top_ram_service or 'the highest-RAM process'}) before deciding whether to restart it.",
                "The Pi has limited RAM and may start swapping — lighten the workload if this persists.",
            ]
        if hottest_disk is not None and hottest_disk["percent"] >= 90:
            issues.append(f"disk {hottest_disk['mount']} is critically full at {hottest_disk['percent']:.1f}%")
            recommendations = recommendations + [
                f"Free space on {hottest_disk['mount']} — clear old logs, backups, and cached files.",
                "A full disk can crash services and DNS logging; act before it reaches 100%.",
            ]
        if temp is not None and float(temp) >= 80:
            issues.append(f"system temperature is high at {float(temp):.1f} C")
            recommendations = recommendations + [
                "Improve cooling (add a heatsink/fan, clear dust) — the Pi throttles above ~80 C.",
                "Check for a runaway process keeping the CPU busy and hot.",
            ]
        if stopped_services:
            names = ", ".join(str(service.get("name")) for service in stopped_services[:3])
            issues.append(f"{len(stopped_services)} monitored service(s) are not running ({names})")
            recommendations = recommendations + [
                f"Restart the stopped service(s): {names}.",
                "If they keep stopping, check their logs for the failure cause.",
            ]
        if not issues:
            recommendations = ["No action needed — CPU, RAM, disk, and temperature are within normal range."]

        issue = "; ".join(issues)
        summary = (issue + ".") if issues else "System health looks good — CPU, RAM, disk, and temperature are all within normal range."
        confidence = "high" if issues else "medium"
        temp_txt = f"{float(temp):.0f} C" if temp is not None else "n/a"
        reason_chain = [
            f"The local monitoring snapshot was collected (CPU {cpu:.0f}%, RAM {ram_percent:.0f}%, temp {temp_txt}).",
            "Service runtime metrics and per-disk usage were inspected.",
        ]
        if issues:
            reason_chain.append(issue)

        section = "monitoring" if "monitor" in question or "monitor" in route else "dashboard"
        return AgentResponse(
            category="service",
            target="system-monitoring",
            matched=True,
            title="Dashboard and monitoring diagnostics",
            summary=summary,
            confidence=confidence,
            section=section,
            subsection="system-health",
            module=self.name,
            checks_run=["system_stats", "service_metrics"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _matches_request(self, question: str, target: str, route: str) -> bool:
        if self._is_excluded(question, target):
            return any(keyword in question or keyword in target for keyword in self._METRIC_KEYWORDS)
        return (
            any(keyword in question or keyword in target for keyword in self._METRIC_KEYWORDS)
            or any(keyword in question or keyword in target for keyword in self._PAGE_KEYWORDS)
        )

    def _is_excluded(self, question: str, target: str) -> bool:
        return any(keyword in question or keyword in target for keyword in self._EXCLUDED_KEYWORDS)

    def _worst_disk(self, disks: list[dict[str, object]]) -> dict[str, float | str] | None:
        worst = None
        for disk in disks:
            used = float(disk.get("used") or 0)
            total = float(disk.get("total") or 0)
            percent = round((used / total) * 100, 1) if total else 0.0
            entry = {"mount": str(disk.get("mount") or "/"), "percent": percent}
            if worst is None or percent > worst["percent"]:
                worst = entry
        return worst

    def _top_service(self, services: list[dict[str, object]]) -> str | None:
        ranked = sorted(
            services,
            key=lambda item: (float(item.get("cpu") or 0), float(item.get("ram") or 0)),
            reverse=True,
        )
        if not ranked:
            return None
        top = ranked[0]
        return f"{top.get('name')} (CPU {float(top.get('cpu') or 0):.1f}%, RAM {float(top.get('ram') or 0):.1f} MB)"

    def _top_service_by(self, services: list[dict[str, object]], metric: str) -> str | None:
        if not services:
            return None
        top = max(services, key=lambda item: float(item.get(metric) or 0))
        return f"{top.get('name')} ({metric.upper()} {float(top.get(metric) or 0):.1f})"
