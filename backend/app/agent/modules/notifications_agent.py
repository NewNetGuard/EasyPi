"""Notification Inbox diagnostics module."""

from __future__ import annotations

from app.agent.adapters.operations import OperationsAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class NotificationsAgent:
    """Explain the combined Jobs, Security, Push, and Watchdog inbox."""

    name = "notifications_agent"
    _FILTERS = {"all", "attention", "jobs", "security", "push", "watchdog"}

    def __init__(self, adapter: OperationsAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        route = str(request.route or "").strip().strip("/").lower().split("/", 1)[0]
        text = f"{request.question} {request.target or ''}".lower()
        return (150 if route == "notifications" else 0) + (90 if any(word in text for word in ("notification", "inbox", "watchdog", "push delivery")) else 0)

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        try:
            payload = await self.adapter.get_notifications(limit=80)
        except Exception as exc:
            return AgentResponse(
                category="service",
                target="notification-inbox",
                matched=True,
                title="Notification source unavailable",
                summary=f"Notification database/source is unavailable: {type(exc).__name__}: {exc}.",
                confidence="low",
                section="notifications",
                subsection="all",
                module=self.name,
                checks_run=["notification_summary", "notification_recent"],
                facts=[AgentFact("Source failure", str(exc), "warning")],
                reason_chain=["The notification source failure was preserved instead of being treated as an empty inbox."],
                recommendations=["Restore the notification data source and retry."],
            )
        summary = dict(payload.get("summary") or {})
        items = [dict(item) for item in payload.get("items") or [] if isinstance(item, dict)]
        active_filter = self._resolve_filter(request)
        visible = self._apply_filter(items, active_filter)
        latest = visible[0] if visible else None
        action_required = int(summary.get("action_required") or 0)
        item_attention = sum(1 for item in items if str(item.get("severity") or "").lower() in {"critical", "warning"})
        aggregate_conflict = action_required != item_attention

        facts = [
            AgentFact("Inbox items", str(summary.get("total") or len(items))),
            AgentFact("Needs attention", str(action_required), "critical" if action_required else "info"),
            AgentFact("Critical", str(summary.get("critical") or 0), "critical" if summary.get("critical") else "info"),
            AgentFact("Warnings", str(summary.get("warning") or summary.get("warnings") or sum(1 for item in items if item.get("severity") == "warning")), "warning" if item_attention else "info"),
            AgentFact("Visible in current view", str(len(visible))),
        ]
        if latest:
            severity = str(latest.get("severity") or "info")
            facts.extend(
                [
                    AgentFact("Latest event", self._safe(latest.get("title"))),
                    AgentFact("Latest source", self._safe(latest.get("source_label") or latest.get("source"))),
                    AgentFact("Latest severity", severity, "critical" if severity == "critical" else "warning" if severity == "warning" else "info"),
                ]
            )

        if aggregate_conflict:
            result_summary = "Notification aggregate and item details conflict, so attention state is unverified."
        elif action_required:
            result_summary = f"Notification Inbox has {action_required} event(s) that need attention."
        elif items:
            result_summary = "Notification Inbox has no critical or warning events that require action right now."
        else:
            result_summary = "Notification Inbox is available and currently empty."

        recommendations = (
            ["Open the newest critical or warning item and follow its link to the owning EasyPi section."]
            if action_required
            else ["No immediate action is required; use a source filter when you want to inspect one event stream."]
        )
        return AgentResponse(
            category="service",
            target="notification-inbox",
            matched=True,
            title="Notification Inbox diagnostics",
            summary=result_summary,
            confidence="low" if aggregate_conflict else "high",
            section="notifications",
            subsection=active_filter,
            module=self.name,
            checks_run=["notification_summary", "notification_recent"],
            facts=facts,
            reason_chain=[
                "The same combined inbox feed used by the Notifications page was read from local EasyPi state.",
                f"The active '{active_filter}' view was applied across Jobs, Security, Push, and Watchdog events.",
            ],
            recommendations=recommendations,
        )

    def _resolve_filter(self, request: AgentRequest) -> str:
        tab = str(request.tab or "").strip().lower()
        if tab in self._FILTERS:
            return tab
        text = f"{request.question} {request.target or ''}".lower()
        for active_filter in ("watchdog", "security", "push", "jobs"):
            if active_filter in text:
                return active_filter
        if any(word in text for word in ("attention", "critical", "warning")):
            return "attention"
        return "all"

    def _apply_filter(self, items: list[dict[str, object]], active_filter: str) -> list[dict[str, object]]:
        if active_filter == "attention":
            return [item for item in items if item.get("severity") in {"critical", "warning"}]
        if active_filter in {"jobs", "security", "push", "watchdog"}:
            return [item for item in items if item.get("source") == active_filter]
        return items

    @staticmethod
    def _safe(value: object) -> str:
        return " ".join(str(value or "Unknown").split())[:180]
