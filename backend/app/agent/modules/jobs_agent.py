"""Jobs Center diagnostics module."""

from __future__ import annotations

from app.agent.adapters.operations import OperationsAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class JobsAgent:
    """Explain queued, running, failed, and completed background work."""

    name = "jobs_agent"
    _FILTERS = {"all", "active", "attention", "completed"}

    def __init__(self, adapter: OperationsAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        route = str(request.route or "").strip().strip("/").lower().split("/", 1)[0]
        text = f"{request.question} {request.target or ''}".lower()
        return (150 if route == "jobs" else 0) + (90 if any(word in text for word in ("job", "background task", "installer")) else 0)

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        payload = await self.adapter.get_jobs(limit=50)
        summary = dict(payload.get("summary") or {})
        jobs = [dict(item) for item in payload.get("jobs") or [] if isinstance(item, dict)]
        active_filter = self._resolve_filter(request)
        visible = self._apply_filter(jobs, active_filter)
        latest = visible[0] if visible else None
        derived_active = sum(1 for item in jobs if item.get("status") in {"running", "queued"})
        derived_attention = sum(1 for item in jobs if item.get("status") in {"failed", "cancelled", "unknown"})
        active_keys_present = "running" in summary or "queued" in summary
        attention_keys_present = any(key in summary for key in ("failed", "cancelled", "unknown"))
        aggregate_active = int(summary.get("running") or 0) + int(summary.get("queued") or 0)
        aggregate_attention = int(summary.get("failed") or 0) + int(summary.get("cancelled") or 0) + int(summary.get("unknown") or 0)
        active = aggregate_active if active_keys_present else derived_active
        attention = aggregate_attention if attention_keys_present else derived_attention
        conflict = (active_keys_present and active != derived_active) or (attention_keys_present and attention != derived_attention)

        facts = [
            AgentFact("Total jobs", str(summary.get("total") or len(jobs))),
            AgentFact("Active", str(active), "warning" if active else "info"),
            AgentFact("Completed", str(summary.get("success") or 0)),
            AgentFact("Needs attention", str(attention), "critical" if attention else "info"),
            AgentFact("Visible in current view", str(len(visible))),
        ]
        if latest:
            status = str(latest.get("status") or "unknown")
            facts.extend(
                [
                    AgentFact("Latest job", self._safe(latest.get("title"))),
                    AgentFact("Latest status", status, "critical" if status in {"failed", "unknown"} else "warning" if status in {"queued", "running", "cancelled"} else "info"),
                    AgentFact("Source", self._safe(latest.get("source"))),
                ]
            )
            if latest.get("created_at"):
                facts.append(AgentFact("Created at", str(latest.get("created_at"))))

        if conflict:
            result_summary = "Jobs Center aggregate and item records are inconsistent, so active job counts are unverified."
        elif attention:
            result_summary = f"Jobs Center has {attention} background operation(s) that need attention."
        elif active:
            result_summary = f"Jobs Center has {active} operation(s) still running or queued."
        elif jobs:
            result_summary = "Jobs Center has no active or failed background operations right now."
        else:
            result_summary = "Jobs Center is available, but no background operations have been recorded yet."

        return AgentResponse(
            category="service",
            target="jobs-center",
            matched=True,
            title="Jobs Center diagnostics",
            summary=result_summary,
            confidence="high",
            section="jobs",
            subsection=active_filter,
            module=self.name,
            checks_run=["jobs_summary", "jobs_recent"],
            facts=facts,
            reason_chain=[
                "The same combined job feed used by Jobs Center was read from local EasyPi state.",
                f"The active '{active_filter}' view was applied before choosing the latest visible operation.",
            ],
            recommendations=self._recommendations(active, attention, latest),
        )

    def _resolve_filter(self, request: AgentRequest) -> str:
        tab = str(request.tab or "").strip().lower()
        if tab in self._FILTERS:
            return tab
        text = f"{request.question} {request.target or ''}".lower()
        if any(word in text for word in ("fail", "attention", "cancel", "unknown")):
            return "attention"
        if any(word in text for word in ("running", "queued", "active", "pending", "stuck")):
            return "active"
        if any(word in text for word in ("completed", "success", "finished")):
            return "completed"
        return "all"

    def _apply_filter(self, jobs: list[dict[str, object]], active_filter: str) -> list[dict[str, object]]:
        if active_filter == "active":
            return [item for item in jobs if item.get("status") in {"running", "queued"}]
        if active_filter == "attention":
            return [item for item in jobs if item.get("status") in {"failed", "cancelled", "unknown"}]
        if active_filter == "completed":
            return [item for item in jobs if item.get("status") == "success"]
        return jobs

    def _recommendations(self, active: int, attention: int, latest: dict[str, object] | None) -> list[str]:
        if attention:
            return ["Open the newest failed or unclear job and inspect its saved status before retrying the originating action."]
        if active:
            return ["Let the active operation finish unless its timestamp and progress show that it is genuinely stuck."]
        if latest:
            return ["No immediate action is required; open the originating section only if its result looks incomplete."]
        return ["Start an EasyPi installer, backup, snapshot, or admin operation to populate Jobs Center."]

    @staticmethod
    def _safe(value: object) -> str:
        return " ".join(str(value or "Unknown").split())[:180]
