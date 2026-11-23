"""Rollback Center diagnostics module."""

from __future__ import annotations

from app.agent.adapters.operations import OperationsAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class RollbackAgent:
    """Explain safe snapshot availability and failure state without restoring anything."""

    name = "rollback_agent"

    def __init__(self, adapter: OperationsAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        route = str(request.route or "").strip().strip("/").lower().split("/", 1)[0]
        text = f"{request.question} {request.target or ''}".lower()
        rollback_words = ("rollback", "restore point", "safe snapshot")
        return (150 if route == "rollback" else 0) + (100 if any(word in text for word in rollback_words) else 0)

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        payload = await self.adapter.get_snapshots(limit=50)
        summary = dict(payload.get("summary") or {})
        snapshots = [dict(item) for item in payload.get("snapshots") or [] if isinstance(item, dict)]
        requested = str(request.entity_id or request.target or "").strip()
        selected = self._find_snapshot(requested, snapshots)
        facts = [
            AgentFact("Total snapshots", str(summary.get("total") or len(snapshots))),
            AgentFact("Ready", str(summary.get("ready") or 0)),
            AgentFact("Active", str(summary.get("active") or 0), "warning" if summary.get("active") else "info"),
            AgentFact("Failed", str(summary.get("failed") or 0), "critical" if summary.get("failed") else "info"),
        ]

        if requested and selected is None:
            result_summary = f"Requested rollback snapshot '{requested}' was not found."
            subsection = "snapshot"
        elif selected:
            status = str(selected.get("status") or "unknown")
            archive_verified = (
                selected.get("archive_exists") is True
                and selected.get("archive_readable", True) is True
            )
            facts.extend(
                [
                    AgentFact("Snapshot", self._safe(selected.get("name"))),
                    AgentFact("Status", status, "critical" if "failed" in status else "warning" if status in {"creating", "restoring"} else "info"),
                    AgentFact("Archive ready", "Yes" if archive_verified else "Unknown", "info" if archive_verified else "warning"),
                    AgentFact("Size", self._format_bytes(selected.get("size_bytes"))),
                ]
            )
            if selected.get("error_message"):
                facts.append(AgentFact("Failure cause", self._safe(selected.get("error_message")), "critical"))
            if status == "ready" and not archive_verified:
                result_summary = f"Rollback snapshot '{self._safe(selected.get('name'))}' is marked ready, but archive existence and readability are unverified."
            elif status == "failed" and selected.get("error_message"):
                result_summary = f"Rollback snapshot '{self._safe(selected.get('name'))}' failed: {self._safe(selected.get('error_message'))}."
            else:
                result_summary = f"Rollback snapshot '{self._safe(selected.get('name'))}' is currently {status}."
            subsection = "snapshot"
        elif int(summary.get("failed") or 0):
            result_summary = f"Rollback Center has {int(summary.get('failed') or 0)} failed snapshot operation(s) that need review."
            subsection = "snapshots"
        elif int(summary.get("active") or 0):
            result_summary = f"Rollback Center has {int(summary.get('active') or 0)} snapshot operation(s) still in progress."
            subsection = "snapshots"
        elif int(summary.get("ready") or 0):
            ready_records = [item for item in snapshots if str(item.get("status") or "") == "ready"]
            verified_ready = sum(
                1
                for item in ready_records
                if item.get("archive_exists") is True and item.get("archive_readable", True) is True
            )
            if verified_ready != int(summary.get("ready") or 0):
                result_summary = "Rollback restore-point data are incomplete: ready status is not backed by a verified readable archive."
            else:
                result_summary = f"Rollback Center has {verified_ready} ready restore point(s)."
            subsection = "snapshots"
        else:
            result_summary = "Rollback Center is available, but no safe snapshots exist yet."
            subsection = "snapshots"

        recommendations = [
            "Review the snapshot name, reason, status, and action preview before starting any restore.",
            "Create a safe snapshot before changing DNS, VPN, security, or other system-wide configuration.",
        ]
        if selected and selected.get("error_message") and "permission" in str(selected.get("error_message")).lower():
            recommendations.insert(0, "Check snapshot directory permissions and the privileged backup runner before retrying.")
        return AgentResponse(
            category="service",
            target=self._safe(selected.get("name")) if selected else "rollback-center",
            matched=True,
            title="Rollback Center diagnostics",
            summary=result_summary,
            confidence="high",
            section="rollback",
            subsection=subsection,
            module=self.name,
            checks_run=["rollback_summary", "rollback_snapshots"],
            facts=facts,
            reason_chain=[
                "The same local snapshot registry used by Rollback Center was read without starting a restore.",
                "Snapshot status and archive availability were checked; archive paths and contents were not exposed.",
            ],
            recommendations=recommendations,
        )

    def _find_snapshot(self, value: str, snapshots: list[dict[str, object]]) -> dict[str, object] | None:
        needle = value.strip().lower()
        if not needle:
            return None
        for snapshot in snapshots:
            snapshot_id = str(snapshot.get("snapshot_id") or "").lower()
            name = str(snapshot.get("name") or "").lower()
            if needle in {snapshot_id, name}:
                return snapshot
        return None

    @staticmethod
    def _safe(value: object) -> str:
        return " ".join(str(value or "Unknown").split())[:180]

    @staticmethod
    def _format_bytes(value: object) -> str:
        try:
            size = int(value or 0)
        except (TypeError, ValueError):
            return "Unknown"
        if size <= 0:
            return "Unknown"
        units = ("B", "KB", "MB", "GB", "TB")
        amount = float(size)
        index = 0
        while amount >= 1024 and index < len(units) - 1:
            amount /= 1024
            index += 1
        return f"{amount:.1f} {units[index]}"
