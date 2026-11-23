"""System backup agent module."""

from __future__ import annotations

from app.agent.adapters.backup import BackupAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class BackupAgent:
    """Explain backup and restore state from local backup history."""

    name = "backup_agent"
    _KEYWORDS = ("backup", "restore", "archive", "download backup", "cancel backup", "delete backup")
    _ROUTES = ("backup",)

    def __init__(self, adapter: BackupAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 100

        if any(token in route for token in self._ROUTES):
            score += 30

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and "backup" not in route:
            return None

        backups = await self.adapter.list_backups()
        if not backups:
            return AgentResponse(
                category="service",
                target="system-backup",
                matched=True,
                title="No backups found",
                summary="EasyPi has no backups yet — if something breaks or the SD card fails, there is nothing to restore from.",
                confidence="high",
                section="system-backup",
                subsection="jobs",
                module=self.name,
                checks_run=["backup_history"],
                facts=[AgentFact("Backups", "0", "warning")],
                reason_chain=[
                    "The backup database was queried.",
                    "No backup jobs were found.",
                ],
                recommendations=[
                    "Create your first backup now from the Backup page (a config backup is quick).",
                    "Take a full backup before risky changes or updates so you can roll back.",
                    "Set up a schedule so backups run automatically.",
                ],
            )

        running = next((item for item in backups if str(item.get("status")) == "running"), None)
        failed = next((item for item in backups if str(item.get("status")) == "failed"), None)
        completed = next((item for item in backups if str(item.get("status")) == "completed"), None)
        requested = next(
            (
                item for item in backups
                if str(item.get("name") or "").strip()
                and str(item.get("name") or "").strip().lower() in f"{target} {question}"
            ),
            None,
        )
        if requested is not None:
            if str(requested.get("status")) == "completed":
                completed = requested
            elif str(requested.get("status")) == "failed":
                failed = requested
            elif str(requested.get("status")) == "running":
                running = requested

        wants_restore = "restore" in question
        wants_download = "download" in question
        wants_cancel = "cancel" in question
        wants_delete = "delete" in question or "remove backup" in question
        wants_failure = any(token in question for token in ("fail", "failed", "failure", "error", "broken"))

        if wants_restore and completed is None:
            reference = failed or backups[0]
            return self._response_for_entry(
                entry=reference,
                summary="No completed backup is available for restore right now.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for completed jobs.",
                    "No completed backup archive is currently available.",
                ],
                recommendations=[
                    "Create a new backup before attempting a restore.",
                    "Inspect the latest failed backup error and fix it first.",
                ],
                subsection="restore",
            )

        if wants_restore and completed is not None:
            if not completed.get("file_path") or not bool(completed.get("file_exists")):
                return self._response_for_entry(
                    entry=completed,
                    summary=f"Backup '{completed.get('name')}' is marked as completed, but its restore archive is missing or unavailable.",
                    confidence="high",
                    reason_chain=[
                        "The backup history was inspected for completed jobs.",
                        "The completed backup record points to a missing local archive file.",
                    ],
                    recommendations=[
                        "Create a fresh backup before attempting restore.",
                        "Avoid relying on this backup record until a new archive is generated successfully.",
                    ],
                    subsection="restore",
                )
            return self._response_for_entry(
                entry=completed,
                summary=f"Backup '{completed.get('name')}' is available for restore, but restore can overwrite current EasyPi state.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for completed jobs.",
                    "A completed backup archive is available for restore.",
                ],
                recommendations=[
                    "Create a fresh backup before restoring if the current state still matters.",
                    "Plan restore during a maintenance window because current configuration may be overwritten.",
                ],
                subsection="restore",
            )

        if wants_download and completed is None:
            reference = failed or backups[0]
            return self._response_for_entry(
                entry=reference,
                summary="No completed backup is currently available for download.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for completed jobs.",
                    "No completed archive is currently available to download.",
                ],
                recommendations=[
                    "Run a new backup first if you need a downloadable archive.",
                ],
                subsection="jobs",
            )

        if wants_download and completed is not None:
            if not completed.get("file_path"):
                return self._response_for_entry(
                    entry=completed,
                    summary=f"Backup '{completed.get('name')}' is completed, but no archive path is recorded for download.",
                    confidence="high",
                    reason_chain=[
                        "The backup history was inspected for completed jobs.",
                        "The selected backup record has no stored archive path.",
                    ],
                    recommendations=[
                        "Create a new backup if you need a downloadable archive.",
                    ],
                    subsection="jobs",
                )
            if not bool(completed.get("file_exists")):
                return self._response_for_entry(
                    entry=completed,
                    summary=f"Backup '{completed.get('name')}' is completed, but the archive file is missing, so download will fail.",
                    confidence="high",
                    reason_chain=[
                        "The backup history was inspected for completed jobs.",
                        "The selected backup record points to a missing local archive file.",
                    ],
                    recommendations=[
                        "Create a fresh backup before trying to download an archive again.",
                    ],
                    subsection="jobs",
                )
            return self._response_for_entry(
                entry=completed,
                summary=f"Backup '{completed.get('name')}' should be downloadable from System Backup.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for completed jobs.",
                    "A completed backup archive is available in local backup history.",
                ],
                recommendations=[
                    "Download the archive now if you need an offline copy before making system changes.",
                ],
                subsection="jobs",
            )

        if wants_delete:
            reference = failed or completed or backups[0]
            if reference.get("status") == "running":
                return self._response_for_entry(
                    entry=reference,
                    summary=f"Backup '{reference.get('name')}' is still running and should not be deleted until it finishes or is cancelled.",
                    confidence="high",
                    reason_chain=[
                        "The backup history was inspected.",
                        "The selected backup is still marked as running.",
                    ],
                    recommendations=[
                        "Cancel the running job first if it was started by mistake.",
                    ],
                    subsection="jobs",
                )
            return self._response_for_entry(
                entry=reference,
                summary=f"Backup '{reference.get('name')}' can be deleted if you no longer need that archive.",
                confidence="medium",
                reason_chain=[
                    "The backup history was inspected.",
                    "A concrete backup archive was selected as the current delete candidate.",
                ],
                recommendations=[
                    "Keep at least one recent recovery point before deleting older backups.",
                ],
                subsection="jobs",
            )

        if wants_failure and failed is not None:
            if "cancelled by user" in str(failed.get("error_message") or "").strip().lower():
                return self._response_for_entry(
                    entry=failed,
                    summary=f"The latest failed backup '{failed.get('name')}' was cancelled by a user, not by a storage or runtime error.",
                    confidence="high",
                    reason_chain=[
                        "The backup history contains a failed job.",
                        "The recorded error message shows that the backup was cancelled manually.",
                    ],
                    recommendations=[
                        "Start a new backup if the cancellation was unintentional.",
                    ],
                    subsection="jobs",
                )
            return self._response_for_entry(
                entry=failed,
                summary=f"The latest failed backup is '{failed.get('name')}'.",
                confidence="high",
                reason_chain=[
                    "The backup history contains a failed job.",
                    "The latest failed job was selected because the question asked about failures.",
                ],
                recommendations=[
                    "Review the recorded error message before retrying the backup.",
                    "Check storage permissions and available disk space.",
                ],
                subsection="jobs",
            )

        if wants_cancel and running is None:
            return self._response_for_entry(
                entry=backups[0],
                summary="No running backup job is available to cancel right now.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for running jobs.",
                    "No job currently reports a running state.",
                ],
                recommendations=[
                    "Start a new backup only if you actually need a fresh archive.",
                ],
                subsection="jobs",
            )

        if wants_cancel and running is not None:
            return self._response_for_entry(
                entry=running,
                summary=f"Backup '{running.get('name')}' is currently running and can be cancelled.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected for running jobs.",
                    "A running backup job is still active.",
                ],
                recommendations=[
                    "Cancel the running job only if it is stuck or was started by mistake.",
                ],
                subsection="jobs",
            )

        if running is not None:
            return self._response_for_entry(
                entry=running,
                summary=f"Backup '{running.get('name')}' is currently running.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected.",
                    "A running backup job is still active.",
                ],
                recommendations=[
                    "Wait for the current job to finish before starting another backup.",
                    "Inspect the backup status in the UI before cancelling the running job.",
                ],
                subsection="jobs",
            )

        if completed is not None:
            return self._response_for_entry(
                entry=completed,
                summary=f"The latest completed backup is '{completed.get('name')}'.",
                confidence="high",
                reason_chain=[
                    "The backup history was inspected.",
                    "The most recent completed backup was selected.",
                ],
                recommendations=[
                    "Download the archive if you want an offline copy.",
                    "Keep at least one recent full backup and one config backup.",
                ],
                subsection="jobs",
            )

        return self._response_for_entry(
            entry=backups[0],
            summary="Backup history is available, but EasyPi could not determine a stronger state yet.",
            confidence="medium",
            reason_chain=[
                "The backup history was inspected.",
                "No running or completed backup was suitable for a stronger explanation.",
            ],
            recommendations=[
                "Open System Backup to inspect the latest backup jobs directly.",
            ],
            subsection="jobs",
        )

    def _response_for_entry(
        self,
        *,
        entry: dict[str, object],
        summary: str,
        confidence: str,
        reason_chain: list[str],
        recommendations: list[str],
        subsection: str,
    ) -> AgentResponse:
        status = str(entry.get("status") or "unknown")
        facts = [
            AgentFact("Backup name", str(entry.get("name") or "Unknown")),
            AgentFact("Type", str(entry.get("type") or "Unknown")),
            AgentFact("Status", status, "critical" if status == "failed" else "info"),
            AgentFact("Created at", str(entry.get("created_at") or "Unknown")),
            AgentFact("Size", str(entry.get("size") or "Unknown")),
            AgentFact("Restore risk", "Current state may be overwritten" if status == "completed" else "Unavailable"),
        ]
        if entry.get("file_path"):
            facts.append(AgentFact("Archive path", str(entry.get("file_path"))))
            facts.append(
                AgentFact(
                    "Archive file present",
                    "Yes" if bool(entry.get("file_exists")) else "No",
                    "info" if bool(entry.get("file_exists")) else "warning",
                )
            )
        error_message = str(entry.get("error_message") or "").strip()
        if error_message:
            facts.append(AgentFact("Error", error_message, "critical"))

        return AgentResponse(
            category="service",
            target="system-backup",
            matched=True,
            title="System backup diagnostics",
            summary=summary,
            confidence=confidence,
            section="system-backup",
            subsection=subsection,
            module=self.name,
            checks_run=["backup_history"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )
