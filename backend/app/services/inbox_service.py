from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Iterable

from sqlalchemy.orm import Session

from app.schemas.inbox import InboxItem, InboxResponse, InboxSummary
from app.schemas.jobs import JobRecord
from app.services.audit_log_service import AuditLogRecord, audit_log_service
from app.services.jobs_service import JobsService
from app.services.push_notification_service import get_push_service
from app.services.proactive_monitor import get_proactive_monitor


@dataclass
class _DatedInboxItem:
    sort_ts: float
    item: InboxItem


class InboxService:
    _SECURITY_NOISE_TITLES = {"Session started", "Session ended", "SSH connection closed"}

    def __init__(
        self,
        *,
        jobs_service: JobsService | None = None,
    ) -> None:
        self.jobs_service = jobs_service or JobsService()

    def list_items(self, db: Session, limit: int = 60) -> InboxResponse:
        safe_limit = max(1, min(limit, 200))
        combined = [
            *self._collect_job_items(db, limit=safe_limit),
            *self._collect_security_items(limit=safe_limit),
            *self._collect_push_items(limit=safe_limit),
            *self._collect_watchdog_items(limit=safe_limit),
        ]
        combined.sort(key=lambda item: item.sort_ts, reverse=True)
        items = [entry.item for entry in combined[:safe_limit]]

        return InboxResponse(
            generated_at=datetime.now(timezone.utc).isoformat(),
            summary=self._build_summary(items),
            items=items,
        )

    def _collect_job_items(self, db: Session, limit: int) -> list[_DatedInboxItem]:
        jobs_response = self.jobs_service.list_jobs(db, limit=limit)
        entries: list[_DatedInboxItem] = []

        for job in jobs_response.jobs:
            if not self._should_include_job(job):
                continue

            timestamp = job.updated_at or job.started_at
            severity = self._job_severity(job.status)
            entries.append(
                _DatedInboxItem(
                    sort_ts=self._parse_timestamp(timestamp),
                    item=InboxItem(
                        event_id=f"job:{job.job_id}",
                        source="jobs",
                        severity=severity,
                        title=job.title,
                        message=job.message or self._default_job_message(job),
                        timestamp=timestamp,
                        route=job.route or "/jobs",
                        source_label="Jobs Center",
                    ),
                )
            )

        return entries

    def _collect_security_items(self, limit: int) -> list[_DatedInboxItem]:
        entries: list[_DatedInboxItem] = []
        for index, record in enumerate(audit_log_service.read_recent(limit=limit * 2)):
            if record.type not in {"warning", "success"}:
                continue
            if record.title in self._SECURITY_NOISE_TITLES:
                continue
            entries.append(
                _DatedInboxItem(
                    sort_ts=self._parse_timestamp(record.timestamp),
                    item=InboxItem(
                        event_id=f"security:{index}:{record.timestamp}:{record.title}",
                        source="security",
                        severity=self._security_severity(record),
                        title=record.title,
                        message=record.details,
                        timestamp=record.timestamp,
                        route="/security",
                        source_label="Security",
                    ),
                )
            )
        return entries[:limit]

    def _collect_push_items(self, limit: int) -> list[_DatedInboxItem]:
        push_service = get_push_service()
        history = list(reversed(push_service.get_history(limit=limit)))
        entries: list[_DatedInboxItem] = []

        for index, entry in enumerate(history):
            timestamp = str(entry.get("timestamp") or "")
            success = int(entry.get("success") or 0)
            failed = int(entry.get("failed") or 0)
            delivery_bits: list[str] = []
            if success:
                delivery_bits.append(f"delivered to {success}")
            if failed:
                delivery_bits.append(f"failed for {failed}")
            delivery_summary = f" ({', '.join(delivery_bits)})" if delivery_bits else ""

            entries.append(
                _DatedInboxItem(
                    sort_ts=self._parse_timestamp(timestamp),
                    item=InboxItem(
                        event_id=f"push:{index}:{timestamp}",
                        source="push",
                        severity="warning" if failed else "info",
                        title=str(entry.get("title") or "Push notification"),
                        message=f"{str(entry.get('body') or '').strip()}{delivery_summary}".strip(),
                        timestamp=timestamp or None,
                        route="/settings?tab=notifications",
                        source_label="Push Notifications",
                    ),
                )
            )

        return entries

    def _collect_watchdog_items(self, limit: int) -> list[_DatedInboxItem]:
        try:
            events = get_proactive_monitor().read_events(limit=limit)
        except Exception:
            events = []
        entries: list[_DatedInboxItem] = []
        for rec in events:
            severity = str(rec.get("severity") or "info")
            if severity not in {"critical", "warning", "success", "info"}:
                severity = "info"
            timestamp = rec.get("triggered_at")
            entries.append(
                _DatedInboxItem(
                    sort_ts=float(rec.get("ts") or self._parse_timestamp(timestamp)),
                    item=InboxItem(
                        event_id=str(rec.get("event_id") or f"watchdog:{rec.get('ts')}"),
                        source="watchdog",
                        severity=severity,  # type: ignore[arg-type]
                        title=str(rec.get("title") or "Watchdog alert"),
                        message=str(rec.get("message") or ""),
                        timestamp=timestamp,
                        route=str(rec.get("route") or "/monitoring"),
                        source_label="Watchdog",
                    ),
                )
            )
        return entries

    def _should_include_job(self, job: JobRecord) -> bool:
        if job.status in {"failed", "unknown", "cancelled", "running", "queued"}:
            return True
        if job.status != "success":
            return False
        timestamp = self._parse_timestamp(job.updated_at or job.started_at)
        return timestamp >= (datetime.now(timezone.utc) - timedelta(days=1)).timestamp()

    def _job_severity(self, status: str) -> str:
        if status in {"failed", "unknown"}:
            return "critical"
        if status == "cancelled":
            return "warning"
        if status == "success":
            return "success"
        return "info"

    def _default_job_message(self, job: JobRecord) -> str:
        if job.status == "success":
            return "Background job completed successfully"
        if job.status == "failed":
            return "Background job failed and needs attention"
        if job.status == "cancelled":
            return "Background job was cancelled"
        if job.status == "queued":
            return "Background job is waiting to start"
        if job.status == "running":
            return "Background job is still running"
        return "Background job state is unknown"

    def _security_severity(self, record: AuditLogRecord) -> str:
        if record.type == "warning":
            return "warning"
        if record.type == "success":
            return "success"
        return "info"

    def _build_summary(self, items: Iterable[InboxItem]) -> InboxSummary:
        summary = InboxSummary()
        for item in items:
            summary.total += 1
            if item.severity == "critical":
                summary.critical += 1
                summary.action_required += 1
            elif item.severity == "warning":
                summary.warning += 1
                summary.action_required += 1
            elif item.severity == "success":
                summary.success += 1
            else:
                summary.info += 1

            if item.source == "jobs":
                summary.jobs += 1
            elif item.source == "security":
                summary.security += 1
            elif item.source == "push":
                summary.push += 1
            elif item.source == "watchdog":
                summary.watchdog += 1
        return summary

    def _parse_timestamp(self, value: str | None) -> float:
        if not value:
            return 0.0

        text = str(value).strip()
        if not text:
            return 0.0

        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            pass

        for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                parsed = datetime.strptime(text, fmt).replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                if parsed > now + timedelta(days=1):
                    parsed = parsed.replace(year=parsed.year - 1)
                return parsed.timestamp()
            except ValueError:
                continue

        return 0.0
