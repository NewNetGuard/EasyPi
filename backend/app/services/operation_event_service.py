from __future__ import annotations

import json
import logging
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.core.paths import get_data_dir

logger = logging.getLogger(__name__)
_EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_OPERATION_EVENTS = 512


@dataclass
class OperationEventRecord:
    event_id: str
    action_id: str
    status: str
    title: str
    subtitle: str | None
    route: str | None
    message: str | None
    started_at: str
    updated_at: str


class OperationEventService:
    def __init__(self, metadata_dir: Path | None = None) -> None:
        self.metadata_dir = metadata_dir or (get_data_dir() / "operations")

    def record_event(
        self,
        *,
        action_id: str,
        status: str,
        title: str,
        subtitle: str | None = None,
        route: str | None = None,
        message: str | None = None,
        started_at: str | None = None,
        updated_at: str | None = None,
        event_id: str | None = None,
    ) -> OperationEventRecord:
        self.metadata_dir.mkdir(parents=True, exist_ok=True)

        now_iso = datetime.now(timezone.utc).isoformat()
        safe_event_id = event_id or f"op-{uuid.uuid4().hex}"
        self._validate_event_id(safe_event_id)
        record = OperationEventRecord(
            event_id=safe_event_id,
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route=route,
            message=message,
            started_at=started_at or now_iso,
            updated_at=updated_at or now_iso,
        )

        payload = {
            "event_id": record.event_id,
            "action_id": record.action_id,
            "status": record.status,
            "title": record.title,
            "subtitle": record.subtitle,
            "route": record.route,
            "message": record.message,
            "started_at": record.started_at,
            "updated_at": record.updated_at,
        }

        path = self._event_path(record.event_id)
        is_new_event = not path.exists()
        try:
            self._write_payload(path, payload)
            if is_new_event:
                self._prune_old_events()
        except Exception as exc:
            logger.warning("Failed to persist operation event %s: %s", record.event_id, exc)
        return record

    def update_event(
        self,
        event_id: str,
        *,
        status: str,
        message: str | None = None,
        updated_at: str | None = None,
    ) -> OperationEventRecord | None:
        """Update an existing event while preserving its identity and start time."""
        path = self._event_path(event_id)
        payload = self._read_payload(path)
        if not payload:
            return None

        return self.record_event(
            event_id=event_id,
            action_id=str(payload.get("action_id") or "unknown"),
            status=status,
            title=str(payload.get("title") or "Admin action"),
            subtitle=self._coerce_optional_str(payload.get("subtitle")),
            route=self._coerce_optional_str(payload.get("route")),
            message=message if message is not None else self._coerce_optional_str(payload.get("message")),
            started_at=str(payload.get("started_at") or "") or None,
            updated_at=updated_at or datetime.now(timezone.utc).isoformat(),
        )

    def list_events(self, limit: int = 40) -> list[OperationEventRecord]:
        if not self.metadata_dir.exists():
            return []

        # Bound legacy directories before parsing their contents. This also
        # ensures a restored installation cannot make the Jobs page scan an
        # unlimited number of historical files.
        self._prune_old_events()

        entries: list[OperationEventRecord] = []
        for path in self.metadata_dir.glob("*.json"):
            payload = self._read_payload(path)
            if not payload:
                continue

            entries.append(
                OperationEventRecord(
                    event_id=str(payload.get("event_id") or path.stem),
                    action_id=str(payload.get("action_id") or "unknown"),
                    status=str(payload.get("status") or "unknown"),
                    title=str(payload.get("title") or "Admin action"),
                    subtitle=self._coerce_optional_str(payload.get("subtitle")),
                    route=self._coerce_optional_str(payload.get("route")),
                    message=self._coerce_optional_str(payload.get("message")),
                    started_at=str(payload.get("started_at") or ""),
                    updated_at=str(payload.get("updated_at") or payload.get("started_at") or ""),
                )
            )

        # Files may be restored or copied later, so filesystem mtime is not the
        # semantic recency of an operation. Sort by the record timestamp and
        # place malformed timestamps last.
        entries.sort(key=self._event_timestamp, reverse=True)
        return entries[: max(0, min(int(limit), MAX_OPERATION_EVENTS))]

    def _prune_old_events(self) -> None:
        """Retain only a bounded set of regular event files."""

        try:
            candidates: list[tuple[int, str, Path]] = []
            for path in self.metadata_dir.glob("*.json"):
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    details = path.stat()
                except OSError:
                    continue
                candidates.append((details.st_mtime_ns, path.name, path))
            candidates.sort(reverse=True)
            for _mtime, _name, path in candidates[MAX_OPERATION_EVENTS:]:
                try:
                    path.unlink()
                except OSError as exc:
                    logger.warning("Failed to prune operation event %s: %s", path, exc)
        except OSError as exc:
            logger.warning("Failed to enumerate operation events for pruning: %s", exc)

    @staticmethod
    def _event_timestamp(record: OperationEventRecord) -> datetime:
        raw = str(record.updated_at or record.started_at or "").strip()
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return datetime.min.replace(tzinfo=timezone.utc)

    def _read_payload(self, path: Path) -> dict[str, Any] | None:
        if path.is_symlink() or not path.is_file():
            logger.warning("Refusing unsafe operation event %s", path)
            return None
        try:
            if path.stat().st_size > 256 * 1024:
                logger.warning("Operation event is too large: %s", path)
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Failed to read operation event %s: %s", path, exc)
            return None

        if not isinstance(payload, dict):
            logger.warning("Operation event %s is not a JSON object", path)
            return None
        return payload

    def _event_path(self, event_id: str) -> Path:
        self._validate_event_id(event_id)
        return self.metadata_dir / f"{event_id}.json"

    def _validate_event_id(self, event_id: str) -> None:
        if not _EVENT_ID_RE.fullmatch(str(event_id or "")):
            raise ValueError("Invalid operation event id")

    def _write_payload(self, path: Path, payload: dict[str, Any]) -> None:
        """Write metadata atomically with private permissions."""
        temp_path = self.metadata_dir / f".{path.name}.{uuid.uuid4().hex}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(temp_path, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=False, indent=2)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_path, path)
            os.chmod(path, 0o600)
        except Exception:
            temp_path.unlink(missing_ok=True)
            raise

    def _coerce_optional_str(self, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None
