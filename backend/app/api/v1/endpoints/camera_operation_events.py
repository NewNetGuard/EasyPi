"""Shared operation event helpers for camera endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.services.operation_event_service import OperationEventService

logger = logging.getLogger("easypi")
operation_event_service = OperationEventService()


def record_camera_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/cameras",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record camera event %s: %s", action_id, exc)
