from __future__ import annotations

import json
from pathlib import Path

import main as main_module

from app.services.operation_event_service import (
    MAX_OPERATION_EVENTS,
    OperationEventService,
)


def test_operation_events_prune_old_files(tmp_path: Path) -> None:
    service = OperationEventService(tmp_path)
    for index in range(MAX_OPERATION_EVENTS + 20):
        service.record_event(
            event_id=f"event-{index:04d}",
            action_id="test.event",
            status="success",
            title="Test",
        )

    assert len(list(tmp_path.glob("*.json"))) == MAX_OPERATION_EVENTS
    assert len(service.list_events(MAX_OPERATION_EVENTS + 100)) == MAX_OPERATION_EVENTS


def test_stable_auth_event_id_does_not_allocate_more_files(tmp_path: Path) -> None:
    service = OperationEventService(tmp_path)
    for status_code in range(100):
        service.record_event(
            event_id="auth-workflow-login-failed",
            action_id="auth.workflow.login",
            status="failed",
            title="Authentication login workflow",
            message=f"HTTP {status_code}",
        )

    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text(encoding="utf-8"))["message"] == "HTTP 99"


def test_public_auth_event_writes_are_throttled(monkeypatch) -> None:
    main_module._auth_event_last_write.clear()
    moments = iter((100.0, 105.0, 111.0))
    monkeypatch.setattr(main_module.time, "monotonic", lambda: next(moments))

    assert main_module._should_record_auth_event("login", "failed") is True
    assert main_module._should_record_auth_event("login", "failed") is False
    assert main_module._should_record_auth_event("login", "failed") is True
