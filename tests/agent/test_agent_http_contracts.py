from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.deps import require_admin
from app.api.v1.endpoints import ai as ai_endpoint

enforce_diagnostic_read_rate_limit = ai_endpoint.enforce_diagnostic_read_rate_limit
enforce_diagnostic_write_rate_limit = ai_endpoint.enforce_diagnostic_write_rate_limit


def _isolated_client(*, authenticated: bool) -> tuple[FastAPI, TestClient]:
    app = FastAPI()
    app.include_router(ai_endpoint.router, prefix="/api/v1/ai")
    if authenticated:
        app.dependency_overrides[require_admin] = lambda: SimpleNamespace(id=7)
    return app, TestClient(app)


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("/diagnostics/explain", {"question": "Check database health"}),
        ("/diagnostics/probe", {"probe_id": "health.dependencies", "parameters": {}}),
        (
            "/diagnostics/action",
            {"action_id": "test.action", "confirmation_token": "x" * 24, "parameters": {}},
        ),
    ],
)
def test_diagnostic_http_endpoints_require_authentication(path, payload) -> None:
    _app, client = _isolated_client(authenticated=False)

    response = client.post(f"/api/v1/ai{path}", json=payload)

    assert response.status_code == 401


def test_probe_http_endpoint_applies_actor_and_response_schema(monkeypatch) -> None:
    captured = {}

    async def run_probe(probe_id, *, parameters, actor_user_id):
        captured.update(probe_id=probe_id, parameters=parameters, actor_user_id=actor_user_id)
        return {
            "success": False,
            "probe_id": probe_id,
            "source_status": "partial",
            "message": "Redis is unavailable.",
            "details": {"redis": "unknown"},
        }

    monkeypatch.setattr(ai_endpoint.diagnostic_service, "run_probe", run_probe)
    app, client = _isolated_client(authenticated=True)
    app.dependency_overrides[enforce_diagnostic_read_rate_limit] = lambda: None

    response = client.post(
        "/api/v1/ai/diagnostics/probe",
        json={"probe_id": "health.dependencies", "parameters": {}},
    )

    assert response.status_code == 200
    assert response.json()["source_status"] == "partial"
    assert captured == {"probe_id": "health.dependencies", "parameters": {}, "actor_user_id": 7}


def test_action_http_endpoint_preserves_failure_contract(monkeypatch) -> None:
    async def execute_action(**kwargs):
        return {
            "action_id": kwargs["action_id"],
            "success": False,
            "message": "sudo denied",
            "data": {"status": "error"},
            "follow_up": None,
        }

    monkeypatch.setattr(ai_endpoint.diagnostic_service, "execute_action", execute_action)
    app, client = _isolated_client(authenticated=True)
    app.dependency_overrides[enforce_diagnostic_write_rate_limit] = lambda: None

    response = client.post(
        "/api/v1/ai/diagnostics/action",
        json={"action_id": "security.fix_firewall", "confirmation_token": "x" * 24, "parameters": {}},
    )

    assert response.status_code == 200
    assert response.json()["success"] is False
    assert response.json()["message"] == "sudo denied"


def test_probe_http_endpoint_propagates_rate_limit() -> None:
    async def limited():
        raise HTTPException(status_code=429, detail="Diagnostic rate limit exceeded")

    app, client = _isolated_client(authenticated=True)
    app.dependency_overrides[enforce_diagnostic_read_rate_limit] = limited

    response = client.post(
        "/api/v1/ai/diagnostics/probe",
        json={"probe_id": "health.dependencies", "parameters": {}},
    )

    assert response.status_code == 429


def test_main_app_rejects_diagnostic_post_without_csrf(monkeypatch) -> None:
    monkeypatch.setenv("ENV", "testing")
    from main import app

    app.dependency_overrides[require_admin] = lambda: SimpleNamespace(id=7)
    try:
        response = TestClient(app).post(
            "/api/v1/ai/diagnostics/probe",
            json={"probe_id": "health.dependencies", "parameters": {}},
        )
    finally:
        app.dependency_overrides.pop(require_admin, None)

    assert response.status_code == 403
    assert response.json()["detail"] == "CSRF token missing"


def test_auth_workflow_validation_failure_is_recorded(monkeypatch) -> None:
    monkeypatch.setenv("ENV", "testing")
    import main as main_module

    main_module._auth_event_last_write.clear()
    events: list[dict[str, object]] = []
    monkeypatch.setattr(
        main_module._auth_operation_events,
        "record_event",
        lambda **event: events.append(event),
    )

    response = TestClient(main_module.app).post("/api/v1/auth/login", json={})

    assert response.status_code == 422
    assert events
    assert events[-1]["action_id"] == "auth.workflow.login"
    assert events[-1]["status"] == "failed"
    assert "HTTP 422" in str(events[-1]["message"])
