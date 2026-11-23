from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
import requests
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.v1.endpoints import notifications
from app.api.v1.endpoints.auth_components import security as auth_security
from app.core import rate_limit
from app.services import push_notification_service as push_module


def test_login_account_limit_is_not_reset_by_another_account(monkeypatch) -> None:
    limiter = rate_limit.RateLimiter()
    monkeypatch.setattr(rate_limit, "rate_limiter", limiter)
    source_ip = "192.0.2.10"

    for _ in range(5):
        rate_limit.check_subject_rate_limit("victim", "login", source_ip)
        rate_limit.reset_subject_rate_limit("ordinary", "login", source_ip)

    with pytest.raises(HTTPException) as exc_info:
        rate_limit.check_subject_rate_limit("victim", "login", source_ip)
    assert exc_info.value.status_code == 429


class _TwoFactorRuntime:
    def __init__(self, user: SimpleNamespace) -> None:
        self.user = user

    def get_current_user(self, _request, _credentials, _db):
        return self.user

    def check_subject_rate_limit(self, subject: object, limit_name: str) -> None:
        rate_limit.check_subject_rate_limit(subject, limit_name)

    def reset_subject_rate_limit(self, subject: object, limit_name: str) -> None:
        rate_limit.reset_subject_rate_limit(subject, limit_name)


class _DB:
    def commit(self) -> None:
        pass


def test_sensitive_two_factor_operations_share_a_per_user_limit(monkeypatch) -> None:
    monkeypatch.setattr(rate_limit, "rate_limiter", rate_limit.RateLimiter())
    user = SimpleNamespace(
        id=7,
        username="limited-user",
        totp_enabled=True,
        totp_secret="encrypted-secret",
        backup_codes='["hashed-code"]',
    )
    monkeypatch.setattr(auth_security, "auth_runtime", lambda: _TwoFactorRuntime(user))
    monkeypatch.setattr(auth_security, "_verify_user_totp", lambda *_args: False)
    monkeypatch.setattr(auth_security, "_record_auth_event", lambda **_kwargs: None)

    for _ in range(5):
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                auth_security.disable_2fa(
                    auth_security.TwoFactorVerifyRequest(code="000000"),
                    object(),
                    None,
                    _DB(),
                )
            )
        assert exc_info.value.status_code == 400

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            auth_security.regenerate_backup_codes(
                auth_security.TwoFactorVerifyRequest(code="000000"),
                object(),
                None,
                _DB(),
            )
        )
    assert exc_info.value.status_code == 429


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1/push",
        "https://[::1]/push",
        "https://example.com/push",
        "https://fcm.googleapis.com:8443/push",
        "https://fcm.googleapis.com@127.0.0.1/push",
        "https://fcm.googleapis.com/push#fragment",
    ],
)
def test_push_endpoint_rejects_unapproved_destinations(endpoint: str) -> None:
    with pytest.raises(ValueError):
        push_module.validate_push_endpoint(endpoint)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://fcm.googleapis.com/fcm/send/token",
        "https://updates.push.services.mozilla.com/wpush/v2/token",
        "https://web.push.apple.com/Q-token",
        "https://wns2-am3p.notify.windows.com/w/token",
    ],
)
def test_push_endpoint_accepts_known_browser_push_services(endpoint: str) -> None:
    assert push_module.validate_push_endpoint(endpoint) == endpoint


def test_webpush_http_session_disables_redirects(monkeypatch) -> None:
    captured = {}

    def fake_request(_self, method, url, **kwargs):
        captured.update(method=method, url=url, kwargs=kwargs)
        return object()

    monkeypatch.setattr(requests.Session, "request", fake_request)
    with push_module._NoRedirectSession() as session:
        session.post("https://fcm.googleapis.com/fcm/send/token", allow_redirects=True)

    assert captured["kwargs"]["allow_redirects"] is False


def test_push_delivery_errors_do_not_disclose_remote_response(monkeypatch) -> None:
    service = push_module.PushNotificationService()
    service.configure("test-private-key", "test-public-key", "admin@example.test")
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/token",
        {"p256dh": "p256dh_test_value_123", "auth": "auth_test_value_123"},
        user_id=3,
    )

    async def fail_delivery(*_args, **_kwargs):
        raise RuntimeError("PRIVATE_INTERNAL_RESPONSE")

    monkeypatch.setattr(service, "_send_to_subscription", fail_delivery)
    result = asyncio.run(
        service.notify_system_alert("Test", "Test", user_id=3)
    )

    assert result["errors"] == ["Push delivery failed"]
    assert "PRIVATE_INTERNAL_RESPONSE" not in str(result)


def test_push_subscription_can_only_be_removed_by_its_owner() -> None:
    service = push_module.PushNotificationService()
    endpoint = "https://fcm.googleapis.com/fcm/send/owner-token"
    service.add_subscription(
        endpoint,
        {"p256dh": "p256dh_test_value_123", "auth": "auth_test_value_123"},
        user_id=11,
    )

    assert service.remove_subscription(endpoint, user_id=12) is False
    assert service.get_subscriptions(user_id=11)[0].endpoint == endpoint
    assert service.remove_subscription(endpoint, user_id=11) is True


def test_push_api_prevents_cross_user_removal_and_reassignment(monkeypatch) -> None:
    service = push_module.PushNotificationService()
    service.configure("test-private-key", "test-public-key", "admin@example.test")
    monkeypatch.setattr(notifications, "get_push_service", lambda: service)
    monkeypatch.setattr(notifications, "_record_notification_event", lambda **_kwargs: None)
    app = FastAPI()
    app.include_router(notifications.router)
    account_created_at = datetime.now(timezone.utc)
    user = SimpleNamespace(id=11, username="owner", created_at=account_created_at)
    app.dependency_overrides[notifications.get_current_user] = lambda: user
    monkeypatch.setattr(
        notifications,
        "_revalidate_push_user_session",
        lambda *_args: user,
    )
    active_user_db = SimpleNamespace(
        rollback=lambda: None,
    )
    app.dependency_overrides[notifications.get_db] = lambda: active_user_db
    body = {
        "endpoint": "https://fcm.googleapis.com/fcm/send/owner-token",
        "keys": {"p256dh": "owner_key_value_123", "auth": "owner_auth_value_123"},
    }

    with TestClient(app) as client:
        assert client.post("/notifications/push/subscribe", json=body).status_code == 200
        user = SimpleNamespace(
            id=12,
            username="other-user",
            created_at=account_created_at,
        )
        response = client.post("/notifications/push/unsubscribe", json=body)
        assert response.status_code == 200
        assert response.json()["success"] is False
        changed_body = {
            **body,
            "keys": {"p256dh": "new_key_value_12345", "auth": "new_auth_value_12345"},
        }
        assert client.post("/notifications/push/subscribe", json=changed_body).status_code == 409
        assert service.get_subscriptions(user_id=12) == []
        assert service.get_subscriptions(user_id=11)[0].keys == body["keys"]

        user = SimpleNamespace(id=11, username="owner", created_at=account_created_at)
        assert client.post("/notifications/push/subscribe", json=changed_body).status_code == 200
        assert service.get_subscriptions(user_id=11)[0].keys == changed_body["keys"]
        assert client.post("/notifications/push/unsubscribe", json=body).json()["success"] is True
        assert service.get_subscriptions() == []
