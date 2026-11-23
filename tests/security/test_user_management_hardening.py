from __future__ import annotations

import asyncio
import json
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.requests import Request

from app.api.v1.endpoints import notifications, users
from app.api.v1.endpoints.auth_components import access
from app.api.v1.endpoints.auth_components.context import RecoveryLoginRequest
from app.core.security import create_access_token, verify_password
from app.models.base import Base
from app.models.session import UserSession
from app.models.user import User
from app.services.push_notification_service import NotificationPayload, PushNotificationService


PUSH_KEYS = {
    "p256dh": "p256dh_test_value_123",
    "auth": "auth_test_value_123",
}


def _request(path: str = "/api/v1/users", token: str | None = None) -> Request:
    headers = [(b"user-agent", b"security-test")]
    if token is not None:
        headers.append((b"authorization", f"Bearer {token}".encode("ascii")))
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": path,
            "headers": headers,
            "client": ("127.0.0.1", 12345),
            "server": ("testserver", 443),
            "scheme": "https",
        }
    )


@pytest.fixture
def database() -> Session:
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(
        engine,
        tables=[User.__table__, UserSession.__table__],
    )
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _user(username: str, *, role: str = "user", active: bool = True) -> User:
    return User(
        username=username,
        email=f"{username}@example.test",
        password_hash="existing-password-hash",
        role=role,
        is_active=active,
        created_at=datetime.now(timezone.utc),
    )


def _push_service(path: Path) -> PushNotificationService:
    service = PushNotificationService()
    service._subs_path = path
    return service


def test_user_push_revocation_is_persisted_and_survives_reload(tmp_path: Path) -> None:
    state_path = tmp_path / "push_subscriptions.json"
    service = _push_service(state_path)
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/old-user",
        PUSH_KEYS,
        user_id=11,
    )
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/other-user",
        PUSH_KEYS,
        user_id=12,
    )

    assert service.remove_user_subscriptions(11) == 1
    assert service.get_subscriptions(user_id=11) == []

    reloaded = _push_service(state_path)
    reloaded._load_subscriptions()
    assert reloaded.get_subscriptions(user_id=11) == []
    assert len(reloaded.get_subscriptions(user_id=12)) == 1


def test_user_push_revocation_rolls_back_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = PushNotificationService()
    endpoint = "https://fcm.googleapis.com/fcm/send/retained-user"
    service.add_subscription(endpoint, PUSH_KEYS, user_id=11)

    def fail_save() -> None:
        raise RuntimeError("disk failure")

    monkeypatch.setattr(service, "_save_subscriptions", fail_save)
    with pytest.raises(RuntimeError, match="disk failure"):
        service.remove_user_subscriptions(11)

    assert service.get_subscriptions(user_id=11)[0].endpoint == endpoint


def test_disabling_and_deleting_users_revoke_push_subscriptions(
    database: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _user("admin", role="admin")
    disabled_user = _user("disabled-user")
    deleted_user = _user("deleted-user")
    database.add_all([admin, disabled_user, deleted_user])
    database.commit()
    service = _push_service(tmp_path / "push_subscriptions.json")
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/disabled-user",
        PUSH_KEYS,
        user_id=disabled_user.id,
    )
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/deleted-user",
        PUSH_KEYS,
        user_id=deleted_user.id,
    )
    monkeypatch.setattr(users, "require_admin", lambda *_args: admin)
    monkeypatch.setattr(users, "get_push_service", lambda: service)
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)

    asyncio.run(
        users.update_user(
            disabled_user.id,
            users.UserUpdateRequest(is_active=False),
            _request(),
            credentials=None,
            db=database,
        )
    )
    asyncio.run(
        users.delete_user(
            deleted_user.id,
            _request(),
            credentials=None,
            db=database,
        )
    )

    assert service.get_subscriptions(user_id=disabled_user.id) == []
    assert service.get_subscriptions(user_id=deleted_user.id) == []
    assert database.get(User, disabled_user.id).is_active is False
    assert database.get(User, deleted_user.id) is None
    assert json.loads((tmp_path / "push_subscriptions.json").read_text()) == []


def test_push_persistence_failure_keeps_account_active(
    database: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _user("admin", role="admin")
    target = _user("target")
    database.add_all([admin, target])
    database.commit()
    service = PushNotificationService()
    service.add_subscription(
        "https://fcm.googleapis.com/fcm/send/target",
        PUSH_KEYS,
        user_id=target.id,
    )
    monkeypatch.setattr(users, "require_admin", lambda *_args: admin)
    monkeypatch.setattr(users, "get_push_service", lambda: service)
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)

    def fail_save() -> None:
        raise RuntimeError("disk failure")

    monkeypatch.setattr(service, "_save_subscriptions", fail_save)

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            users.update_user(
                target.id,
                users.UserUpdateRequest(is_active=False),
                _request(),
                credentials=None,
                db=database,
            )
        )

    database.refresh(target)
    assert exc_info.value.status_code == 500
    assert target.is_active is True
    assert len(service.get_subscriptions(user_id=target.id)) == 1


@pytest.mark.parametrize("mutation", ["disable", "delete"])
@pytest.mark.parametrize("first", ["subscribe", "admin"])
def test_push_registration_is_serialized_with_account_revocation(
    mutation: str,
    first: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    engine = create_engine(
        f"sqlite:///{tmp_path / f'push-race-{mutation}-{first}.db'}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(
        engine,
        tables=[User.__table__, UserSession.__table__],
    )
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    with session_factory() as setup_db:
        admin = _user("race-admin", role="admin")
        target = _user("race-target")
        setup_db.add_all([admin, target])
        setup_db.commit()
        admin_id = admin.id
        target_id = target.id
        session_jti = str(uuid.uuid4())
        setup_db.add(
            UserSession(
                user_id=target_id,
                token_jti=session_jti,
                expires_at=datetime.now(timezone.utc) + timedelta(days=1),
            )
        )
        setup_db.commit()
        access_token = create_access_token(
            {"sub": target_id},
            session_id=session_jti,
        )

    service = _push_service(tmp_path / f"push-race-{mutation}-{first}.json")
    service.configure("test-private-key", "test-public-key", "admin@example.test")
    monkeypatch.setattr(users, "get_push_service", lambda: service)
    monkeypatch.setattr(notifications, "get_push_service", lambda: service)
    monkeypatch.setattr(
        users,
        "require_admin",
        lambda *_args: SimpleNamespace(id=admin_id, username="race-admin"),
    )
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)
    monkeypatch.setattr(notifications, "_record_notification_event", lambda **_kwargs: None)

    authorized = threading.Event()
    start_subscription = threading.Event()
    subscription_at_barrier = threading.Event()
    release_subscription = threading.Event()
    admin_at_barrier = threading.Event()
    release_admin = threading.Event()
    subscription_done = threading.Event()
    admin_done = threading.Event()
    outcomes: dict[str, object] = {}

    original_add = service.add_subscription
    original_remove = service.remove_user_subscriptions

    def controlled_add(*args, **kwargs):
        if first == "subscribe":
            subscription_at_barrier.set()
            assert release_subscription.wait(5)
        return original_add(*args, **kwargs)

    def controlled_remove(*args, **kwargs):
        result = original_remove(*args, **kwargs)
        if first == "admin":
            admin_at_barrier.set()
            assert release_admin.wait(5)
        return result

    monkeypatch.setattr(service, "add_subscription", controlled_add)
    monkeypatch.setattr(service, "remove_user_subscriptions", controlled_remove)

    def subscribe_worker() -> None:
        with session_factory() as request_db:
            stale_user = request_db.get(User, target_id)
            assert stale_user is not None
            authorized.set()
            assert start_subscription.wait(5)
            try:
                outcomes["subscribe"] = asyncio.run(
                    notifications.subscribe_to_push(
                        notifications.PushSubscriptionRequest(
                            endpoint=(
                                "https://fcm.googleapis.com/fcm/send/"
                                f"race-{mutation}-{first}"
                            ),
                            keys=PUSH_KEYS,
                        ),
                        http_request=_request(
                            "/api/v1/notifications/push/subscribe",
                            token=access_token,
                        ),
                        current_user=stale_user,
                        db=request_db,
                    )
                )
            except Exception as exc:  # expected when revocation commits first
                outcomes["subscribe"] = exc
            finally:
                subscription_done.set()

    def admin_worker() -> None:
        with session_factory() as admin_db:
            try:
                if mutation == "disable":
                    outcomes["admin"] = asyncio.run(
                        users.update_user(
                            target_id,
                            users.UserUpdateRequest(is_active=False),
                            _request(),
                            credentials=None,
                            db=admin_db,
                        )
                    )
                else:
                    outcomes["admin"] = asyncio.run(
                        users.delete_user(
                            target_id,
                            _request(),
                            credentials=None,
                            db=admin_db,
                        )
                    )
            except Exception as exc:
                outcomes["admin"] = exc
            finally:
                admin_done.set()

    subscribe_thread = threading.Thread(target=subscribe_worker)
    admin_thread = threading.Thread(target=admin_worker)
    subscribe_thread.start()
    assert authorized.wait(5)

    if first == "subscribe":
        start_subscription.set()
        assert subscription_at_barrier.wait(5)
        admin_thread.start()
        assert not admin_done.wait(0.25)
        release_subscription.set()
    else:
        admin_thread.start()
        assert admin_at_barrier.wait(5)
        start_subscription.set()
        assert not subscription_done.wait(0.25)
        release_admin.set()

    subscribe_thread.join(5)
    admin_thread.join(5)
    assert not subscribe_thread.is_alive()
    assert not admin_thread.is_alive()
    assert not isinstance(outcomes.get("admin"), Exception)
    if first == "admin":
        assert isinstance(outcomes.get("subscribe"), HTTPException)
        assert outcomes["subscribe"].status_code == 401
    else:
        assert not isinstance(outcomes.get("subscribe"), Exception)

    with session_factory() as verification_db:
        stored_user = verification_db.get(User, target_id)
        if mutation == "disable":
            assert stored_user is not None
            assert stored_user.is_active is False
        else:
            assert stored_user is None
    assert service.get_subscriptions(user_id=target_id) == []
    engine.dispose()


def test_reenabled_account_cannot_subscribe_with_revoked_session(
    database: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _user("reenable-admin", role="admin")
    target = _user("reenable-target")
    database.add_all([admin, target])
    database.commit()
    session_jti = str(uuid.uuid4())
    database.add(
        UserSession(
            user_id=target.id,
            token_jti=session_jti,
            expires_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )
    database.commit()
    access_token = create_access_token({"sub": target.id}, session_id=session_jti)
    service = _push_service(tmp_path / "reenabled-push-subscriptions.json")
    service.configure("test-private-key", "test-public-key", "admin@example.test")
    monkeypatch.setattr(users, "require_admin", lambda *_args: admin)
    monkeypatch.setattr(users, "get_push_service", lambda: service)
    monkeypatch.setattr(notifications, "get_push_service", lambda: service)
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)
    monkeypatch.setattr(notifications, "_record_notification_event", lambda **_kwargs: None)

    asyncio.run(
        users.update_user(
            target.id,
            users.UserUpdateRequest(is_active=False),
            _request(),
            credentials=None,
            db=database,
        )
    )
    asyncio.run(
        users.update_user(
            target.id,
            users.UserUpdateRequest(is_active=True),
            _request(),
            credentials=None,
            db=database,
        )
    )

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(
            notifications.subscribe_to_push(
                notifications.PushSubscriptionRequest(
                    endpoint="https://fcm.googleapis.com/fcm/send/reenabled-user",
                    keys=PUSH_KEYS,
                ),
                http_request=_request(
                    "/api/v1/notifications/push/subscribe",
                    token=access_token,
                ),
                current_user=target,
                db=database,
            )
        )

    assert exc_info.value.status_code == 401
    assert service.get_subscriptions(user_id=target.id) == []
    stored_session = database.scalar(
        select(UserSession).where(UserSession.token_jti == session_jti)
    )
    assert stored_session is not None
    assert stored_session.is_active is False


def test_queued_push_skips_subscription_revoked_after_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = PushNotificationService()
    service.configure("test-private-key", "test-public-key", "admin@example.test")
    revoked_endpoint = "https://fcm.googleapis.com/fcm/send/revoked-queued-user"
    active_endpoint = "https://fcm.googleapis.com/fcm/send/active-queued-user"
    service.add_subscription(revoked_endpoint, PUSH_KEYS, user_id=11)
    service.add_subscription(active_endpoint, PUSH_KEYS, user_id=12)
    original_get_subscriptions = service.get_subscriptions
    snapshot_taken = False

    def stale_snapshot(*args, **kwargs):
        nonlocal snapshot_taken
        subscriptions = original_get_subscriptions(*args, **kwargs)
        if not snapshot_taken:
            snapshot_taken = True
            service.remove_user_subscriptions(11)
        return subscriptions

    delivered: list[str] = []

    async def record_delivery(subscription, _payload_json):
        delivered.append(subscription.endpoint)

    monkeypatch.setattr(service, "get_subscriptions", stale_snapshot)
    monkeypatch.setattr(service, "_send_to_subscription", record_delivery)

    result = asyncio.run(
        service.send_notification(NotificationPayload(title="Test", body="Test"))
    )

    assert delivered == [active_endpoint]
    assert result["success"] == 1
    assert result["failed"] == 0


def test_user_management_rejects_own_password_and_2fa_changes(
    database: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _user("admin", role="admin")
    admin.totp_enabled = True
    admin.totp_secret = "encrypted-secret"
    admin.backup_codes = "[]"
    database.add(admin)
    database.commit()
    monkeypatch.setattr(users, "require_admin", lambda *_args: admin)
    monkeypatch.setattr(users, "check_rate_limit", lambda *_args: None)
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)

    with pytest.raises(HTTPException) as password_error:
        asyncio.run(
            users.reset_user_password(
                admin.id,
                users.UserPasswordResetRequest(new_password="StrongPassword1!"),
                _request(),
                credentials=None,
                db=database,
            )
        )
    with pytest.raises(HTTPException) as two_factor_error:
        asyncio.run(
            users.disable_user_2fa(
                admin.id,
                _request(),
                credentials=None,
                db=database,
            )
        )

    database.refresh(admin)
    assert password_error.value.status_code == 400
    assert two_factor_error.value.status_code == 400
    assert admin.password_hash == "existing-password-hash"
    assert admin.totp_enabled is True
    assert admin.totp_secret == "encrypted-secret"


def test_admin_can_still_reset_another_users_password_and_2fa(
    database: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    admin = _user("admin", role="admin")
    target = _user("target")
    target.totp_enabled = True
    target.totp_secret = "encrypted-secret"
    target.backup_codes = "[]"
    database.add_all([admin, target])
    database.commit()
    monkeypatch.setattr(users, "require_admin", lambda *_args: admin)
    monkeypatch.setattr(users, "check_rate_limit", lambda *_args: None)
    monkeypatch.setattr(users, "_record_user_event", lambda **_kwargs: None)

    asyncio.run(
        users.reset_user_password(
            target.id,
            users.UserPasswordResetRequest(new_password="StrongPassword1!"),
            _request(),
            credentials=None,
            db=database,
        )
    )
    asyncio.run(
        users.disable_user_2fa(
            target.id,
            _request(),
            credentials=None,
            db=database,
        )
    )

    database.refresh(target)
    assert verify_password("StrongPassword1!", target.password_hash) is True
    assert target.totp_enabled is False
    assert target.totp_secret is None
    assert target.backup_codes is None


def test_recovery_login_selects_one_active_admin_when_several_exist(
    database: Session,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_admin = _user("first-admin", role="admin", active=False)
    recovery_admin = _user("recovery-admin", role="admin")
    other_admin = _user("other-admin", role="admin")
    database.add_all([first_admin, recovery_admin, other_admin])
    database.commit()

    from app.db import init_db

    monkeypatch.setattr(init_db, "has_recovery_token", lambda: True)
    monkeypatch.setattr(init_db, "verify_recovery_token", lambda _token: True)
    monkeypatch.setattr(
        access,
        "auth_runtime",
        lambda: SimpleNamespace(
            check_rate_limit=lambda *_args: None,
            reset_rate_limit=lambda *_args: None,
        ),
    )
    monkeypatch.setattr(
        access,
        "create_token_pair",
        lambda _data: (
            "access-token",
            "refresh-token",
            "00000000-0000-0000-0000-000000000001",
            datetime.now(timezone.utc) + timedelta(hours=1),
        ),
    )
    monkeypatch.setattr(access, "set_auth_cookies", lambda *_args: None)

    response = asyncio.run(
        access.recovery_login(
            RecoveryLoginRequest(recovery_token="correct-recovery-token"),
            _request("/api/v1/auth/recovery-login"),
            database,
        )
    )
    payload = json.loads(response.body)
    sessions = database.scalars(select(UserSession)).all()

    assert response.status_code == 200
    assert payload["user"]["username"] == "recovery-admin"
    assert len(sessions) == 1
    assert sessions[0].user_id == recovery_admin.id
