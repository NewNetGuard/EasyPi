from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints.auth_components import security as auth_security


class _DB:
    def __init__(self) -> None:
        self.commit_count = 0

    def commit(self) -> None:
        self.commit_count += 1


class _CookieRuntime:
    def __init__(self, user: SimpleNamespace) -> None:
        self.user = user
        self.calls: list[tuple[object, object, object]] = []

    def get_current_user(
        self,
        request: object,
        credentials: object,
        db: object,
    ) -> SimpleNamespace:
        self.calls.append((request, credentials, db))
        return self.user

    def check_subject_rate_limit(self, _subject: object, _limit_name: str) -> None:
        return None

    def reset_subject_rate_limit(self, _subject: object, _limit_name: str) -> None:
        return None


def _install_auth_fakes(
    monkeypatch: pytest.MonkeyPatch,
    user: SimpleNamespace,
) -> _CookieRuntime:
    runtime = _CookieRuntime(user)
    monkeypatch.setattr(auth_security, "auth_runtime", lambda: runtime)
    monkeypatch.setattr(auth_security, "_verify_user_totp", lambda *_args: True)
    monkeypatch.setattr(
        auth_security,
        "generate_backup_codes",
        lambda _count: (["plain-code"], ["hashed-code"]),
    )
    monkeypatch.setattr(auth_security, "_record_auth_event", lambda **_kwargs: None)
    return runtime


def test_enable_2fa_accepts_cookie_auth_without_a_bearer_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        id=1,
        username="admin",
        totp_enabled=False,
        totp_secret="encrypted-secret",
        backup_codes=None,
    )
    runtime = _install_auth_fakes(monkeypatch, user)
    database = _DB()
    request = SimpleNamespace(cookies={"easypi_access_token": "cookie-token"})

    response = asyncio.run(
        auth_security.enable_2fa(
            auth_security.TwoFactorEnableRequest(code="123456"),
            request,
            None,
            database,
        )
    )

    assert response.backup_codes == ["plain-code"]
    assert user.totp_enabled is True
    assert json.loads(user.backup_codes) == ["hashed-code"]
    assert runtime.calls == [(request, None, database)]
    assert database.commit_count == 1


def test_disable_2fa_accepts_cookie_auth_without_a_bearer_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        id=1,
        username="admin",
        totp_enabled=True,
        totp_secret="encrypted-secret",
        backup_codes='["hashed-code"]',
    )
    runtime = _install_auth_fakes(monkeypatch, user)
    database = _DB()
    request = SimpleNamespace(cookies={"easypi_access_token": "cookie-token"})

    response = asyncio.run(
        auth_security.disable_2fa(
            auth_security.TwoFactorVerifyRequest(code="123456"),
            request,
            None,
            database,
        )
    )

    assert response["success"] is True
    assert user.totp_enabled is False
    assert user.totp_secret is None
    assert user.backup_codes is None
    assert runtime.calls == [(request, None, database)]
    assert database.commit_count == 1


def test_backup_code_regeneration_accepts_cookie_auth_without_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = SimpleNamespace(
        id=1,
        username="admin",
        totp_enabled=True,
        totp_secret="encrypted-secret",
        backup_codes='["old-code"]',
    )
    runtime = _install_auth_fakes(monkeypatch, user)
    database = _DB()
    request = SimpleNamespace(cookies={"easypi_access_token": "cookie-token"})

    response = asyncio.run(
        auth_security.regenerate_backup_codes(
            auth_security.TwoFactorVerifyRequest(code="123456"),
            request,
            None,
            database,
        )
    )

    assert response.backup_codes == ["plain-code"]
    assert json.loads(user.backup_codes) == ["hashed-code"]
    assert runtime.calls == [(request, None, database)]
    assert database.commit_count == 1


def test_csrf_bootstrap_is_single_flight_and_uses_current_cookie() -> None:
    source = (
        Path(__file__).resolve().parents[2] / "frontend/src/utils/csrf.ts"
    ).read_text(encoding="utf-8")

    assert "const csrfRequests = new Map" in source
    assert "const existing = csrfRequests.get(apiBaseUrl)" in source
    assert "csrfRequests.set(apiBaseUrl, request)" in source
    assert "return getCsrfToken()" in source
    assert "return data.csrf_token" not in source
