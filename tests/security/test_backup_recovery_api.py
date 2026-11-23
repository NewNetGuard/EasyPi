from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import backup as backup_endpoint
from app.schemas.backup import RecoveryKeyExportRequest
from app.services import backup_service as backup_service_module
from app.services.backup_service import BackupService
from fastapi import BackgroundTasks, HTTPException, Request

PACKAGE_NAME = "import-12345678-1234-1234-1234-123456789abc.epikey"
EXPORT_NAME = "recovery-key-12345678-1234-1234-1234-123456789abc.epikey"
PASSPHRASE = "correct horse battery staple"
FINGERPRINT = "ab" * 32


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/api/v1/backup/recovery-key/export",
            "headers": [],
            "client": ("192.0.2.10", 12345),
        }
    )


def test_recovery_reauthentication_has_its_own_failure_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checks: list[str] = []
    resets: list[str] = []
    monkeypatch.setattr(
        backup_endpoint,
        "check_rate_limit",
        lambda _request, name: checks.append(name),
    )
    monkeypatch.setattr(
        backup_endpoint,
        "reset_rate_limit",
        lambda _request, name: resets.append(name),
    )
    monkeypatch.setattr(backup_endpoint, "verify_password", lambda *_args: False)
    admin = SimpleNamespace(
        password_hash="stored-hash",
        totp_enabled=False,
        totp_secret=None,
    )

    with pytest.raises(HTTPException) as error:
        backup_endpoint._verify_recovery_key_reauthentication(
            _request(),
            admin,
            current_password="wrong password",
            totp_code=None,
        )

    assert error.value.status_code == 403
    assert checks == ["backup_recovery_key"]
    assert resets == []


def test_recovery_reauthentication_requires_totp_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resets: list[str] = []
    monkeypatch.setattr(backup_endpoint, "check_rate_limit", lambda *_args: None)
    monkeypatch.setattr(
        backup_endpoint,
        "reset_rate_limit",
        lambda _request, name: resets.append(name),
    )
    monkeypatch.setattr(backup_endpoint, "verify_password", lambda *_args: True)
    monkeypatch.setattr(backup_endpoint, "decrypt_password", lambda _value: "SECRET")
    monkeypatch.setattr(
        backup_endpoint,
        "verify_totp",
        lambda secret, code: secret == "SECRET" and code == "123456",
    )
    admin = SimpleNamespace(
        password_hash="stored-hash",
        totp_enabled=True,
        totp_secret="enc:value",
    )

    with pytest.raises(HTTPException) as missing:
        backup_endpoint._verify_recovery_key_reauthentication(
            _request(),
            admin,
            current_password="correct password",
            totp_code=None,
        )
    assert missing.value.status_code == 403
    assert resets == []

    backup_endpoint._verify_recovery_key_reauthentication(
        _request(),
        admin,
        current_password="correct password",
        totp_code="123456",
    )
    assert resets == ["backup_recovery_key"]


def test_export_schedules_privileged_cleanup_after_response(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exported = tmp_path / EXPORT_NAME
    exported.write_bytes(b"protected package")
    cleaned: list[str] = []

    async def export(_passphrase: str) -> Path:
        return exported

    async def cleanup(package_name: str) -> None:
        cleaned.append(package_name)

    monkeypatch.setattr(
        backup_endpoint,
        "_verify_recovery_key_reauthentication",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(backup_endpoint.backup_service, "export_recovery_key", export)
    monkeypatch.setattr(
        backup_endpoint.backup_service,
        "cleanup_recovery_export",
        cleanup,
    )
    background_tasks = BackgroundTasks()
    payload = RecoveryKeyExportRequest(
        current_password="admin password",
        package_passphrase=PASSPHRASE,
    )

    response = asyncio.run(
        backup_endpoint.export_recovery_key(
            payload,
            _request(),
            background_tasks,
            admin=object(),
        )
    )

    assert response.headers["cache-control"] == "no-store"
    assert cleaned == []
    asyncio.run(background_tasks())
    assert cleaned == [EXPORT_NAME]


def test_failed_reauthentication_is_audited_without_running_export(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[dict[str, object]] = []

    def reject(*_args, **_kwargs) -> None:
        raise HTTPException(status_code=403, detail="Reauthentication failed")

    async def unexpected_export(_passphrase: str) -> Path:
        raise AssertionError("export must not run after failed reauthentication")

    monkeypatch.setattr(
        backup_endpoint,
        "_verify_recovery_key_reauthentication",
        reject,
    )
    monkeypatch.setattr(
        backup_endpoint.backup_service,
        "export_recovery_key",
        unexpected_export,
    )
    monkeypatch.setattr(
        backup_endpoint,
        "_record_backup_event",
        lambda **event: events.append(event),
    )
    payload = RecoveryKeyExportRequest(
        current_password="wrong password",
        package_passphrase=PASSPHRASE,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(
            backup_endpoint.export_recovery_key(
                payload,
                _request(),
                BackgroundTasks(),
                admin=object(),
            )
        )

    assert error.value.status_code == 403
    assert len(events) == 1
    assert events[0]["action_id"] == "backup.recovery-key.export"
    assert events[0]["status"] == "failed"
    assert "wrong password" not in str(events[0])


class _FakeProcess:
    def __init__(self, stdout: bytes) -> None:
        self.returncode = 0
        self.stdout = stdout
        self.communicated: list[bytes | None] = []

    async def communicate(self, payload: bytes | None = None) -> tuple[bytes, bytes]:
        self.communicated.append(payload)
        return self.stdout, b""

    def kill(self) -> None:
        raise AssertionError("the fake process must not time out")

    async def wait(self) -> int:
        return self.returncode


def test_service_passes_package_passphrase_only_over_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(
        (
            f"RECOVERY_KEY_FINGERPRINT={FINGERPRINT}\n"
            "RECOVERY_KEY_IMPORTED=YES\n"
        ).encode()
    )
    invocation: dict[str, object] = {}

    async def spawn(*args, **kwargs):
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return process

    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        spawn,
    )

    fingerprint, imported = asyncio.run(
        BackupService().import_recovery_key(PACKAGE_NAME, PASSPHRASE)
    )

    assert fingerprint == FINGERPRINT
    assert imported is True
    assert PASSPHRASE not in " ".join(str(value) for value in invocation["args"])
    assert process.communicated == [PASSPHRASE.encode() + b"\n"]


def test_service_rejects_malformed_privileged_helper_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(f"RECOVERY_KEY_FINGERPRINT={FINGERPRINT}\n".encode())

    async def spawn(*_args, **_kwargs):
        return process

    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        spawn,
    )

    with pytest.raises(HTTPException) as error:
        asyncio.run(BackupService().import_recovery_key(PACKAGE_NAME, PASSPHRASE))

    assert error.value.status_code == 500
    assert "invalid response" in str(error.value.detail).lower()


def test_privileged_cleanup_uses_fixed_delete_action_without_a_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = _FakeProcess(b"RECOVERY_FILE_DELETED=YES\n")
    invocation: dict[str, object] = {}

    async def spawn(*args, **kwargs):
        invocation["args"] = args
        invocation["kwargs"] = kwargs
        return process

    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        spawn,
    )

    asyncio.run(BackupService().cleanup_recovery_export(EXPORT_NAME))

    assert invocation["args"][-2:] == ("delete", EXPORT_NAME)
    assert invocation["kwargs"]["stdin"] == asyncio.subprocess.DEVNULL
    assert process.communicated == [None]


def test_recovery_helper_has_a_name_scoped_privileged_delete() -> None:
    helper = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "backup"
        / "recovery_key.sh"
    ).read_text(encoding="utf-8")

    assert "^(export|import|delete)$" in helper
    assert '[[ "${NAME}" == recovery-key-* ]]' in helper
    assert 'rm -f -- "${destination}"' in helper


def test_backup_archive_import_uses_root_validated_copy_and_no_overwrite() -> None:
    root = Path(__file__).resolve().parents[2]
    helper = (root / "scripts/backup/import_archive.sh").read_text(encoding="utf-8")
    runner = (root / "scripts/runner").read_text(encoding="utf-8")
    nginx = (root / "templates/nginx/easypi.conf").read_text(encoding="utf-8")

    assert '[[ ! -e "${destination}" && ! -L "${destination}" ]]' in helper
    assert 'install -o root -g root -m 0600 -- "${source_path}" "${STAGED_ARCHIVE}"' in helper
    assert '"${CRYPTO_HELPER}" verify "${STAGED_ARCHIVE}"' in helper
    assert '"${RESTORE_VALIDATOR}" --validate-only "${VALIDATION_FILE}"' in helper
    assert '${BACKUP_DIR}/.restore.XXXXXX.tar.gz' in helper
    assert helper.index('"${CRYPTO_HELPER}" verify "${STAGED_ARCHIVE}"') < helper.index(
        'mv -- "${STAGED_ARCHIVE}" "${destination}"'
    )
    assert '["backup/import_archive.sh"]=1' in runner
    location = nginx.split("location = /api/v1/backup/import", 1)[1].split("}", 1)[0]
    assert "auth_request /_easypi_admin_auth;" in location
    assert "client_max_body_size 4G;" in location
    admin_auth = nginx.split("location = /_easypi_admin_auth", 1)[1].split("}", 1)[0]
    assert "/api/v1/auth/admin-check" in admin_auth


def test_backup_archive_service_accepts_only_valid_privileged_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = tmp_path / "full-2026-09-04-12-30.epibak"
    process = _FakeProcess(f"BACKUP_FILE={expected}\n".encode())
    invocation: dict[str, object] = {}

    async def spawn(*args, **_kwargs):
        invocation["args"] = args
        return process

    service = BackupService()
    monkeypatch.setattr(backup_service_module.asyncio, "create_subprocess_exec", spawn)
    monkeypatch.setattr(service, "resolve_backup_archive_path", lambda value: Path(value))

    result = asyncio.run(
        service.import_backup_archive(
            "import-12345678-1234-1234-1234-123456789abc.epibak",
            expected.name,
        )
    )

    assert result == expected
    assert invocation["args"][-3:] == (
        "backup/import_archive.sh",
        "import-12345678-1234-1234-1234-123456789abc.epibak",
        expected.name,
    )
