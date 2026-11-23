from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.models.backup import BackupStatus, BackupType
from app.services import backup_service as backup_service_module
from app.services.backup_service import BackupService
from fastapi import HTTPException


class _Query:
    def __init__(self, value: object) -> None:
        self.value = value

    def filter(self, *_args: object) -> "_Query":
        return self

    def first(self) -> object:
        return self.value

    def all(self) -> list[object]:
        if isinstance(self.value, list):
            return self.value
        return [] if self.value is None else [self.value]


class _DB:
    def __init__(self, value: object) -> None:
        self.value = value
        self.deleted: list[object] = []
        self.commit_count = 0

    def query(self, *_args: object) -> _Query:
        return _Query(self.value)

    def delete(self, value: object) -> None:
        self.deleted.append(value)

    def commit(self) -> None:
        self.commit_count += 1

    def close(self) -> None:
        return None


def _completed_backup(path: Path, backup_type: BackupType) -> SimpleNamespace:
    return SimpleNamespace(
        id=1,
        name="Release safety backup",
        type=backup_type,
        status=BackupStatus.COMPLETED,
        file_path=str(path),
    )


@pytest.mark.parametrize("backup_type", [BackupType.CONFIG, BackupType.FULL])
def test_all_backup_types_use_the_single_validated_restore_engine(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    backup_type: BackupType,
) -> None:
    archive = tmp_path / f"{backup_type.value}-2026-09-02-20-00-00.epibak"
    archive.write_bytes(b"encrypted-placeholder")
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(tmp_path))
    service = BackupService()
    calls: list[tuple[str, str]] = []

    async def scheduled(script_path: str, backup_file: str) -> None:
        calls.append((script_path, backup_file))

    monkeypatch.setattr(service, "_run_restore_script", scheduled)
    result = asyncio.run(
        service.restore_backup(1, _DB(_completed_backup(archive, backup_type)))
    )

    assert result["status"] == "started"
    assert len(calls) == 1
    assert Path(calls[0][0]).name == "restore_config_backup.sh"
    assert calls[0][1] == str(archive.resolve())


def test_restore_api_does_not_report_started_when_scheduler_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "full-2026-09-02-20-00-00.epibak"
    archive.write_bytes(b"encrypted-placeholder")
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(tmp_path))
    service = BackupService()

    async def rejected(_script_path: str, _backup_file: str) -> None:
        raise RuntimeError("sensitive sudo failure")

    monkeypatch.setattr(service, "_run_restore_script", rejected)
    with pytest.raises(HTTPException) as error:
        asyncio.run(
            service.restore_backup(
                1,
                _DB(_completed_backup(archive, BackupType.FULL)),
            )
        )

    assert error.value.status_code == 500
    assert "sensitive sudo failure" not in str(error.value.detail)


def test_runner_has_no_nonexistent_full_restore_entry() -> None:
    runner = Path(__file__).resolve().parents[2] / "scripts" / "runner"
    assert "restore_full_backup.sh" not in runner.read_text(encoding="utf-8")


def test_backup_archive_resolver_rejects_outside_and_unexpected_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    valid = backup_root / "config-2026-09-02-20-00-00.epibak"
    valid.write_bytes(b"backup")
    outside = tmp_path / "full-2026-09-02-20-00-00.epibak"
    outside.write_bytes(b"not-in-backup-root")
    unexpected = backup_root / "arbitrary.txt"
    unexpected.write_text("not a backup", encoding="utf-8")
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(backup_root))

    assert BackupService.resolve_backup_archive_path(str(valid)) == valid.resolve()
    with pytest.raises(ValueError, match="Invalid backup archive path"):
        BackupService.resolve_backup_archive_path(str(unexpected))
    with pytest.raises(ValueError, match="unsafe"):
        BackupService.resolve_backup_archive_path(str(outside))


def test_backup_completion_requires_one_explicit_archive_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    archive = backup_root / "config-2026-09-02-20-00-00.epibak"
    archive.write_bytes(b"backup")
    job = _completed_backup(archive, BackupType.CONFIG)
    job.status = BackupStatus.RUNNING
    job.error_message = None
    database = _DB(job)
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(backup_root))
    monkeypatch.setattr(backup_service_module, "SessionLocal", lambda: database)

    class _Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            marker = f"BACKUP_FILE={archive}\n".encode()
            return marker + marker, b""

    async def create_process(*_args: object, **_kwargs: object) -> _Process:
        return _Process()

    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )

    asyncio.run(BackupService()._run_backup_script(1, "config"))

    assert job.status == BackupStatus.FAILED
    assert job.error_message == "Backup helper returned an invalid archive marker"
    assert database.commit_count == 1


def test_backup_completion_accepts_one_validated_archive_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    archive = backup_root / "full-2026-09-02-20-00-00.epibak"
    archive.write_bytes(b"encrypted backup")
    job = _completed_backup(archive, BackupType.FULL)
    job.status = BackupStatus.RUNNING
    job.error_message = None
    job.size_bytes = 0
    database = _DB(job)
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(backup_root))
    monkeypatch.setattr(backup_service_module, "SessionLocal", lambda: database)

    class _Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return f"BACKUP_FILE={archive}\n".encode(), b""

    async def create_process(*_args: object, **_kwargs: object) -> _Process:
        return _Process()

    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )

    asyncio.run(BackupService()._run_backup_script(1, "full"))

    assert job.status == BackupStatus.COMPLETED
    assert job.file_path == str(archive.resolve())
    assert job.size_bytes == len(b"encrypted backup")
    assert job.error_message is None
    assert database.commit_count == 1


def test_failed_privileged_delete_preserves_file_and_database_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backup_root = tmp_path / "backups"
    backup_root.mkdir()
    archive = backup_root / "config-2026-09-02-20-00-00.epibak"
    archive.write_bytes(b"backup")
    job = _completed_backup(archive, BackupType.CONFIG)
    database = _DB(job)
    monkeypatch.setattr(backup_service_module, "BACKUP_DIR", str(backup_root))
    monkeypatch.setattr(
        backup_service_module.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )

    with pytest.raises(HTTPException) as error:
        BackupService().delete_backup(1, database)

    assert error.value.status_code == 500
    assert "record was preserved" in str(error.value.detail)
    assert archive.exists()
    assert database.deleted == []
    assert database.commit_count == 0


def test_restore_status_reports_valid_detached_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_file = tmp_path / "latest.json"
    status_file.write_text(
        json.dumps(
            {
                "archive": "full-2026-09-02-20-00-00.epibak",
                "status": "failed-rolled-back",
                "updated_at": "2026-09-02T20:01:02Z",
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(backup_service_module, "RESTORE_STATUS_FILE", status_file)

    result = BackupService.get_restore_status()

    assert result.status == "failed-rolled-back"
    assert result.archive == "full-2026-09-02-20-00-00.epibak"
    assert result.updated_at is not None
    assert result.updated_at.isoformat() == "2026-09-02T20:01:02+00:00"


def test_restore_status_missing_is_idle_and_invalid_payload_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_file = tmp_path / "latest.json"
    monkeypatch.setattr(backup_service_module, "RESTORE_STATUS_FILE", status_file)
    assert BackupService.get_restore_status().status == "idle"

    status_file.write_text(
        '{"archive":"../../etc/shadow","status":"success",'
        '"updated_at":"2026-09-02T20:01:02Z"}',
        encoding="utf-8",
    )
    with pytest.raises(HTTPException) as error:
        BackupService.get_restore_status()

    assert error.value.status_code == 503
    assert error.value.detail == "Restore status is unavailable"


def test_stale_running_backups_are_reconciled_after_restart(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    running = SimpleNamespace(
        status=BackupStatus.RUNNING,
        error_message=None,
    )
    database = _DB([running])
    monkeypatch.setattr(backup_service_module, "SessionLocal", lambda: database)

    assert BackupService.reconcile_interrupted_backups() == 1
    assert running.status == BackupStatus.FAILED
    assert running.error_message == "Interrupted by backend restart"
    assert database.commit_count == 1


def test_cancel_rejects_untracked_running_backup() -> None:
    job = SimpleNamespace(
        id=71,
        name="Untracked backup",
        status=BackupStatus.RUNNING,
        error_message=None,
    )
    database = _DB(job)

    with pytest.raises(HTTPException) as error:
        asyncio.run(BackupService().cancel_backup(job.id, database))

    assert error.value.status_code == 409
    assert database.commit_count == 0
    assert job.status == BackupStatus.RUNNING


def test_cancel_waits_for_child_exit_before_reporting_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = SimpleNamespace(
        id=72,
        name="Cancelable backup",
        status=BackupStatus.RUNNING,
        error_message=None,
    )
    caller_database = _DB(job)
    worker_database = _DB(job)
    child_exited = False

    class _Process:
        returncode: int | None = None

        async def communicate(self) -> tuple[bytes, bytes]:
            await asyncio.Event().wait()
            return b"", b""

        def terminate(self) -> None:
            return None

        def kill(self) -> None:
            return None

        async def wait(self) -> int:
            nonlocal child_exited
            child_exited = True
            self.returncode = -15
            return self.returncode

    async def create_process(*_args: object, **_kwargs: object) -> _Process:
        return _Process()

    monkeypatch.setattr(backup_service_module, "SessionLocal", lambda: worker_database)
    monkeypatch.setattr(
        backup_service_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )

    async def exercise() -> dict[str, str]:
        task = asyncio.create_task(BackupService()._run_backup_script(job.id, "full"))
        backup_service_module._running_tasks[job.id] = task
        task.add_done_callback(
            lambda _task: backup_service_module._running_tasks.pop(job.id, None)
        )
        while job.id not in backup_service_module._running_processes:
            await asyncio.sleep(0)
        return await BackupService().cancel_backup(job.id, caller_database)

    result = asyncio.run(exercise())

    assert result["status"] == "cancelled"
    assert child_exited is True
    assert job.status == BackupStatus.FAILED
    assert job.error_message == "Cancelled by user"
    assert job.id not in backup_service_module._running_processes
    assert job.id not in backup_service_module._cancellation_requests
