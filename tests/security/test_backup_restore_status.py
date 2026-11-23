from __future__ import annotations

from pathlib import Path

from app.schemas.rollback import RollbackSnapshotRecord
from app.services.rollback_service import RollbackService


def _service(tmp_path: Path) -> RollbackService:
    return RollbackService(
        metadata_dir=tmp_path / "metadata",
        scripts_dir=tmp_path / "scripts",
        backup_dir=tmp_path / "backups",
        restore_status_file=tmp_path / "restore-status.json",
    )


def _restoring_record(service: RollbackService) -> RollbackSnapshotRecord:
    archive = service.backup_dir / "config-2026-09-02-12-30-45.epibak"
    record = RollbackSnapshotRecord(
        snapshot_id="rollback-restore-test",
        name="Before upgrade",
        status="restoring",
        created_at="2026-09-02T12:00:00+00:00",
        updated_at="2026-09-02T12:30:00+00:00",
        archive_path=str(archive),
        last_restore_status="running",
    )
    service._save_snapshot(record)
    return record


def test_restore_result_marks_snapshot_ready_only_after_detached_success(
    tmp_path: Path, monkeypatch,
) -> None:
    service = _service(tmp_path)
    record = _restoring_record(service)
    monkeypatch.setattr(
        service,
        "_read_restore_result",
        lambda: {
            "archive": "config-2026-09-02-12-30-45.epibak",
            "status": "success",
            "updated_at": "2026-09-02T12:31:00Z",
        },
    )

    service._reconcile_restore_results()

    reconciled = service._get_snapshot(record.snapshot_id)
    assert reconciled.status == "ready"
    assert reconciled.last_restore_status == "success"
    assert reconciled.last_restored_at == "2026-09-02T12:31:00Z"


def test_rolled_back_restore_is_reported_as_failed(
    tmp_path: Path, monkeypatch,
) -> None:
    service = _service(tmp_path)
    record = _restoring_record(service)
    monkeypatch.setattr(
        service,
        "_read_restore_result",
        lambda: {
            "archive": "config-2026-09-02-12-30-45.epibak",
            "status": "failed-rolled-back",
            "updated_at": "2026-09-02T12:31:00Z",
        },
    )

    service._reconcile_restore_results()

    reconciled = service._get_snapshot(record.snapshot_id)
    assert reconciled.status == "restore-failed"
    assert reconciled.last_restore_status == "failed-rolled-back"
    assert "reapplied" in (reconciled.error_message or "")


def test_missing_final_result_marks_inactive_restore_interrupted(
    tmp_path: Path, monkeypatch,
) -> None:
    service = _service(tmp_path)
    record = _restoring_record(service)
    monkeypatch.setattr(service, "_read_restore_result", lambda: None)
    monkeypatch.setattr(service, "_restore_unit_active", lambda: False)

    service._reconcile_restore_results()

    reconciled = service._get_snapshot(record.snapshot_id)
    assert reconciled.status == "restore-failed"
    assert reconciled.last_restore_status == "interrupted"
