from __future__ import annotations

import asyncio
import io
import json
import os
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from PIL import Image

from app.agent.adapters.cloud import CloudAdapter
from app.agent.adapters.extended_diagnostics import ExtendedDiagnosticsAdapter
from app.agent.core.contracts import AgentRequest
from app.agent.core.probe_routing import normalize_probe_selections, select_probe
from app.agent.core.probes import AgentProbeRegistry
from app.services.operation_event_service import OperationEventService


def test_probe_registry_rejects_success_with_explicit_error() -> None:
    async def handler(_parameters):
        return {
            "success": True,
            "source_status": "ok",
            "message": "Probe completed.",
            "error": "sensor checksum failed",
        }

    registry = AgentProbeRegistry()
    registry.register("test.conflict", handler, allowed_keys=set())

    result = asyncio.run(registry.run("test.conflict", {}))

    assert result["success"] is False
    assert result["source_status"] == "conflict"
    assert "sensor checksum failed" in result["message"]


def test_targetless_task_inventory_surfaces_failed_tasks(monkeypatch) -> None:
    from app.api.v1.endpoints import tasks as tasks_module

    monkeypatch.setattr(
        tasks_module,
        "active_tasks",
        {
            "failed-1": {
                "id": "failed-1",
                "status": "failed",
                "message": "worker exited 23",
                "process": SimpleNamespace(returncode=23),
            }
        },
    )

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("tasks.runtime", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert result["failed_tasks"] == ["failed-1"]


def test_device_inventory_surfaces_blocked_devices(monkeypatch) -> None:
    from app.services import unknown_device_admission_service as service_module

    class FakeService:
        def list_devices(self, *, include_blocked: bool):
            assert include_blocked is True
            return [{"id": "dev-blocked", "status": "blocked"}]

        def is_block_mode(self):
            return True

    monkeypatch.setattr(service_module, "UnknownDeviceAdmissionService", FakeService)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("devices.admission", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert result["unresolved_devices"] == ["dev-blocked"]


def test_heuristic_inventory_surfaces_active_critical_alert(monkeypatch) -> None:
    from app.api.v1.endpoints import heuristics as heuristics_module

    async def fake_get_alerts(**_kwargs):
        return {
            "alerts": [
                {
                    "id": "alert-1",
                    "severity": "critical",
                    "state": "blocked",
                    "acknowledged": False,
                }
            ],
            "total": 1,
            "unacknowledged": 1,
        }

    monkeypatch.setattr(heuristics_module, "get_alerts", fake_get_alerts)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("heuristics.alerts", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert "1 critical" in result["message"]


@pytest.mark.parametrize(
    ("running", "state"),
    [(False, "active"), (True, "failed")],
)
def test_service_runtime_detects_conflicting_fields(monkeypatch, running: bool, state: str) -> None:
    from app.core import service_manager as service_module
    from app.schemas.service import ServiceStatus

    class FakeManager:
        def get_service_status(self, _name: str):
            return ServiceStatus(running=running, installed=True, state=state)

    monkeypatch.setattr(service_module, "ServiceManager", FakeManager)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("services.runtime", {"service_name": "nginx"})
    )

    assert result["success"] is False
    assert result["source_status"] == "conflict"


def test_dns_profile_target_must_match_a_binding(tmp_path: Path, monkeypatch) -> None:
    import config

    (tmp_path / "profiles.json").write_text(
        json.dumps({"profiles": [{"id": "p1", "name": "default", "enabled": True}]}),
        encoding="utf-8",
    )
    (tmp_path / "bindings.json").write_text(
        json.dumps(
            {"bindings": [{"id": "b1", "name": "tablet", "profile_id": "p1", "enabled": True}]}
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        config,
        "get_settings",
        lambda: SimpleNamespace(NETPROTECTION_DATA_DIR=tmp_path),
    )

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("dns.profiles", {"target": "phone"})
    )

    assert result["success"] is False
    assert result["source_status"] == "unavailable"
    assert result["bindings"] == []


def test_dns_rewrite_validation_checks_required_rule_fields(tmp_path: Path, monkeypatch) -> None:
    import config

    (tmp_path / "rewrites.json").write_text(
        json.dumps({"rules": [{"id": "bad", "domain": "", "answer": "", "rewrite_type": "A"}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        config,
        "get_settings",
        lambda: SimpleNamespace(NETPROTECTION_DATA_DIR=tmp_path),
    )

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("dns.rewrites", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert result["malformed_records"] == 1


def test_cloud_thumbnail_requires_full_image_decode(tmp_path: Path, monkeypatch) -> None:
    from app.services import picloud_service as cloud_module

    source = tmp_path / "photo.jpg"
    source.write_bytes(b"source")
    image_bytes = io.BytesIO()
    Image.new("RGB", (16, 16), (20, 40, 60)).save(image_bytes, format="JPEG")
    thumbnail = tmp_path / "thumb.jpg"
    thumbnail.write_bytes(image_bytes.getvalue()[:-2])
    service = cloud_module.pi_cloud_service
    monkeypatch.setattr(
        service,
        "metadata",
        lambda _file_id: SimpleNamespace(
            model_dump=lambda **_kwargs: {"id": "photo-1", "mime": "image/jpeg"}
        ),
    )
    monkeypatch.setattr(service, "resolve_file", lambda _file_id: source)
    monkeypatch.setattr(service, "_find_thumbnail_path", lambda _file_id, _name: thumbnail)
    monkeypatch.setattr(service, "_should_thumbnail", lambda _mime, _name: True)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("cloud.metadata", {"entity_id": "photo-1"})
    )

    assert result["success"] is False
    assert result["thumbnail_ready"] is False


def test_telegram_stop_checks_available_postcondition() -> None:
    class StillRunningService:
        def stop_telegram_bot(self):
            return None

        def get_telegram_status(self):
            return {"enabled": True, "is_running": True, "message": "Still running"}

    result = CloudAdapter(service=StillRunningService()).stop_telegram_bot()

    assert result["success"] is False
    assert result["status"]["is_running"] is True


def test_prism_probe_rejects_failed_flowgraph_event(tmp_path: Path, monkeypatch) -> None:
    from app.agent.adapters import extended_diagnostics as extended_module

    flowgraph = tmp_path / "flowgraph.jsonl"
    flowgraph.write_text(
        json.dumps({"status": "failed", "error": "pipeline crashed", "event": "worker_exit"})
        + "\n",
        encoding="utf-8",
    )
    real_path = extended_module.Path
    monkeypatch.setattr(
        extended_module,
        "Path",
        lambda value: flowgraph
        if str(value) == "/var/lib/easypi/prism/flowgraph.jsonl"
        else real_path(value),
    )

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("prism.pipeline", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert "pipeline crashed" in result["message"]


def test_threat_journal_uses_entry_timestamp_not_file_mtime(tmp_path: Path, monkeypatch) -> None:
    from app.agent.adapters import extended_diagnostics as extended_module

    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        "2020-01-01T00:00:00+00:00 host sshd[1]: Failed password for root\n",
        encoding="utf-8",
    )
    now = datetime.now(timezone.utc).timestamp()
    os.utime(auth_log, (now, now))
    secure_log = tmp_path / "secure"
    real_path = extended_module.Path

    def mapped_path(value):
        if str(value) == "/var/log/auth.log":
            return auth_log
        if str(value) == "/var/log/secure":
            return secure_log
        return real_path(value)

    monkeypatch.setattr(extended_module, "Path", mapped_path)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("threat_monitor.journal", {}))

    assert result["success"] is False
    assert result["source_status"] == "stale"


def test_auth_syslog_timestamp_is_interpreted_in_system_local_timezone(tmp_path: Path) -> None:
    adapter = ExtendedDiagnosticsAdapter()
    local_now = datetime.now().astimezone().replace(microsecond=0)
    auth_log = tmp_path / "auth.log"
    auth_log.write_text(
        f"{local_now.strftime('%b %d %H:%M:%S')} host sshd[1]: Accepted publickey\n",
        encoding="utf-8",
    )

    observed = adapter._latest_auth_log_timestamp(
        auth_log,
        now=local_now.astimezone(timezone.utc),
    )

    assert observed is not None
    assert abs((observed - local_now.astimezone(timezone.utc)).total_seconds()) < 1


@pytest.mark.parametrize(
    ("status", "error_message", "size_delta"),
    [("failed", "backup command exited 2", 0), ("ready", None, 4096)],
)
def test_backup_integrity_checks_snapshot_metadata(
    tmp_path: Path,
    monkeypatch,
    status: str,
    error_message: str | None,
    size_delta: int,
) -> None:
    from app.services import rollback_service as rollback_module

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    archive_path = backup_dir / "snapshot.tar"
    content = b"config"
    with tarfile.open(archive_path, "w") as archive:
        info = tarfile.TarInfo("etc/easypi/config.json")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    actual_size = archive_path.stat().st_size
    snapshot = SimpleNamespace(
        archive_path=str(archive_path),
        status=status,
        error_message=error_message,
        size_bytes=actual_size + size_delta,
    )

    class FakeRollbackService:
        def get_snapshot(self, _snapshot_id):
            return snapshot

    FakeRollbackService.backup_dir = backup_dir
    monkeypatch.setattr(rollback_module, "RollbackService", FakeRollbackService)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("backup.integrity", {"snapshot_id": "snap-1"})
    )

    assert result["success"] is False
    assert result["source_status"] == "conflict"


def test_wireguard_endpoint_requires_host_and_port() -> None:
    assert ExtendedDiagnosticsAdapter._valid_wireguard_endpoint("definitely-not-an-endpoint") is False
    assert ExtendedDiagnosticsAdapter._valid_wireguard_endpoint("vpn.example:51820") is True
    assert ExtendedDiagnosticsAdapter._valid_wireguard_endpoint("[2001:db8::1]:51820") is True


def test_same_probe_can_be_selected_for_multiple_targets() -> None:
    selected = normalize_probe_selections(
        select_probe(
            AgentRequest(
                question="Check service runtime for nginx and service runtime for redis"
            )
        )
    )

    assert selected == [
        ("services.runtime", {"service_name": "nginx"}),
        ("services.runtime", {"service_name": "redis"}),
    ]


def test_all_multi_probe_types_receive_local_targets() -> None:
    selected = normalize_probe_selections(
        select_probe(
            AgentRequest(
                question="Check DNS profile for phone and file outcome for report.txt"
            )
        )
    )

    assert selected == [
        ("dns.profiles", {"target": "phone"}),
        ("files.outcome", {"target": "report.txt"}),
    ]


def test_operation_event_target_does_not_match_longer_entity_name(tmp_path: Path) -> None:
    events = OperationEventService(tmp_path / "events")
    now = datetime.now(timezone.utc)
    events.record_event(
        event_id="exact-report",
        action_id="files.write",
        status="failed",
        title="Save report.txt",
        message="Saving report.txt failed: disk full",
        started_at=(now - timedelta(seconds=10)).isoformat(),
        updated_at=(now - timedelta(seconds=10)).isoformat(),
    )
    events.record_event(
        event_id="backup-report",
        action_id="files.write",
        status="success",
        title="Save report.txt.bak",
        message="Saving report.txt.bak succeeded",
        started_at=now.isoformat(),
        updated_at=now.isoformat(),
    )

    result = asyncio.run(
        ExtendedDiagnosticsAdapter(events).run("files.outcome", {"target": "report.txt"})
    )

    assert result["success"] is False
    assert result["event"]["event_id"] == "exact-report"
