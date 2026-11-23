from __future__ import annotations

import asyncio
import io
import json
import os
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from PIL import Image

from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.extended_diagnostics import ExtendedDiagnosticsAdapter
from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.settings import SettingsAdapter
from app.agent.adapters.setup import SetupAdapter
from app.agent.adapters.wireguard import WireGuardAdapter
from app.agent.core.actions import AgentActionRegistry
from app.agent.core.contracts import AgentRequest
from app.agent.core.probe_routing import normalize_probe_selections, select_probe
from app.agent.core.probes import AgentProbeRegistry
from app.agent.modules.netprotection_agent import NetProtectionAgent
from app.agent.modules.network_toolkit_agent import NetworkToolkitAgent
from app.agent.modules.rollback_agent import RollbackAgent
from app.agent.modules.settings_agent import SettingsAgent


class _Db:
    def close(self) -> None:
        pass


@pytest.mark.parametrize(
    ("payload", "expected_message"),
    [
        (
            {"success": True, "message": "completed", "error_message": "postcondition failed"},
            "postcondition failed",
        ),
        (
            {"success": True, "message": "completed", "errors": ["verification failed"]},
            "verification failed",
        ),
        (
            {
                "success": False,
                "message": "Action completed successfully",
                "error": "disk full",
            },
            "disk full",
        ),
    ],
)
def test_action_registry_prioritizes_all_error_contracts(
    payload: dict,
    expected_message: str,
) -> None:
    registry = AgentActionRegistry()
    registry.register("test.error-contract", lambda _parameters: payload, allowed_keys=set())
    token = registry.issue_confirmation("test.error-contract", {})

    result = asyncio.run(
        registry.execute("test.error-contract", {}, confirmation_token=token)
    )

    assert result.success is False
    assert expected_message in result.message


def test_probe_registry_rejects_error_message_with_success() -> None:
    async def handler(_parameters):
        return {
            "success": True,
            "source_status": "ok",
            "message": "completed",
            "error_message": "checksum failed",
        }

    registry = AgentProbeRegistry()
    registry.register("test.error-message", handler, allowed_keys=set())

    result = asyncio.run(registry.run("test.error-message", {}))

    assert result["success"] is False
    assert result["source_status"] == "conflict"
    assert "checksum failed" in result["message"]


class _NoneSecurityService:
    async def fix_firewall(self):
        return None

    async def fix_password_auth(self):
        return None

    async def fix_filesystem_readonly(self):
        return None

    async def start_outdated_packages_fix(self):
        return None


@pytest.mark.parametrize(
    "method_name",
    [
        "fix_firewall",
        "fix_password_auth",
        "fix_filesystem_readonly",
        "start_outdated_packages_fix",
    ],
)
def test_security_actions_fail_closed_on_none(method_name: str) -> None:
    adapter = SecurityAdapter(service=_NoneSecurityService(), session_factory=_Db)

    result = asyncio.run(getattr(adapter, method_name)())

    assert result["success"] is False
    assert "no completion evidence" in result["message"]


class _NoneThreatMonitor:
    async def start_monitoring(self):
        return None

    async def stop_monitoring(self):
        return None


@pytest.mark.parametrize(
    "method_name",
    ["start_threat_monitoring", "stop_threat_monitoring"],
)
def test_threat_monitor_actions_fail_closed_on_none(method_name: str) -> None:
    adapter = ServiceStatusAdapter(
        netprotection=SimpleNamespace(),
        tailscale=SimpleNamespace(),
        threat_monitor=_NoneThreatMonitor(),
    )

    result = asyncio.run(getattr(adapter, method_name)())

    assert result["success"] is False
    assert "no" in result["message"].lower()


def test_setup_restart_fails_closed_on_none(monkeypatch) -> None:
    import app.agent.adapters.setup as setup_module

    async def no_result():
        return None

    monkeypatch.setattr(setup_module, "restart_easypi_services", no_result)

    result = asyncio.run(SetupAdapter().restart_services())

    assert result["success"] is False


def test_wireguard_restart_fails_closed_on_none(monkeypatch) -> None:
    import app.agent.adapters.wireguard as wireguard_module

    async def no_result():
        return None

    monkeypatch.setattr(wireguard_module, "restart_wireguard_service", no_result)

    result = asyncio.run(WireGuardAdapter().restart_service())

    assert result["success"] is False


@pytest.mark.parametrize("targeted", [False, True])
def test_task_running_state_conflicts_with_exited_process(monkeypatch, targeted: bool) -> None:
    from app.api.v1.endpoints import tasks as tasks_module

    task_id = "finished-but-running"
    monkeypatch.setattr(
        tasks_module,
        "active_tasks",
        {
            task_id: {
                "id": task_id,
                "status": "running",
                "process": SimpleNamespace(returncode=0),
            }
        },
    )
    parameters = {"task_id": task_id} if targeted else {}

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("tasks.runtime", parameters))

    assert result["success"] is False
    assert result["source_status"] == "conflict"


def test_malformed_heuristic_record_cannot_become_healthy(monkeypatch) -> None:
    from app.api.v1.endpoints import heuristics as heuristics_module

    async def get_alerts(**_kwargs):
        return {"alerts": [None], "total": 1, "unacknowledged": 1}

    monkeypatch.setattr(heuristics_module, "get_alerts", get_alerts)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("heuristics.alerts", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert result["malformed_records"] == 1


def test_inconsistent_heuristic_counters_cannot_become_healthy(monkeypatch) -> None:
    from app.api.v1.endpoints import heuristics as heuristics_module

    async def get_alerts(**_kwargs):
        return {"alerts": [], "total": 1, "unacknowledged": 1}

    monkeypatch.setattr(heuristics_module, "get_alerts", get_alerts)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("heuristics.alerts", {}))

    assert result["success"] is False
    assert result["source_status"] == "conflict"


def test_dns_targets_do_not_use_substring_matches(tmp_path: Path, monkeypatch) -> None:
    import config

    (tmp_path / "profiles.json").write_text(
        json.dumps({"profiles": [{"id": "p1", "name": "default", "enabled": True}]}),
        encoding="utf-8",
    )
    (tmp_path / "bindings.json").write_text(
        json.dumps({"bindings": [{"id": "b1", "name": "phone2", "profile_id": "p1"}]}),
        encoding="utf-8",
    )
    (tmp_path / "rewrites.json").write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "id": "r1",
                        "domain": "notexample.com",
                        "answer": "192.168.1.8",
                        "rewrite_type": "A",
                    }
                ],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        config,
        "get_settings",
        lambda: SimpleNamespace(NETPROTECTION_DATA_DIR=tmp_path),
    )
    adapter = ExtendedDiagnosticsAdapter()

    profile = asyncio.run(adapter.run("dns.profiles", {"target": "phone"}))
    rewrite = asyncio.run(adapter.run("dns.rewrites", {"target": "example.com"}))

    assert profile["success"] is False
    assert profile["source_status"] == "unavailable"
    assert rewrite["success"] is False
    assert rewrite["source_status"] == "unavailable"


def test_camera_action_target_does_not_use_substring_match() -> None:
    camera = SimpleNamespace(
        id="camera-1",
        name="FrontDoor",
        ip="192.168.1.50",
        get_rtsp_url=lambda: "rtsp://192.168.1.50/live",
    )

    class FakeSession:
        def query(self, _model):
            return self

        def order_by(self, _column):
            return self

        def all(self):
            return [camera]

        def close(self):
            return None

    recordings = SimpleNamespace(
        capture_snapshot=AsyncMock(return_value={"success": True})
    )
    adapter = CamerasAdapter(recordings=recordings, session_factory=FakeSession)

    result = asyncio.run(adapter.capture_snapshot("Front"))

    assert result["success"] is False
    assert recordings.capture_snapshot.await_count == 0


def test_camera_restart_requires_explicit_stop_success(monkeypatch) -> None:
    adapter = CamerasAdapter()
    stop = AsyncMock(return_value={"message": "no success field"})
    start = AsyncMock(return_value={"success": True})
    monkeypatch.setattr(adapter, "stop_recording", stop)
    monkeypatch.setattr(adapter, "start_recording", start)

    result = asyncio.run(adapter.restart_recording("FrontDoor"))

    assert result["success"] is False
    assert start.await_count == 0


def test_tailscale_target_does_not_use_substring_match(monkeypatch) -> None:
    import app.services.remote_access.tailscale_admin_api as tailscale_module

    class FakeTailscaleAPI:
        def __init__(self):
            self.config = SimpleNamespace(api_key="secret", tailnet="example.ts.net")

        def load_config(self, *, migrate_plaintext: bool):
            assert migrate_plaintext is False
            return self.config

        async def list_devices(self):
            return [
                tailscale_module.DeviceInfo(
                    id="device-2",
                    name="node2.example.ts.net",
                    hostname="node2",
                    user="owner@example.com",
                    tailscale_ips=["100.64.0.2"],
                    advertised_routes=[],
                    enabled_routes=[],
                    is_exit_node=False,
                    is_exit_node_enabled=False,
                )
            ]

        async def close(self):
            return None

    monkeypatch.setattr(tailscale_module, "TailscaleAdminAPI", FakeTailscaleAPI)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("tailscale.routes", {"target": "node"})
    )

    assert result["success"] is False
    assert result["source_status"] == "unavailable"


def test_settings_unknown_target_does_not_fall_back_to_first_user() -> None:
    class FakeResult:
        def __init__(self, *, users=None, scalar_value=0):
            self.users = users or []
            self.scalar_value = scalar_value

        def scalars(self):
            return self

        def all(self):
            return self.users

        def scalar(self):
            return self.scalar_value

    alice = SimpleNamespace(
        id=1,
        username="Alice",
        role="admin",
        email="alice@example.com",
        is_active=True,
        totp_enabled=False,
        backup_codes=None,
        last_login=None,
        last_login_ip=None,
    )

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def execute(self, _query):
            self.calls += 1
            return FakeResult(users=[alice]) if self.calls == 1 else FakeResult()

        def close(self):
            return None

    adapter = SettingsAdapter(session_factory=FakeSession)

    assert adapter._get_user_context("MissingUser") is None


@pytest.mark.parametrize(
    ("selector", "target", "records"),
    [
        (
            NetProtectionAgent(SimpleNamespace())._find_client,
            "Front",
            [{"name": "FrontDoor", "ip": "192.168.1.50"}],
        ),
        (
            NetworkToolkitAgent(SimpleNamespace())._find_cached_device,
            "printer",
            [{"ip": "192.168.1.60", "hostname": "printer2", "vendor": "Acme"}],
        ),
        (
            RollbackAgent(SimpleNamespace())._find_snapshot,
            "backup2",
            [{"snapshot_id": "snapshot-1", "name": "backup"}],
        ),
    ],
)
def test_entity_selectors_do_not_use_substring_matches(selector, target, records) -> None:
    assert selector(target, records) is None


@pytest.mark.parametrize("section", ["notifications", "security", "overview"])
def test_settings_missing_user_is_unavailable(section: str) -> None:
    class MissingUserSettings:
        async def get_notification_state(self, *, username_hint=None):
            return {"username": None}

        async def get_security_state(self, *, username_hint=None):
            return {"username": None}

        async def get_overview(self, *, username_hint=None):
            return {
                "general": {"timezone": "UTC"},
                "notifications": {"username": None},
                "security": {"username": None},
                "user": {"username": None},
            }

    agent = SettingsAgent(MissingUserSettings())
    if section == "notifications":
        awaitable = agent._notifications_response(
            username_hint="MissingUser", question="notifications"
        )
    elif section == "security":
        awaitable = agent._security_response(
            username_hint="MissingUser", question="2fa"
        )
    else:
        awaitable = agent._overview_response(username_hint="MissingUser")

    response = asyncio.run(awaitable)

    assert response.source_status == "unavailable"
    assert response.confidence == "low"


def test_backup_probe_rejects_symlink_like_restore_does(tmp_path: Path, monkeypatch) -> None:
    import app.services.rollback_service as rollback_module

    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    real_archive = backup_dir / "real.tar"
    with tarfile.open(real_archive, "w") as archive:
        data = b"config"
        member = tarfile.TarInfo("etc/easypi/config.json")
        member.size = len(data)
        archive.addfile(member, io.BytesIO(data))
    link_archive = backup_dir / "snapshot-link.tar"
    os.symlink(real_archive, link_archive)
    snapshot = SimpleNamespace(
        archive_path=str(link_archive),
        status="ready",
        error_message=None,
        size_bytes=real_archive.stat().st_size,
    )

    class FakeRollbackService:
        def get_snapshot(self, _snapshot_id):
            return snapshot

    FakeRollbackService.backup_dir = backup_dir
    monkeypatch.setattr(rollback_module, "RollbackService", FakeRollbackService)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run(
            "backup.integrity", {"snapshot_id": "snapshot-link"}
        )
    )

    assert result["success"] is False
    assert "symbolic link" in result["message"]


@pytest.mark.parametrize(
    ("last_check", "expected_status"),
    [
        ((datetime.now(timezone.utc) + timedelta(days=3)).isoformat(), "conflict"),
        ((datetime.now(timezone.utc) + timedelta(hours=12)).isoformat(), "conflict"),
        ((datetime.now(timezone.utc) - timedelta(days=30)).isoformat(), "stale"),
    ],
)
def test_personal_dns_freshness_precedes_offline_state(
    monkeypatch,
    last_check: str,
    expected_status: str,
) -> None:
    import app.agent.adapters.personal_dns as personal_dns_module

    class FakePersonalDNS:
        def get_latest_deploy(self, *, user_id: int):
            assert user_id == 7
            return {
                "status": "deployed",
                "is_online": False,
                "last_check": last_check,
            }

    monkeypatch.setattr(personal_dns_module, "PersonalDNSAdapter", FakePersonalDNS)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run(
            "personal_dns.tenancy", {"actor_user_id": 7}
        )
    )

    assert result["success"] is False
    assert result["source_status"] == expected_status


def test_targeted_discovery_requires_target_reply(monkeypatch) -> None:
    import socket

    from app.services.ptz import discovery

    devices = discovery.DiscoveryResult(
        [], probes_sent=2, transport_errors=[], receive_failed=False
    )
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth0")])
    monkeypatch.setattr(discovery, "discover", lambda **_kwargs: devices)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run(
            "camera.discovery", {"target": "192.168.1.50"}
        )
    )

    assert result["success"] is False
    assert "did not reply" in result["message"]


def test_discovery_surfaces_partial_interface_failure(monkeypatch) -> None:
    import socket

    from app.services.ptz import discovery

    devices = discovery.DiscoveryResult(
        [],
        probes_sent=2,
        transport_errors=["interface wlan0: network unreachable"],
        receive_failed=False,
    )
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "eth0"), (2, "wlan0")])
    monkeypatch.setattr(discovery, "discover", lambda **_kwargs: devices)

    result = asyncio.run(ExtendedDiagnosticsAdapter().run("camera.discovery", {}))

    assert result["success"] is False
    assert result["source_status"] == "partial"
    assert "wlan0" in result["message"]


def test_camera_live_message_identifies_network_failure(monkeypatch) -> None:
    import app.api.v1.endpoints.camera_helpers as camera_helpers
    import app.db.session as session_module
    import app.services.mediamtx_client as mediamtx_module

    camera = SimpleNamespace(id="cam-1", ip="192.168.1.50", port=554)

    class Query:
        def filter(self, *_args):
            return self

        def first(self):
            return camera

    class Db:
        def query(self, *_args):
            return Query()

        def close(self):
            pass

    image = io.BytesIO()
    Image.new("RGB", (8, 8), "white").save(image, format="JPEG")

    class Media:
        async def get_stream_info(self, _camera_id):
            return {"sourceReady": True}

        async def capture_snapshot(self, _camera_id):
            return True, image.getvalue(), ""

    monkeypatch.setattr(session_module, "SessionLocal", Db)
    monkeypatch.setattr(camera_helpers, "check_camera_online", lambda _ip, _port: False)
    monkeypatch.setattr(mediamtx_module, "mediamtx_client", Media())

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("camera.live", {"camera_id": "cam-1"})
    )

    assert result["success"] is False
    assert result["frame_valid"] is True
    assert "network" in result["message"].lower()
    assert "no valid frame" not in result["message"].lower()


@pytest.mark.parametrize(
    ("question", "parameter", "expected"),
    [
        ("Check WireGuard artifact for AliceVPN", "entity_id", "AliceVPN"),
        ("Check file outcome for Quarterly Report.pdf", "target", "Quarterly Report.pdf"),
    ],
)
def test_natural_language_target_preserves_identity(
    question: str,
    parameter: str,
    expected: str,
) -> None:
    selected = normalize_probe_selections(select_probe(AgentRequest(question=question)))

    assert selected[0][1][parameter] == expected
