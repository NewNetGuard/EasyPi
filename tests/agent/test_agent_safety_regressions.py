from __future__ import annotations

import asyncio
import json
import io
import os
import tarfile
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.agent.adapters.extended_diagnostics import ExtendedDiagnosticsAdapter
from app.agent.adapters.cloud import CloudAdapter
from app.agent.adapters.personal_dns import PersonalDNSAdapter
from app.agent.core.actions import AgentActionPlanner, AgentActionRegistry
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse
from app.agent.core.gateway import AgentGateway
from app.agent.core.probe_routing import build_probe_response, select_probe
from app.agent.core.probes import AgentProbeRegistry
from app.agent.core.registry import AgentRegistry
from app.agent.core.response_builder import finalize_response
from app.agent.core.router import AgentRouter
from app.agent.core.sanitization import normalize_agent_request
from app.api.v1.endpoints import files as files_endpoint
from app.services.ai_diagnostic_service import AIDiagnosticService
from app.services.operation_event_service import OperationEventService


def test_failed_file_write_records_failed_operation_event(monkeypatch) -> None:
    events: list[dict[str, object]] = []

    def fail_write(_path: str, _content: str) -> dict[str, str]:
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(files_endpoint.files_service, "write_file", fail_write)
    monkeypatch.setattr(
        files_endpoint,
        "_record_file_event",
        lambda **event: events.append(event),
    )

    with pytest.raises(PermissionError, match="read-only filesystem"):
        files_endpoint.write_file(
            {"path": "/srv/easypi/config.yml", "content": "value"},
            SimpleNamespace(id=7),
        )

    assert events
    assert events[-1]["action_id"] == "files.write"
    assert events[-1]["status"] == "failed"
    assert "PermissionError" in str(events[-1]["message"])


def test_action_confirmation_is_payload_bound_and_single_use() -> None:
    calls: list[dict[str, object]] = []

    async def handler(parameters: dict[str, object]) -> None:
        calls.append(parameters)

    registry = AgentActionRegistry()
    registry.register("test.change", handler, allowed_keys={"target"}, required_keys={"target"})
    token = registry.issue_confirmation("test.change", {"target": "alpha"})

    wrong_payload = asyncio.run(
        registry.execute("test.change", {"target": "beta"}, confirmation_token=token)
    )
    replay = asyncio.run(
        registry.execute("test.change", {"target": "alpha"}, confirmation_token=token)
    )
    valid_token = registry.issue_confirmation("test.change", {"target": "alpha"})
    no_confirmation_from_handler = asyncio.run(
        registry.execute("test.change", {"target": "alpha"}, confirmation_token=valid_token)
    )

    assert wrong_payload.success is False
    assert replay.success is False
    assert no_confirmation_from_handler.success is False
    assert calls == [{"target": "alpha"}]


def test_action_confirmation_is_bound_to_authenticated_actor() -> None:
    calls = 0

    async def handler(_parameters: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {"success": True, "message": "done"}

    registry = AgentActionRegistry()
    registry.register("test.change", handler, allowed_keys=set())
    token = registry.issue_confirmation("test.change", {}, actor_user_id=7)

    wrong_actor = asyncio.run(
        registry.execute("test.change", {}, confirmation_token=token, actor_user_id=8)
    )
    valid_token = registry.issue_confirmation("test.change", {}, actor_user_id=7)
    valid_actor = asyncio.run(
        registry.execute("test.change", {}, confirmation_token=valid_token, actor_user_id=7)
    )

    assert wrong_actor.success is False
    assert valid_actor.success is True
    assert calls == 1


@pytest.mark.parametrize(
    ("action_id", "status"),
    [
        ("backup.create_full", "started"),
        ("backup.cancel_latest_running", "cancelled"),
        ("threat_monitor.start", "started"),
        ("threat_monitor.start", "already_running"),
        ("threat_monitor.stop", "stopped"),
        ("threat_monitor.stop", "already_stopped"),
    ],
)
def test_action_registry_accepts_completed_lifecycle_statuses(action_id: str, status: str) -> None:
    async def handler(_parameters: dict[str, object]) -> dict[str, object]:
        return {"status": status}

    registry = AgentActionRegistry()
    registry.register(action_id, handler, allowed_keys=set())
    token = registry.issue_confirmation(action_id, {})

    result = asyncio.run(registry.execute(action_id, {}, confirmation_token=token))

    assert result.success is True


def test_cancelled_status_is_not_generic_success_for_unrelated_action() -> None:
    async def handler(_parameters: dict[str, object]) -> dict[str, object]:
        return {"status": "cancelled"}

    registry = AgentActionRegistry()
    registry.register("test.lifecycle", handler, allowed_keys=set())
    token = registry.issue_confirmation("test.lifecycle", {})

    result = asyncio.run(registry.execute("test.lifecycle", {}, confirmation_token=token))

    assert result.success is False


def test_action_registry_explicit_failure_wins_over_successful_status() -> None:
    async def handler(_parameters: dict[str, object]) -> dict[str, object]:
        return {"success": False, "status": "started", "error": "start verification failed"}

    registry = AgentActionRegistry()
    registry.register("test.lifecycle", handler, allowed_keys=set())
    token = registry.issue_confirmation("test.lifecycle", {})

    result = asyncio.run(registry.execute("test.lifecycle", {}, confirmation_token=token))

    assert result.success is False
    assert result.message == "start verification failed"


def test_probe_registry_rejects_unknown_parameters_and_bounds_failures() -> None:
    async def failing(_parameters: dict[str, object]) -> dict[str, object]:
        raise TimeoutError("source timed out")

    registry = AgentProbeRegistry()
    registry.register("test.read", failing, allowed_keys={"target"})

    unexpected = asyncio.run(registry.run("test.read", {"command": "whoami"}))
    failed = asyncio.run(registry.run("test.read", {"target": "alpha"}))

    assert unexpected["success"] is False
    assert "Unsupported probe parameters" in str(unexpected["message"])
    assert failed["success"] is False
    assert failed["source_status"] == "unavailable"
    assert "TimeoutError" in str(failed["message"])


@pytest.mark.parametrize("payload", [None, {}])
def test_probe_registry_treats_absent_evidence_as_unavailable(payload) -> None:
    async def handler(_parameters):
        return payload

    registry = AgentProbeRegistry()
    registry.register("test.absent", handler, allowed_keys=set())

    result = asyncio.run(registry.run("test.absent", {}))

    assert result["success"] is False
    assert result["source_status"] == "unavailable"
    assert "no diagnostic evidence" in str(result["message"])


def test_probe_registry_requires_explicit_success_contract() -> None:
    async def handler(_parameters):
        return {"message": "Evidence exists but health was not classified."}

    registry = AgentProbeRegistry()
    registry.register("test.ambiguous", handler, allowed_keys=set())

    result = asyncio.run(registry.run("test.ambiguous", {}))

    assert result["success"] is False
    assert result["source_status"] == "unavailable"


def test_cloud_void_start_contract_and_available_postcondition() -> None:
    class VoidService:
        started = False

        def start_telegram_bot(self):
            self.started = True
            return None

    service = VoidService()
    completed = CloudAdapter(service=service).start_telegram_bot()

    class RefusedService:
        def start_telegram_bot(self):
            return None

        def get_telegram_status(self):
            return {"enabled": False, "message": "Token not set"}

    refused = CloudAdapter(service=RefusedService()).start_telegram_bot()

    assert service.started is True
    assert completed["success"] is True
    assert refused["success"] is False
    assert refused["message"] == "Token not set"


def test_personal_dns_adapter_applies_tenant_filter() -> None:
    deploy = SimpleNamespace(
        id=1,
        vps_ip="192.0.2.10",
        domain="dns.example.test",
        dns_ipv4="192.0.2.10",
        admin_url=None,
        doh_url=None,
        dot_address=None,
        status="failed",
        deployment_date=datetime(2026, 8, 31),
        last_check=None,
        is_online=False,
        wireguard_installed=False,
        warnings=[],
        recommendations=[],
        deployment_log="failure",
    )

    class Query:
        filter_called = False

        def filter(self, _condition):
            self.filter_called = True
            return self

        def order_by(self, *_columns):
            return self

        def first(self):
            return deploy

    query = Query()

    class Session:
        def query(self, _model):
            return query

        def close(self):
            return None

    result = PersonalDNSAdapter(session_factory=Session).get_latest_deploy(user_id=7)

    assert query.filter_called is True
    assert result is not None
    assert result["id"] == 1


def test_personal_dns_probe_uses_server_actor_not_client_value() -> None:
    captured: dict[str, object] = {}

    class Gateway:
        async def run_probe(self, probe_id: str, *, parameters=None):
            captured["probe_id"] = probe_id
            captured["parameters"] = parameters
            return {"success": True}

    service = AIDiagnosticService.__new__(AIDiagnosticService)
    service.gateway = Gateway()
    asyncio.run(
        service.run_probe(
            "personal_dns.tenancy",
            parameters={"actor_user_id": 999},
            actor_user_id=7,
        )
    )

    assert captured["parameters"] == {"actor_user_id": 7}


def test_request_normalization_preserves_only_valid_server_actor() -> None:
    normalized = normalize_agent_request(AgentRequest(question="status", actor_user_id=7))
    invalid = normalize_agent_request(AgentRequest(question="status", actor_user_id=-1))

    assert normalized.actor_user_id == 7
    assert invalid.actor_user_id is None


def test_profile_probe_reports_disabled_profile_conflict(tmp_path, monkeypatch) -> None:
    (tmp_path / "profiles.json").write_text(
        json.dumps({"profiles": [{"id": "p1", "name": "Kids", "enabled": False}]}),
        encoding="utf-8",
    )
    (tmp_path / "bindings.json").write_text(
        json.dumps({"bindings": [{"id": "b1", "profile_id": "p1", "name": "phone", "enabled": True}]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "config.get_settings",
        lambda: SimpleNamespace(NETPROTECTION_DATA_DIR=tmp_path),
    )
    adapter = ExtendedDiagnosticsAdapter(OperationEventService(tmp_path / "events"))

    result = asyncio.run(adapter.run("dns.profiles", {"target": "phone"}))

    assert result["success"] is False
    assert result["source_status"] == "conflict"
    assert result["conflicts"] == [
        {"binding_id": "b1", "profile_id": "p1", "reason": "profile_disabled"}
    ]


def test_rewrite_probe_distinguishes_corrupt_store_from_empty_store(tmp_path, monkeypatch) -> None:
    (tmp_path / "rewrites.json").write_text("{not-json", encoding="utf-8")
    monkeypatch.setattr(
        "config.get_settings",
        lambda: SimpleNamespace(NETPROTECTION_DATA_DIR=tmp_path),
    )
    adapter = ExtendedDiagnosticsAdapter(OperationEventService(tmp_path / "events"))

    result = asyncio.run(adapter.run("dns.rewrites", {}))

    assert result["success"] is False
    assert result["source_status"] == "unavailable"
    assert "JSONDecodeError" in str(result["message"])


def test_operation_evidence_uses_event_timestamp_instead_of_file_mtime(tmp_path) -> None:
    events = OperationEventService(tmp_path / "events")
    current_time = datetime.now(timezone.utc).isoformat()
    events.record_event(
        event_id="files-fresh",
        action_id="files.write",
        status="success",
        title="Fresh file save",
        message="The current file save succeeded.",
        started_at=current_time,
        updated_at=current_time,
    )
    events.record_event(
        event_id="files-stale",
        action_id="files.write",
        status="success",
        title="Historical file save",
        message="A historical file save succeeded.",
        started_at="2020-01-01T00:00:00+00:00",
        updated_at="2020-01-01T00:00:00+00:00",
    )
    fresh_path = events.metadata_dir / "files-fresh.json"
    stale_path = events.metadata_dir / "files-stale.json"
    fresh_mtime = fresh_path.stat().st_mtime
    os.utime(stale_path, (fresh_mtime + 10, fresh_mtime + 10))

    result = asyncio.run(ExtendedDiagnosticsAdapter(events).run("files.outcome", {}))

    assert result["success"] is True
    assert result["source_status"] == "ok"
    assert result["event"]["event_id"] == "files-fresh"


def test_action_result_contract_is_fail_closed_and_exposes_errors() -> None:
    async def status_error(_parameters):
        return {"status": "error", "message": "sudo denied"}

    async def explicit_error(_parameters):
        return {"success": False, "error": "restart failed"}

    registry = AgentActionRegistry()
    registry.register("test.status", status_error, allowed_keys=set())
    registry.register("test.error", explicit_error, allowed_keys=set())
    status_token = registry.issue_confirmation("test.status", {})
    error_token = registry.issue_confirmation("test.error", {})

    status_result = asyncio.run(registry.execute("test.status", {}, confirmation_token=status_token))
    error_result = asyncio.run(registry.execute("test.error", {}, confirmation_token=error_token))

    assert status_result.success is False
    assert status_result.message == "sudo denied"
    assert error_result.success is False
    assert error_result.message == "restart failed"


def test_stale_response_never_receives_confirmation_action() -> None:
    class SecurityModule:
        name = "security_agent"

        def score(self, _request):
            return 100

        async def explain(self, _request):
            return AgentResponse(
                category="service",
                target="firewall_inactive",
                matched=True,
                title="Security",
                summary="Firewall was inactive in the saved scan.",
                confidence="high",
                module=self.name,
                facts=[AgentFact("Last scan", "2020-01-01T00:00:00Z")],
            )

    modules = AgentRegistry([SecurityModule()])
    gateway = AgentGateway(modules, AgentRouter(modules), action_planner=AgentActionPlanner())
    response = asyncio.run(gateway.explain(AgentRequest(question="Fix firewall", route="security")))

    assert response.source_status == "stale"
    assert response.actions == []


def test_backup_integrity_rejects_parent_traversal(tmp_path, monkeypatch) -> None:
    archive_path = tmp_path / "unsafe.tar"
    with tarfile.open(archive_path, "w") as archive:
        member = tarfile.TarInfo("../../etc/passwd")
        content = b"unsafe"
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    class Rollback:
        backup_dir = tmp_path

        def get_snapshot(self, _snapshot_id):
            return SimpleNamespace(archive_path=str(archive_path))

    monkeypatch.setattr("app.services.rollback_service.RollbackService", Rollback)
    result = asyncio.run(ExtendedDiagnosticsAdapter().run("backup.integrity", {"snapshot_id": "x"}))

    assert result["success"] is False
    assert "unsafe archive member path" in result["message"]


@pytest.mark.parametrize("returncode,expected_success", [(0, True), (1, False)])
def test_backup_integrity_uses_privileged_verifier_for_real_epibak(
    tmp_path,
    monkeypatch,
    returncode: int,
    expected_success: bool,
) -> None:
    archive_path = tmp_path / "config-2026-09-01-12-00-00.epibak"
    archive_path.write_bytes(b"EASYPIBK1-encrypted-payload")
    snapshot = SimpleNamespace(
        archive_path=str(archive_path),
        status="ready",
        error_message=None,
        size_bytes=archive_path.stat().st_size,
    )

    class Rollback:
        backup_dir = tmp_path
        runner = tmp_path / "runner"

        def get_snapshot(self, _snapshot_id):
            return snapshot

    observed: list[list[str]] = []

    def verify(command, **_kwargs):
        observed.append(command)
        return SimpleNamespace(returncode=returncode, stdout="", stderr="")

    monkeypatch.setattr("app.services.rollback_service.RollbackService", Rollback)
    monkeypatch.setattr("app.agent.adapters.extended_diagnostics.subprocess.run", verify)

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run(
            "backup.integrity", {"snapshot_id": "snapshot-encrypted"}
        )
    )

    assert result["success"] is expected_success
    assert result["source_status"] == ("ok" if expected_success else "partial")
    assert observed == [
        [
            "sudo",
            "-n",
            str(Rollback.runner),
            "backup/backup_file.sh",
            "verify",
            archive_path.name,
        ]
    ]


@pytest.mark.parametrize(
    ("question", "target", "expected"),
    [
        ("database health", None, "health.dependencies"),
        ("camera PTZ health", "cam-1", "camera.ptz"),
        ("camera discovery", None, "camera.discovery"),
        ("camera live view", "cam-1", "camera.live"),
        ("DNS profile bindings", None, "dns.profiles"),
        ("DNS rewrite manager", None, "dns.rewrites"),
        ("PRISM DPI pipeline", None, "prism.pipeline"),
        ("threat journal ingestion", None, "threat_monitor.journal"),
        ("Tailscale route approval", None, "tailscale.routes"),
        ("Tailscale Funnel status", None, "tailscale.funnel"),
        ("notification delivery outcome", None, "notifications.delivery"),
        ("cloud metadata preview", "f-1", "cloud.metadata"),
        ("file mutation outcome", "a.txt", "files.outcome"),
        ("terminal live PTY", None, "terminal.live"),
        ("login workflow failure", None, "auth.workflow"),
        ("WireGuard QR artifact", "peer", "wireguard.artifacts"),
        ("marketplace runtime", None, "marketplace.runtime"),
        ("AI inference", None, "ai.inference"),
        ("backup archive integrity", "snap-1", "backup.integrity"),
        ("Personal DNS tenancy", None, "personal_dns.tenancy"),
        ("unknown device admission", "dev-1", "devices.admission"),
        ("heuristic alerts", None, "heuristics.alerts"),
        ("NetProtection components", None, "netprotection.components"),
        ("task runtime", "task-1", "tasks.runtime"),
        ("service runtime", "svc-1", "services.runtime"),
    ],
)
def test_every_extended_probe_has_natural_language_routing(question, target, expected) -> None:
    selected = select_probe(AgentRequest(question=question, target=target, actor_user_id=7))

    assert selected is not None
    assert selected[0] == expected


def test_one_question_can_select_multiple_independent_probes() -> None:
    selected = select_probe(
        AgentRequest(
            question="Check database health and camera live view",
            target="camera-1",
            actor_user_id=7,
        )
    )

    assert isinstance(selected, list)
    assert {probe_id for probe_id, _parameters in selected} == {
        "health.dependencies",
        "camera.live",
    }


def test_task_runtime_inventory_routes_without_target() -> None:
    selected = select_probe(AgentRequest(question="Check task runtime"))

    assert selected == ("tasks.runtime", {})


def test_multi_probe_targets_are_extracted_per_probe() -> None:
    selected = select_probe(
        AgentRequest(
            question="Check camera live view for front-door and service runtime for nginx",
            target="front-door",
        )
    )

    assert isinstance(selected, list)
    parameters = {probe_id: values for probe_id, values in selected}
    assert parameters["camera.live"] == {"camera_id": "front-door"}
    assert parameters["services.runtime"] == {"service_name": "nginx"}


def test_probe_only_intent_runs_without_a_generic_module() -> None:
    calls = 0

    async def probe(_parameters):
        nonlocal calls
        calls += 1
        return {"success": True, "source_status": "ok", "message": "Database is healthy."}

    class NoModuleRouter:
        def select(self, _request):
            return None

    probes = AgentProbeRegistry()
    probes.register("health.dependencies", probe, allowed_keys=set())
    modules = AgentRegistry([])
    gateway = AgentGateway(modules, NoModuleRouter(), probe_registry=probes)

    response = asyncio.run(gateway.explain(AgentRequest(question="Check database health")))

    assert calls == 1
    assert response.module == "diagnostic_probes"
    assert response.summary == "Database is healthy."
    assert response.source_status == "ok"


@pytest.mark.parametrize(
    "probe_id,payload_field,payload_value",
    [
        ("dns.profiles", "conflicts", []),
        ("tasks.runtime", "conflicting_tasks", []),
    ],
)
def test_empty_probe_conflict_collections_do_not_create_false_conflict(
    probe_id: str,
    payload_field: str,
    payload_value: list[object],
) -> None:
    response = build_probe_response(
        AgentRequest(question=probe_id),
        [
            (
                probe_id,
                {
                    "success": True,
                    "source_status": "ok",
                    "message": "Live diagnostic source loaded successfully.",
                    payload_field: payload_value,
                },
            )
        ],
    )

    finalized = finalize_response(response)

    assert finalized.source_status == "ok"
    assert any(fact.label == f"Probe {payload_field.replace('_', ' ')}" for fact in finalized.facts)


def test_targeted_probe_replaces_conflicting_module_conclusion_and_actions() -> None:
    class StoppedModule:
        name = "system_services_agent"

        async def explain(self, _request):
            return AgentResponse(
                category="service",
                target="netprotection",
                matched=True,
                title="NetProtection service",
                summary="NetProtection is installed but not running locally.",
                confidence="high",
                module=self.name,
                facts=[AgentFact("Service running", "No")],
            )

    class StoppedRouter:
        def select(self, _request):
            return StoppedModule()

    async def healthy(_parameters):
        return {
            "success": True,
            "source_status": "ok",
            "message": "Service is running.",
            "running": True,
        }

    probes = AgentProbeRegistry()
    probes.register(
        "services.runtime",
        healthy,
        allowed_keys={"service_name"},
        required_keys={"service_name"},
    )
    modules = AgentRegistry([StoppedModule()])
    gateway = AgentGateway(modules, StoppedRouter(), probe_registry=probes)

    response = asyncio.run(
        gateway.explain(
            AgentRequest(question="What is the service status?", target="netprotection")
        )
    )

    assert response.module == "diagnostic_probes"
    assert response.summary == "Service is running."
    assert response.actions == []
    assert all(fact.value != "No" for fact in response.facts)


def test_malformed_jpeg_like_payload_is_not_a_valid_camera_frame() -> None:
    payload = b"\xff\xd8" + (b"x" * 128)

    assert ExtendedDiagnosticsAdapter._valid_image_payload(payload) is False


def test_truncated_real_jpeg_is_not_a_valid_camera_frame() -> None:
    from PIL import Image

    stream = io.BytesIO()
    Image.new("RGB", (16, 16), (255, 0, 0)).save(stream, format="JPEG")
    truncated = stream.getvalue()[:-2]

    assert ExtendedDiagnosticsAdapter._valid_image_payload(truncated) is False


def test_personal_dns_deployed_is_healthy_and_old_online_flag_is_stale(monkeypatch) -> None:
    adapter = ExtendedDiagnosticsAdapter()
    current = {
        "id": 11,
        "status": "deployed",
        "is_online": True,
        "last_check": datetime.now(timezone.utc).isoformat(),
    }
    monkeypatch.setattr(
        PersonalDNSAdapter,
        "get_latest_deploy",
        lambda _self, *, user_id: current,
    )
    healthy = asyncio.run(adapter.run("personal_dns.tenancy", {"actor_user_id": 7}))

    current["status"] = "active"
    current["last_check"] = "2020-01-01T00:00:00+00:00"
    stale = asyncio.run(adapter.run("personal_dns.tenancy", {"actor_user_id": 7}))

    assert healthy["success"] is True
    assert healthy["source_status"] == "ok"
    assert stale["success"] is False
    assert stale["source_status"] == "stale"


@pytest.mark.parametrize(
    ("online", "last_check", "expected_status"),
    [
        (None, datetime.now(timezone.utc).isoformat(), "partial"),
        (True, "not-a-timestamp", "unavailable"),
        (True, None, "unavailable"),
    ],
)
def test_personal_dns_requires_current_online_observation(
    monkeypatch,
    online,
    last_check,
    expected_status,
) -> None:
    deploy = {
        "id": 12,
        "status": "deployed",
        "is_online": online,
        "last_check": last_check,
    }
    monkeypatch.setattr(
        PersonalDNSAdapter,
        "get_latest_deploy",
        lambda _self, *, user_id: deploy,
    )

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("personal_dns.tenancy", {"actor_user_id": 7})
    )

    assert result["success"] is False
    assert result["source_status"] == expected_status


def test_future_ptz_evidence_is_conflicting(monkeypatch) -> None:
    class Query:
        def filter(self, *_args):
            return self

        def first(self):
            return SimpleNamespace(id="camera-1")

    class Db:
        def query(self, *_args):
            return Query()

        def close(self):
            return None

    monkeypatch.setattr("app.db.session.SessionLocal", lambda: Db())
    monkeypatch.setattr(
        "app.services.ptz.service.build_capabilities_response",
        lambda _camera: {
            "ptz_detected": True,
            "last_probe_at": "2099-01-01T00:00:00+00:00",
            "probe_error": None,
        },
    )

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("camera.ptz", {"camera_id": "camera-1"})
    )

    assert result["success"] is False
    assert result["source_status"] == "conflict"


def test_camera_discovery_without_transport_metadata_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr("socket.if_nameindex", lambda: [(2, "eth0")])
    monkeypatch.setattr("app.services.ptz.discovery.discover", lambda **_kwargs: [])

    result = asyncio.run(
        ExtendedDiagnosticsAdapter().run("camera.discovery", {"interface": "eth0"})
    )

    assert result["success"] is False
    assert result["source_status"] == "unavailable"


def test_normal_gateway_explain_executes_selected_probe() -> None:
    calls = 0

    class Module:
        name = "dashboard_agent"

        def score(self, _request):
            return 100

        async def explain(self, _request):
            return AgentResponse(
                category="service",
                target="dependencies",
                matched=True,
                title="Dependencies",
                summary="Base response.",
                confidence="medium",
                module=self.name,
            )

    async def probe(_parameters):
        nonlocal calls
        calls += 1
        return {"success": False, "source_status": "partial", "message": "Redis is unavailable."}

    probes = AgentProbeRegistry()
    probes.register("health.dependencies", probe, allowed_keys=set())
    modules = AgentRegistry([Module()])
    gateway = AgentGateway(modules, AgentRouter(modules), probe_registry=probes)
    response = asyncio.run(gateway.explain(AgentRequest(question="Check database health")))

    assert calls == 1
    assert "probe:health.dependencies" in response.checks_run
    assert response.source_status == "partial"
    assert response.actions == []
