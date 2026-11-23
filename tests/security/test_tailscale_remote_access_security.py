from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.api.remote_access.tailscale_admin import ApproveRoutesRequest, SetCredentialsRequest
from app.api.remote_access.tailscale_api import StatusResponse
from app.api.remote_access.tailscale_api import SaveAuthkeyRequest
from app.services.remote_access.tailscale_admin_api import DeviceInfo, TailscaleAdminAPI
from app.services.remote_access.tailscale_config import TailscaleConfig
from app.services.remote_access.tailscale_service import TailscaleRemoteAccessService
from pydantic import ValidationError
from scripts.utils import tailscale_control


def _device(
    identifier: str,
    ip: str,
    *,
    advertised: list[str],
    enabled: list[str] | None = None,
) -> DeviceInfo:
    return DeviceInfo(
        id=identifier,
        name=identifier,
        hostname=identifier,
        user="owner@example.test",
        tailscale_ips=[ip],
        advertised_routes=advertised,
        enabled_routes=enabled or [],
        is_exit_node=False,
        is_exit_node_enabled=False,
    )


def test_auto_approve_only_targets_the_local_easypi_node(monkeypatch: pytest.MonkeyPatch) -> None:
    api = TailscaleAdminAPI()
    local = _device("node-local", "100.64.0.10", advertised=["192.168.1.0/24"])
    untrusted = _device("node-other", "100.64.0.11", advertised=["0.0.0.0/0"])
    approved: list[tuple[str, list[str]]] = []

    async def list_devices() -> list[DeviceInfo]:
        return [untrusted, local]

    async def approve_routes(device_id: str, routes: list[str]) -> dict[str, bool]:
        approved.append((device_id, routes))
        return {"ok": True}

    monkeypatch.setattr(api, "list_devices", list_devices)
    monkeypatch.setattr(api, "approve_routes", approve_routes)

    result = asyncio.run(api.auto_approve_easypi_routes(["100.64.0.10"]))

    assert approved == [("node-local", ["192.168.1.0/24"])]
    assert result["approved"] == [
        {"device": "node-local", "routes_approved": ["192.168.1.0/24"]}
    ]


def test_auto_approve_fails_closed_without_one_exact_local_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = TailscaleAdminAPI()

    async def list_devices() -> list[DeviceInfo]:
        return [_device("other", "100.64.0.11", advertised=["0.0.0.0/0"])]

    monkeypatch.setattr(api, "list_devices", list_devices)

    with pytest.raises(RuntimeError, match="uniquely match"):
        asyncio.run(api.auto_approve_easypi_routes(["100.64.0.10"]))


def test_route_approval_rejects_unadvertised_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    api = TailscaleAdminAPI()

    async def get_device(_device_id: str) -> DeviceInfo:
        return _device("local", "100.64.0.10", advertised=["192.168.1.0/24"])

    monkeypatch.setattr(api, "get_device", get_device)

    with pytest.raises(ValueError, match="not advertising"):
        asyncio.run(api.approve_routes("local", ["0.0.0.0/0"]))


def test_route_approval_preserves_existing_enabled_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    api = TailscaleAdminAPI()
    posted: dict[str, object] = {}

    async def get_device(_device_id: str) -> DeviceInfo:
        return _device(
            "local",
            "100.64.0.10",
            advertised=["192.168.1.0/24", "10.0.0.0/24"],
            enabled=["192.168.1.0/24"],
        )

    class Response:
        def raise_for_status(self) -> None:
            pass

        def json(self) -> dict[str, bool]:
            return {"ok": True}

    class Client:
        async def post(self, url: str, **kwargs):
            posted.update(url=url, **kwargs)
            return Response()

    async def get_client() -> Client:
        return Client()

    monkeypatch.setattr(api, "get_device", get_device)
    monkeypatch.setattr(api, "_get_client", get_client)
    api.config.api_key = "secret"

    asyncio.run(api.approve_routes("local", ["10.0.0.0/24"]))

    assert posted["json"] == {"routes": ["10.0.0.0/24", "192.168.1.0/24"]}


@pytest.mark.parametrize(
    "model,payload",
    [
        (SaveAuthkeyRequest, {"authkey": "tskey-too-short"}),
        (SaveAuthkeyRequest, {"authkey": "tskey-" + "a" * 16 + "!"}),
        (SaveAuthkeyRequest, {"authkey": "tskey-api-" + "a" * 24}),
        (SetCredentialsRequest, {"api_key": "tskey-api-too-short", "tailnet": "example.ts.net"}),
        (ApproveRoutesRequest, {"routes": ["192.168.1.7/24"]}),
        (ApproveRoutesRequest, {"routes": ["192.168.1.0/24", "192.168.1.0/24"]}),
    ],
)
def test_tailscale_requests_reject_values_the_root_or_remote_api_cannot_use(
    model,
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_tailscale_auth_key_is_removed_from_argv_and_deleted_after_use(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "tskey-auth-" + "a" * 32
    key_path = tmp_path / "auth-key"

    def mkstemp(*, prefix: str, dir: str):
        assert prefix == "easypi-tailscale-auth."
        assert dir == "/run"
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        return descriptor, str(key_path)

    def run(command: list[str], **_kwargs):
        assert all(secret not in argument for argument in command)
        auth_argument = next(argument for argument in command if argument.startswith("--authkey="))
        assert auth_argument == f"--authkey=file:{key_path}"
        assert key_path.read_text(encoding="utf-8") == secret
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(tailscale_control, "read_request", lambda: {
        "action": "up",
        "auth_key": secret,
    })
    monkeypatch.setattr(tailscale_control, "tailscale_binary", lambda: "/usr/bin/tailscale")
    monkeypatch.setattr(tailscale_control.tempfile, "mkstemp", mkstemp)
    monkeypatch.setattr(tailscale_control.os, "fchmod", lambda _fd, _mode: None, raising=False)
    monkeypatch.setattr(tailscale_control.subprocess, "run", run)

    with pytest.raises(SystemExit) as exc_info:
        tailscale_control.main()

    assert exc_info.value.code == 0
    assert not key_path.exists()


def _service(tmp_path, monkeypatch: pytest.MonkeyPatch) -> TailscaleRemoteAccessService:
    monkeypatch.setenv("EASYPI_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("EASYPI_BACKEND_DATA_DIR", str(tmp_path / "legacy"))
    return TailscaleRemoteAccessService(TailscaleConfig(authkey="", interface="eth0"))


def test_enable_does_not_report_success_when_required_routes_fail(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_get_tailscale_status_json", lambda: {"BackendState": "Running"})
    monkeypatch.setattr(service, "_detect_lan_cidr", lambda: "192.168.1.0/24")
    monkeypatch.setattr(service, "_enable_ip_forwarding", lambda: (True, "ok"))
    monkeypatch.setattr(service, "_run_tailscale_control", lambda _request: (False, "", "denied"))
    monkeypatch.setattr(service, "get_status", lambda: SimpleNamespace(to_dict=lambda: {}))

    result = service.enable_remote_access()

    assert result["success"] is False
    assert result["error"]["code"] == "TAILSCALE_SETTINGS_ERROR"
    assert service._load_state()["enabled"] is False


def test_enable_applies_exit_node_forwarding_optimization(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    commands: list[list[str]] = []
    monkeypatch.setattr(
        service,
        "_get_tailscale_status_json",
        lambda: {"BackendState": "Running"},
    )
    monkeypatch.setattr(service, "_detect_lan_cidr", lambda: "192.168.1.0/24")
    monkeypatch.setattr(service, "_enable_ip_forwarding", lambda: (True, "ok"))
    monkeypatch.setattr(service, "_run_tailscale_control", lambda _request: (True, "", ""))
    monkeypatch.setattr(service, "_setup_nat_rules", lambda _cidr: (True, "ok"))
    monkeypatch.setattr(
        service,
        "_run_command",
        lambda command, check=False: (commands.append(command) is None, "", ""),
    )
    monkeypatch.setattr(service, "get_status", lambda: SimpleNamespace(to_dict=lambda: {}))

    result = service.enable_remote_access()

    assert result["success"] is True
    assert any(command[-2:] == ["settings/tailscale_performance.sh", "apply"] for command in commands)


def test_disable_fails_if_tailscale_stays_reachable(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service(tmp_path, monkeypatch)
    service._save_state({"enabled": True, "last_error": None})
    monkeypatch.setattr(service, "_get_tailscale_status_json", lambda: {"BackendState": "Running"})

    def control(request: dict[str, object]):
        if request["action"] == "down":
            return False, "", "down failed"
        return True, "", ""

    monkeypatch.setattr(service, "_run_tailscale_control", control)
    monkeypatch.setattr(service, "get_status", lambda: SimpleNamespace(to_dict=lambda: {}))

    result = service.disable_remote_access()

    assert result["success"] is False
    assert result["error"]["code"] == "TAILSCALE_STILL_RUNNING"
    assert service._load_state()["enabled"] is True


def test_tailscale_installer_verifies_daemon_and_logs_out_before_stopping() -> None:
    script = (Path(__file__).resolve().parents[2] / "scripts/services/tailscale.sh").read_text(
        encoding="utf-8"
    )

    assert "systemctl enable --now tailscaled" in script
    assert "systemctl is-active --quiet tailscaled" in script
    logout_position = script.index('tailscale logout >> "$LOGFILE"')
    stop_position = script.index('systemctl stop tailscaled >> "$LOGFILE"')
    assert logout_position < stop_position


@pytest.mark.parametrize(
    "tags,eligible",
    [([], True), (["tag:easypi"], False)],
)
def test_taildrop_status_rejects_tagged_easypi_nodes(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    tags: list[str],
    eligible: bool,
) -> None:
    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(
        service,
        "_get_tailscale_status_json",
        lambda: {
            "BackendState": "Running",
            "Self": {
                "UserID": 42,
                "Tags": tags,
                "TailscaleIPs": ["100.64.0.10"],
                "AllowedIPs": [],
            },
        },
    )
    monkeypatch.setattr(service, "_get_tailscale_prefs", lambda: {})
    monkeypatch.setattr(service, "_detect_lan_cidr", lambda: "192.168.1.0/24")
    monkeypatch.setattr(
        service,
        "_run_command",
        lambda command, check=False: (
            command[-1] == "easypi-taildrop-import.service",
            "",
            "",
        ),
    )

    status = service.get_status()

    assert status.taildrop_importer_active is True
    assert status.taildrop_device_eligible is eligible


def test_taildrop_receiver_is_inactive_when_tailscale_is_not_running(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path, monkeypatch)
    monkeypatch.setattr(service, "_get_tailscale_status_json", lambda: None)
    monkeypatch.setattr(service, "_detect_lan_cidr", lambda: "192.168.1.0/24")
    monkeypatch.setattr(
        service,
        "_run_command",
        lambda command, check=False: (
            command[-1] == "easypi-taildrop-import.service",
            "",
            "",
        ),
    )

    status = service.get_status()

    assert status.tailscale_running is False
    assert status.taildrop_importer_active is False


def test_taildrop_status_fields_survive_api_serialization() -> None:
    response = StatusResponse(
        enabled=True,
        tailscale_running=True,
        lan_cidr="192.168.1.0/24",
        tailscale_ips=["100.64.0.10"],
        advertised_routes=[],
        exit_node_advertised=False,
        hostname="easypi",
        tailnet="example.ts.net",
        backend_state="Running",
        last_error=None,
        last_enabled_at=None,
        taildrop_importer_active=True,
        taildrop_device_eligible=True,
        taildrop_error="Not enough disk space",
        taildrop_free_bytes=1024,
        taildrop_reserve_bytes=2048,
    )

    payload = response.model_dump()

    assert payload["taildrop_importer_active"] is True
    assert payload["taildrop_device_eligible"] is True
    assert payload["taildrop_error"] == "Not enough disk space"
    assert payload["taildrop_free_bytes"] == 1024
    assert payload["taildrop_reserve_bytes"] == 2048


def test_taildrop_capacity_error_is_loaded_from_protected_status_file(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_file = tmp_path / "taildrop-status.json"
    status_file.write_text(
        json.dumps(
            {
                "version": 1,
                "error": "Not enough disk space",
                "free_bytes": 1024,
                "reserve_bytes": 2048,
                "deferred_files": 1,
            }
        ),
        encoding="utf-8",
    )
    status_file.chmod(0o640)
    monkeypatch.setenv("EASYPI_TAILDROP_STATUS_FILE", str(status_file))
    service = _service(tmp_path, monkeypatch)

    payload = service._load_taildrop_status()

    assert payload["error"] == "Not enough disk space"
    assert payload["free_bytes"] == 1024
    assert payload["reserve_bytes"] == 2048
