from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from pydantic import ValidationError

from app.api.deps import require_admin
from app.api.remote_access.tailscale_relay import (
    RelayCredentials,
    RelayDeployRequest,
    router,
)
from app.services.remote_access.tailscale_relay_service import (
    RelayBusyError,
    RelayOperationError,
    TailscaleRelayService,
)


def _service(tmp_path: Path) -> TailscaleRelayService:
    script = tmp_path / "relay.sh"
    script.write_text("#!/bin/bash\n", encoding="utf-8")
    return TailscaleRelayService(
        state_path=tmp_path / "state" / "relay.json",
        script_path=script,
    )


def test_all_peer_relay_routes_require_an_administrator() -> None:
    routes = [route for route in router.routes if isinstance(route, APIRoute)]
    assert routes
    for route in routes:
        assert any(dependency.call is require_admin for dependency in route.dependant.dependencies), route.path


@pytest.mark.parametrize(
    "payload",
    [
        {"host": "192.168.1.20", "ssh_password": "secret"},
        {"host": "8.8.8.8", "ssh_user": "root;id", "ssh_password": "secret"},
        {"host": "8.8.8.8", "ssh_password": "secret", "relay_port": 22},
        {"host": "8.8.8.8", "ssh_password": "secret", "public_endpoint": "127.0.0.1:40000"},
        {"host": "8.8.8.8", "ssh_password": "secret", "relay_name": "relay;id"},
        {"host": "8.8.8.8", "ssh_password": "secret", "auth_key": "tskey-api-" + "a" * 32},
    ],
)
def test_deploy_request_rejects_unsafe_remote_values(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        RelayDeployRequest.model_validate(payload)


def test_credentials_require_exactly_one_authentication_method() -> None:
    with pytest.raises(ValidationError):
        RelayCredentials.model_validate(
            {
                "host": "8.8.8.8",
                "auth_method": "password",
                "ssh_password": "secret",
                "ssh_key": "also-secret",
            }
        )


def test_saved_credentials_may_be_reused_without_resubmitting_a_secret() -> None:
    request = RelayCredentials.model_validate(
        {
            "host": "8.8.8.8",
            "auth_method": "password",
        }
    )
    assert request.ssh_password is None
    assert request.ssh_key is None


def test_udp_443_is_supported_but_other_privileged_relay_ports_are_rejected() -> None:
    request = RelayDeployRequest.model_validate(
        {
            "host": "8.8.8.8",
            "ssh_password": "secret",
            "relay_port": 443,
        }
    )
    assert request.relay_port == 443
    assert request.public_endpoint == "8.8.8.8:443"

    with pytest.raises(ValidationError):
        RelayDeployRequest.model_validate(
            {
                "host": "8.8.8.8",
                "ssh_password": "secret",
                "relay_port": 80,
            }
        )


def test_connection_check_saves_only_encrypted_credential_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)

    class FakeClient:
        def close(self) -> None:
            pass

    deleted: list[str] = []
    monkeypatch.setattr(service, "_connect", lambda **_credentials: FakeClient())
    monkeypatch.setattr(service, "_privilege_prefix", lambda _client: "")
    monkeypatch.setattr(
        service,
        "_read_command",
        lambda _client, _command, timeout: ("debian 12", "", 0),
    )
    monkeypatch.setattr(service, "_secret_store", lambda name, value: "host")
    monkeypatch.setattr(service, "_secret_delete", deleted.append)

    result = service.check_connection(
        host="8.8.8.8",
        port=22,
        user="root",
        password="ssh-secret",
        private_key=None,
    )

    assert result["credential_configured"] is True
    assert result["credential_type"] == "password"
    assert result["credential_protection"] == "system encryption"
    assert deleted == ["ssh-private-key"]
    saved = service.load_state()
    assert saved["credential_configured"] is True
    assert saved["credential_type"] == "password"
    assert "ssh-secret" not in service.state_path.read_text(encoding="utf-8")


def test_saved_credential_is_bound_to_the_original_vps_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    service._save_state(
        {
            "host": "8.8.8.8",
            "ssh_port": 22,
            "ssh_user": "root",
            "credential_configured": True,
            "credential_type": "password",
        }
    )
    monkeypatch.setattr(service, "_secret_read", lambda name: "stored-secret")

    assert service._stored_credentials(
        host="8.8.8.8", port=22, user="root"
    ) == ("stored-secret", None)
    with pytest.raises(RelayOperationError, match="Enter the VPS SSH credential once"):
        service._stored_credentials(host="8.8.4.4", port=22, user="root")


def test_relay_state_never_persists_credentials(tmp_path: Path) -> None:
    service = _service(tmp_path)
    service._save_state(
        {
            "configured": True,
            "host": "8.8.8.8",
            "ssh_password": "ssh-secret",
            "ssh_key": "key-secret",
            "auth_key": "tskey-auth-secret",
        }
    )

    raw = service.state_path.read_text(encoding="utf-8")
    assert "ssh-secret" not in raw
    assert "key-secret" not in raw
    assert "tskey-auth-secret" not in raw
    if os.name != "nt":
        assert service.state_path.stat().st_mode & 0o077 == 0


def test_policy_grant_uses_a_dedicated_non_user_relay_identity() -> None:
    grant = TailscaleRelayService._policy_grant()
    parsed = json.loads(grant)
    assert parsed == {
        "tagOwners": {"tag:easypi-relay": ["autogroup:admin"]},
        "grants": [
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:self"],
                "ip": ["*"],
            },
            {
                "src": ["autogroup:member"],
                "dst": ["autogroup:internet"],
                "ip": ["*"],
            },
            {
                "src": ["autogroup:member"],
                "dst": ["tag:easypi-relay"],
                "app": {"tailscale.com/cap/relay": []},
            }
        ],
    }
    assert all(rule["src"] != ["*"] and rule["dst"] != ["*"] for rule in parsed["grants"])


def test_remote_result_parser_rejects_unstructured_output() -> None:
    with pytest.raises(RelayOperationError, match="valid relay status"):
        TailscaleRelayService._parse_result("installation complete")


def test_remote_result_parser_reads_expected_fields() -> None:
    result = TailscaleRelayService._parse_result(
        "EASYPI_RELAY_RESULT installed=true daemon=true enabled=true listening=true "
        "managed=false firewall=true isolated=true relay_tagged=true shields_up=true "
        "version=1.90.2 tailscale_ip=100.64.12.34 "
        "relay_name=easypi-fast-relay relay_port=40000 public_endpoint=8.8.8.8:40000\n"
    )
    assert result["enabled"] is True
    assert result["listening"] is True
    assert result["managed_install"] is False
    assert result["tailscale_ip"] == "100.64.12.34"
    assert result["isolation_active"] is True
    assert result["relay_tagged"] is True
    assert result["shields_up"] is True


def test_failed_deploy_attempts_remote_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = _service(tmp_path)
    actions: list[str] = []

    def run_remote(*, action: str, **_request):
        actions.append(action)
        if action == "deploy":
            raise RelayOperationError("deploy failed")
        return {"enabled": False}

    monkeypatch.setattr(service, "_run_remote", run_remote)
    with pytest.raises(RelayOperationError, match="deploy failed"):
        asyncio.run(
            service.operate(
                "deploy",
                host="8.8.8.8",
                port=22,
                user="root",
                password="secret",
                private_key=None,
            )
        )
    assert actions == ["deploy", "uninstall"]


def test_concurrent_operation_fails_fast(tmp_path: Path) -> None:
    service = _service(tmp_path)

    async def scenario() -> None:
        await service._operation_lock.acquire()
        try:
            with pytest.raises(RelayBusyError):
                await service.operate(
                    "status",
                    host="8.8.8.8",
                    port=22,
                    user="root",
                    password="secret",
                    private_key=None,
                )
        finally:
            service._operation_lock.release()

    asyncio.run(scenario())


def test_remote_script_keeps_auth_key_out_of_process_arguments() -> None:
    script = (
        Path(__file__).resolve().parents[2]
        / "scripts"
        / "services"
        / "tailscale_peer_relay.sh"
    ).read_text(encoding="utf-8")
    assert '--authkey="file:${auth_key_file}"' in script
    assert '--auth-key="$AUTH_KEY"' not in script
    assert "Tailscale 1.86 or newer is required" in script
    assert 'tailscale set --relay-server-port=""' in script
    assert 'if [[ "$INSTALLED_BY_EASYPI" == "true" ]]' in script
    assert '"$SAVED_RELAY_PORT" != "$RELAY_PORT"' in script
    assert "RELAY_PORT == 443" in script
    assert "Relay UDP port must be 443 or between 1024 and 65535" in script
    assert 'fail "Relay UDP port must be between 1024 and 65535"' not in script
    assert "ss -H -lun 2>/dev/null | awk '{print $4}'" in script
    assert "ss -H -lun 2>/dev/null | awk '{print $5}'" not in script
    assert "wait_for_tailscaled" in script
    assert 'RELAY_TAG="tag:easypi-relay"' in script
    assert '--advertise-tags="$RELAY_TAG"' in script
    assert "tailscale set --shields-up=true --accept-routes=false --accept-dns=false --ssh=false" in script
    assert 'fail "The existing VPS node is not isolated.' in script
    deploy_block = script.split("    deploy)", 1)[1].split("        ;;", 1)[0]
    assert deploy_block.index("install_tailscale") < deploy_block.index("save_state")
    assert deploy_block.index("save_state") < deploy_block.index("wait_for_tailscaled")
    assert deploy_block.index("wait_for_tailscaled") < deploy_block.index("ensure_relay_identity")
    restart_block = script.split("    restart)", 1)[1].split("        ;;", 1)[0]
    assert restart_block.index("systemctl restart tailscaled") < restart_block.index(
        "wait_for_tailscaled"
    )
    assert restart_block.index("wait_for_tailscaled") < restart_block.index(
        "ensure_relay_identity"
    )


def test_exit_node_performance_optimization_is_persistent_and_privileged() -> None:
    root = Path(__file__).resolve().parents[2]
    script = (root / "scripts" / "settings" / "tailscale_performance.sh").read_text(
        encoding="utf-8"
    )
    unit = (root / "templates" / "systemd" / "easypi-tailscale-performance.service").read_text(
        encoding="utf-8"
    )
    runner = (root / "scripts" / "runner").read_text(encoding="utf-8")
    installer = (root / "install.sh").read_text(encoding="utf-8")

    assert "rx-udp-gro-forwarding on rx-gro-list off" in script
    assert 'ACTION" == "restore"' in script
    assert "refusing untrusted Tailscale performance state" in script
    assert '"AdvertiseExitNode"' in script
    assert "settings/tailscale_performance.sh" in runner
    assert "tailscale_performance.sh auto" in unit
    assert "easypi-tailscale-performance.service" in installer
    assert "ethtool" in installer


def test_relay_credential_broker_keeps_secrets_out_of_process_arguments() -> None:
    root = Path(__file__).resolve().parents[2]
    broker = (root / "scripts" / "settings" / "tailscale_relay_secrets.sh").read_text(
        encoding="utf-8"
    )
    runner = (root / "scripts" / "runner").read_text(encoding="utf-8")

    assert 'head -c 65537 > "$plain_file"' in broker
    assert 'systemd-creds encrypt --with-key=host' in broker
    assert 'systemd-creds decrypt --name="$credential_id"' in broker
    assert "tailscale_relay_secrets.sh <store|read|delete|mode>" in broker
    assert '["settings/tailscale_relay_secrets.sh"]=1' in runner

