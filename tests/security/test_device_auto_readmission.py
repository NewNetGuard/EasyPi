from __future__ import annotations

import asyncio
import importlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services.netprotection_components.parental import ParentalMixin
from app.services.netprotection_components.detection_parts.fail_closed import (
    DetectionFailClosedMixin,
)
from app.services.netprotection_components.settings import SettingsMixin
from app.services.proactive_monitor import ProactiveMonitor
from app.services.unknown_device_admission_service import (
    UnknownDeviceAdmissionService,
)


MAC = "02:00:00:00:00:55"


def test_authenticated_mobile_tunnel_uses_existing_admission_inventory(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "settings.json").write_text(
        '{"unknown_devices":{"mode":"block"}}', encoding="utf-8"
    )
    registry = data_dir / "mobile-home-tunnel-peers.json"
    device_id = "6852f92f-9750-4567-bcfd-0e3374f8d0b0"
    registry.write_text(
        json.dumps(
            {
                "version": 1,
                "devices": [{"id": device_id, "address": "10.77.0.2"}],
            }
        ),
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(tmp_path / "missing-dhcp",),
        mobile_tunnel_registry_path=registry,
    )

    discovered = service.refresh()

    assert len(discovered) == 1
    assert discovered[0]["ip"] == "10.77.0.2"
    assert discovered[0]["sources"] == ["mobile_tunnel"]
    assert discovered[0]["vendor"] == "Authenticated mobile tunnel"
    assert discovered[0]["mac"] == service.mobile_tunnel_mac(device_id)
    assert discovered[0]["mac"].startswith("02:")
    assert service.refresh() == []
    assert service.list_devices()[0]["status"] == "pending"


def _write_dhcp_observation(
    path: Path, ip: str, *, include_traffic_binding: bool = True
) -> None:
    now = time.time()
    path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": ip,
                        "mac": MAC,
                        "hostname": "Phone",
                        "last_seen_timestamp": now,
                    }
                ],
                "address_bindings": (
                    {
                        ip: {
                            "mac": MAC,
                            "assigned_at_timestamp": now,
                            "last_seen_timestamp": now,
                        }
                    }
                    if include_traffic_binding
                    else {}
                ),
            }
        ),
        encoding="utf-8",
    )


def test_known_mac_is_queued_for_automatic_rebind_not_new_device(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "phone-id",
                        "name": "Phone",
                        "ip": "192.168.1.55",
                        "ids": ["192.168.1.55"],
                        "mac": MAC,
                        "shield_profile": "kids",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dhcp_path = tmp_path / "dhcp.json"
    _write_dhcp_observation(dhcp_path, "192.168.1.77")
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
    )

    discovered = service.refresh()
    assert len(discovered) == 1
    assert discovered[0]["managed_device"] is True
    assert discovered[0]["status"] == "reconnecting"
    assert service.list_devices() == []
    assert service.list_rebindings()[0]["ip"] == "192.168.1.77"

    device_id = discovered[0]["id"]
    service.mark_rebinding_failed(device_id)
    assert service.list_devices()[0]["auto_rebind_failed"] is True
    assert service.list_rebindings() == []

    # A later, genuinely new DHCP address is a fresh rebind opportunity.
    _write_dhcp_observation(dhcp_path, "192.168.1.78")
    service.refresh()
    rebound = service.list_rebindings()[0]
    assert rebound["ip"] == "192.168.1.78"
    assert "auto_rebind_failed" not in rebound


def test_dhcp_only_claim_cannot_auto_rebind_managed_mac(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "phone-id",
                        "name": "Phone",
                        "ip": "192.168.1.55",
                        "ids": ["192.168.1.55"],
                        "mac": MAC,
                        "shield_profile": "kids",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dhcp_path = tmp_path / "dhcp.json"
    _write_dhcp_observation(
        dhcp_path, "192.168.1.77", include_traffic_binding=False
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
    )

    assert service.refresh() == []
    assert service.list_rebindings() == []
    assert service.list_devices(include_blocked=True) == []


def test_latest_real_traffic_binding_wins_for_managed_mac(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "phone-id",
                        "name": "Phone",
                        "ip": "192.168.1.55",
                        "ids": ["192.168.1.55"],
                        "mac": MAC,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    now = time.time()
    dhcp_path = tmp_path / "dhcp.json"
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "192.168.1.88",
                        "mac": MAC,
                        "last_seen_timestamp": now,
                    }
                ],
                "address_bindings": {
                    # Lexically higher but older: file ordering must not decide.
                    "192.168.1.88": {
                        "mac": MAC,
                        "assigned_at_timestamp": now - 10,
                        "last_seen_timestamp": now - 5,
                    },
                    "192.168.1.77": {
                        "mac": MAC,
                        "assigned_at_timestamp": now - 2,
                        "last_seen_timestamp": now,
                    },
                },
            }
        ),
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
    )

    assert service.refresh()[0]["ip"] == "192.168.1.77"
    assert service.list_rebindings()[0]["ip"] == "192.168.1.77"


def test_recent_traffic_can_use_older_dhcp_hostname_for_display(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    now = time.time()
    dhcp_path = tmp_path / "dhcp.json"
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "192.168.1.77",
                        "mac": MAC,
                        "hostname": "POCO-M3",
                        "last_seen_timestamp": now - 3600,
                    }
                ],
                "address_bindings": {
                    "192.168.1.77": {
                        "mac": MAC,
                        "assigned_at_timestamp": now - 10,
                        "last_seen_timestamp": now,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
    )

    discovered = service.refresh()

    assert discovered[0]["hostname"] == "POCO-M3"
    assert discovered[0]["sources"] == ["traffic"]


def test_proactive_rebind_updates_only_observed_identity(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    admission_module = importlib.import_module(
        "app.services.unknown_device_admission_service"
    )
    netprotection_module = importlib.import_module(
        "app.services.netprotection_service"
    )

    class AdmissionHarness:
        allowed: list[str] = []

        def mark_allowed(self, device_id: str) -> None:
            self.allowed.append(device_id)

        def mark_rebinding_failed(self, _device_id: str) -> None:
            raise AssertionError("successful rebind must not be marked failed")

    class NetProtectionHarness:
        calls: list[tuple[dict, bool]] = []

        async def approve_client_transactional(
            self, payload: dict, *, require_existing: bool = False
        ) -> dict:
            self.calls.append((payload, require_existing))
            return {"success": True}

    admission = AdmissionHarness()
    netprotection = NetProtectionHarness()
    monkeypatch.setattr(
        admission_module, "unknown_device_admission_service", admission
    )
    monkeypatch.setattr(
        netprotection_module, "netprotection_service", netprotection
    )

    asyncio.run(
        ProactiveMonitor(tmp_path)._rebind_known_device(
            {
                "id": "unknown_known-phone",
                "ip": "192.168.1.77",
                "mac": MAC,
                "managed_name": "Phone",
                "managed_profile": "kids",
            }
        )
    )

    assert netprotection.calls == [
        (
            {
                "ip": "192.168.1.77",
                "ids": ["192.168.1.77"],
                "mac": MAC,
            },
            True,
        )
    ]
    assert admission.allowed == ["unknown_known-phone"]


class _ApprovalHarness(ParentalMixin):
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._client_policy_lock = asyncio.Lock()
        self.actions: list[str] = []

    @staticmethod
    def _first_client_ip(client: dict) -> str:
        return str(client.get("ip") or "")

    async def _run_vpn_blocking_action(
        self, action: str, *_args: object, **_kwargs: object
    ) -> dict:
        self.actions.append(action)
        return {"success": True}

    async def sync_unknown_device_admission_policy(self) -> bool:
        return True


def test_automatic_rebind_cannot_recreate_a_deleted_managed_device(
    tmp_path: Path,
) -> None:
    (tmp_path / "clients.json").write_text('{"clients":[]}', encoding="utf-8")
    harness = _ApprovalHarness(tmp_path)

    with pytest.raises(ValueError, match="no longer exists"):
        asyncio.run(
            harness.approve_client_transactional(
                {"ip": "192.168.1.77", "ids": ["192.168.1.77"], "mac": MAC},
                require_existing=True,
            )
        )

    assert json.loads((tmp_path / "clients.json").read_text(encoding="utf-8")) == {
        "clients": []
    }
    assert harness.actions == ["hold-admission"]


class _FailedApprovalHarness(_ApprovalHarness):
    async def _add_client_unlocked(self, _client_data: dict) -> dict:
        for name in ("clients.json", "devices.json", "profiles.json", "bindings.json"):
            path = self.data_dir / name
            path.write_text("cancelled-policy", encoding="utf-8")
            path.chmod(0o600)
        (self.data_dir / "bindings.bak").write_text(
            "cancelled-policy", encoding="utf-8"
        )
        return {
            "success": True,
            "sync": {"ok": False, "warnings": ["firewall failed"]},
            "ip_blocking": {"ok": True, "warnings": []},
        }

    async def _sync_blocklist(self) -> dict:
        return {"ok": True, "warnings": []}

    async def _sync_ip_blocking(self, _clients: list[dict]) -> dict:
        return {"ok": True, "warnings": []}


def test_failed_device_approval_restores_policy_metadata_and_backup(
    tmp_path: Path,
) -> None:
    original_files = {
        "clients.json": '{"clients": []}',
        "devices.json": "[]",
        "profiles.json": '{"profiles": []}',
        "bindings.json": '{"bindings": []}',
        "bindings.bak": '{"bindings": [{"id": "previous"}]}',
    }
    for name, content in original_files.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o640)

    harness = _FailedApprovalHarness(tmp_path)
    with pytest.raises(RuntimeError, match="firewall failed"):
        asyncio.run(
            harness.approve_client_transactional(
                {"name": "Phone", "ip": "192.168.1.77", "mac": MAC}
            )
        )

    for name, content in original_files.items():
        path = tmp_path / name
        assert path.read_text(encoding="utf-8") == content
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o640


def test_recent_admission_ip_is_not_replaced_by_old_neighbor_cache(
    tmp_path: Path,
) -> None:
    class NormalizationHarness(ParentalMixin):
        data_dir = tmp_path

        @staticmethod
        def _normalize_client_id(value: object) -> str:
            return str(value or "phone-id")

        @staticmethod
        def _first_client_ip(client: dict) -> str:
            return str(client.get("ip") or "")

        @staticmethod
        def _resolve_ipv4_from_mac(_mac: str) -> str:
            return "192.168.1.55"

        @staticmethod
        def _resolve_mac_from_arp(_ip: str) -> str:
            return ""

    clients = [
        {
            "id": "phone-id",
            "name": "Phone",
            "ip": "192.168.1.77",
            "ids": ["192.168.1.77"],
            "mac": MAC,
            "ip_observed_timestamp": time.time(),
        }
    ]
    warnings: list[str] = []
    devices = asyncio.run(
        NormalizationHarness()._normalize_parental_devices(
            clients,
            {"clients": clients},
            tmp_path / "clients.json",
            warnings,
        )
    )

    assert warnings == []
    assert devices[0]["ip"] == "192.168.1.77"
    assert clients[0]["ip"] == "192.168.1.77"


def test_stale_neighbor_is_not_used_as_current_device_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResolverHarness(DetectionFailClosedMixin):
        pass

    def fake_run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=f"192.168.1.55 dev eth0 lladdr {MAC} STALE\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ResolverHarness()._resolve_ipv4_from_mac(MAC) == ""


def test_active_neighbor_lookup_uses_valid_repeated_nud_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ResolverHarness(DetectionFailClosedMixin):
        pass

    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess:
        commands.append(command)
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout=f"192.168.1.77 dev eth0 lladdr {MAC} REACHABLE\n",
            stderr="",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert ResolverHarness()._resolve_ipv4_from_mac(MAC) == "192.168.1.77"
    assert commands == [
        [
            "ip",
            "-4",
            "neigh",
            "show",
            "nud",
            "reachable",
            "nud",
            "delay",
            "nud",
            "probe",
        ]
    ]


def test_invalid_unknown_device_mode_fails_closed(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "settings.json").write_text(
        '{"unknown_devices":{"mode":"corrupt"}}', encoding="utf-8"
    )
    service = UnknownDeviceAdmissionService(data_dir)
    assert service.is_block_mode() is True

    (data_dir / "settings.json").write_text(
        '{"unknown_devices":{"mode":"default"}}', encoding="utf-8"
    )
    assert service.is_block_mode() is False


def test_explicit_block_survives_return_to_old_managed_pair(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    old_ip = "192.168.1.55"
    new_ip = "192.168.1.77"
    (data_dir / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "id": "phone-id",
                        "name": "Phone",
                        "ip": old_ip,
                        "ids": [old_ip],
                        "mac": MAC,
                        "shield_profile": "kids",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    dhcp_path = tmp_path / "dhcp.json"
    _write_dhcp_observation(dhcp_path, new_ip)
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
    )

    discovered = service.refresh()[0]
    service.block(discovered["id"])
    _write_dhcp_observation(dhcp_path, old_ip)
    service.refresh()

    blocked = service.list_devices(include_blocked=True)
    assert len(blocked) == 1
    assert blocked[0]["status"] == "blocked"
    assert blocked[0]["ip"] == old_ip


class _SettingsHarness(SettingsMixin):
    def __init__(self) -> None:
        self.actions: list[tuple[str, str | None, str | None]] = []

    async def _run_vpn_blocking_action(
        self,
        action: str,
        client_ip: str | None = None,
        client_mac: str | None = None,
        **_kwargs: object,
    ) -> dict:
        self.actions.append((action, client_ip, client_mac))
        return {"success": True}


def test_administrator_block_is_published_by_privileged_firewall_runner() -> None:
    harness = _SettingsHarness()
    assert asyncio.run(
        harness.block_unknown_device_admission("192.168.1.77", MAC)
    ) is True
    assert harness.actions == [("block-admission", "192.168.1.77", MAC)]


class _SuccessfulApprovalHarness(_ApprovalHarness):
    async def _add_client_unlocked(self, _client_data: dict) -> dict:
        return {"success": True, "sync": {"ok": True, "warnings": []}}


def test_allow_removes_persistent_mac_block_before_transaction_hold(
    tmp_path: Path,
) -> None:
    harness = _SuccessfulApprovalHarness(tmp_path)
    result = asyncio.run(
        harness.approve_client_transactional(
            {"name": "Phone", "ip": "192.168.1.77", "mac": MAC},
            release_persistent_block=True,
        )
    )
    assert result["success"] is True
    assert harness.actions == [
        "hold-admission",
        "unblock-admission",
        "release-admission",
    ]


def test_persistent_admission_block_has_root_owned_atomic_firewall_path() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(
        encoding="utf-8"
    )
    assert 'ADMISSION_BLOCK_FILE="$STATE_DIR/admission_blocked_macs.json"' in script
    assert 'ADMISSION_BLOCK_CHAIN="EASYPI_ADMISSION_BLOCK"' in script
    assert "migrate_legacy_admission_blocks" in script
    assert "block-admission)" in script
    assert "unblock-admission)" in script
    assert '-m mac --mac-source "$blocked_mac"' in script
    assert 'print("default" if raw_mode == "default" else "block")' in script
    sync_body = script[script.index("sync_from_devices() {") :]
    assert sync_body.index("sync_admission_blocks") < sync_body.index(
        "sync_admission_holds"
    )


def test_device_sync_reconciles_owned_dns_redirect_rules() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(
        encoding="utf-8"
    )
    remove_body = script[
        script.index("remove_dns_redirect() {") : script.index(
            "reconcile_dns_redirects() {"
        )
    ]
    assert '[[ "$valid_ip" == "true" || "$valid_mac" == "true" ]]' in remove_body
    sync_body = script[script.index("sync_from_devices() {") :]
    assert sync_body.index("reconcile_dns_redirects") < sync_body.index(
        'setup_vpn_blocking "$block_ip"'
    )


def test_dhcp_observer_sandbox_allows_read_only_iproute_discovery() -> None:
    unit = Path("templates/systemd/easypi-dhcp-observer.service").read_text(
        encoding="utf-8"
    )
    assert "CapabilityBoundingSet=CAP_NET_RAW" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "IPAddressDeny=any" in unit
    assert "RestrictAddressFamilies=AF_PACKET AF_UNIX AF_NETLINK" in unit
    assert "SystemCallFilter=~@mount @resources" in unit
    assert "SystemCallFilter=~@mount @privileged @resources" not in unit


def test_block_api_activates_firewall_before_persisting_ui_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices_module = importlib.import_module(
        "app.api.endpoints.netprotection_api.devices"
    )
    order: list[str] = []
    device_id = "unknown_" + "a" * 20

    class AdmissionHarness:
        @staticmethod
        def get_device(_device_id: str) -> dict:
            order.append("read")
            return {"id": device_id, "ip": "192.168.1.77", "mac": MAC}

        @staticmethod
        def block(_device_id: str) -> dict:
            order.append("persist")
            return {
                "id": device_id,
                "ip": "192.168.1.77",
                "mac": MAC,
                "status": "blocked",
            }

    class NetProtectionHarness:
        @staticmethod
        async def block_unknown_device_admission(_ip: str, _mac: str) -> bool:
            order.append("firewall")
            return True

    monkeypatch.setattr(
        devices_module, "unknown_device_admission_service", AdmissionHarness()
    )
    monkeypatch.setattr(
        devices_module, "netprotection_service", NetProtectionHarness()
    )
    monkeypatch.setattr(devices_module, "_record_netprotection_event", lambda **_kw: None)

    result = asyncio.run(devices_module.block_unknown_device(device_id, object()))
    assert result["success"] is True
    assert order == ["read", "firewall", "persist"]


def test_block_api_does_not_persist_when_firewall_activation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices_module = importlib.import_module(
        "app.api.endpoints.netprotection_api.devices"
    )
    device_id = "unknown_" + "b" * 20
    persisted = False

    class AdmissionHarness:
        @staticmethod
        def get_device(_device_id: str) -> dict:
            return {"id": device_id, "ip": "192.168.1.77", "mac": MAC}

        @staticmethod
        def block(_device_id: str) -> dict:
            nonlocal persisted
            persisted = True
            return {}

    class NetProtectionHarness:
        @staticmethod
        async def block_unknown_device_admission(_ip: str, _mac: str) -> bool:
            return False

    monkeypatch.setattr(
        devices_module, "unknown_device_admission_service", AdmissionHarness()
    )
    monkeypatch.setattr(
        devices_module, "netprotection_service", NetProtectionHarness()
    )
    monkeypatch.setattr(devices_module, "_record_netprotection_event", lambda **_kw: None)

    with pytest.raises(HTTPException) as caught:
        asyncio.run(devices_module.block_unknown_device(device_id, object()))
    assert caught.value.status_code == 503
    assert persisted is False


def test_firewall_refresh_is_atomic_and_serialization_fails_closed() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(
        encoding="utf-8"
    )
    smartdns_body = script[
        script.index("update_smartdns_ipset() {") : script.index(
            "ensure_smartdns_ipset() {"
        )
    ]
    assert 'ipset destroy "$SMARTDNS_IPSET"' not in smartdns_body
    assert 'ipset swap "$SMARTDNS_STAGING_IPSET" "$SMARTDNS_IPSET"' in smartdns_body
    assert 'flock -w 30 9 2>/dev/null || true' not in script
    assert 'exit 75' in script
