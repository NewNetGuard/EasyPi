from __future__ import annotations

import asyncio
import hashlib
import importlib
import json
import sqlite3
import time
from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.dhcp_identity import DHCPAddressBinding, DHCPIdentity
from app.services.netprotection_components.parental import ParentalMixin
from app.services.prism_identity_service import PrismIdentityError, PrismIdentityService
from app.services.unknown_device_admission_service import (
    UnknownDeviceAdmissionService,
    UnknownDeviceNotFound,
)


OLD_MAC = "02:00:00:00:00:10"
NEW_MAC = "02:00:00:00:00:20"
OLD_IP = "192.168.1.10"
NEW_IP = "192.168.1.20"


def _identity(ip: str, mac: str, *, client_id: str | None = None) -> DHCPIdentity:
    now = time.time()
    return DHCPIdentity(
        ip=ip,
        mac=mac,
        hostname="POCO-M3",
        vendor_class="android-dhcp-15",
        last_seen_timestamp=now,
        ip_first_seen_timestamp=now - 30,
        lease_expires_timestamp=now + 3600,
        client_id=client_id,
        parameter_request_list=(1, 3, 6, 15, 26, 28, 51, 58, 59),
        dhcp_fingerprint="7f627cde27b85b37",
        ownership_verified=True,
        ownership_last_seen_timestamp=now,
    )


def _binding(ip: str, mac: str, assigned: float, seen: float) -> DHCPAddressBinding:
    return DHCPAddressBinding(
        ip=ip,
        mac=mac,
        assigned_at_timestamp=assigned,
        last_seen_timestamp=seen,
    )


def _client() -> dict:
    return {
        "id": "dev_phone",
        "name": "My Phone",
        "ip": OLD_IP,
        "ids": [OLD_IP],
        "mac": OLD_MAC,
        "shield_profile": "kids",
        "blocked_services": ["youtube"],
    }


def _write_prism(path: Path, old_start: float, new_start: float) -> None:
    records = []
    for ip, start in ((OLD_IP, old_start), (NEW_IP, new_start)):
        for index in range(15):
            records.append(
                {
                    "event": "flow_assessment",
                    "timestamp": start + index + 1,
                    "client_ip": ip,
                    "server_name": f"service-{index % 6}.private.example.test",
                    "features": {"tls_fingerprint": "a" * 16},
                }
            )
    path.write_text("\n".join(json.dumps(item) for item in records) + "\n")


def test_mac_derived_dhcp_client_id_is_not_independent_identity(tmp_path: Path) -> None:
    service = PrismIdentityService(tmp_path, prism_path=tmp_path / "missing")
    identity = _identity(OLD_IP, OLD_MAC, client_id="01" + OLD_MAC.replace(":", ""))

    assert service._dhcp_features(identity, OLD_MAC)["stable_client_id"] is None
    assert not (tmp_path / "prism_identity.key").exists()


def test_platform_and_transition_alone_do_not_suggest_replacement(tmp_path: Path) -> None:
    now = time.time()
    service = PrismIdentityService(tmp_path, prism_path=tmp_path / "missing")
    clients = [_client()]
    old_binding = _binding(OLD_IP, OLD_MAC, now - 120, now - 10)
    new_binding = _binding(NEW_IP, NEW_MAC, now - 5, now)
    service.refresh_profiles(clients, [_identity(OLD_IP, OLD_MAC)], [old_binding])

    result = service.assess(
        {"ip": NEW_IP, "mac": NEW_MAC},
        clients,
        [_identity(NEW_IP, NEW_MAC)],
        [old_binding, new_binding],
    )

    assert result is None


def test_three_passive_groups_can_only_suggest_review(tmp_path: Path) -> None:
    now = time.time()
    prism_path = tmp_path / "flowgraph.jsonl"
    _write_prism(prism_path, now - 100, now - 5)
    service = PrismIdentityService(tmp_path, prism_path=prism_path)
    clients = [_client()]
    old_binding = _binding(OLD_IP, OLD_MAC, now - 120, now - 10)
    new_binding = _binding(NEW_IP, NEW_MAC, now - 5, now)
    service.refresh_profiles(clients, [_identity(OLD_IP, OLD_MAC)], [old_binding])

    result = service.assess(
        {"ip": NEW_IP, "mac": NEW_MAC},
        clients,
        [_identity(NEW_IP, NEW_MAC)],
        [old_binding, new_binding],
    )

    assert result is not None
    assert result["confidence"] == 90
    assert result["identity_state"] == "possible_mac_change"
    assert result["automatic"] is False
    state_text = (tmp_path / "prism_identity.json").read_text()
    assert "private.example.test" not in state_text


def test_simultaneously_active_old_mac_is_a_hard_conflict(tmp_path: Path) -> None:
    now = time.time()
    prism_path = tmp_path / "flowgraph.jsonl"
    _write_prism(prism_path, now - 100, now - 30)
    service = PrismIdentityService(tmp_path, prism_path=prism_path)
    clients = [_client()]
    old_binding = _binding(OLD_IP, OLD_MAC, now - 120, now)
    new_binding = _binding(NEW_IP, NEW_MAC, now - 30, now)
    service.refresh_profiles(clients, [_identity(OLD_IP, OLD_MAC)], [old_binding])

    result = service.assess(
        {"ip": NEW_IP, "mac": NEW_MAC},
        clients,
        [_identity(NEW_IP, NEW_MAC)],
        [old_binding, new_binding],
    )

    assert result is not None
    assert result["automatic"] is False
    assert "simultaneous_active_mac" in result["conflicts"]


@pytest.mark.parametrize("reuse_ip", [False, True])
def test_new_huawei_does_not_inherit_samsung_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reuse_ip: bool
) -> None:
    from app.services import unknown_device_admission_service as admission_module

    now = time.time()
    ip = OLD_IP if reuse_ip else NEW_IP
    samsung = replace(_identity(OLD_IP, OLD_MAC), hostname="S23-pol-zovatela-NewNetGuard")
    huawei = replace(
        _identity(ip, NEW_MAC), hostname="HUAWEI-phone", vendor_class="android-dhcp-12"
    )
    old_binding = _binding(OLD_IP, OLD_MAC, now - 120, now - 10)
    new_binding = _binding(ip, NEW_MAC, now - 5, now)
    admission = UnknownDeviceAdmissionService(
        tmp_path, arp_path=tmp_path / "missing-arp", dhcp_paths=(),
        prism_path=tmp_path / "missing-prism",
    )
    clients = [{**_client(), "name": "Samsung S23"}]
    admission.identity_service.refresh_profiles(clients, [samsung], [old_binding])
    monkeypatch.setattr(admission_module, "load_dhcp_identities", lambda _: [huawei])
    monkeypatch.setattr(
        admission_module, "load_dhcp_address_bindings", lambda _: [old_binding, new_binding]
    )
    monkeypatch.setattr(admission, "_load_managed_clients", lambda: clients)
    monkeypatch.setattr(
        admission, "_collect_observations",
        lambda *_: [{"ip": ip, "mac": NEW_MAC, "hostname": "HUAWEI-phone", "sources": ["traffic"]}],
    )

    [device] = admission.refresh()

    assert device["status"] == "pending"
    assert device["managed_device"] is False
    assert device["identity_candidate"] is None
    assert clients[0]["mac"] == OLD_MAC


def test_retired_alias_is_stale_until_new_source_traffic_arrives(
    tmp_path: Path,
) -> None:
    now = time.time()
    service = PrismIdentityService(tmp_path, prism_path=tmp_path / "missing")
    service.refresh_profiles(
        [_client()],
        [_identity(OLD_IP, OLD_MAC)],
        [_binding(OLD_IP, OLD_MAC, now - 60, now - 5)],
    )
    service.record_migration("dev_phone", OLD_MAC, NEW_MAC)
    state = json.loads((tmp_path / "prism_identity.json").read_text())
    retired_at = state["profiles"]["dev_phone"]["aliases"][0]["retired_at"]

    stale_binding = _binding(OLD_IP, OLD_MAC, now - 60, retired_at - 1)
    assert service.stale_retired_aliases([stale_binding]) == {OLD_MAC}

    returned_binding = _binding(OLD_IP, OLD_MAC, retired_at + 1, retired_at + 2)
    assert service.stale_retired_aliases([returned_binding]) == set()


def test_stale_retired_alias_does_not_reappear_in_quarantine(tmp_path: Path) -> None:
    now = time.time()
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "prism_identity.json").write_text(
        json.dumps(
            {
                "version": 1,
                "profiles": {
                    "dev_phone": {
                        "device_id": "dev_phone",
                        "active_mac": NEW_MAC,
                        "aliases": [
                            {
                                "mac": OLD_MAC,
                                "status": "retired",
                                "retired_at": now - 10,
                            }
                        ],
                    }
                },
            }
        )
    )
    dhcp_path = tmp_path / "dhcp.json"
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": OLD_IP,
                        "mac": OLD_MAC,
                        "hostname": "POCO-M3",
                        "last_seen_timestamp": now - 20,
                    }
                ],
                "address_bindings": {
                    OLD_IP: {
                        "mac": OLD_MAC,
                        "assigned_at_timestamp": now - 60,
                        "last_seen_timestamp": now - 20,
                    }
                },
            }
        )
    )
    admission = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
        prism_path=tmp_path / "missing-prism",
    )

    assert admission.refresh() == []
    assert admission.list_devices() == []


def test_quarantined_device_can_match_from_local_dns_without_internet(
    tmp_path: Path,
) -> None:
    now = time.time()
    dns_path = tmp_path / "flow_log.db"
    with sqlite3.connect(dns_path) as connection:
        connection.execute(
            "CREATE TABLE flow_log (timestamp TEXT, domain TEXT, client_id TEXT)"
        )
        timestamp = datetime.now(timezone.utc).isoformat()
        rows = []
        for ip in (OLD_IP, NEW_IP):
            client_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
            for index in range(24):
                rows.append(
                    (timestamp, f"background-{index % 15}.example.test", client_hash)
                )
        connection.executemany("INSERT INTO flow_log VALUES (?, ?, ?)", rows)
    service = PrismIdentityService(
        tmp_path,
        prism_path=tmp_path / "missing-prism",
        dns_log_path=dns_path,
    )
    clients = [_client()]
    old_binding = _binding(OLD_IP, OLD_MAC, now - 120, now - 10)
    new_binding = _binding(NEW_IP, NEW_MAC, now - 5, now)
    service.refresh_profiles(clients, [_identity(OLD_IP, OLD_MAC)], [old_binding])

    result = service.assess(
        {"ip": NEW_IP, "mac": NEW_MAC},
        clients,
        [_identity(NEW_IP, NEW_MAC)],
        [old_binding, new_binding],
    )

    assert result is not None
    assert result["confidence"] == 85
    assert result["automatic"] is False
    assert "background-" not in (tmp_path / "prism_identity.json").read_text()


def test_raw_stable_client_identifier_is_never_persisted(tmp_path: Path) -> None:
    now = time.time()
    raw_id = "ff00112233445566778899aabbccddeeff"
    service = PrismIdentityService(tmp_path, prism_path=tmp_path / "missing")
    service.refresh_profiles(
        [_client()],
        [_identity(OLD_IP, OLD_MAC, client_id=raw_id)],
        [_binding(OLD_IP, OLD_MAC, now - 30, now)],
    )

    state_text = (tmp_path / "prism_identity.json").read_text()
    assert raw_id not in state_text
    assert len((tmp_path / "prism_identity.key").read_bytes()) == 32


def test_unsafe_identity_state_cannot_suppress_quarantine(tmp_path: Path) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    (data_dir / "prism_identity.json").write_text("not-json")
    now = time.time()
    dhcp_path = tmp_path / "dhcp.json"
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": NEW_IP,
                        "mac": NEW_MAC,
                        "hostname": "POCO-M3",
                        "last_seen_timestamp": now,
                    }
                ],
                "address_bindings": {
                    NEW_IP: {
                        "mac": NEW_MAC,
                        "assigned_at_timestamp": now - 2,
                        "last_seen_timestamp": now,
                    }
                },
            }
        )
    )
    admission = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=tmp_path / "missing-arp",
        dhcp_paths=(dhcp_path,),
        prism_path=tmp_path / "missing-prism",
    )

    discovered = admission.refresh()

    assert len(discovered) == 1
    assert discovered[0]["status"] == "pending"
    assert discovered[0]["identity_candidate"] is None


class _MigrationHarness(ParentalMixin):
    def __init__(self, data_dir: Path, *, fail_action: str | None = None) -> None:
        self.data_dir = data_dir
        self._client_policy_lock = asyncio.Lock()
        self.actions: list[str] = []
        self.fail_action = fail_action

    @staticmethod
    def _first_client_ip(client: dict) -> str:
        return str(client.get("ip") or "")

    @staticmethod
    def _normalize_client_id(value: object) -> str:
        return str(value)

    @staticmethod
    def _is_valid_ipv4(value: str) -> bool:
        return value in {OLD_IP, NEW_IP}

    @staticmethod
    def _resolve_ipv4_from_mac(_mac: str) -> str:
        return ""

    @staticmethod
    def _resolve_mac_from_arp(_ip: str) -> str:
        return ""

    async def _sync_blocklist(self) -> dict:
        return {"ok": True, "warnings": []}

    async def _sync_ip_blocking(self, _clients: list[dict]) -> dict:
        return {"ok": True, "warnings": []}

    async def sync_unknown_device_admission_policy(self) -> bool:
        return True

    async def _run_vpn_blocking_action(
        self, action: str, *_args: object, **_kwargs: object
    ) -> dict:
        self.actions.append(action)
        return {"success": action != self.fail_action}


def test_identity_migration_keeps_device_id_and_policy(tmp_path: Path) -> None:
    original = {"clients": [_client()]}
    (tmp_path / "clients.json").write_text(json.dumps(original))
    harness = _MigrationHarness(tmp_path)

    result = asyncio.run(
        harness.approve_client_transactional(
            {"ip": NEW_IP, "ids": [NEW_IP], "mac": NEW_MAC},
            existing_client_id="dev_phone",
            release_persistent_block=True,
        )
    )

    client = result["client"]
    assert client["id"] == "dev_phone"
    assert client["mac"] == NEW_MAC
    assert client["blocked_services"] == ["youtube"]
    assert client["shield_profile"] == "kids"
    assert client["mac_history"][-1]["mac"] == OLD_MAC
    assert client["mac_history"][-1]["status"] == "retired"
    assert harness.actions == [
        "hold-admission",
        "hold-admission",
        "unblock-admission",
        "block-admission",
        "release-admission",
        "release-admission",
    ]


def test_failed_old_mac_retirement_rolls_policy_back(tmp_path: Path) -> None:
    original = {"clients": [_client()]}
    original_text = json.dumps(original)
    (tmp_path / "clients.json").write_text(original_text)
    harness = _MigrationHarness(tmp_path, fail_action="block-admission")

    with pytest.raises(RuntimeError, match="retire"):
        asyncio.run(
            harness.approve_client_transactional(
                {"ip": NEW_IP, "ids": [NEW_IP], "mac": NEW_MAC},
                existing_client_id="dev_phone",
                release_persistent_block=True,
            )
        )

    assert json.loads((tmp_path / "clients.json").read_text()) == original
    assert harness.actions[-1] == "release-admission"


def test_corrupt_identity_state_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "prism_identity.json").write_text("[]")
    service = PrismIdentityService(tmp_path, prism_path=tmp_path / "missing")
    with pytest.raises(PrismIdentityError):
        service.assess(
            {"ip": NEW_IP, "mac": NEW_MAC},
            [_client()],
            [_identity(NEW_IP, NEW_MAC)],
            [_binding(NEW_IP, NEW_MAC, time.time() - 1, time.time())],
        )


def test_replacement_api_uses_server_observed_pair_and_proposed_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices_module = importlib.import_module(
        "app.api.endpoints.netprotection_api.devices"
    )
    unknown_id = "unknown_" + "a" * 20
    calls: list[tuple[dict, dict]] = []

    class AdmissionHarness:
        @staticmethod
        def refresh() -> list:
            return []

        @staticmethod
        def get_device(_device_id: str) -> dict:
            return {
                "id": unknown_id,
                "ip": NEW_IP,
                "mac": NEW_MAC,
                "identity_candidate": {
                    "device_id": "dev_phone",
                    "identity_state": "possible_mac_change",
                    "confidence": 55,
                    "conflicts": [],
                },
            }

        @staticmethod
        def mark_allowed(_device_id: str) -> None:
            raise UnknownDeviceNotFound("already removed by proactive monitor")

    class NetProtectionHarness:
        @staticmethod
        async def approve_client_transactional(payload: dict, **kwargs: object) -> dict:
            calls.append((payload, kwargs))
            return {"client": _client()}

    monkeypatch.setattr(
        devices_module, "unknown_device_admission_service", AdmissionHarness()
    )
    monkeypatch.setattr(
        devices_module, "netprotection_service", NetProtectionHarness()
    )
    monkeypatch.setattr(devices_module, "_record_netprotection_event", lambda **_kw: None)

    result = asyncio.run(
        devices_module.replace_unknown_device_identity(
            unknown_id,
            SimpleNamespace(target_device_id="dev_phone"),
            object(),
        )
    )

    assert result["success"] is True
    assert calls == [
        (
            {"ip": NEW_IP, "ids": [NEW_IP], "mac": NEW_MAC},
            {
                "existing_client_id": "dev_phone",
                "release_persistent_block": True,
            },
        )
    ]
