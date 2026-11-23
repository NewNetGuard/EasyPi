from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import time
from pathlib import Path

import pytest

from app.api.v1.endpoints import heuristics as heuristics_api
from app.api.endpoints.netprotection_api.compatibility_components import (
    firewall_parental as parental_api,
)
from app.api.endpoints.netprotection_api.compatibility_components.firewall_parental import (
    _is_parental_client,
)
from app.services.netprotection_components.parental import ParentalMixin
from easypi_netprotection.profiles.models import DeviceProfile, FilterLevel
from easypi_netprotection.verdict.engine_components.policy_checks import (
    VerdictPolicyChecksMixin,
)
from easypi_netprotection.verdict.evidence import EvidenceChain
from easypi_netprotection.verdict.outcome import VerdictAction


class _ParentalDocumentsHarness(ParentalMixin):
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir


def test_parental_membership_is_explicit_for_new_records() -> None:
    assert _is_parental_client({"parental_managed": True}) is True
    assert (
        _is_parental_client(
            {
                "parental_managed": False,
                "parental_enabled": True,
                "blocked_services": ["youtube"],
            }
        )
        is False
    )


def test_legacy_parental_membership_does_not_include_normal_admission() -> None:
    assert (
        _is_parental_client(
            {
                "parental_enabled": False,
                "safesearch_enabled": False,
                "safebrowsing_enabled": True,
                "blocked_services": [],
                "custom_blocked_domains": [],
            }
        )
        is False
    )
    assert _is_parental_client({"parental_enabled": True}) is True
    assert _is_parental_client({"safesearch_enabled": True}) is True
    assert _is_parental_client({"blocked_services": ["youtube"]}) is True
    assert _is_parental_client({"custom_blocked_domains": ["example.test"]}) is False


class _TransactionalParentalHarness(ParentalMixin):
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._client_policy_lock = asyncio.Lock()
        self.sync_results = [
            {"ok": False, "warnings": ["publication failed"]},
            {"ok": True, "warnings": []},
        ]

    async def _sync_blocklist(self) -> dict:
        result = self.sync_results.pop(0)
        if not result["ok"]:
            for name in ("devices.json", "profiles.json", "bindings.json"):
                path = self.data_dir / name
                path.write_text("cancelled-policy", encoding="utf-8")
                path.chmod(0o600)
            (self.data_dir / "bindings.bak").write_text(
                "cancelled-policy", encoding="utf-8"
            )
        return result

    async def _sync_ip_blocking(self, _clients: list[dict]) -> dict:
        return {"ok": True, "warnings": []}

    @staticmethod
    def _normalize_client_id(value: object) -> str:
        return str(value or "device")

    @staticmethod
    def _first_client_ip(client: dict) -> str:
        return str(client.get("ip") or "")

    @staticmethod
    def _resolve_ipv4_from_mac(_mac: str) -> str:
        return ""


def test_failed_parental_publication_restores_client_state(tmp_path: Path) -> None:
    original = {
        "clients": [
            {
                "id": "phone",
                "name": "Phone",
                "ip": "192.168.1.20",
                "ids": ["192.168.1.20"],
                "mac": "02:00:00:00:00:20",
                "parental_managed": True,
                "parental_enabled": True,
                "custom_blocked_domains": ["work-rule.example"],
                "bypass_mode": "quarantine",
            }
        ]
    }
    clients_path = tmp_path / "clients.json"
    clients_path.write_text(json.dumps(original), encoding="utf-8")
    clients_path.chmod(0o640)
    original_policy_files = {
        "devices.json": "[]",
        "profiles.json": '{"profiles": []}',
        "bindings.json": '{"bindings": []}',
    }
    for name, content in original_policy_files.items():
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        path.chmod(0o640)
    bindings_backup = tmp_path / "bindings.bak"
    bindings_backup.write_text("previous-policy", encoding="utf-8")
    bindings_backup.chmod(0o640)
    harness = _TransactionalParentalHarness(tmp_path)

    with pytest.raises(RuntimeError, match="DNS/firewall"):
        asyncio.run(
            harness.update_parental_client_transactional(
                "Phone",
                {
                    **original["clients"][0],
                    "parental_managed": False,
                    "parental_enabled": False,
                },
            )
        )

    assert json.loads(clients_path.read_text(encoding="utf-8")) == original
    for name, content in original_policy_files.items():
        path = tmp_path / name
        assert path.read_text(encoding="utf-8") == content
        if os.name != "nt":
            assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert bindings_backup.read_text(encoding="utf-8") == "previous-policy"
    if os.name != "nt":
        assert stat.S_IMODE(clients_path.stat().st_mode) == 0o640
        assert stat.S_IMODE(bindings_backup.stat().st_mode) == 0o640


class _ParentalApiService:
    def __init__(self, data_dir: Path, clients: list[dict]) -> None:
        self.data_dir = data_dir
        self.clients = clients
        self.updated: dict | None = None
        self.updated_name: str | None = None
        self.added: dict | None = None

    async def process_fail_closed_requests(self) -> None:
        return None

    async def get_clients(self) -> dict:
        return {"clients": self.clients}

    async def list_fail_closed_clients(self) -> list[str]:
        return []

    async def update_parental_client_transactional(
        self, name: str, payload: dict
    ) -> dict:
        self.updated_name = name
        self.updated = payload
        return {
            "success": True,
            "sync": {"ok": True, "warnings": []},
            "ip_blocking": {"ok": True, "warnings": []},
        }

    async def add_parental_client_transactional(self, payload: dict) -> dict:
        self.added = payload
        return {
            "success": True,
            "sync": {"ok": True, "warnings": []},
            "ip_blocking": {"ok": True, "warnings": []},
        }


def test_parental_api_filters_server_side_and_inventory_can_opt_in(
    tmp_path: Path, monkeypatch
) -> None:
    service = _ParentalApiService(
        tmp_path,
        [
            {"id": "normal", "name": "Normal", "parental_managed": False},
            {"id": "child", "name": "Child", "parental_managed": True},
        ],
    )
    monkeypatch.setattr(parental_api, "netprotection_service", service)
    visible = asyncio.run(
        parental_api.get_parental_clients_compat(False, _admin=object())
    )
    inventory = asyncio.run(
        parental_api.get_parental_clients_compat(True, _admin=object())
    )

    assert [item["name"] for item in visible] == ["Child"]
    assert [item["name"] for item in inventory] == ["Normal", "Child"]


def test_removing_parental_control_preserves_other_device_rules(
    tmp_path: Path, monkeypatch
) -> None:
    service = _ParentalApiService(
        tmp_path,
        [
            {
                "id": "phone",
                "name": "Phone",
                "parental_managed": True,
                "parental_enabled": True,
                "safesearch_enabled": True,
                "blocked_services": ["youtube"],
                "custom_blocked_domains": ["work-rule.example"],
                "bypass_mode": "quarantine",
            }
        ],
    )
    monkeypatch.setattr(parental_api, "netprotection_service", service)
    monkeypatch.setattr(parental_api, "_record_netprotection_event", lambda **_: None)

    asyncio.run(parental_api.delete_parental_client_compat("Phone", _admin=object()))

    assert service.updated is not None
    assert service.updated["parental_managed"] is False
    assert service.updated["parental_enabled"] is False
    assert service.updated["blocked_services"] == []
    assert service.updated["custom_blocked_domains"] == ["work-rule.example"]
    assert service.updated["bypass_mode"] == "quarantine"


def test_parental_label_is_removed_and_can_be_reused(
    tmp_path: Path, monkeypatch
) -> None:
    old_device = {
        "id": "old-phone",
        "name": "POCO-M3",
        "parental_name": "Childs Phone",
        "mac": "02:00:00:00:00:20",
        "parental_managed": True,
        "parental_enabled": True,
    }
    service = _ParentalApiService(tmp_path, [old_device])
    monkeypatch.setattr(parental_api, "netprotection_service", service)
    monkeypatch.setattr(parental_api, "_record_netprotection_event", lambda **_: None)

    asyncio.run(
        parental_api.delete_parental_client_compat("Childs Phone", _admin=object())
    )

    assert service.updated_name == "POCO-M3"
    assert service.updated is not None
    assert "parental_name" not in service.updated
    assert service.updated["parental_managed"] is False

    service.clients = [service.updated]
    asyncio.run(
        parental_api.add_parental_client_compat(
            {
                "name": "Childs Phone",
                "mac": "02:00:00:00:00:21",
                "ip": "192.168.1.21",
            },
            _admin=object(),
        )
    )

    assert service.added is not None
    assert service.added["parental_name"] == "Childs Phone"
    assert service.added["name"] == "Childs Phone"


def test_readding_existing_device_keeps_general_device_name(
    tmp_path: Path, monkeypatch
) -> None:
    device = {
        "id": "phone",
        "name": "POCO-M3",
        "mac": "02:00:00:00:00:20",
        "parental_managed": False,
        "custom_blocked_domains": ["work-rule.example"],
    }
    service = _ParentalApiService(tmp_path, [device])
    monkeypatch.setattr(parental_api, "netprotection_service", service)
    monkeypatch.setattr(parental_api, "_record_netprotection_event", lambda **_: None)

    asyncio.run(
        parental_api.add_parental_client_compat(
            {
                "name": "Childs Phone",
                "mac": "02:00:00:00:00:20",
                "ip": "192.168.1.20",
            },
            _admin=object(),
        )
    )

    assert service.updated_name == "POCO-M3"
    assert service.updated is not None
    assert service.updated["name"] == "POCO-M3"
    assert service.updated["parental_name"] == "Childs Phone"
    assert service.updated["custom_blocked_domains"] == ["work-rule.example"]


def test_hidden_device_name_does_not_reserve_parental_label(
    tmp_path: Path, monkeypatch
) -> None:
    hidden_device = {
        "id": "old-phone",
        "name": "Childs Phone",
        "mac": "02:00:00:00:00:20",
        "parental_managed": False,
    }
    service = _ParentalApiService(tmp_path, [hidden_device])
    monkeypatch.setattr(parental_api, "netprotection_service", service)
    monkeypatch.setattr(parental_api, "_record_netprotection_event", lambda **_: None)

    asyncio.run(
        parental_api.add_parental_client_compat(
            {
                "name": "Childs Phone",
                "mac": "02:00:00:00:00:21",
                "ip": "192.168.1.21",
            },
            _admin=object(),
        )
    )

    assert service.added is not None
    assert service.added["name"] == "Device-000021"
    assert service.added["parental_name"] == "Childs Phone"


def _device(*, parental: bool) -> dict:
    return {
        "id": "comp",
        "name": "Comp",
        "ip": "192.168.1.18",
        "mac": "02:00:00:00:00:18",
        "enabled": True,
        "parental": parental,
        "safesearch": False,
        "safebrowsing": True,
        "shield_profile": "balanced",
        "blocked_services": [],
        "custom_blocked_domains": [],
        "custom_allowed_domains": [],
        "bypass_mode": "warn",
    }


def test_managed_profile_records_explicit_parental_state(tmp_path: Path) -> None:
    harness = _ParentalDocumentsHarness(tmp_path)

    *_, normal_profiles, _ = harness._build_parental_policy_documents(
        [_device(parental=False)]
    )
    normal = normal_profiles[0]
    assert normal["name"] == "Device policy: Comp"
    assert normal["parental_enabled"] is False
    assert normal["filter_level"] == "standard"

    *_, parental_profiles, _ = harness._build_parental_policy_documents(
        [_device(parental=True)]
    )
    parental = parental_profiles[0]
    assert parental["name"] == "Parental: Comp"
    assert parental["parental_enabled"] is True


class _Profiles:
    def __init__(self, profile: DeviceProfile) -> None:
        self.profile = profile
        self.blocked_queries = 0

    def lookup_profile(self, _client_ip: str, _client_mac: str | None):
        return self.profile

    def record_query(
        self, _client_ip: str, _client_mac: str | None, *, blocked: bool
    ) -> None:
        if blocked:
            self.blocked_queries += 1


class _PolicyHarness(VerdictPolicyChecksMixin):
    _managed_parental_profile_prefix = "parental_device_"
    _ALERTING_BYPASS_GROUPS = ("vpn", "proxy", "tor", "smartdns")
    _blocklist = None

    def __init__(self, profile: DeviceProfile) -> None:
        self._profiles = _Profiles(profile)
        self.events: list[str] = []

    @staticmethod
    def _is_bypass_domain(_domain: str) -> bool:
        return True

    @staticmethod
    def _bypass_domain_group(_domain: str) -> str:
        return "vpn"

    def _record_bypass_event(
        self, _client_ip: str, _flow_id: str, domain: str, *, leak: bool
    ) -> None:
        self.events.append(f"{domain}:{leak}")


def _check_vpnbook(profile: DeviceProfile):
    harness = _PolicyHarness(profile)
    result = harness._check_device_profile(
        "www.vpnbook.com",
        "192.168.1.18",
        "02:00:00:00:00:18",
        "flow-1",
        EvidenceChain("flow-1"),
        time.monotonic(),
    )
    return harness, result


def test_profile_prefix_alone_does_not_enable_parental_anti_bypass() -> None:
    profile = DeviceProfile(
        id="parental_device_comp",
        name="Device policy: Comp",
        filter_level=FilterLevel.STANDARD,
        parental_enabled=False,
    )

    harness, result = _check_vpnbook(profile)

    assert result is None
    assert harness.events == []
    assert harness._profiles.blocked_queries == 0


def test_explicit_parental_control_enables_anti_bypass() -> None:
    profile = DeviceProfile(
        id="parental_device_comp",
        name="Parental: Comp",
        filter_level=FilterLevel.STANDARD,
        parental_enabled=True,
    )

    harness, result = _check_vpnbook(profile)

    assert result is not None
    assert result.action is VerdictAction.DENY
    assert harness.events == ["www.vpnbook.com:True"]
    assert harness._profiles.blocked_queries == 1


def test_profile_parental_state_round_trips_and_legacy_defaults_off() -> None:
    profile = DeviceProfile(
        id="parental_device_phone",
        name="Parental: Phone",
        parental_enabled=True,
    )
    assert DeviceProfile.from_dict(profile.to_dict()).parental_enabled is True

    legacy = profile.to_dict()
    legacy.pop("parental_enabled")
    assert DeviceProfile.from_dict(legacy).parental_enabled is False


def _insert_flow(
    connection: sqlite3.Connection,
    *,
    timestamp: str,
    domain: str,
    status: str,
    evidence: str,
    confidence: int = 100,
) -> None:
    connection.execute(
        """
        INSERT INTO flow_log(timestamp, domain, status, evidence_summary, confidence, categories)
        VALUES (?, ?, ?, ?, ?, '')
        """,
        (timestamp, domain, status, evidence, confidence),
    )


def test_ai_alerts_exclude_policy_blocks_and_resolved_history(
    tmp_path: Path, monkeypatch
) -> None:
    data_dir = tmp_path / "data" / "netprotection"
    data_dir.mkdir(parents=True)
    database = data_dir / "flow_log.db"
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE flow_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain TEXT NOT NULL,
            status TEXT NOT NULL,
            evidence_summary TEXT,
            confidence INTEGER,
            categories TEXT
        )
        """
    )
    _insert_flow(
        connection,
        timestamp="2026-09-26T10:00:00+00:00",
        domain="www.vpnbook.com",
        status="blocked",
        evidence="anti-bypass endpoint: Parental: Comp",
    )
    _insert_flow(
        connection,
        timestamp="2026-09-26T10:01:00+00:00",
        domain="chatgpt.com",
        status="blocked",
        evidence="unknown device blocked pending administrator approval",
    )
    _insert_flow(
        connection,
        timestamp="2026-09-26T10:02:00+00:00",
        domain="active-ai.example",
        status="blocked",
        evidence="Heuristics score: 82.0 (block)",
        confidence=82,
    )
    _insert_flow(
        connection,
        timestamp="2026-09-26T10:03:00+00:00",
        domain="resolved-ai.example",
        status="blocked",
        evidence="Heuristics score: 88.0 (block)",
        confidence=88,
    )
    _insert_flow(
        connection,
        timestamp="2026-09-26T10:04:00+00:00",
        domain="resolved-ai.example",
        status="allowed",
        evidence="upstream",
        confidence=15,
    )
    connection.commit()
    connection.close()

    monkeypatch.setattr(heuristics_api, "ROOT_DIR", tmp_path)
    result = asyncio.run(
        heuristics_api.get_alerts(
            severity=None,
            alert_type=None,
            acknowledged=None,
            limit=50,
            current_user=object(),
        )
    )

    assert [alert["domain"] for alert in result["alerts"]] == [
        "active-ai.example"
    ]
    assert result["unacknowledged"] == 1
