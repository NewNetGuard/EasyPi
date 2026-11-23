from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

from app.services.netprotection_components.analytics_parts.statistics import (
    AnalyticsStatisticsMixin,
)
from app.services.network_toolkit_components.gateway import NetworkGatewayMixin
from app.services.unknown_device_admission_service import UnknownDeviceAdmissionService


class GatewayVerificationHarness(NetworkGatewayMixin):
    def __init__(
        self,
        conntrack: str,
        neighbours: str,
        *,
        allowed: bool = True,
        conntrack_rc: int = 0,
    ) -> None:
        self.conntrack = conntrack
        self.neighbours = neighbours
        self.allowed = allowed
        self.conntrack_rc = conntrack_rc

    async def get_gateway_mode_status(self) -> dict:
        return {
            "enabled": True,
            "ip_forward": True,
            "nat_enabled": True,
            "static_ip": True,
        }

    async def _get_default_route(self) -> dict:
        return {"gateway": "10.23.1.1", "interface": "eth0"}

    async def _get_interface_ip(self, _interface: str) -> tuple[str, bool]:
        return "10.23.1.21", True

    async def _run_cmd(self, command: list[str], timeout: int = 10) -> tuple[int, str, str]:
        del timeout
        if command[:3] == ["sudo", "conntrack", "-L"]:
            return self.conntrack_rc, self.conntrack, ""
        if command[:3] == ["ip", "neigh", "show"]:
            return 0, self.neighbours, ""
        raise AssertionError(f"unexpected command: {command}")

    def _gateway_pair_allowed(self, mac: str, ip: str) -> bool:
        del mac, ip
        return self.allowed


class GatewayMutationHarness(NetworkGatewayMixin):
    def __init__(self) -> None:
        self.saved_state: dict = {}

    async def _get_default_route(self) -> dict:
        return {"gateway": "10.23.1.1", "interface": "eth0"}

    async def _get_interface_ip(self, _interface: str) -> tuple[str, bool]:
        return "10.23.1.25", True

    async def _detect_lan_wan_interfaces(self, _interface: str) -> tuple[str, str]:
        return "eth0", "eth0"

    async def _get_interface_prefix_len(self, _interface: str) -> int:
        return 24

    def _write_gateway_state(self, state: dict) -> None:
        self.saved_state = state

    async def _persist_ip_forward(self, _enabled: bool) -> None:
        return None

    async def _run_runner(
        self, _script: str, _args: list[str], timeout: int
    ) -> tuple[bool, str]:
        del timeout
        return True, ""

    async def _configure_ufw_route(
        self, _lan: str, _wan: str, *, enable: bool
    ) -> None:
        del enable

    async def _persist_firewall_rules(self) -> None:
        return None

    async def _ensure_gateway_fix_timer(self, *, enable: bool) -> None:
        del enable

    async def get_gateway_mode_status(self) -> dict:
        return {
            "enabled": bool(self.saved_state.get("enabled")),
            "static_ip": True,
            "nat_enabled": bool(self.saved_state.get("enabled")),
            "ip_forward": bool(self.saved_state.get("enabled")),
        }

    async def verify_gateway_effective(self) -> dict:
        return {
            "configured": bool(self.saved_state.get("enabled")),
            "effective": bool(self.saved_state.get("enabled")),
            "devices_routed": 1 if self.saved_state.get("enabled") else 0,
        }


class OnboardingHarness(AnalyticsStatisticsMixin):
    def __init__(self, data_dir: Path) -> None:
        self.flow_log_path = data_dir / "flow_log.db"

    async def get_active_devices(self, hours: int = 24) -> list[dict]:
        assert hours == 24
        return [
            {
                "client_id": "privacy-hash-without-current-ip-attribution",
                "ip": "",
                "name": "Unresolved device",
            }
        ]

    async def get_schedule_enforcement_status(self) -> dict:
        return {"gateway_enforcement": True}


def test_blocked_conntrack_attempt_is_not_reported_as_working_internet() -> None:
    conntrack = (
        "tcp 6 119 SYN_SENT src=10.23.1.29 dst=8.8.8.8 sport=41000 "
        "dport=443 [UNREPLIED] src=8.8.8.8 dst=10.23.1.21 sport=443 "
        "dport=41000 mark=0 use=1"
    )
    neighbours = (
        "10.23.1.29 dev eth0 lladdr 02:00:00:00:01:05 REACHABLE\n"
        "10.23.1.1 dev eth0 lladdr 02:00:00:00:01:0d REACHABLE"
    )

    result = asyncio.run(
        GatewayVerificationHarness(conntrack, neighbours).verify_gateway_effective()
    )

    assert result["effective"] is False
    assert result["devices_routed"] == 0
    assert result["devices_present"] == 1
    assert result["present_ips"] == ["10.23.1.29"]


def test_completed_bidirectional_conntrack_flow_is_reported() -> None:
    conntrack = (
        "tcp 6 431999 ESTABLISHED src=10.23.1.29 dst=8.8.8.8 "
        "sport=41000 dport=443 src=8.8.8.8 dst=10.23.1.21 sport=443 "
        "dport=41000 [ASSURED] mark=0 use=1"
    )
    neighbours = "10.23.1.29 dev eth0 lladdr 02:00:00:00:01:05 REACHABLE"

    result = asyncio.run(
        GatewayVerificationHarness(conntrack, neighbours).verify_gateway_effective()
    )

    assert result["effective"] is True
    assert result["devices_routed"] == 1
    assert result["device_ips"] == ["10.23.1.29"]


def test_stale_neighbours_are_not_reported_as_present() -> None:
    neighbours = (
        "10.23.1.12 dev eth0 lladdr 02:00:00:00:01:0b STALE\n"
        "10.23.1.14 dev eth0 lladdr 02:00:00:00:01:08 STALE"
    )
    result = asyncio.run(
        GatewayVerificationHarness("", neighbours).verify_gateway_effective()
    )
    assert result["devices_present"] == 0
    assert result["present_ips"] == []
    assert result["devices_routed"] == 0


def test_stale_successful_flow_does_not_override_current_quarantine() -> None:
    conntrack = (
        "tcp 6 431999 ESTABLISHED src=10.23.1.29 dst=8.8.8.8 "
        "sport=41000 dport=443 src=8.8.8.8 dst=10.23.1.21 sport=443 "
        "dport=41000 [ASSURED] mark=0 use=1"
    )
    neighbours = "10.23.1.29 dev eth0 lladdr 02:00:00:00:01:05 REACHABLE"

    result = asyncio.run(
        GatewayVerificationHarness(
            conntrack, neighbours, allowed=False
        ).verify_gateway_effective()
    )

    assert result["effective"] is False
    assert result["devices_routed"] == 0
    assert result["devices_present"] == 1


def test_missing_conntrack_is_reported_as_unavailable_not_missing_traffic() -> None:
    neighbours = "10.23.1.26 dev eth0 lladdr 02:00:00:00:01:08 REACHABLE"

    result = asyncio.run(
        GatewayVerificationHarness(
            "",
            neighbours,
            conntrack_rc=127,
        ).verify_gateway_effective()
    )

    assert result["verification_available"] is False
    assert result["effective"] is False
    assert result["devices_present"] == 1


def test_enable_returns_authoritative_status_for_immediate_ui_update() -> None:
    result = asyncio.run(GatewayMutationHarness().enable_gateway_mode())

    assert result["success"] is True
    assert result["status"]["enabled"] is True
    assert result["verification"]["effective"] is True


def test_disable_returns_authoritative_status_for_immediate_ui_update() -> None:
    harness = GatewayMutationHarness()
    harness.saved_state = {"enabled": True}

    result = asyncio.run(harness.disable_gateway_mode())

    assert result["success"] is True
    assert result["status"]["enabled"] is False


def test_onboarding_counts_dns_traffic_before_ip_attribution(tmp_path: Path) -> None:
    result = asyncio.run(OnboardingHarness(tmp_path).get_onboarding_status())
    dns_step = next(step for step in result["steps"] if step["key"] == "dns")

    assert dns_step["done"] is True
    assert dns_step["detail"] == "1 device(s) are querying EasyPi."


def test_onboarding_refreshes_external_dns_state_automatically() -> None:
    component = Path(
        "frontend/src/components/dashboard/OnboardingCard.tsx"
    ).read_text(encoding="utf-8")

    assert "refetchInterval: 5_000" in component


def test_installer_provides_conntrack_for_gateway_verification() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")

    assert "net-tools iproute2 conntrack speedtest-cli" in installer


def test_gateway_mode_prevents_same_subnet_router_bypass() -> None:
    firewall = Path("scripts/settings/network_firewall.sh").read_text(encoding="utf-8")
    persistence = Path("scripts/settings/gateway_config.sh").read_text(encoding="utf-8")
    repair = Path("scripts/setup/gateway_fix.sh").read_text(encoding="utf-8")

    for content in (firewall, persistence, repair):
        assert "net.ipv4.conf.all.send_redirects=0" in content or (
            "net.ipv4.conf.all.send_redirects = 0" in content
        )
        assert "net.ipv4.conf.default.send_redirects=0" in content or (
            "net.ipv4.conf.default.send_redirects = 0" in content
        )
    assert 'net.ipv4.conf.${wan}.send_redirects=0' in firewall
    assert 'net.ipv4.conf.${lan}.send_redirects=0' in firewall
    assert 'net.ipv4.conf.${iface}.send_redirects=0' in repair


def test_gateway_repair_service_can_run_repeatedly_from_its_timer() -> None:
    generated_unit = Path("scripts/settings/gateway_config.sh").read_text(
        encoding="utf-8"
    )
    packaged_unit = Path(
        "templates/systemd/easypi-gateway-fix.service"
    ).read_text(encoding="utf-8")
    timer = Path("templates/systemd/easypi-gateway-fix.timer").read_text(
        encoding="utf-8"
    )

    assert "Type=oneshot" in generated_unit
    assert "Type=oneshot" in packaged_unit
    assert "RemainAfterExit=yes" not in generated_unit
    assert "RemainAfterExit=yes" not in packaged_unit
    assert "OnUnitActiveSec=60" in timer


def test_stale_arp_entries_do_not_create_unknown_device_notifications(
    tmp_path: Path,
) -> None:
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "10.23.1.1 0x1 0x2 02:00:00:00:01:0d * eth0\n"
        "10.23.1.29 0x1 0x2 02:00:00:00:01:05 * eth0\n",
        encoding="utf-8",
    )
    routes = tmp_path / "route"
    routes.write_text(
        "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
        "eth0 00000000 0159A8C0 0003 0 0 100 00000000 0 0 0\n",
        encoding="ascii",
    )
    service = UnknownDeviceAdmissionService(
        tmp_path / "data",
        arp_path=arp,
        route_path=routes,
        dhcp_paths=(tmp_path / "missing-observations.json",),
    )

    observations = service._collect_observations()

    assert observations == []


def test_stale_arp_only_pending_notification_is_removed(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    mac = "02:00:00:00:01:05"
    (data_dir / "unknown_device_admission.json").write_text(
        json.dumps(
            {
                "version": 1,
                "devices": [
                    {
                        "id": UnknownDeviceAdmissionService.device_id(mac),
                        "ip": "10.23.1.22",
                        "mac": mac,
                        "status": "pending",
                        "sources": ["arp"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        f"10.23.1.22 0x1 0x2 {mac} * eth0\n",
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=arp,
        dhcp_paths=(tmp_path / "missing-observations.json",),
    )

    assert service.refresh() == []
    assert service.list_devices(include_blocked=True) == []


def test_every_local_interface_is_removed_from_unknown_device_review(
    tmp_path: Path, monkeypatch,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "settings.json").write_text(
        '{"unknown_devices":{"mode":"block"}}', encoding="utf-8"
    )
    (data_dir / "unknown_device_admission.json").write_text(
        json.dumps(
            {
                "version": 1,
                "devices": [
                    {
                        "id": "wifi-interface",
                        "ip": "10.23.1.24",
                        "mac": "02:00:00:00:01:04",
                        "status": "pending",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "10.23.1.24 0x1 0x2 02:00:00:00:01:04 * wlan0\n"
        "10.23.1.25 0x1 0x2 02:00:00:00:01:03 * eth0\n"
        "10.23.1.26 0x1 0x2 02:00:00:00:01:08 * eth0\n",
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir,
        arp_path=arp,
        route_path=tmp_path / "missing-route",
        dhcp_paths=(tmp_path / "observations.json",),
    )
    now = time.time()
    (tmp_path / "observations.json").write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "10.23.1.26",
                        "mac": "02:00:00:00:01:08",
                        "last_seen_timestamp": now,
                    }
                ],
                "address_bindings": {
                    "10.23.1.26": {
                        "mac": "02:00:00:00:01:08",
                        "assigned_at_timestamp": now,
                        "last_seen_timestamp": now,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        service,
        "_local_ipv4_addresses",
        lambda: {"10.23.1.24", "10.23.1.25"},
    )

    discovered = service.refresh()

    assert [(item["ip"], item["mac"]) for item in discovered] == [
        ("10.23.1.26", "02:00:00:00:01:08")
    ]
    assert [item["ip"] for item in service.list_devices()] == ["10.23.1.26"]


def test_gateway_status_requires_approved_pair_without_pending_decision(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    (data_dir / "settings.json").write_text(
        '{"unknown_devices":{"mode":"block"}}', encoding="utf-8"
    )
    (data_dir / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "mac": "02:00:00:00:01:05",
                        "ip": "10.23.1.29",
                        "name": "Phone",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    state_path = data_dir / "unknown_device_admission.json"
    state_path.write_text(
        json.dumps(
            {
                "version": 1,
                "devices": [
                    {
                        "id": "pending-phone",
                        "mac": "02:00:00:00:01:05",
                        "ip": "10.23.1.29",
                        "status": "pending",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(data_dir)

    assert service.is_pair_allowed("02:00:00:00:01:05", "10.23.1.29") is False

    state_path.write_text('{"version":1,"devices":[]}', encoding="utf-8")

    assert service.is_pair_allowed("02:00:00:00:01:05", "10.23.1.29") is True
    assert service.is_pair_allowed("02:00:00:00:01:08", "10.23.1.30") is False
