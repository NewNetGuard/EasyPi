from __future__ import annotations

import asyncio
import ipaddress
import struct
import time
from types import SimpleNamespace

from app.services import proactive_monitor as monitor_module
from app.services.dhcp_identity import load_ipv6_bypass_routers
from app.services.dhcp_observer import (
    PACKET_MULTICAST,
    PACKET_OUTGOING,
    DHCPObservationStore,
    parse_router_advertisement,
    process_ipv6_frame,
)
from app.services.proactive_monitor import ProactiveMonitor

ROUTER_MAC = bytes.fromhex("aabbccddee01")


def router_advertisement(
    *,
    prefix: str = "2001:db8:1::",
    lifetime: int = 1800,
    hop_limit: int = 255,
    managed: bool = False,
) -> bytes:
    option = struct.pack(
        "!BBBBIII", 3, 4, 64, 0xC0, 86400, 14400, 0
    ) + ipaddress.IPv6Address(prefix).packed
    icmp = struct.pack(
        "!BBHBBHII", 134, 0, 0, 64, 0x80 if managed else 0, lifetime, 0, 0
    ) + option
    ipv6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, hop_limit)
    ipv6 += ipaddress.IPv6Address("fe80::1").packed + ipaddress.IPv6Address("ff02::1").packed
    ethernet = bytes.fromhex("333300000001") + ROUTER_MAC + struct.pack("!H", 0x86DD)
    return ethernet + ipv6 + icmp


def test_router_advertisement_with_global_prefix_is_recognised() -> None:
    parsed = parse_router_advertisement(router_advertisement(), observed_at=100.0)
    assert parsed == {
        "router_mac": "AA:BB:CC:DD:EE:01",
        "router_lifetime": 1800,
        "managed": False,
        "global_prefixes": ["2001:db8:1::/64"],
        "last_seen_timestamp": 100.0,
    }


def test_forged_local_and_malformed_advertisements_are_not_global() -> None:
    # A forwarded (hop limit below 255) advertisement is not a LAN router.
    assert parse_router_advertisement(router_advertisement(hop_limit=64)) is None
    # Unique-local addresses cannot reach the internet.
    assert parse_router_advertisement(router_advertisement(prefix="fd00::"))["global_prefixes"] == []
    assert parse_router_advertisement(router_advertisement()[:-10]) is None
    broken = bytearray(router_advertisement())
    broken[14 + 40 + 16 + 1] = 0  # zero-length option
    assert parse_router_advertisement(bytes(broken)) is None


def test_observer_persists_advertisements_and_ignores_its_own(tmp_path) -> None:
    path = tmp_path / "dhcp_observations.json"
    store = DHCPObservationStore(path)
    process_ipv6_frame(store, router_advertisement(prefix="2001:db8:9::"), PACKET_OUTGOING, 10.0)
    assert store.ipv6_routers == {}
    process_ipv6_frame(store, router_advertisement(), PACKET_MULTICAST, time.time())
    store.flush()
    reloaded = DHCPObservationStore(path)
    assert reloaded.ipv6_routers["AA:BB:CC:DD:EE:01"]["global_prefixes"] == ["2001:db8:1::/64"]


def test_only_recent_default_routers_with_global_addressing_are_exposed(tmp_path) -> None:
    path = tmp_path / "dhcp_observations.json"
    now = time.time()
    store = DHCPObservationStore(path)
    store.observe_router_advertisement(parse_router_advertisement(router_advertisement(), now))
    store.flush()
    assert load_ipv6_bypass_routers((path,), now=now)[0]["global_prefixes"] == ["2001:db8:1::/64"]
    assert load_ipv6_bypass_routers((path,), now=now + 3 * 60 * 60) == []

    no_default = DHCPObservationStore(tmp_path / "no-default.json")
    no_default.observe_router_advertisement(parse_router_advertisement(router_advertisement(lifetime=0), now))
    no_default.flush()
    assert load_ipv6_bypass_routers((tmp_path / "no-default.json",), now=now) == []

    dhcpv6 = DHCPObservationStore(tmp_path / "dhcpv6.json")
    dhcpv6.observe_router_advertisement(
        parse_router_advertisement(router_advertisement(prefix="fd00::", managed=True), now)
    )
    dhcpv6.flush()
    assert load_ipv6_bypass_routers((tmp_path / "dhcpv6.json",), now=now)[0]["managed"] is True


def test_watchdog_warns_once_while_stealth_devices_are_exposed(tmp_path, monkeypatch) -> None:
    import app.services.dhcp_identity as identity
    import app.services.stealth_service as stealth

    routers = [{"router_mac": "AA:BB:CC:DD:EE:01", "global_prefixes": ["2001:db8:1::/64"], "managed": False}]
    covered = {"value": (False, {"10.23.1.35"})}
    monkeypatch.setattr(identity, "load_ipv6_bypass_routers", lambda: list(routers))
    monkeypatch.setattr(
        stealth, "get_stealth_service",
        lambda: SimpleNamespace(covered_ips=lambda: covered["value"]),
    )
    watchdog = ProactiveMonitor(tmp_path)
    emitted: list[dict] = []
    watchdog._emit = lambda **record: emitted.append(record)  # type: ignore[method-assign]

    asyncio.run(watchdog._check_stealth_ipv6())
    asyncio.run(watchdog._check_stealth_ipv6())
    assert [record["severity"] for record in emitted] == ["warning"]
    assert "2001:db8:1::/64" in emitted[0]["message"]
    assert emitted[0]["event_id"] == "watchdog:stealth-ipv6"

    routers.clear()
    asyncio.run(watchdog._check_stealth_ipv6())
    assert [record["severity"] for record in emitted] == ["warning", "success"]

    # Without devices on Stealth, IPv6 on the LAN is not a Stealth bypass.
    routers.append({"router_mac": "AA:BB:CC:DD:EE:01", "global_prefixes": ["2001:db8:1::/64"], "managed": False})
    covered["value"] = (False, set())
    asyncio.run(watchdog._check_stealth_ipv6())
    assert len(emitted) == 2
    assert monitor_module.ProactiveMonitor is ProactiveMonitor
