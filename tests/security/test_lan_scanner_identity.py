from __future__ import annotations

import asyncio
import io
import json
import socket
from types import SimpleNamespace

import psutil

from app.schemas.network import NetworkHost
from app.schemas.network_toolkit import LANDevice
from app.services.native_scanner_components import scanner as scanner_module
from app.services.native_scanner_components.scanner import NativeNetworkScanner
from app.services.network_toolkit_components.discovery import NetworkDiscoveryMixin
from app.utils.time import utc_now


def test_own_interfaces_are_grouped_as_one_easypi(monkeypatch) -> None:
    link = getattr(psutil, "AF_LINK")
    monkeypatch.setattr(
        psutil,
        "net_if_addrs",
        lambda: {
            "eth0": [
                SimpleNamespace(family=link, address="02:00:00:00:01:03"),
                SimpleNamespace(family=socket.AF_INET, address="10.23.1.25"),
            ],
            "wlan0": [
                SimpleNamespace(family=link, address="02:00:00:00:01:04"),
                SimpleNamespace(family=socket.AF_INET, address="10.23.1.24"),
            ],
        },
    )
    rows = [
        LANDevice(
            id=ip,
            ip=ip,
            mac=mac,
            hostname="easypi.local",
            status="online",
            lastSeen=utc_now(),
            ports=[22, 53, 443],
            deviceType="pi",
        )
        for ip, mac in (
            ("10.23.1.24", "02:00:00:00:01:04"),
            ("10.23.1.25", "02:00:00:00:01:03"),
        )
    ]

    merged = NetworkDiscoveryMixin()._merge_local_device_rows(
        rows, "10.23.1.0/24"
    )

    assert len(merged) == 1
    assert merged[0].id == "local-easypi"
    assert merged[0].isLocalDevice is True
    assert {item["ip"] for item in merged[0].interfaces} == {
        "10.23.1.24",
        "10.23.1.25",
    }


def test_strong_identity_clues_override_ambiguous_huawei_vendor() -> None:
    scanner = NetworkDiscoveryMixin()
    windows_host = NetworkHost(
        ip="10.23.1.26",
        mac="02:00:00:00:01:08",
        vendor="Huawei",
        dhcp_vendor_class="MSFT 5.0",
    )
    phone = NetworkHost(
        ip="10.23.1.27",
        mac="02:00:00:00:01:09",
        vendor="Huawei",
        hostname="android-phone",
    )
    ambiguous = NetworkHost(
        ip="10.23.1.28",
        mac="02:00:00:00:01:0A",
        vendor="Huawei",
    )

    assert scanner._guess_device_type(windows_host) == "computer"
    assert scanner._guess_device_type(phone) == "phone"
    assert scanner._guess_device_type(ambiguous) == "unknown"


def test_failed_proc_arp_entry_is_not_reported_as_online(monkeypatch) -> None:
    arp_table = (
        "IP address HW type Flags HW address Mask Device\n"
        "10.23.1.22 0x1 0x2 02:00:00:00:01:01 * eth0\n"
        "10.23.1.23 0x1 0x0 02:00:00:00:01:02 * eth0\n"
    )
    real_open = open

    def fake_open(path, *args, **kwargs):
        if str(path) == "/host_proc_net_arp":
            raise FileNotFoundError(path)
        if str(path) == "/proc/net/arp":
            return io.StringIO(arp_table)
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(scanner_module, "resolve_arp_scan_binary", lambda: None)
    monkeypatch.setattr("builtins.open", fake_open)

    entries = asyncio.run(NativeNetworkScanner()._get_arp_cache())

    assert entries == {"10.23.1.22": "02:00:00:00:01:01"}


def test_cached_device_uses_live_prism_mac_alias(monkeypatch) -> None:
    scanner = NetworkDiscoveryMixin()
    scanner._last_scan_devices = [
        {
            "ip": "10.23.1.18",
            "mac": "02:00:00:00:01:06",
            "hostname": "Childs Phone",
        }
    ]
    scanner._last_scan_time = utc_now()
    monkeypatch.setattr(
        scanner, "_default_gateway_ip", lambda: "10.23.1.1", raising=False
    )
    monkeypatch.setattr(scanner, "_own_ipv4_addresses", lambda: set(), raising=False)
    monkeypatch.setattr(
        scanner,
        "_live_ipv4_by_mac",
        lambda: {"02:00:00:00:01:0c": "10.23.1.17"},
    )
    monkeypatch.setattr(
        scanner,
        "_retired_prism_aliases",
        lambda: {"02:00:00:00:01:06": "02:00:00:00:01:0c"},
    )

    result = asyncio.run(scanner.get_cached_devices())

    assert result["devices"] == [
        {
            "ip": "10.23.1.17",
            "mac": "02:00:00:00:01:0c",
            "hostname": "Childs Phone",
            "is_online": True,
            "last_seen": result["devices"][0]["last_seen"],
            "is_router": False,
        }
    ]


def test_live_retired_alias_is_not_silently_reassigned(monkeypatch) -> None:
    scanner = NetworkDiscoveryMixin()
    scanner._last_scan_devices = [
        {
            "ip": "10.23.1.18",
            "mac": "02:00:00:00:01:06",
            "hostname": "Childs Phone",
        }
    ]
    scanner._last_scan_time = utc_now()
    monkeypatch.setattr(
        scanner, "_default_gateway_ip", lambda: "10.23.1.1", raising=False
    )
    monkeypatch.setattr(scanner, "_own_ipv4_addresses", lambda: set(), raising=False)
    monkeypatch.setattr(
        scanner,
        "_live_ipv4_by_mac",
        lambda: {
            "02:00:00:00:01:06": "10.23.1.18",
            "02:00:00:00:01:0c": "10.23.1.17",
        },
    )
    monkeypatch.setattr(
        scanner,
        "_retired_prism_aliases",
        lambda: {"02:00:00:00:01:06": "02:00:00:00:01:0c"},
    )

    result = asyncio.run(scanner.get_cached_devices())

    assert result["devices"][0]["mac"] == "02:00:00:00:01:06"
    assert result["devices"][0]["ip"] == "10.23.1.18"
    assert result["devices"][0]["is_online"] is True


def test_approved_device_is_available_without_lan_scan(monkeypatch, tmp_path) -> None:
    scanner = NetworkDiscoveryMixin()
    clients_path = tmp_path / "clients.json"
    clients_path.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "name": "Child Phone",
                        "ip": "10.23.1.16",
                        "mac": "02:00:00:00:01:07",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    scanner.MANAGED_DEVICE_PATHS = (clients_path,)
    scanner._last_scan_devices = []
    scanner._last_scan_time = None
    monkeypatch.setattr(scanner, "_load_scan_cache", lambda: ([], None))
    monkeypatch.setattr(
        scanner, "_default_gateway_ip", lambda: "10.23.1.1", raising=False
    )
    monkeypatch.setattr(
        scanner,
        "_own_ipv4_addresses",
        lambda: {"10.23.1.25"},
        raising=False,
    )
    monkeypatch.setattr(scanner, "_live_ipv4_by_mac", lambda: {})
    monkeypatch.setattr(scanner, "_retired_prism_aliases", lambda: {})

    result = asyncio.run(scanner.get_cached_devices())

    assert result["devices"] == [
        {
            "ip": "10.23.1.16",
            "mac": "02:00:00:00:01:07",
            "hostname": "Child Phone",
            "vendor": None,
            "source": "managed",
            "is_online": False,
            "is_router": False,
        }
    ]
    assert result["last_scan_time"] is None


def test_approved_device_enriches_scan_and_uses_live_ip(monkeypatch, tmp_path) -> None:
    scanner = NetworkDiscoveryMixin()
    clients_path = tmp_path / "clients.json"
    clients_path.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "name": "Family Laptop",
                        "ip": "10.23.1.19",
                        "mac": "02:00:00:00:01:08",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    scanner.MANAGED_DEVICE_PATHS = (clients_path,)
    scanner._last_scan_devices = [
        {
            "ip": "10.23.1.19",
            "mac": "02:00:00:00:01:08",
            "hostname": "old-hostname",
            "vendor": "Huawei",
        }
    ]
    scanner._last_scan_time = utc_now()
    monkeypatch.setattr(
        scanner, "_default_gateway_ip", lambda: "10.23.1.1", raising=False
    )
    monkeypatch.setattr(scanner, "_own_ipv4_addresses", lambda: set(), raising=False)
    monkeypatch.setattr(
        scanner,
        "_live_ipv4_by_mac",
        lambda: {"02:00:00:00:01:08": "10.23.1.20"},
    )
    monkeypatch.setattr(scanner, "_retired_prism_aliases", lambda: {})

    result = asyncio.run(scanner.get_cached_devices())
    device = result["devices"][0]

    assert device["hostname"] == "Family Laptop"
    assert device["vendor"] == "Huawei"
    assert device["ip"] == "10.23.1.20"
    assert device["source"] == "managed+scan"
    assert device["is_online"] is True


def test_approved_prism_identity_wins_stale_scan_alias(monkeypatch, tmp_path) -> None:
    scanner = NetworkDiscoveryMixin()
    clients_path = tmp_path / "clients.json"
    clients_path.write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "name": "Child Phone",
                        "ip": "10.23.1.17",
                        "mac": "02:00:00:00:01:0C",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    scanner.MANAGED_DEVICE_PATHS = (clients_path,)
    scanner._last_scan_devices = [
        {
            "ip": "10.23.1.18",
            "mac": "02:00:00:00:01:06",
            "hostname": "stale-name",
        }
    ]
    scanner._last_scan_time = utc_now()
    monkeypatch.setattr(
        scanner, "_default_gateway_ip", lambda: "10.23.1.1", raising=False
    )
    monkeypatch.setattr(scanner, "_own_ipv4_addresses", lambda: set(), raising=False)
    monkeypatch.setattr(
        scanner,
        "_live_ipv4_by_mac",
        lambda: {"02:00:00:00:01:0c": "10.23.1.17"},
    )
    monkeypatch.setattr(
        scanner,
        "_retired_prism_aliases",
        lambda: {"02:00:00:00:01:06": "02:00:00:00:01:0c"},
    )

    result = asyncio.run(scanner.get_cached_devices())

    assert len(result["devices"]) == 1
    assert result["devices"][0]["hostname"] == "Child Phone"
    assert result["devices"][0]["mac"] == "02:00:00:00:01:0c"
