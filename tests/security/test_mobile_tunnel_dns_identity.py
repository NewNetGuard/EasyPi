"""The DNS filter must recognise an approved Mobile home-tunnel phone.

A tunnel phone has no neighbour (ARP) entry, so without the peer registry the
filter saw no MAC, treated the phone as an unknown device and refused every
DNS answer while Protection was on.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from app.services.unknown_device_admission_service import (
    UnknownDeviceAdmissionService,
)
from easypi_netprotection.profiles.manager import ProfileManager
from easypi_netprotection.profiles.mobile_tunnel import (
    MobileTunnelPeers,
    mobile_tunnel_mac,
)
from easypi_netprotection.server import NetProtectionServer

PHONE_ID = "3f1c2b7e-8d4a-4c55-9b0e-2a6f1d9c7e41"
PHONE_IP = "10.77.0.3"


def _write_registry(data_dir: Path, devices: list[dict[str, str]]) -> None:
    (data_dir / "mobile-home-tunnel-peers.json").write_text(
        json.dumps({"version": 1, "devices": devices}), encoding="utf-8"
    )


def _server(data_dir: Path) -> NetProtectionServer:
    server = object.__new__(NetProtectionServer)
    server._mobile_tunnel_peers = MobileTunnelPeers(data_dir)
    return server


def test_pseudo_mac_matches_the_admission_firewall() -> None:
    assert (
        mobile_tunnel_mac(PHONE_ID)
        == UnknownDeviceAdmissionService.mobile_tunnel_mac(PHONE_ID).lower()
    )


def test_approved_tunnel_phone_is_a_known_device(tmp_path: Path) -> None:
    _write_registry(tmp_path, [{"id": PHONE_ID, "address": PHONE_IP}])
    manager = ProfileManager(tmp_path)
    profile = manager.create_profile("Device policy: phone (mobile)")
    manager.create_binding(
        profile.id, "mac", mobile_tunnel_mac(PHONE_ID), name="phone (mobile)"
    )
    manager.create_binding(profile.id, "ip", PHONE_IP, name="phone (mobile)")

    mac = asyncio.run(_server(tmp_path)._resolve_client_mac(PHONE_IP))

    assert mac == mobile_tunnel_mac(PHONE_ID)
    assert manager.is_known_device(PHONE_IP, mac) is True


def test_address_not_in_registry_stays_unknown(tmp_path: Path) -> None:
    _write_registry(tmp_path, [{"id": PHONE_ID, "address": PHONE_IP}])
    server = _server(tmp_path)

    assert asyncio.run(server._resolve_client_mac("10.77.0.4")) is None


def test_removed_phone_loses_identity_on_next_query(tmp_path: Path) -> None:
    _write_registry(tmp_path, [{"id": PHONE_ID, "address": PHONE_IP}])
    server = _server(tmp_path)
    assert asyncio.run(server._resolve_client_mac(PHONE_IP)) is not None

    _write_registry(tmp_path, [])

    assert asyncio.run(server._resolve_client_mac(PHONE_IP)) is None


def test_invalid_registry_admits_no_tunnel_peer(tmp_path: Path) -> None:
    # A duplicate address makes the whole registry invalid, as in the firewall.
    _write_registry(
        tmp_path,
        [
            {"id": PHONE_ID, "address": PHONE_IP},
            {"id": "6852f92f-9750-4567-bcfd-0e3374f8d0b0", "address": PHONE_IP},
        ],
    )

    assert asyncio.run(_server(tmp_path)._resolve_client_mac(PHONE_IP)) is None


def test_missing_registry_admits_no_tunnel_peer(tmp_path: Path) -> None:
    assert asyncio.run(_server(tmp_path)._resolve_client_mac(PHONE_IP)) is None
