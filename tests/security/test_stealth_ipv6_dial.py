"""Phones get the VPS's own public IPv6 endpoint to try before IPv4."""

from __future__ import annotations

from app.services.stealth_components.ssh import StealthSshMixin

IP_OUTPUT = """\
2: ens3    inet6 2001:db8:10::2/64 scope global \       valid_lft forever preferred_lft forever
2: ens3    inet6 2a01:4f8:1:2::5/64 scope global temporary dynamic \       valid_lft 600sec
2: ens3    inet6 2a01:4f8:1:2::7/64 scope global deprecated \       valid_lft 0sec
2: ens3    inet6 fd00:1::2/64 scope global \       valid_lft forever
2: ens3    inet6 2a01:4f8:1:2::2/64 scope global \       valid_lft forever preferred_lft forever
"""


def test_only_a_stable_public_ipv6_is_used() -> None:
    # Documentation (2001:db8::/32), temporary, deprecated and ULA addresses
    # are skipped; the first stable global unicast address wins.
    assert StealthSshMixin._parse_public_ipv6(IP_OUTPUT) == "2a01:4f8:1:2::2"


def test_no_public_ipv6_means_ipv4_only() -> None:
    assert StealthSshMixin._parse_public_ipv6("") == ""
    assert StealthSshMixin._parse_public_ipv6("2: ens3 inet6 fe80::1/64 scope link") == ""
    assert StealthSshMixin._parse_public_ipv6("inet6 not-an-address") == ""


def test_discovery_failure_keeps_ipv4_working() -> None:
    class Broken:
        def exec_command(self, *_args, **_kwargs):
            raise OSError("channel closed")

    assert StealthSshMixin._discover_public_ipv6(Broken()) == ""


def test_mobile_profile_offers_ipv6_first_only_when_known(monkeypatch) -> None:
    from app.services.stealth_service import StealthService

    service = StealthService()
    meta = {
        "server_address": "vpn.example:443",
        "psk_key": "11" * 32,
        "client_auth_key": "22" * 32,
        "reality_public": "33" * 32,
        "ssh": {"ip_shield_deployed": True, "public_ipv6": "2a01:4f8:1:2::2"},
    }
    monkeypatch.setattr(service, "_meta", lambda: meta)
    monkeypatch.setattr(service, "_ip_shield_address", lambda _meta: "198.51.100.7")
    device = "3f1c2b7e-8d4a-4c55-9b0e-2a6f1d9c7e41"

    profile = service.mobile_client_profile("10.10.0.3/32", device)
    assert profile["server_dial_address"] == "198.51.100.7:443"
    assert profile["server_dial_address6"] == "[2a01:4f8:1:2::2]:443"

    meta["ssh"]["public_ipv6"] = "fd00::1"
    assert service.mobile_client_profile("10.10.0.3/32", device)["server_dial_address6"] == ""
    del meta["ssh"]["public_ipv6"]
    assert service.mobile_client_profile("10.10.0.3/32", device)["server_dial_address6"] == ""


def test_learned_ipv6_survives_saving_and_loading_the_stealth_settings(tmp_path) -> None:
    # The settings loader keeps only known SSH fields; the learned address
    # must be one of them or phones never receive it.
    from app.services.stealth_service import StealthService

    service = StealthService()
    service._data_dir = tmp_path
    service._meta_path = tmp_path / "stealth_meta.json"
    meta = service._meta()
    assert meta["ssh"]["public_ipv6"] == ""
    meta["ssh"]["public_ipv6"] = "2a01:4f8:1:2::2"
    service._save_meta(meta)

    assert service._meta()["ssh"]["public_ipv6"] == "2a01:4f8:1:2::2"
