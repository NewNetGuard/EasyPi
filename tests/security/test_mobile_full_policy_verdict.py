"""A phone filtering outside the home tunnel gets the complete NetProtection
policy for every domain it asks about, not a reduced copy, and only for an
enrolled home-tunnel identity."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import dns.message
import pytest
from aiohttp.test_utils import TestClient, TestServer

from easypi_netprotection.chronicle.flow_log import FlowStatus
from easypi_netprotection.mobile_verdict import (
    VERDICT_PATH,
    MobileVerdictListener,
    normalize_domain,
)
from easypi_netprotection.profiles.mobile_tunnel import MobileTunnelPeers
from easypi_netprotection.server import NetProtectionServer, QueryOutcome

PHONE_ID = "3f1c2b7e-8d4a-4c55-9b0e-2a6f1d9c7e41"
PHONE_IP = "10.77.0.3"


def _server(tmp_path: Path, status: FlowStatus | None, seen: list) -> NetProtectionServer:
    (tmp_path / "mobile-home-tunnel-peers.json").write_text(
        json.dumps({"version": 1, "devices": [{"id": PHONE_ID, "address": PHONE_IP}]}),
        encoding="utf-8",
    )
    server = object.__new__(NetProtectionServer)
    server._mobile_tunnel_peers = MobileTunnelPeers(tmp_path)

    async def outcome(data: bytes, client_addr, protocol: str) -> QueryOutcome:
        query = dns.message.from_wire(data)
        seen.append((str(query.question[0].name), client_addr[0], protocol))
        return QueryOutcome(b"wire", status)

    server.handle_dns_query_outcome = outcome
    return server


def test_enrolled_phone_gets_the_regular_query_path_decision(tmp_path: Path) -> None:
    seen: list = []
    server = _server(tmp_path, FlowStatus.BLOCKED, seen)

    result = asyncio.run(server.resolve_mobile_verdict("ads.example", PHONE_IP))

    assert result == (True, "blocked")
    # Same identity and same path as the phone's DNS inside the home tunnel.
    assert seen == [("ads.example.", PHONE_IP, "mobile")]


def test_allowed_and_rewritten_names_are_not_blocked(tmp_path: Path) -> None:
    for status in (FlowStatus.UPSTREAM, FlowStatus.REDIRECTED, FlowStatus.FAILED):
        server = _server(tmp_path, status, [])
        assert asyncio.run(server.resolve_mobile_verdict("site.example", PHONE_IP)) == (
            False,
            status.value,
        )


def test_no_decision_is_an_error_not_an_allow(tmp_path: Path) -> None:
    server = _server(tmp_path, None, [])

    with pytest.raises(RuntimeError):
        asyncio.run(server.resolve_mobile_verdict("site.example", PHONE_IP))


@pytest.mark.parametrize("address", ["10.77.0.4", "192.168.1.20", "127.0.0.1"])
def test_only_an_enrolled_tunnel_identity_can_be_asked_for(tmp_path: Path, address: str) -> None:
    seen: list = []
    server = _server(tmp_path, FlowStatus.UPSTREAM, seen)

    assert asyncio.run(server.resolve_mobile_verdict("site.example", address)) is None
    assert seen == []


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("xn--e1afmkfd.xn--p1ai", "xn--e1afmkfd.xn--p1ai"),
        ("localhost", None),
        ("-bad.example", None),
        ("a" * 64 + ".example", None),
        ("пример.рф", None),
        ("exa mple.com", None),
        (5, None),
    ],
)
def test_domain_validation(value, expected) -> None:
    assert normalize_domain(value) == expected


def test_listener_protocol(tmp_path: Path) -> None:
    calls: list = []

    async def resolver(domain: str, client_ip: str):
        calls.append((domain, client_ip))
        return None if client_ip == "10.77.0.9" else (True, "blocked")

    listener = MobileVerdictListener(tmp_path, resolver)

    async def run() -> None:
        async with TestClient(TestServer(listener.build_app())) as client:
            ok = await client.post(VERDICT_PATH, json={"domain": "Ads.Example", "client_ip": PHONE_IP})
            assert ok.status == 200
            assert await ok.json() == {"domain": "ads.example", "blocked": True, "status": "blocked"}

            unknown = await client.post(VERDICT_PATH, json={"domain": "a.example", "client_ip": "10.77.0.9"})
            assert unknown.status == 403

            for body in (
                {"domain": "localhost", "client_ip": PHONE_IP},
                {"domain": "a.example"},
                {"domain": "a.example", "client_ip": PHONE_IP, "extra": 1},
                ["a.example"],
            ):
                bad = await client.post(VERDICT_PATH, json=body)
                assert bad.status == 400

    asyncio.run(run())
    assert calls == [("ads.example", PHONE_IP), ("a.example", "10.77.0.9")]


def test_listener_refuses_to_replace_a_regular_file(tmp_path: Path) -> None:
    (tmp_path / "verdict.sock").write_text("not a socket", encoding="utf-8")
    listener = MobileVerdictListener(tmp_path, lambda *_: None)

    with pytest.raises(RuntimeError):
        listener._remove_stale_socket()


def _device(state: str = "active") -> SimpleNamespace:
    return SimpleNamespace(home_tunnel_state=state, home_tunnel_address=f"{PHONE_IP}/32")


def test_phone_check_uses_the_full_policy(monkeypatch) -> None:
    from app.api.v1.endpoints import mobile
    from app.services.mobile_verdict_client import MobileVerdict

    asked: list = []

    def full(domain: str, address: str):
        asked.append((domain, address))
        return MobileVerdict(blocked=True, status="blocked")

    monkeypatch.setattr(mobile, "full_policy_verdict", full)
    request = mobile.PrismDnsCheckRequest(domain="games.example")

    response = mobile.prism_dns_check(request, _device())

    assert asked == [("games.example", PHONE_IP)]
    assert response.blocked is True
    assert response.reason == "easypi_policy"
    assert response.cache_ttl_seconds == 60
    assert len(response.policy_version) == 16


def test_phone_check_falls_back_when_netprotection_is_unreachable(monkeypatch) -> None:
    from app.api.v1.endpoints import mobile

    monkeypatch.setattr(mobile, "full_policy_verdict", lambda *_: None)
    monkeypatch.setattr(
        mobile, "get_profile_manager",
        lambda: SimpleNamespace(lookup_profile=lambda _address: None),
    )
    blocklist = SimpleNamespace(
        reload_if_changed=lambda: None,
        is_blocked=lambda domain, check_allowlist: domain == "ads.example",
    )
    monkeypatch.setattr(mobile, "get_blocklist_filter", lambda: blocklist)

    blocked = mobile.prism_dns_check(mobile.PrismDnsCheckRequest(domain="ads.example"), _device())
    allowed = mobile.prism_dns_check(mobile.PrismDnsCheckRequest(domain="site.example"), _device())

    assert (blocked.blocked, blocked.reason) == (True, "easypi_blocklist")
    assert (allowed.blocked, allowed.reason) == (False, "allowed")


def test_phone_without_home_tunnel_never_impersonates_an_address(monkeypatch) -> None:
    from app.api.v1.endpoints import mobile

    def must_not_be_called(*_args):
        raise AssertionError("no tunnel identity, no full-policy question")

    monkeypatch.setattr(mobile, "full_policy_verdict", must_not_be_called)
    blocklist = SimpleNamespace(reload_if_changed=lambda: None, is_blocked=lambda *_a, **_k: False)
    monkeypatch.setattr(mobile, "get_blocklist_filter", lambda: blocklist)

    response = mobile.prism_dns_check(
        mobile.PrismDnsCheckRequest(domain="site.example"), _device(state="pending")
    )

    assert response.blocked is False


def test_client_reports_unavailable_without_the_socket(tmp_path: Path, monkeypatch) -> None:
    from app.services import mobile_verdict_client

    monkeypatch.setattr(mobile_verdict_client, "get_netprotection_data_dir", lambda: tmp_path)

    assert mobile_verdict_client.full_policy_verdict("site.example", PHONE_IP) is None


def test_policy_version_changes_with_any_policy_file(tmp_path: Path, monkeypatch) -> None:
    from app.services import mobile_verdict_client

    monkeypatch.setattr(mobile_verdict_client, "get_netprotection_data_dir", lambda: tmp_path)
    profiles = tmp_path / "profiles.json"
    profiles.write_text("{}", encoding="utf-8")
    first = mobile_verdict_client.policy_version()
    assert first == mobile_verdict_client.policy_version()

    profiles.write_text('{"changed": true}', encoding="utf-8")
    second = mobile_verdict_client.policy_version()
    assert second != first

    (tmp_path / "schedules.json").write_text("[]", encoding="utf-8")
    assert mobile_verdict_client.policy_version() != second


def test_unrelated_files_do_not_flush_the_phone_cache(tmp_path: Path, monkeypatch) -> None:
    from app.services import mobile_verdict_client

    monkeypatch.setattr(mobile_verdict_client, "get_netprotection_data_dir", lambda: tmp_path)
    before = mobile_verdict_client.policy_version()
    (tmp_path / "flow_log.db").write_text("busy", encoding="utf-8")
    (tmp_path / "watchdog_events.jsonl").write_text("{}", encoding="utf-8")

    assert mobile_verdict_client.policy_version() == before
