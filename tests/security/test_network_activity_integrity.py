from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import sqlite3
import struct
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import dns.message
import pytest

from app.api.v1.endpoints import network_activity
from app.services import dhcp_identity
from app.services.dhcp_identity import (
    DHCPAddressBinding,
    DHCPIdentity,
    load_dhcp_address_bindings,
    load_dhcp_identities,
)
from app.services.dhcp_observer import (
    PACKET_HOST,
    PACKET_OUTGOING,
    CaptureScope,
    DHCPObservationStore,
    parse_dhcp_frame,
    parse_capture_scopes,
    parse_ipv4_source_frame,
    process_captured_frame,
)
from app.services.netprotection_service import NetProtectionService
from app.services.netprotection_components.settings import SettingsMixin
from easypi_netprotection.healthcheck import (
    RESOLVER_HEALTHCHECK_DOMAIN,
    is_internal_resolver_healthcheck,
)
from easypi_netprotection.server import NetProtectionServer, ServerStats


def _client_id(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


TEST_LAN_NETWORKS = (ipaddress.IPv4Network("10.23.1.0/24"),)


@pytest.fixture
def observed_now(monkeypatch) -> float:
    """Keep freshness assertions independent of system-clock resolution/jumps."""
    now = 1788100000.0
    monkeypatch.setattr(dhcp_identity, "time", SimpleNamespace(time=lambda: now))
    return now


def _dhcp_frame(
    *,
    bootp_op: int,
    source_port: int,
    destination_port: int,
    message_type: int,
    assigned_ip: str | None = None,
    requested_ip: str | None = None,
) -> bytes:
    payload = bytearray(240)
    payload[0] = bootp_op
    payload[1] = 1
    payload[2] = 6
    payload[28:34] = bytes.fromhex("020000000201")
    if assigned_ip:
        payload[16:20] = socket.inet_aton(assigned_ip)
    payload[236:240] = b"\x63\x82\x53\x63"
    options = bytearray((53, 1, message_type))
    if requested_ip:
        options.extend((50, 4))
        options.extend(socket.inet_aton(requested_ip))
    options.append(255)
    payload.extend(options)

    udp_length = 8 + len(payload)
    udp = struct.pack("!HHHH", source_port, destination_port, udp_length, 0)
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + udp_length)
    ip[9] = socket.IPPROTO_UDP
    ethernet = b"\x00" * 12 + struct.pack("!H", 0x0800)
    return ethernet + bytes(ip) + udp + bytes(payload)


def _ipv4_source_frame(
    *,
    source_mac: str = "02:00:00:00:01:05",
    source_ip: str = "10.23.1.32",
    source_port: int = 53000,
    destination_port: int = 53,
) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8, 0)
    ip = bytearray(20)
    ip[0] = 0x45
    struct.pack_into("!H", ip, 2, 20 + len(udp))
    ip[9] = socket.IPPROTO_UDP
    ip[12:16] = socket.inet_aton(source_ip)
    ip[16:20] = socket.inet_aton("10.23.1.21")
    ethernet = (
        bytes.fromhex("020000000202")
        + bytes.fromhex(source_mac.replace(":", ""))
        + struct.pack("!H", 0x0800)
    )
    return ethernet + bytes(ip) + udp


def _create_flow_log(path: Path) -> None:
    with sqlite3.connect(path) as db:
        db.execute(
            """
            CREATE TABLE flow_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                client_id TEXT NOT NULL,
                device_id TEXT,
                status TEXT NOT NULL,
                verdict TEXT NOT NULL,
                confidence INTEGER,
                response_ips TEXT,
                response_code TEXT,
                latency_ms REAL,
                cached INTEGER,
                upstream_used TEXT,
                evidence_summary TEXT,
                matcher_id TEXT,
                categories TEXT
            )
            """
        )
        now = datetime.now().isoformat()
        stale = (datetime.now() - timedelta(hours=25)).isoformat()
        rows = [
            (
                "allowed-flow",
                now,
                "allowed.example",
                "A",
                _client_id("10.23.1.31"),
                None,
                "upstream",
                "allow",
                100,
                "203.0.113.1",
                "NOERROR",
                1.0,
                0,
                "1.1.1.1",
                "",
                None,
                "[]",
            ),
            (
                "blocked-flow",
                now,
                "blocked.example",
                "A",
                _client_id("10.23.1.31"),
                None,
                "blocked",
                "deny",
                100,
                "",
                "NOERROR",
                1.0,
                0,
                None,
                "domain in blocklist",
                "test-rule",
                "[]",
            ),
            (
                "health-probe",
                now,
                "example.com",
                "A",
                _client_id("127.0.0.1"),
                None,
                "upstream",
                "allow",
                100,
                "93.184.216.34",
                "NOERROR",
                1.0,
                0,
                "1.1.1.1",
                "",
                None,
                "[]",
            ),
            (
                "unmapped-flow",
                now,
                "camera.example",
                "A",
                _client_id("10.23.2.10"),
                None,
                "blocked",
                "deny",
                100,
                "",
                "NOERROR",
                1.0,
                0,
                None,
                "domain in blocklist",
                "test-rule",
                "[]",
            ),
            (
                "stale-flow",
                stale,
                "stale.example",
                "A",
                _client_id("10.23.1.35"),
                None,
                "upstream",
                "allow",
                100,
                "203.0.113.2",
                "NOERROR",
                1.0,
                0,
                "1.1.1.1",
                "",
                None,
                "[]",
            ),
        ]
        db.executemany(
            """
            INSERT INTO flow_log (
                flow_id, timestamp, domain, query_type, client_id, device_id,
                status, verdict, confidence, response_ips, response_code,
                latency_ms, cached, upstream_used, evidence_summary, matcher_id,
                categories
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )


def test_query_log_and_device_activity_remain_usable(tmp_path: Path) -> None:
    db_path = tmp_path / "flow_log.db"
    _create_flow_log(db_path)

    service = NetProtectionService()
    service.flow_log_path = db_path

    async def get_clients():
        return {
            "clients": [
                {
                    "id": "phone",
                    "name": "Phone",
                    "ip": "10.23.1.31",
                }
            ]
        }

    async def get_devices():
        return []

    service.get_clients = get_clients
    service.get_devices = get_devices
    service._collect_lan_client_ips = lambda: {"127.0.0.1"}

    async def check() -> None:
        verdicts = await service.get_verdicts(
            client_ip="10.23.1.31",
            limit=20,
        )
        assert verdicts["total"] == 2
        assert len(verdicts["data"]) == 2
        blocked = next(item for item in verdicts["data"] if item["verdict"] == "deny")
        assert blocked["block_source_key"] == "blocklist"
        assert blocked["block_source"] == "Blocklist"

        without_system = await service.get_verdicts(
            limit=20,
            include_system=False,
        )
        assert without_system["total"] == 4
        assert all(
            item["client_id"] != _client_id("127.0.0.1")
            for item in without_system["data"]
        )

        devices = await service.get_active_devices(hours=24)
        assert [device["ip"] for device in devices] == ["10.23.1.31", ""]
        assert devices[0]["requestsCount"] == 2
        assert devices[0]["blockedCount"] == 1
        assert devices[0]["identityResolved"] is True
        assert devices[1]["name"] == f"Unresolved device {_client_id('10.23.2.10')[:8]}"
        assert devices[1]["client_id"] == _client_id("10.23.2.10")
        assert devices[1]["identityResolved"] is False
        assert devices[1]["requestsCount"] == 1
        assert devices[1]["blockedCount"] == 1
        assert all(device["client_id"] != _client_id("127.0.0.1") for device in devices)

        detail = await service.get_device_detail("10.23.1.31", period="24h")
        assert detail["totals"] == {"total": 2, "blocked": 1, "allowed": 1}

    asyncio.run(check())


def test_mobile_stats_only_include_the_requested_phone(tmp_path: Path) -> None:
    db_path = tmp_path / "flow_log.db"
    _create_flow_log(db_path)

    service = NetProtectionService()
    service.flow_log_path = db_path

    async def check() -> None:
        stats = await service.get_mobile_client_stats("10.23.1.31")

        assert stats["num_dns_queries"] == 2
        assert stats["num_blocked_filtering"] == 1
        assert sum(stats["dns_queries"]) == 2
        assert sum(stats["blocked_filtering"]) == 1
        assert stats["top_blocked_domains"] == {"blocked.example": 1}

    asyncio.run(check())


def test_resolver_healthcheck_is_loopback_only(
    monkeypatch,
) -> None:
    assert is_internal_resolver_healthcheck("127.0.0.1", RESOLVER_HEALTHCHECK_DOMAIN)
    assert is_internal_resolver_healthcheck(
        "::ffff:127.0.0.1", RESOLVER_HEALTHCHECK_DOMAIN
    )
    assert not is_internal_resolver_healthcheck(
        "10.23.1.31", RESOLVER_HEALTHCHECK_DOMAIN
    )
    assert not is_internal_resolver_healthcheck(
        "127.0.0.1", f"sub.{RESOLVER_HEALTHCHECK_DOMAIN}"
    )

    captured: dict[str, bytes] = {}

    class FakeSocket:
        def settimeout(self, _timeout: float) -> None:
            pass

        def sendto(self, data: bytes, _address) -> None:
            captured["query"] = data

        def recvfrom(self, _size: int):
            return captured["query"][:2] + b"\x81\x80", ("127.0.0.1", 53)

        def close(self) -> None:
            pass

    monkeypatch.setattr(socket, "socket", lambda *_args, **_kwargs: FakeSocket())
    assert SettingsMixin()._dns_probe("127.0.0.1", 53, 1.0)

    query = captured["query"]
    offset = 12
    labels: list[str] = []
    while query[offset]:
        length = query[offset]
        offset += 1
        labels.append(query[offset : offset + length].decode())
        offset += length
    assert ".".join(labels) == RESOLVER_HEALTHCHECK_DOMAIN


def test_resolver_healthcheck_does_not_change_server_counters() -> None:
    server = object.__new__(NetProtectionServer)
    server.stats = ServerStats()
    server._generate_flow_id = lambda: "health-test"
    query = dns.message.make_query(RESOLVER_HEALTHCHECK_DOMAIN, "A").to_wire()

    async def check() -> None:
        async def successful_upstream(_data: bytes, _client_ip: str) -> bytes:
            return b"upstream-response"

        server._direct_upstream_query = successful_upstream
        response = await server._process_dns_query(query, ("127.0.0.1", 53000), "udp")
        assert response == b"upstream-response"
        assert server.stats.to_dict() == ServerStats().to_dict()

        async def failed_upstream(_data: bytes, _client_ip: str) -> None:
            return None

        server._direct_upstream_query = failed_upstream
        server._make_error_response = lambda *_args: b"servfail"
        response = await server._process_dns_query(query, ("::1", 53000), "udp")
        assert response == b"servfail"
        assert server.stats.to_dict() == ServerStats().to_dict()

        server._is_safe_mode = lambda: True
        server._direct_upstream_query = successful_upstream
        normal_query = dns.message.make_query("ordinary.example", "A").to_wire()
        response = await server._process_dns_query(
            normal_query, ("10.23.1.31", 53000), "udp"
        )
        assert response == b"upstream-response"
        assert server.stats.total_queries == 1
        assert server.stats.udp_queries == 1
        assert server.stats.upstream_queries == 1
        assert server.stats.allowed_queries == 1
        assert server.stats.errors == 0

    asyncio.run(check())


def test_prism_activity_recovers_sites_missing_from_dns_log(tmp_path: Path) -> None:
    flowgraph_path = tmp_path / "flowgraph.jsonl"
    rows = [
        [],
        {
            "event": "flow_assessment",
            "timestamp": 1788099999.0,
            "flow": "tcp:10.23.1.32:39999>198.51.100.10:443",
            "session_id": 9,
            "client_ip": "10.23.1.32",
            "server_name": "broken.example",
            "revision": "not-an-integer",
            "verdict": "allow",
        },
        {
            "event": "flow_assessment",
            "timestamp": 1788100000.0,
            "flow": "tcp:10.23.1.32:40000>198.51.100.11:443",
            "session_id": 10,
            "client_ip": "10.23.1.32",
            "server_name": "news.example",
            "revision": 1,
            "verdict": "ambiguous",
        },
        {
            "event": "flow_assessment",
            "timestamp": 1788100001.0,
            "flow": "tcp:10.23.1.32:40000>198.51.100.11:443",
            "session_id": 10,
            "client_ip": "10.23.1.32",
            "server_name": "news.example",
            "revision": 2,
            "verdict": "allow",
        },
        {
            "event": "flow_assessment",
            "timestamp": 1788100002.0,
            "flow": "tcp:10.23.1.33:40001>203.0.113.5:443",
            "session_id": 11,
            "client_ip": "10.23.1.33",
            "server_name": "other.example",
            "revision": 1,
            "verdict": "allow",
        },
    ]
    flowgraph_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    service = NetProtectionService()
    service.prism_flowgraph_path = flowgraph_path

    activity = asyncio.run(
        service.get_prism_device_activity("10.23.1.32", limit=200)
    )
    assert len(activity) == 1
    assert activity[0]["domain"] == "news.example"
    assert activity[0]["source"] == "prism"
    assert activity[0]["queryType"] == "TLS"
    assert activity[0]["status"] == "observed"
    assert activity[0]["client_ip"] == "10.23.1.32"


def test_global_prism_activity_is_bounded_and_excludes_loopback(tmp_path: Path) -> None:
    flowgraph_path = tmp_path / "flowgraph.jsonl"
    base = {
        "event": "flow_assessment",
        "timestamp": 1788100000.0,
        "flow": "tcp:10.23.1.32:40000>198.51.100.11:443",
        "session_id": 10,
        "client_ip": "10.23.1.32",
        "server_name": "phone.example",
        "revision": 1,
        "verdict": "allow",
    }
    rows = [
        base,
        {
            **base,
            "timestamp": 1788100001.0,
            "flow": "tcp:10.23.1.33:40001>198.51.100.12:443",
            "session_id": 11,
            "client_ip": "10.23.1.33",
            "server_name": "tablet.example",
        },
        {
            **base,
            "timestamp": 1788100002.0,
            "flow": "tcp:127.0.0.1:40002>198.51.100.13:443",
            "session_id": 12,
            "client_ip": "127.0.0.1",
            "server_name": "internal.example",
        },
    ]
    flowgraph_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    service = NetProtectionService()
    service.prism_flowgraph_path = flowgraph_path
    activity = asyncio.run(service.get_prism_activity(limit=1))

    assert len(activity) == 1
    assert activity[0]["domain"] == "tablet.example"
    assert activity[0]["client_ip"] == "10.23.1.33"


def test_global_prism_endpoint_requires_valid_sanitized_rows(monkeypatch) -> None:
    class FakePrismService:
        async def get_prism_activity(self, limit: int):
            assert limit == 200
            return [
                {
                    "id": "prism-one",
                    "timestamp": "2026-08-30T16:00:00",
                    "domain": "site.example",
                    "queryType": "TLS",
                    "status": "observed",
                    "source": "prism",
                    "reason": "observed",
                    "client_ip": "10.23.1.32",
                },
                {
                    "id": "prism-invalid",
                    "timestamp": "2026-08-30T16:00:01",
                    "domain": "invalid.example",
                    "client_ip": "not-an-ip",
                },
            ]

    monkeypatch.setattr(network_activity, "netprotection_service", FakePrismService())
    result = asyncio.run(network_activity.get_prism_activity(limit=200, _admin=object()))

    assert result["total"] == 1
    assert result["data"][0]["client_ip"] == "10.23.1.32"
    assert result["data"][0]["source"] == "prism"


def test_device_traffic_combines_dns_and_prism_activity(monkeypatch) -> None:
    class FakeNetProtectionService:
        async def get_verdicts(self, **_kwargs):
            return {
                "data": [
                    {
                        "flow_id": "dns-flow",
                        "time": "2026-08-30T16:00:00.000000",
                        "domain": "dns.example",
                        "query_type": "A",
                        "status": "upstream",
                        "verdict": "allow",
                        "reason": "",
                        "latency_ms": 2.0,
                        "response": [],
                    }
                ]
            }

        async def get_prism_device_activity(self, _client_ip: str, limit: int):
            assert limit == 200
            return [
                {
                    "id": "prism-flow",
                    "timestamp": "2026-08-30T16:00:01.000000",
                    "domain": "site.example",
                    "queryType": "TLS",
                    "status": "observed",
                    "source": "prism",
                    "reason": "Hostname observed in encrypted traffic by Prisma DPI",
                }
            ]

        async def get_device_detail(self, _client_ip: str, period: str):
            assert period == "24h"
            return {
                "totals": {"total": 1, "blocked": 0, "allowed": 1},
                "topQueried": [],
                "topBlocked": [],
            }

    monkeypatch.setattr(
        network_activity, "netprotection_service", FakeNetProtectionService()
    )
    result = asyncio.run(
        network_activity.get_device_traffic(
            "10.23.1.32", limit=200, _admin=object()
        )
    )

    assert [item["domain"] for item in result["recentQueries"]] == [
        "site.example",
        "dns.example",
    ]
    assert result["recentQueries"][0]["source"] == "prism"
    assert result["recentQueries"][1]["source"] == "dns"


def test_device_traffic_keeps_dns_log_when_prism_reader_fails(monkeypatch) -> None:
    class FailingPrismService:
        async def get_verdicts(self, **_kwargs):
            return {
                "data": [
                    {
                        "flow_id": "dns-flow",
                        "time": "2026-08-30T16:00:00.000000",
                        "domain": "still-visible.example",
                        "query_type": "A",
                        "status": "upstream",
                        "verdict": "allow",
                        "reason": "",
                        "latency_ms": 2.0,
                        "response": [],
                    }
                ]
            }

        async def get_prism_device_activity(self, _client_ip: str, limit: int):
            raise ValueError("corrupt telemetry")

        async def get_device_detail(self, _client_ip: str, period: str):
            return {
                "totals": {"total": 1, "blocked": 0, "allowed": 1},
                "topQueried": [],
                "topBlocked": [],
            }

    monkeypatch.setattr(network_activity, "netprotection_service", FailingPrismService())
    result = asyncio.run(
        network_activity.get_device_traffic(
            "10.23.1.32", limit=200, _admin=object()
        )
    )
    assert [item["domain"] for item in result["recentQueries"]] == [
        "still-visible.example"
    ]
    assert result["recentQueries"][0]["source"] == "dns"


def test_domain_connections_keep_sites_and_separate_service_traffic() -> None:
    service = NetProtectionService()
    rows = [
        (100.0, "www.google.com", "upstream"),
        # A phone's background traffic immediately before a real navigation
        # must not be treated as a lack of network-wide idle time.
        (155.0, "graph.facebook.com", "upstream"),
        (160.0, "news.example", "upstream"),
        (161.0, "cdn.news.example", "upstream"),
        (162.0, "fonts.googleapis.com", "upstream"),
        (164.0, "analytics.example.net", "upstream"),
        (200.0, "g.whatsapp.net", "upstream"),
        (201.0, "media.whatsapp.net", "upstream"),
        (202.0, "static.whatsapp.net", "upstream"),
        (203.0, "edge.whatsapp.net", "upstream"),
        (240.0, "blocked.example", "blocked"),
        (244.0, "failed.example", "failed"),
        (245.0, "redirected.example", "redirected"),
        (246.0, "cached.example", "cached"),
        (247.0, "allowed.example", "allowed"),
        (248.0, "retry.example", "failed"),
        (248.2, "retry.example", "upstream"),
        (241.0, "cdn.blocked.example", "upstream"),
        (242.0, "static.blocked.example", "upstream"),
        (243.0, "media.blocked.example", "upstream"),
        (300.0, "www.google.com", "upstream"),
        (360.0, "www.google.com", "upstream"),
        (400.0, "mail.google.com", "upstream"),
        (401.0, "inbox.google.com", "upstream"),
        (402.0, "accounts.google.com", "upstream"),
        (403.0, "fonts.googleapis.com", "upstream"),
    ]

    activity = service._dns_domain_connections(rows)

    by_host = {item["host"]: item for item in activity}
    assert "blocked.example" not in by_host
    assert "failed.example" not in by_host
    assert "redirected.example" not in by_host
    assert by_host["cached.example"]["source"] == "dns"
    assert by_host["allowed.example"]["source"] == "dns"
    assert by_host["retry.example"]["source"] == "dns"
    assert by_host["news.example"]["domain"] == "news.example"
    assert by_host["news.example"]["traffic_class"] == "site"
    assert by_host["www.google.com"]["traffic_class"] == "site"
    assert by_host["mail.google.com"]["traffic_class"] == "service"
    assert by_host["inbox.google.com"]["traffic_class"] == "service"
    assert by_host["accounts.google.com"]["traffic_class"] == "service"
    assert by_host["fonts.googleapis.com"]["traffic_class"] == "service"
    assert by_host["graph.facebook.com"]["traffic_class"] == "service"
    assert all(item["source"] == "dns" for item in activity)


def test_domain_connections_include_tls_hosts_without_scoring_payload_shape(
    tmp_path: Path,
) -> None:
    flowgraph_path = tmp_path / "flowgraph.jsonl"

    def prism_row(
        flow: str,
        server_name: str,
        timestamp: float,
        *,
        root_server_name: bool = True,
        client_payload_bytes: int | str = 700,
        compact_client_hello: bool = True,
    ) -> dict:
        return {
            "event": "flow_assessment",
            "timestamp": timestamp,
            "flow": flow,
            "session_id": int(timestamp),
            "client_ip": "10.23.1.32",
            "server_name": server_name,
            "revision": 1,
            "verdict": "allow",
            "confidence": 0.7,
            "features": {
                "root_server_name": root_server_name,
                "compact_client_hello": compact_client_hello,
                "client_payload_bytes": client_payload_bytes,
                "server_payload_bytes": 15000,
                "first_client_application_record": 41,
                "first_server_application_record": 4090,
                "session_flow_count": 3,
                "session_distinct_sni": 2,
                "burst_flow_count": 4,
            },
        }

    rows = [
        prism_row("tcp:valid", "daily.example", 1788100100.0),
        prism_row(
            "tcp:large-hello",
            "news.example",
            1788100100.5,
            compact_client_hello=False,
        ),
        prism_row(
            "tcp:app-api",
            "graph.facebook.com",
            1788100101.0,
            root_server_name=False,
        ),
        prism_row("tcp:background", "yastatic.net", 1788100102.0),
        prism_row("tcp:gmail-sync", "mail.google.com", 1788100102.5),
        prism_row(
            "tcp:corrupt",
            "corrupt.example",
            1788100103.0,
            client_payload_bytes="broken",
        ),
    ]
    flowgraph_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )

    service = NetProtectionService()
    service.flow_log_path = tmp_path / "missing-flow-log.db"
    service.prism_flowgraph_path = flowgraph_path

    activity = asyncio.run(
        service.get_browsing_activity("10.23.1.32", limit=50)
    )

    assert [item["host"] for item in activity] == [
        "corrupt.example",
        "mail.google.com",
        "yastatic.net",
        "graph.facebook.com",
        "news.example",
        "daily.example",
    ]
    assert all(item["source"] == "tls" for item in activity)
    by_host = {item["host"]: item for item in activity}
    assert by_host["daily.example"]["traffic_class"] == "site"
    assert by_host["mail.google.com"]["traffic_class"] == "service"
    assert by_host["graph.facebook.com"]["traffic_class"] == "service"

    current_binding_only = asyncio.run(
        service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            device_identity="current-mac",
            since_epoch=1788100100.25,
        )
    )
    assert [item["host"] for item in current_binding_only] == [
        "corrupt.example",
        "mail.google.com",
        "yastatic.net",
        "graph.facebook.com",
        "news.example",
    ]


def test_domain_connections_merge_dns_and_tls_for_the_same_host() -> None:
    service = NetProtectionService()
    merged = service._merge_domain_connections(
        [
            {
                "id": "dns-event",
                "timestamp_epoch": 100.0,
                "timestamp": "1970-01-01T00:01:40",
                "domain": "daily.example",
                "host": "www.daily.example",
                "source": "dns",
                "traffic_class": "site",
            },
            {
                "id": "tls-event",
                "timestamp_epoch": 102.0,
                "timestamp": "1970-01-01T00:01:42",
                "domain": "daily.example",
                "host": "www.daily.example",
                "source": "tls",
                "traffic_class": "site",
            },
        ],
        200,
    )

    assert merged == [
        {
            "id": "dns-event",
            "timestamp": "1970-01-01T00:01:42",
            "domain": "daily.example",
            "host": "www.daily.example",
            "source": "dns+tls",
            "traffic_class": "site",
        }
    ]


def test_domain_connection_limit_is_applied_per_traffic_tab() -> None:
    service = NetProtectionService()
    activity = [
        {
            "id": f"service-{index}",
            "timestamp_epoch": float(1000 + index),
            "timestamp": datetime.fromtimestamp(1000 + index).isoformat(),
            "domain": "googleapis.com",
            "host": f"api-{index}.googleapis.com",
            "source": "dns",
            "traffic_class": "service",
        }
        for index in range(201)
    ]
    activity.append(
        {
            "id": "site",
            "timestamp_epoch": 999.0,
            "timestamp": datetime.fromtimestamp(999).isoformat(),
            "domain": "daily.example",
            "host": "daily.example",
            "source": "tls",
            "traffic_class": "site",
        }
    )

    merged = service._merge_domain_connections(activity, 200)

    assert len([row for row in merged if row["traffic_class"] == "service"]) == 200
    assert [row["host"] for row in merged if row["traffic_class"] == "site"] == [
        "daily.example"
    ]


def test_unlimited_prism_read_defers_limit_until_after_classification(
    tmp_path: Path,
) -> None:
    path = tmp_path / "flowgraph.jsonl"
    events = []
    for index in range(201):
        events.append(
            {
                "event": "flow_assessment",
                "timestamp": 2000.0 + index,
                "flow": f"tcp:service:{index}",
                "session_id": index + 1,
                "client_ip": "10.23.1.32",
                "server_name": f"api-{index}.googleapis.com",
                "revision": 1,
            }
        )
    events.insert(
        0,
        {
            "event": "flow_assessment",
            "timestamp": 1000.0,
            "flow": "tcp:site",
            "session_id": 999,
            "client_ip": "10.23.1.32",
            "server_name": "daily.example",
            "revision": 1,
        },
    )
    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    rows = NetProtectionService._read_prism_device_activity(
        path, "10.23.1.32", 0
    )

    assert len(rows) == 202
    assert any(row["domain"] == "daily.example" for row in rows)


def test_browsing_activity_cache_avoids_repeated_full_reads(monkeypatch) -> None:
    service = NetProtectionService()
    calls = 0

    async def build(address: str, since_epoch: float):
        nonlocal calls
        calls += 1
        assert address == "10.23.1.32"
        assert since_epoch in {1000.0, 2000.0}
        return [
            {
                "id": "cached",
                "timestamp": "2026-08-30T16:00:00",
                "domain": "daily.example",
                "host": "daily.example",
                "source": "tls",
                "traffic_class": "site",
            }
        ]

    monkeypatch.setattr(service, "_build_browsing_activity", build)

    async def check() -> None:
        first = await service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            device_identity="mac_one",
            since_epoch=1000.0,
        )
        first[0]["host"] = "caller-mutation.example"
        second = await service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            device_identity="mac_one",
            since_epoch=1000.0,
        )
        assert calls == 1
        assert second[0]["host"] == "daily.example"

        await service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            force_refresh=True,
            device_identity="mac_one",
            since_epoch=1000.0,
        )
        assert calls == 2
        await service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            force_refresh=True,
            device_identity="mac_one",
            since_epoch=1000.0,
        )
        assert calls == 2

        await service.get_browsing_activity(
            "10.23.1.32",
            limit=50,
            device_identity="mac_two",
            since_epoch=2000.0,
        )
        assert calls == 3

    asyncio.run(check())


def test_dhcp_observer_resets_current_ip_ownership_boundary(tmp_path: Path) -> None:
    store_path = tmp_path / "dhcp.json"
    store = DHCPObservationStore(store_path)
    base = {
        "mac": "02:00:00:00:01:05",
        "ipv4": "10.23.1.32",
        "observed_at": "2026-08-30T10:00:00+00:00",
        "observed_timestamp": 100.0,
        "message_type": "ack",
        "ownership_confirmed": True,
    }
    store.observe(base)
    assert store.devices[base["mac"]]["ip_first_seen_timestamp"] == 100.0

    store.observe(
        {
            **base,
            "observed_at": "2026-08-30T10:01:00+00:00",
            "observed_timestamp": 160.0,
        }
    )
    assert store.devices[base["mac"]]["ip_first_seen_timestamp"] == 100.0

    store.observe(
        {
            **base,
            "ipv4": "10.23.1.33",
            "message_type": "request",
            "ownership_confirmed": False,
            "observed_at": "2026-08-30T10:01:15+00:00",
            "observed_timestamp": 175.0,
        }
    )
    assert store.devices[base["mac"]]["ipv4"] == "10.23.1.32"
    assert store.devices[base["mac"]]["ip_first_seen_timestamp"] == 100.0
    assert store.address_owners["10.23.1.32"]["last_seen_timestamp"] == 160.0
    assert "10.23.1.33" not in store.address_owners

    second_mac = "22:33:44:55:66:77"
    store.observe(
        {
            **base,
            "mac": second_mac,
            "message_type": "request",
            "ownership_confirmed": False,
            "observed_at": "2026-08-30T10:01:30+00:00",
            "observed_timestamp": 190.0,
        }
    )
    assert second_mac in store.devices
    assert "ipv4" not in store.devices[second_mac]
    assert store.address_owners["10.23.1.32"]["mac"] == base["mac"]

    store.observe(
        {
            **base,
            "mac": second_mac,
            "observed_at": "2026-08-30T10:02:00+00:00",
            "observed_timestamp": 200.0,
        }
    )
    assert store.devices[second_mac]["ip_first_seen_timestamp"] == 200.0

    store.observe(
        {
            **base,
            "mac": second_mac,
            "ipv4": "10.23.1.33",
            "observed_at": "2026-08-30T10:03:00+00:00",
            "observed_timestamp": 250.0,
        }
    )
    assert store.devices[second_mac]["ip_first_seen_timestamp"] == 250.0
    store.flush()
    ownership = {
        identity.mac: identity.ownership_verified
        for identity in load_dhcp_identities((store_path,))
    }
    assert ownership[base["mac"]] is False
    assert ownership[second_mac] is True

    # The intermediate ownership of .246 must survive both the second phone
    # moving away and a process restart.
    reloaded = DHCPObservationStore(store_path)
    assert reloaded.address_owners["10.23.1.32"]["mac"] == second_mac
    reloaded.observe(
        {
            **base,
            "observed_at": "2026-08-30T10:04:00+00:00",
            "observed_timestamp": 300.0,
        }
    )
    assert reloaded.devices[base["mac"]]["ip_first_seen_timestamp"] == 300.0
    assert reloaded.address_owners["10.23.1.32"] == {
        "mac": base["mac"],
        "assigned_at_timestamp": 300.0,
        "last_seen_timestamp": 300.0,
    }


@pytest.mark.parametrize("legacy_version", [1, 2])
def test_dhcp_observer_migrates_legacy_store_fail_closed(
    tmp_path: Path, legacy_version: int
) -> None:
    path = tmp_path / "dhcp.json"
    path.write_text(
        json.dumps(
            {
                "version": legacy_version,
                "devices": [
                    {
                        "mac": "02:00:00:00:01:05",
                        "ipv4": "10.23.1.32",
                        "last_seen_timestamp": 500.0,
                        "ip_first_seen_timestamp": 100.0,
                    }
                ],
                "address_owners": {
                    "10.23.1.32": {
                        "mac": "02:00:00:00:01:05",
                        "assigned_at_timestamp": 100.0,
                        "last_seen_timestamp": 500.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert load_dhcp_identities((path,))[0].ownership_verified is False
    store = DHCPObservationStore(path)
    assert store.dirty is True
    assert store.address_owners == {}
    store.flush()

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 5
    assert payload["address_owners"] == {}
    assert load_dhcp_identities((path,))[0].ownership_verified is False

    store.observe(
        {
            "mac": "02:00:00:00:01:05",
            "ipv4": "10.23.1.32",
            "observed_at": "2026-08-30T10:10:00+00:00",
            "observed_timestamp": 600.0,
            "message_type": "ack",
            "ownership_confirmed": True,
        }
    )
    assert store.devices["02:00:00:00:01:05"]["ip_first_seen_timestamp"] == 600.0
    store.flush()
    identities = load_dhcp_identities((path,))
    assert len(identities) == 1
    assert identities[0].ownership_verified is True
    assert identities[0].ownership_last_seen_timestamp == 600.0
    assert identities[0].ip_first_seen_timestamp == 600.0


def test_dhcp_parser_confirms_ownership_only_from_server_ack() -> None:
    ack = parse_dhcp_frame(
        _dhcp_frame(
            bootp_op=2,
            source_port=67,
            destination_port=68,
            message_type=5,
            assigned_ip="10.23.1.32",
        ),
        observed_at=100.0,
    )
    assert ack is not None
    assert ack["ipv4"] == "10.23.1.32"
    assert ack["ownership_confirmed"] is True

    request = parse_dhcp_frame(
        _dhcp_frame(
            bootp_op=1,
            source_port=68,
            destination_port=67,
            message_type=3,
            requested_ip="10.23.1.32",
        ),
        observed_at=101.0,
    )
    assert request is not None
    assert request["ipv4"] == "10.23.1.32"
    assert request["ownership_confirmed"] is False

    forged_direction = parse_dhcp_frame(
        _dhcp_frame(
            bootp_op=2,
            source_port=68,
            destination_port=67,
            message_type=5,
            assigned_ip="10.23.1.32",
        ),
        observed_at=102.0,
    )
    assert forged_direction is None


def test_ipv4_source_parser_accepts_real_usage_and_rejects_dhcp_request() -> None:
    usage = parse_ipv4_source_frame(
        _ipv4_source_frame(),
        allowed_networks=TEST_LAN_NETWORKS,
        observed_at=100.0,
    )
    assert usage == {
        "mac": "02:00:00:00:01:05",
        "ipv4": "10.23.1.32",
        "observed_timestamp": 100.0,
    }
    assert (
        parse_ipv4_source_frame(
            _ipv4_source_frame(source_port=68, destination_port=67),
            allowed_networks=TEST_LAN_NETWORKS,
            observed_at=101.0,
        )
        is None
    )
    assert (
        parse_ipv4_source_frame(
            _ipv4_source_frame(source_ip="0.0.0.0"),
            allowed_networks=TEST_LAN_NETWORKS,
            observed_at=102.0,
        )
        is None
    )


def test_ipv4_source_parser_rejects_wan_and_easypi_addresses() -> None:
    local_addresses = frozenset({ipaddress.IPv4Address("10.23.1.21")})
    assert (
        parse_ipv4_source_frame(
            _ipv4_source_frame(source_ip="8.8.8.8"),
            allowed_networks=TEST_LAN_NETWORKS,
            local_addresses=local_addresses,
            observed_at=103.0,
        )
        is None
    )
    assert (
        parse_ipv4_source_frame(
            _ipv4_source_frame(source_ip="10.23.1.21"),
            allowed_networks=TEST_LAN_NETWORKS,
            local_addresses=local_addresses,
            observed_at=104.0,
        )
        is None
    )


def test_capture_scopes_are_private_directly_connected_and_fail_closed() -> None:
    payload = [
        {
            "ifname": "eth0",
            "addr_info": [
                {
                    "family": "inet",
                    "local": "10.23.1.21",
                    "prefixlen": 24,
                }
            ],
        },
        {
            "ifname": "docker0",
            "addr_info": [
                {"family": "inet", "local": "172.17.0.1", "prefixlen": 16}
            ],
        },
        {
            "ifname": "wan0",
            "addr_info": [
                {"family": "inet", "local": "192.168.1.10", "prefixlen": 24}
            ],
        },
    ]

    scopes = parse_capture_scopes(
        payload,
        default_route_interfaces=("wan0",),
    )
    assert scopes == (
        CaptureScope(
            interface="eth0",
            networks=TEST_LAN_NETWORKS,
            local_addresses=frozenset(
                {ipaddress.IPv4Address("10.23.1.21")}
            ),
        ),
    )
    assert parse_capture_scopes(
        payload,
        requested_interfaces=("eth0",),
        requested_networks=("10.23.1.0/25",),
    )[0].networks == (ipaddress.IPv4Network("10.23.1.0/25"),)
    with pytest.raises(RuntimeError, match="not directly connected"):
        parse_capture_scopes(
            payload,
            requested_interfaces=("eth0",),
            requested_networks=("10.23.2.0/24",),
        )


def test_mobile_tunnel_does_not_displace_shared_lan_gateway() -> None:
    def interface(name, address, link_type=None):
        return {
            "ifname": name,
            "link_type": link_type,
            "addr_info": [{"family": "inet", "local": address, "prefixlen": 24}],
        }

    scopes = parse_capture_scopes(
        [
            interface("eth0", "10.23.1.25", "ether"),
            interface("easypi-mobile0", "10.77.0.1"),
            interface("other-layer3", "10.78.0.1", "none"),
        ],
        default_route_interfaces=("eth0",),
    )
    assert [scope.interface for scope in scopes] == ["eth0"]


def test_packet_processing_ignores_outgoing_and_non_lan_traffic(
    tmp_path: Path,
) -> None:
    store = DHCPObservationStore(tmp_path / "dhcp.json")
    scope = CaptureScope(
        interface="eth0",
        networks=TEST_LAN_NETWORKS,
        local_addresses=frozenset({ipaddress.IPv4Address("10.23.1.21")}),
    )

    process_captured_frame(
        store,
        _ipv4_source_frame(),
        PACKET_OUTGOING,
        scope,
        observed_at=200.0,
    )
    process_captured_frame(
        store,
        _ipv4_source_frame(source_ip="8.8.8.8"),
        PACKET_HOST,
        scope,
        observed_at=201.0,
    )
    process_captured_frame(
        store,
        _ipv4_source_frame(source_ip="10.23.1.21"),
        PACKET_HOST,
        scope,
        observed_at=202.0,
    )
    assert store.address_bindings == {}

    process_captured_frame(
        store,
        _ipv4_source_frame(),
        PACKET_HOST,
        scope,
        observed_at=203.0,
    )
    assert store.address_bindings["10.23.1.32"] == {
        "mac": "02:00:00:00:01:05",
        "assigned_at_timestamp": 203.0,
        "last_seen_timestamp": 203.0,
    }


def test_v3_store_preserves_only_server_ack_as_binding(tmp_path: Path) -> None:
    path = tmp_path / "dhcp.json"
    path.write_text(
        json.dumps(
            {
                "version": 3,
                "devices": [
                    {
                        "mac": "02:00:00:00:01:05",
                        "ipv4": "10.23.1.32",
                        "message_type": "request",
                        "last_seen_timestamp": 550.0,
                        "ip_first_seen_timestamp": 100.0,
                    }
                ],
                "address_owners": {
                    "10.23.1.32": {
                        "mac": "02:00:00:00:01:05",
                        "assigned_at_timestamp": 100.0,
                        "last_seen_timestamp": 400.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    store = DHCPObservationStore(path)
    assert store.address_bindings["10.23.1.32"] == {
        "mac": "02:00:00:00:01:05",
        "assigned_at_timestamp": 100.0,
        "last_seen_timestamp": 400.0,
    }
    store.flush()
    assert json.loads(path.read_text(encoding="utf-8"))["version"] == 5
    assert load_dhcp_identities((path,))[0].ownership_verified is True
    assert load_dhcp_address_bindings((path,))[0].assigned_at_timestamp == 100.0


def test_v4_request_candidate_is_discarded_during_migration(tmp_path: Path) -> None:
    path = tmp_path / "dhcp.json"
    path.write_text(
        json.dumps(
            {
                "version": 4,
                "devices": [],
                "address_owners": {},
                "address_candidates": {
                    "10.23.1.32": {
                        "mac": "02:00:00:00:01:05",
                        "assigned_at_timestamp": 100.0,
                        "last_seen_timestamp": 200.0,
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    store = DHCPObservationStore(path)
    assert store.address_bindings == {}
    store.flush()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 5
    assert payload["address_bindings"] == {}
    assert "address_candidates" not in payload


def test_browsing_identity_rejects_previous_mac_after_ip_reuse(monkeypatch, observed_now) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            assert device_ip == "10.23.1.32"
            return "22:33:44:55:66:77"

    identities = [
        DHCPIdentity(
            ip="10.23.1.32",
            mac="AA:BB:CC:DD:EE:FF",
            hostname="Old phone",
            vendor_class=None,
            last_seen_timestamp=100.0,
            ip_first_seen_timestamp=50.0,
            lease_expires_timestamp=None,
            ownership_verified=True,
        ),
        DHCPIdentity(
            ip="10.23.1.32",
            mac="22:33:44:55:66:77",
            hostname="New phone",
            vendor_class=None,
            last_seen_timestamp=220.0,
            ip_first_seen_timestamp=200.0,
            lease_expires_timestamp=None,
            ownership_verified=True,
        ),
    ]
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: identities)
    monkeypatch.setattr(
        network_activity,
        "load_dhcp_address_bindings",
        lambda: [
            DHCPAddressBinding(
                ip="10.23.1.32",
                mac="22:33:44:55:66:77",
                assigned_at_timestamp=200.0,
                last_seen_timestamp=observed_now,
            )
        ],
    )

    identity_id, since_epoch = network_activity._resolve_browsing_identity(
        "10.23.1.32", "22:33:44:55:66:77"
    )
    assert identity_id.startswith("mac_")
    assert since_epoch == 200.0

    with pytest.raises(network_activity.HTTPException) as rejected:
        network_activity._resolve_browsing_identity(
            "10.23.1.32", "AA:BB:CC:DD:EE:FF"
        )
    assert rejected.value.status_code == 409


def test_browsing_identity_does_not_treat_client_request_as_fresh_ownership(
    monkeypatch,
) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            assert device_ip == "10.23.1.32"
            return ""

    now = datetime.now().timestamp()
    identity = DHCPIdentity(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        hostname="Phone",
        vendor_class=None,
        last_seen_timestamp=now,
        ip_first_seen_timestamp=100.0,
        lease_expires_timestamp=None,
        ownership_verified=True,
        ownership_last_seen_timestamp=100.0,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(
        network_activity,
        "load_dhcp_identities",
        lambda: [identity],
    )
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: []
    )

    with pytest.raises(network_activity.HTTPException) as rejected:
        network_activity._resolve_browsing_identity(
            "10.23.1.32", "02:00:00:00:01:05"
        )
    assert rejected.value.status_code == 409


def test_browsing_identity_rejects_arp_only_history_without_dhcp(
    monkeypatch, tmp_path: Path
) -> None:
    class IdentityService:
        data_dir = tmp_path

        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            assert device_ip == "10.23.1.32"
            return "22:33:44:55:66:77"

    (tmp_path / "clients.json").write_text(
        json.dumps(
            {
                "clients": [
                    {
                        "mac": "22:33:44:55:66:77",
                        "ip": "10.23.1.32",
                        "ids": ["10.23.1.32"],
                        "created_at": "2026-01-01T00:00:00",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: [])
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: []
    )

    with pytest.raises(network_activity.HTTPException) as rejected:
        network_activity._resolve_browsing_identity(
            "10.23.1.32", "22:33:44:55:66:77"
        )
    assert rejected.value.status_code == 409
    assert "verified device traffic" in rejected.value.detail


def test_real_address_usage_tracks_ip_transitions_but_requests_do_not(
    tmp_path: Path,
) -> None:
    path = tmp_path / "dhcp.json"
    store = DHCPObservationStore(path)

    def request(mac: str, seen: float) -> None:
        store.observe(
            {
                "mac": mac,
                "ipv4": "10.23.1.32",
                "observed_at": "2026-08-30T18:00:00+00:00",
                "observed_timestamp": seen,
                "message_type": "request",
                "ownership_confirmed": False,
            }
        )

    first_mac = "02:00:00:00:01:05"
    second_mac = "22:33:44:55:66:77"
    request(first_mac, 100.0)
    request(second_mac, 150.0)
    assert store.address_bindings == {}

    store.observe_address_usage(
        {"mac": first_mac, "ipv4": "10.23.1.32", "observed_timestamp": 200.0}
    )
    store.observe_address_usage(
        {"mac": first_mac, "ipv4": "10.23.1.32", "observed_timestamp": 270.0}
    )
    assert store.address_bindings["10.23.1.32"] == {
        "mac": first_mac,
        "assigned_at_timestamp": 200.0,
        "last_seen_timestamp": 270.0,
    }

    request(second_mac, 280.0)
    assert store.address_bindings["10.23.1.32"]["mac"] == first_mac
    store.observe_address_usage(
        {"mac": second_mac, "ipv4": "10.23.1.32", "observed_timestamp": 300.0}
    )
    store.observe_address_usage(
        {"mac": first_mac, "ipv4": "10.23.1.32", "observed_timestamp": 400.0}
    )
    assert store.address_bindings["10.23.1.32"] == {
        "mac": first_mac,
        "assigned_at_timestamp": 400.0,
        "last_seen_timestamp": 400.0,
    }
    assert store.address_owners == {}

    store.flush()
    bindings = load_dhcp_address_bindings((path,))
    assert bindings == [
        DHCPAddressBinding(
            ip="10.23.1.32",
            mac=first_mac,
            assigned_at_timestamp=400.0,
            last_seen_timestamp=400.0,
        )
    ]


def test_browsing_identity_accepts_real_usage_with_exact_current_arp(
    monkeypatch, observed_now,
) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            assert device_ip == "10.23.1.32"
            return "02:00:00:00:01:05"

    binding = DHCPAddressBinding(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        assigned_at_timestamp=300.0,
        last_seen_timestamp=observed_now,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: [])
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: [binding]
    )

    identity_id, since_epoch = network_activity._resolve_browsing_identity(
        "10.23.1.32", "02:00:00:00:01:05"
    )
    assert identity_id.startswith("mac_")
    assert since_epoch == 300.0


@pytest.mark.parametrize("arp_mac", ["", "22:33:44:55:66:77"])
def test_browsing_identity_rejects_binding_without_matching_arp(
    monkeypatch, observed_now, arp_mac: str
) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            return arp_mac

    binding = DHCPAddressBinding(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        assigned_at_timestamp=300.0,
        last_seen_timestamp=observed_now,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: [])
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: [binding]
    )

    with pytest.raises(network_activity.HTTPException) as rejected:
        network_activity._resolve_browsing_identity(
            "10.23.1.32", "02:00:00:00:01:05"
        )
    assert rejected.value.status_code == 409


def test_browsing_identity_rejects_stale_traffic_binding(monkeypatch) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            return "02:00:00:00:01:05"

    stale_binding = DHCPAddressBinding(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        assigned_at_timestamp=100.0,
        last_seen_timestamp=100.0,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: [])
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: [stale_binding]
    )

    with pytest.raises(network_activity.HTTPException) as rejected:
        network_activity._resolve_browsing_identity(
            "10.23.1.32", "02:00:00:00:01:05"
        )
    assert rejected.value.status_code == 409


def test_real_usage_transition_supersedes_old_ack_history_boundary(
    monkeypatch, observed_now,
) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            return "02:00:00:00:01:05"

    identity = DHCPIdentity(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        hostname="Phone",
        vendor_class=None,
        last_seen_timestamp=350.0,
        ip_first_seen_timestamp=100.0,
        lease_expires_timestamp=None,
        ownership_verified=True,
        ownership_last_seen_timestamp=100.0,
    )
    binding = DHCPAddressBinding(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        assigned_at_timestamp=300.0,
        last_seen_timestamp=observed_now,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: [identity])
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: [binding]
    )

    _, since_epoch = network_activity._resolve_browsing_identity(
        "10.23.1.32", "02:00:00:00:01:05"
    )
    assert since_epoch == 300.0


def test_current_traffic_binding_supersedes_stale_identity_metadata(
    monkeypatch, observed_now,
) -> None:
    class IdentityService:
        def _resolve_mac_from_arp(self, device_ip: str) -> str:
            return "02:00:00:00:01:05"

    identities = [
        DHCPIdentity(
            ip="10.23.1.32",
            mac="22:33:44:55:66:77",
            hostname="Stale device",
            vendor_class=None,
            last_seen_timestamp=400.0,
            ip_first_seen_timestamp=200.0,
            lease_expires_timestamp=None,
            ownership_verified=False,
        ),
        DHCPIdentity(
            ip="10.23.1.32",
            mac="02:00:00:00:01:05",
            hostname="Current phone",
            vendor_class=None,
            last_seen_timestamp=300.0,
            ip_first_seen_timestamp=100.0,
            lease_expires_timestamp=None,
            ownership_verified=False,
        ),
    ]
    binding = DHCPAddressBinding(
        ip="10.23.1.32",
        mac="02:00:00:00:01:05",
        assigned_at_timestamp=300.0,
        last_seen_timestamp=observed_now,
    )
    monkeypatch.setattr(network_activity, "netprotection_service", IdentityService())
    monkeypatch.setattr(network_activity, "load_dhcp_identities", lambda: identities)
    monkeypatch.setattr(
        network_activity, "load_dhcp_address_bindings", lambda: [binding]
    )

    _, since_epoch = network_activity._resolve_browsing_identity(
        "10.23.1.32", "02:00:00:00:01:05"
    )
    assert since_epoch == 300.0


def test_browsing_activity_endpoint_sanitizes_generated_rows(monkeypatch) -> None:
    class FakeBrowsingService:
        async def get_browsing_activity(
            self,
            client_ip: str,
            limit: int,
            force_refresh: bool,
            device_identity: str,
            since_epoch: float,
        ):
            assert client_ip == "10.23.1.32"
            assert limit == 50
            assert force_refresh is False
            assert device_identity == "mac_verified"
            assert since_epoch == 1788100000.0
            return [
                {
                    "id": "browse-one",
                    "timestamp": "2026-08-30T16:00:00",
                    "domain": "daily.example",
                    "host": "www.daily.example",
                    "source": "dns+tls",
                    "traffic_class": "site",
                },
                {
                    "id": "invalid-source",
                    "timestamp": "2026-08-30T16:00:01",
                    "domain": "invalid.example",
                    "host": "invalid.example",
                    "source": "untrusted",
                    "traffic_class": "site",
                },
                {
                    "id": "invalid-class",
                    "timestamp": "2026-08-30T16:00:02",
                    "domain": "invalid.example",
                    "host": "invalid.example",
                    "source": "dns",
                    "traffic_class": "untrusted",
                },
            ]

    monkeypatch.setattr(
        network_activity, "netprotection_service", FakeBrowsingService()
    )
    monkeypatch.setattr(
        network_activity,
        "_resolve_browsing_identity",
        lambda _ip, _mac: ("mac_verified", 1788100000.0),
    )
    result = asyncio.run(
        network_activity.get_device_browsing_activity(
            "10.23.1.32",
            mac="02:00:00:00:01:05",
            limit=50,
            refresh=False,
            _admin=object(),
        )
    )

    assert result["total"] == 1
    assert result["activity"][0] == {
        "id": "browse-one",
        "timestamp": "2026-08-30T16:00:00",
        "domain": "daily.example",
        "host": "www.daily.example",
        "source": "dns+tls",
        "trafficClass": "site",
        "status": "connected",
    }
