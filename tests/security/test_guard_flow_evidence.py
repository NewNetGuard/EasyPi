from __future__ import annotations

import asyncio
from datetime import datetime
from types import SimpleNamespace

from easypi_netprotection.chronicle.flow_log import FlowStatus
from easypi_netprotection.server import NetProtectionServer


class _FlowLogger:
    def __init__(self) -> None:
        self.entry = None

    def log(self, entry) -> None:
        self.entry = entry


def test_blocked_flow_records_actual_nxdomain_response() -> None:
    server = NetProtectionServer.__new__(NetProtectionServer)
    server.flow_logger = _FlowLogger()
    server.metrics = None
    server.config = SimpleNamespace(block_mode="nxdomain")
    verdict = SimpleNamespace(action=SimpleNamespace(value="deny"), confidence=100)

    asyncio.run(
        server._log_flow(
            "flow-test",
            "ads.example",
            "A",
            "192.0.2.1",
            "udp",
            FlowStatus.BLOCKED,
            verdict,
            datetime.now(),
        )
    )

    assert server.flow_logger.entry.response_code == "NXDOMAIN"


def test_failed_flow_records_servfail_response() -> None:
    server = NetProtectionServer.__new__(NetProtectionServer)
    server.flow_logger = _FlowLogger()
    server.metrics = None
    server.config = SimpleNamespace(block_mode="nxdomain")

    asyncio.run(
        server._log_flow(
            "flow-test",
            "example.com",
            "A",
            "192.0.2.1",
            "udp",
            FlowStatus.FAILED,
            None,
            datetime.now(),
        )
    )

    assert server.flow_logger.entry.response_code == "SERVFAIL"


def _upstream_answer(rcode: int) -> bytes:
    import dns.message
    import dns.rcode

    query = dns.message.make_query("example.org", "A")
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return response.to_wire()


def test_forwarded_flow_records_the_upstream_rcode() -> None:
    import dns.rcode

    from easypi_netprotection.server import _wire_rcode

    assert _wire_rcode(_upstream_answer(dns.rcode.SERVFAIL)) == "SERVFAIL"
    assert _wire_rcode(_upstream_answer(dns.rcode.NXDOMAIN)) == "NXDOMAIN"
    assert _wire_rcode(_upstream_answer(dns.rcode.NOERROR)) == "NOERROR"
    assert _wire_rcode(b"\x00") == "SERVFAIL"

    server = NetProtectionServer.__new__(NetProtectionServer)
    server.flow_logger = _FlowLogger()
    server.metrics = None
    server.config = SimpleNamespace(block_mode="nxdomain")
    verdict = SimpleNamespace(action=SimpleNamespace(value="observe"), confidence=50)

    asyncio.run(
        server._log_flow(
            "flow-test",
            "example.org",
            "A",
            "192.0.2.1",
            "udp",
            FlowStatus.UPSTREAM,
            verdict,
            datetime.now(),
            response_code=_wire_rcode(_upstream_answer(dns.rcode.SERVFAIL)),
        )
    )

    assert server.flow_logger.entry.status == FlowStatus.UPSTREAM
    assert server.flow_logger.entry.response_code == "SERVFAIL"


def test_forward_path_passes_the_upstream_rcode_to_the_flow_log() -> None:
    import dns.message
    import dns.rcode

    server = NetProtectionServer.__new__(NetProtectionServer)
    server.flow_logger = _FlowLogger()
    server.metrics = None
    server.config = SimpleNamespace(block_mode="nxdomain")
    server.stats = SimpleNamespace(
        total_queries=0, allowed_queries=0, upstream_queries=0,
        blocked_queries=0, errors=0,
    )
    server._update_protocol_stats = lambda protocol: None
    server._is_safe_mode = lambda: False
    server._generate_flow_id = lambda: "flow-test"
    verdict = SimpleNamespace(action=SimpleNamespace(value="observe"), confidence=50)

    async def _verdict(*args, **kwargs):
        return verdict

    async def _upstream(data, client_ip):
        return _upstream_answer(dns.rcode.SERVFAIL)

    async def _post(*args, **kwargs):
        return None, []

    server._get_verdict = _verdict
    server._direct_upstream_query = _upstream
    server._check_post_resolution = _post

    query = dns.message.make_query("example.org", "A").to_wire()
    outcome = asyncio.run(server._process_dns_query(query, ("192.0.2.1", 5000), "udp"))

    assert dns.message.from_wire(outcome[0]).rcode() == dns.rcode.SERVFAIL
    assert server.flow_logger.entry.response_code == "SERVFAIL"
