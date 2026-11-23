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
