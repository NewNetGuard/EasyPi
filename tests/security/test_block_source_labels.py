"""Every block shows who made it.

The engine records its decisive verdict reason in the flow log, the user's own
blacklist is told apart from downloaded blocklists, and older log rows are
still labelled from their evidence summary.
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.netprotection_service import NetProtectionService
from easypi_netprotection.chronicle.flow_log import FLOW_REASON_PREFIX, FlowStatus
from easypi_netprotection.server import NetProtectionServer
from easypi_netprotection.verdict.blocklist_filter import (
    BLOCK_SOURCE_LIST,
    BLOCK_SOURCE_USER,
    BlocklistFilter,
)
from easypi_netprotection.verdict.engine import VerdictAction, VerdictReason


def _classify(summary: str = "", verdict: str = "deny", categories: str = ""):
    service = NetProtectionService.__new__(NetProtectionService)
    return service._classify_block_source(summary, verdict, categories)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("blocklist", ("blocklist", "Blocklist")),
        ("blacklist", ("blacklist", "Your blacklist")),
        ("shadow_mode", ("shadow", "Shadow Mode")),
        ("newly_registered", ("nrd", "New (NRD)")),
        ("advertising", ("ad_ai", "Ad/Tracker AI")),
        ("heuristics_block", ("heuristic", "Heuristics")),
        ("domain_anomaly", ("name", "Name check")),
        ("parental_control", ("parental", "Parental")),
        ("app_blocked", ("app", "App block")),
    ],
)
def test_recorded_engine_reason_decides_the_label(reason, expected) -> None:
    # The evidence summary would say something else; the recorded reason wins.
    assert _classify("Device anomaly: burst", "deny", f"{FLOW_REASON_PREFIX}{reason}") == expected


@pytest.mark.parametrize(
    ("summary", "expected"),
    [
        ("shadow_mode: admin-promoted block (score=72.0)", ("shadow", "Shadow Mode")),
        ("domain is known malicious (score: 5)", ("name", "Name check")),
        ("domain categorized as tracking", ("name", "Name check")),
        (
            "domain name looks machine-generated (suspicious_tld, excessive_hyphens)",
            ("name", "Name check"),
        ),
        ("domain in user blacklist: example.com", ("blacklist", "Your blacklist")),
        ("domain in blocklist: ads.example", ("blocklist", "Blocklist")),
        ("ad-genesis: parasitic cross-site ad branch", ("ad_ai", "Ad/Tracker AI")),
    ],
)
def test_older_rows_are_labelled_from_their_summary(summary, expected) -> None:
    assert _classify(summary) == expected


def test_device_restriction_sources_are_marked() -> None:
    sources = NetProtectionService.DEVICE_RESTRICTION_SOURCES
    assert {"parental", "schedule", "profile", "app", "safesearch"} <= sources
    assert not sources & {"blocklist", "blacklist", "shadow", "ad_ai", "heuristic", "nrd", "name"}


def test_blocklist_filter_tells_the_users_blacklist_apart(tmp_path: Path) -> None:
    (tmp_path / "verified_blocklist.txt").write_text("ads.example\n")
    (tmp_path / "user_blocklist.txt").write_text("mine.example\n")
    lists = BlocklistFilter(tmp_path)
    assert lists.block_source("mine.example") == BLOCK_SOURCE_USER
    assert lists.block_source("cdn.mine.example") == BLOCK_SOURCE_USER
    assert lists.block_source("ads.example") == BLOCK_SOURCE_LIST
    assert lists.block_source("clean.example") is None
    assert lists.is_blocked("ads.example") and not lists.is_blocked("clean.example")


def test_flow_log_records_the_verdict_reason() -> None:
    logged = []
    server = NetProtectionServer.__new__(NetProtectionServer)
    server.flow_logger = SimpleNamespace(log=logged.append)
    server.metrics = None
    server.config = SimpleNamespace(block_mode="zero_ip")
    verdict = SimpleNamespace(
        action=VerdictAction.DENY,
        reason=VerdictReason.SHADOW_MODE,
        confidence=72,
        evidence=[],
    )
    asyncio.run(
        server._log_flow(
            "flow", "example.com", "A", "192.168.1.20", "udp",
            FlowStatus.BLOCKED, verdict, datetime.now(),
        )
    )
    assert logged[0].categories == [f"{FLOW_REASON_PREFIX}shadow_mode"]
