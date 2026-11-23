"""Blocked & Allowed: network-wide blocks split into sites and trackers.

Sites are what someone tried to open, trackers what a page or app loaded in the
background. Device restrictions (parental controls and the like) never appear,
and whatever the user allowed is listed with where they allowed it.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.api.endpoints.netprotection_api.policy import DomainDecision
from app.services.netprotection_components.policy_data import ALLOWLIST_SOURCE_BLOCKED_TAB
from app.services.netprotection_service import NetProtectionService
from easypi_netprotection.chronicle.flow_log import FLOW_REASON_PREFIX, FlowLogStorage

PHONE = "192.168.1.20"
LAPTOP = "192.168.1.30"


def _service(tmp_path: Path) -> NetProtectionService:
    service = NetProtectionService.__new__(NetProtectionService)
    service.data_dir = tmp_path
    service.flow_log_path = tmp_path / "flow_log.db"
    service._trigger_lists_reload = lambda: None

    async def clients():
        return {"clients": [{"name": "Phone", "ids": [PHONE]}, {"name": "Laptop", "ids": [LAPTOP]}]}

    async def devices():
        return []

    service.get_clients = clients
    service.get_devices = devices
    with sqlite3.connect(service.flow_log_path) as db:
        db.executescript(FlowLogStorage.SCHEMA)
    return service


def _log(service: NetProtectionService, rows: list[tuple]) -> None:
    """rows: (seconds_ago, domain, ip, status, reason)."""
    now = datetime.now()
    with sqlite3.connect(service.flow_log_path) as db:
        for index, (ago, domain, ip, status, reason) in enumerate(
            sorted(rows, key=lambda row: -row[0])
        ):
            db.execute(
                "INSERT INTO flow_log (flow_id, timestamp, domain, query_type, client_id,"
                " status, verdict, confidence, evidence_summary, categories)"
                " VALUES (?, ?, ?, 'A', ?, ?, ?, 100, '', ?)",
                (
                    f"flow-{index}",
                    (now - timedelta(seconds=ago)).isoformat(),
                    domain,
                    service._hash_client_ip(ip),
                    status,
                    "deny" if status == "blocked" else "allow",
                    f"{FLOW_REASON_PREFIX}{reason}" if reason else "",
                ),
            )


def _overview(service: NetProtectionService, **kwargs):
    return asyncio.run(service.get_blocked_overview(**kwargs))


def _domains(items):
    return {item["domain"] for item in items}


def test_sites_and_trackers_are_split_by_how_they_were_requested(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _log(service, [
        # Someone tried to open a blocked site: nothing else around it.
        (600, "virustotal.com", PHONE, "blocked", "heuristics_block"),
        # A page loads, and a blocked domain follows within a second.
        (300, "news.example", PHONE, "allowed", None),
        (299.5, "statsbeam.example", PHONE, "blocked", "blocklist"),
        # The engine already said it is an ad network.
        (200, "pubnet.example", PHONE, "blocked", "advertising"),
        # The name alone is an unmistakable tracker.
        (100, "ads.someshop.example", PHONE, "blocked", "blocklist"),
    ])
    overview = _overview(service)
    assert _domains(overview["sites"]) == {"virustotal.com"}
    assert _domains(overview["trackers"]) == {
        "statsbeam.example", "pubnet.example", "ads.someshop.example",
    }
    basis = {item["domain"]: item["basis"] for item in overview["sites"] + overview["trackers"]}
    assert basis == {
        "virustotal.com": "behavior",
        "statsbeam.example": "behavior",
        "pubnet.example": "reason",
        "ads.someshop.example": "name",
    }
    site = overview["sites"][0]
    assert (site["source_key"], site["source_label"]) == ("heuristic", "Heuristics")
    assert site["devices"] == ["Phone"]


def test_a_domain_loaded_under_several_sites_is_a_tracker(tmp_path: Path) -> None:
    service = _service(tmp_path)
    rows = []
    for index, site in enumerate(["a-news.example", "b-shop.example", "c-blog.example"]):
        start = 1000 - index * 100
        rows.append((start, site, PHONE, "allowed", None))
        rows.append((start - 2, "widget.example", PHONE, "blocked", "blocklist"))
    # Opened directly a few more times, so most occurrences are standalone.
    rows += [(50 - n, "widget.example", PHONE, "blocked", "blocklist") for n in range(0, 40, 10)]
    _log(service, rows)
    assert _domains(_overview(service)["trackers"]) == {"widget.example"}


def test_device_restrictions_and_allowed_domains_are_not_listed_as_blocked(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_whitelist("allowed.example"))
    _log(service, [
        (500, "game.example", PHONE, "blocked", "parental_control"),
        (400, "late.example", PHONE, "blocked", "schedule_blocked"),
        (300, "cdn.allowed.example", PHONE, "blocked", "blocklist"),
        (200, "shadowed.example", PHONE, "blocked", "shadow_mode"),
    ])
    overview = _overview(service)
    listed = _domains(overview["sites"]) | _domains(overview["trackers"])
    assert listed == {"shadowed.example"}
    assert [item["domain"] for item in overview["allowed"]] == ["allowed.example"]
    assert overview["allowed"][0]["source_label"] == "Lists"


def test_overview_filters_by_device(tmp_path: Path) -> None:
    service = _service(tmp_path)
    _log(service, [
        (300, "phone-only.example", PHONE, "blocked", "blocklist"),
        (200, "laptop-only.example", LAPTOP, "blocked", "blocklist"),
    ])
    overview = _overview(service, client_id=LAPTOP)
    assert _domains(overview["sites"]) | _domains(overview["trackers"]) == {"laptop-only.example"}


def test_the_latest_decision_wins_and_keeps_both_lists_consistent(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_blacklist("virustotal.com"))

    asyncio.run(service.set_domain_decision("virustotal.com", "allow"))
    assert (tmp_path / "allowlist.txt").read_text().splitlines() == ["virustotal.com"]
    assert (tmp_path / "user_blocklist.txt").read_text().splitlines() == []
    meta = json.loads((tmp_path / "allowlist_meta.json").read_text())
    assert meta["virustotal.com"]["source"] == ALLOWLIST_SOURCE_BLOCKED_TAB
    assert _overview(service)["allowed"][0]["source_label"] == "Blocked & Allowed"

    asyncio.run(service.set_domain_decision("virustotal.com", "block"))
    assert (tmp_path / "allowlist.txt").read_text().splitlines() == []
    assert (tmp_path / "user_blocklist.txt").read_text().splitlines() == ["virustotal.com"]
    assert _overview(service)["allowed"] == []


@pytest.mark.parametrize(
    "domain", ["example", "a\nb.com", "*.exa mple.com", "-bad.example", "x" * 254, "exa mple.com"]
)
def test_decision_accepts_only_a_single_host_name(domain: str) -> None:
    with pytest.raises(ValidationError):
        DomainDecision(domain=domain, decision="allow")


def test_decision_normalises_the_host_name() -> None:
    assert DomainDecision(domain=" VirusTotal.COM. ", decision="allow").domain == "virustotal.com"
    # An entry already covers subdomains, so a wildcard is the same host.
    assert DomainDecision(domain="*.example.com", decision="allow").domain == "example.com"
    with pytest.raises(ValidationError):
        DomainDecision(domain="virustotal.com", decision="maybe")
