"""The user's allow and block lists stay well-formed and survive concurrent writers.

Three guarantees:
- a list entry is always exactly one host name, whatever screen, endpoint or
  assistant action added it, so no input can smuggle extra lines into a list;
- a shared zone such as co.uk can never be allowed, because an allow covers
  subdomains and would let every site registered under the zone through;
- the backend and the engine's hit counters share the *_meta.json files, so
  writes replace files in one step and an unreadable file is never wiped.
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import threading
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.api.endpoints.netprotection_api import policy as policy_api
from app.api.endpoints.netprotection_api.context import DomainAction
from app.services.netprotection_components.policy_data import (
    ALLOWLIST_SOURCE_BLOCKED_TAB,
    ALLOWLIST_SOURCE_SHADOW_MODE,
    is_shared_zone,
    normalize_list_domain,
)
from app.services.netprotection_service import NetProtectionService
from easypi_netprotection import list_files
from easypi_netprotection.list_files import write_text_atomic
from easypi_netprotection.verdict.blocklist_filter import BlocklistFilter


def _service(tmp_path: Path) -> NetProtectionService:
    service = NetProtectionService.__new__(NetProtectionService)
    service.data_dir = tmp_path
    service.flow_log_path = tmp_path / "flow_log.db"
    service._trigger_lists_reload = lambda: None
    return service


def _lines(path: Path) -> list[str]:
    return path.read_text().splitlines() if path.exists() else []


# ---------------------------------------------------------------- host names


@pytest.mark.parametrize(
    ("typed", "stored"),
    [
        ("Example.com", "example.com"),
        ("example.com.", "example.com"),
        ("https://Example.com/path?q=1", "example.com"),
        ("example.com:443", "example.com"),
        ("user@example.com", "example.com"),
        ("*.example.com", "example.com"),
        ("пример.рф", "xn--e1afmkfd.xn--p1ai"),
        ("_dmarc.example.com", "_dmarc.example.com"),
    ],
)
def test_what_people_paste_becomes_one_host(typed: str, stored: str) -> None:
    assert normalize_list_domain(typed) == stored


@pytest.mark.parametrize(
    "typed",
    [
        "",
        "com",
        "a\nb.example.com",
        "evil.com\nco.uk",
        "foo bar.com",
        "<script>.example.com",
        # How a hostile DNS query name reaches the logs and Shadow Mode.
        "a\\010b.example.com",
        "-bad.example.com",
        "a" * 64 + ".com",
    ],
)
def test_anything_but_one_host_is_refused(typed: str) -> None:
    with pytest.raises(ValueError):
        normalize_list_domain(typed)


@pytest.mark.parametrize("zone", ["co.uk", "com.au", "com.tr", "co.ke", "gov.ua"])
def test_shared_zones_are_recognised(zone: str) -> None:
    assert is_shared_zone(zone)


@pytest.mark.parametrize("site", ["bbc.co.uk", "example.com", "id.me", "github.io", "x.com"])
def test_ordinary_sites_are_not_shared_zones(site: str) -> None:
    assert not is_shared_zone(site)


# --------------------------------------------------------- every add path


def test_service_refuses_a_bad_name_and_leaves_the_lists_untouched(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_whitelist("good.example"))
    asyncio.run(service.add_to_blacklist("bad.example"))
    for add in (service.add_to_whitelist, service.add_to_blacklist):
        with pytest.raises(ValueError):
            asyncio.run(add("evil.example\ncom"))
    assert _lines(tmp_path / "allowlist.txt") == ["good.example"]
    assert _lines(tmp_path / "user_blocklist.txt") == ["bad.example"]


def test_a_shared_zone_cannot_be_allowed_but_can_be_blocked(tmp_path: Path) -> None:
    service = _service(tmp_path)
    with pytest.raises(ValueError, match="shared domain zone"):
        asyncio.run(service.add_to_whitelist("co.uk"))
    assert not (tmp_path / "allowlist.txt").exists()
    asyncio.run(service.add_to_blacklist("co.uk"))
    assert _lines(tmp_path / "user_blocklist.txt") == ["co.uk"]


def test_refused_unblock_keeps_the_domain_in_the_blacklist(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_blacklist("co.uk"))
    with pytest.raises(ValueError):
        asyncio.run(service.set_domain_decision("co.uk", "allow"))
    assert _lines(tmp_path / "user_blocklist.txt") == ["co.uk"]
    assert not (tmp_path / "allowlist.txt").exists()


def test_unblock_stores_the_normalized_host(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.set_domain_decision("VirusTotal.com.", "allow"))
    assert _lines(tmp_path / "allowlist.txt") == ["virustotal.com"]
    meta = json.loads((tmp_path / "allowlist_meta.json").read_text())
    assert meta["virustotal.com"]["source"] == ALLOWLIST_SOURCE_BLOCKED_TAB


def test_shadow_approval_of_a_hostile_name_is_refused(tmp_path: Path) -> None:
    service = _service(tmp_path)
    hostile = "x\\010co.uk"
    with sqlite3.connect(tmp_path / "shadow_mode.db") as db:
        db.execute(
            "CREATE TABLE shadow_domains (domain TEXT PRIMARY KEY, action TEXT,"
            " action_at REAL, action_by TEXT, notes TEXT)"
        )
        db.execute("INSERT INTO shadow_domains (domain, action) VALUES (?, 'promoted')", (hostile,))
    result = asyncio.run(service.shadow_domain_action(hostile, "dismiss"))
    assert result["success"] is False
    assert not (tmp_path / "allowlist.txt").exists()


def test_assistant_reports_a_refused_allow(tmp_path: Path) -> None:
    from app.agent.adapters.netprotection import NetProtectionAdapter

    adapter = NetProtectionAdapter.__new__(NetProtectionAdapter)
    adapter.service = _service(tmp_path)
    result = asyncio.run(adapter.add_to_whitelist("co.uk"))
    assert result["success"] is False
    assert "shared domain zone" in result["message"]


@pytest.mark.parametrize("endpoint", [policy_api.add_to_whitelist, policy_api.add_to_blacklist])
def test_list_endpoints_answer_400_for_a_bad_name(
    endpoint, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(policy_api, "netprotection_service", _service(tmp_path))
    monkeypatch.setattr(policy_api, "_record_netprotection_event", lambda **_: None)
    with pytest.raises(HTTPException) as refused:
        asyncio.run(endpoint(DomainAction(domain="a\nb.example"), _admin=None))
    assert refused.value.status_code == 400


def test_domain_decision_endpoint_answers_400_for_a_shared_zone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(policy_api, "netprotection_service", _service(tmp_path))
    monkeypatch.setattr(policy_api, "_record_netprotection_event", lambda **_: None)
    request = policy_api.DomainDecision(domain="co.uk", decision="allow")
    with pytest.raises(HTTPException) as refused:
        asyncio.run(policy_api.set_domain_decision(request, _admin=None))
    assert refused.value.status_code == 400


def test_old_malformed_entries_can_still_be_removed(tmp_path: Path) -> None:
    (tmp_path / "allowlist.txt").write_text("good.example\nweird entry\n")
    service = _service(tmp_path)
    asyncio.run(service.remove_from_whitelist("weird entry"))
    assert _lines(tmp_path / "allowlist.txt") == ["good.example"]


# ------------------------------------------------------- safe file writes


def test_atomic_write_replaces_content_and_keeps_permissions(tmp_path: Path) -> None:
    target = tmp_path / "allowlist.txt"
    target.write_text("old")
    os.chmod(target, 0o640)
    mode = target.stat().st_mode
    write_text_atomic(target, "new")
    assert target.read_text() == "new"
    assert target.stat().st_mode == mode
    assert [p.name for p in tmp_path.iterdir()] == ["allowlist.txt"]


def test_a_failed_write_leaves_the_old_file_and_no_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "allowlist.txt"
    target.write_text("old")

    def broken_replace(*_args):
        raise OSError("disk full")

    monkeypatch.setattr(list_files.os, "replace", broken_replace)
    with pytest.raises(OSError):
        write_text_atomic(target, "new")
    assert target.read_text() == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["allowlist.txt"]


def test_engine_hit_counter_never_wipes_an_unreadable_meta_file(tmp_path: Path) -> None:
    meta = tmp_path / "allowlist_meta.json"
    meta.write_text('{"cut short')
    BlocklistFilter(tmp_path)._increment_allowlist_hits("example.com")
    assert meta.read_text() == '{"cut short'


def test_engine_hit_counter_keeps_where_an_allow_came_from(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_whitelist("example.com", source=ALLOWLIST_SOURCE_SHADOW_MODE))
    BlocklistFilter(tmp_path)._increment_allowlist_hits("example.com")
    entry = json.loads((tmp_path / "allowlist_meta.json").read_text())["example.com"]
    assert entry["hits"] == 1
    assert entry["source"] == ALLOWLIST_SOURCE_SHADOW_MODE


def test_ui_edits_and_engine_hit_counts_do_not_lose_each_other(tmp_path: Path) -> None:
    """Interleave UI adds with the engine's per-query hit counting."""
    service = _service(tmp_path)
    engine = BlocklistFilter(tmp_path)
    asyncio.run(service.add_to_whitelist("counted.example"))
    domains = [f"site{i}.example" for i in range(40)]

    def count_hits() -> None:
        for _ in range(200):
            engine._increment_allowlist_hits("counted.example")

    counter = threading.Thread(target=count_hits)
    counter.start()
    for domain in domains:
        asyncio.run(service.add_to_whitelist(domain, source=ALLOWLIST_SOURCE_SHADOW_MODE))
    counter.join()

    meta = json.loads((tmp_path / "allowlist_meta.json").read_text())
    assert meta["counted.example"]["hits"] == 200
    assert all(meta[domain]["source"] == ALLOWLIST_SOURCE_SHADOW_MODE for domain in domains)
    assert _lines(tmp_path / "allowlist.txt") == ["counted.example", *domains]
