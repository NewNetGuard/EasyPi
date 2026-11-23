"""Approving a domain in Shadow Mode records it in the user's allowlist.

The engine never read Shadow Mode's own "approved" mark, and Shadow Mode
could promote an approved domain back to a block. The allowlist is checked
before Shadow Mode, so writing the approval there makes it permanent.
"""
from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from app.services.netprotection_components.policy_data import (
    ALLOWLIST_SOURCE_LISTS,
    ALLOWLIST_SOURCE_SHADOW_MODE,
)
from app.services.netprotection_service import NetProtectionService


def _service(tmp_path: Path, *domains: str) -> NetProtectionService:
    service = NetProtectionService.__new__(NetProtectionService)
    service.data_dir = tmp_path
    service._trigger_lists_reload = lambda: None
    with sqlite3.connect(tmp_path / "shadow_mode.db") as db:
        db.execute(
            "CREATE TABLE shadow_domains (domain TEXT PRIMARY KEY, action TEXT,"
            " action_at REAL, action_by TEXT, notes TEXT)"
        )
        db.executemany(
            "INSERT INTO shadow_domains (domain, action) VALUES (?, 'promoted')",
            [(domain,) for domain in domains],
        )
    return service


def _allowlist(tmp_path: Path) -> list[str]:
    path = tmp_path / "allowlist.txt"
    return path.read_text().splitlines() if path.exists() else []


def test_approving_a_shadow_domain_allowlists_it_with_its_source(tmp_path: Path) -> None:
    service = _service(tmp_path, "virustotal.com")
    result = asyncio.run(service.shadow_domain_action("virustotal.com", "dismiss"))
    assert result["success"] is True
    assert _allowlist(tmp_path) == ["virustotal.com"]
    meta = json.loads((tmp_path / "allowlist_meta.json").read_text())
    assert meta["virustotal.com"]["source"] == ALLOWLIST_SOURCE_SHADOW_MODE
    with sqlite3.connect(tmp_path / "shadow_mode.db") as db:
        assert db.execute("SELECT action FROM shadow_domains").fetchone()[0] == "dismissed"
    listed = asyncio.run(service.get_whitelist())
    assert listed[0]["source"] == ALLOWLIST_SOURCE_SHADOW_MODE


def test_unknown_shadow_domain_is_not_allowlisted(tmp_path: Path) -> None:
    service = _service(tmp_path, "virustotal.com")
    result = asyncio.run(service.shadow_domain_action("other.example", "dismiss"))
    assert result["success"] is False
    assert _allowlist(tmp_path) == []


def test_blocking_a_shadow_domain_removes_an_earlier_approval(tmp_path: Path) -> None:
    service = _service(tmp_path, "bad.example", "keep.example")

    async def no_matchers(_matcher):
        return {}

    service.add_matcher = no_matchers
    asyncio.run(service.shadow_domain_action("bad.example", "dismiss"))
    asyncio.run(service.shadow_domain_action("keep.example", "dismiss"))
    assert asyncio.run(service.shadow_domain_action("bad.example", "promote"))["success"]
    # The block is the latest decision; other approvals are untouched.
    assert _allowlist(tmp_path) == ["keep.example"]


def test_allowlist_sources_are_validated_and_default_to_lists(tmp_path: Path) -> None:
    service = _service(tmp_path)
    asyncio.run(service.add_to_whitelist("example.com"))
    assert asyncio.run(service.get_whitelist())[0]["source"] == ALLOWLIST_SOURCE_LISTS
    with pytest.raises(ValueError):
        asyncio.run(service.add_to_whitelist("example.org", source="unknown"))
    assert _allowlist(tmp_path) == ["example.com"]
