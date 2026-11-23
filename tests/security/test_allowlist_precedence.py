"""The user's allowlist overrides every network-wide default block.

Restrictions an administrator enabled for a specific device (quarantine,
schedules, device rules, parental controls, app blocking, SafeSearch) stay in
force even for an allowlisted domain. Everything that applies to the whole
network by default (Shadow Mode, blocklists, NRD, heuristics, Ad-Genesis and
name-based intel) never blocks a domain the user allowed.
"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from easypi_netprotection.verdict.engine import (
    EvidenceSource,
    VerdictAction,
    VerdictEngine,
    VerdictReason,
    VerdictResult,
)

DOMAIN = "virustotal.com"


class _Lists:
    def __init__(self, allowed: bool, blocked: bool = False):
        self.allowed = allowed
        self.blocked = blocked

    def reload_if_changed(self) -> bool:
        return False

    def is_allowed(self, _domain: str) -> bool:
        return self.allowed

    def block_source(self, _domain: str, check_allowlist: bool = True) -> str | None:
        return "list" if self.blocked else None


class _ParentalProfile:
    enabled = True
    filter_level = "strict"

    @staticmethod
    def is_active_now() -> bool:
        return True


class _Profiles:
    block_unknown_devices = False

    def __init__(self, parental: bool):
        self.parental = parental

    def lookup_profile(self, _ip, _mac):
        return _ParentalProfile() if self.parental else None

    def is_known_device(self, _ip, _mac) -> bool:
        return True


def _deny(stage: str):
    def stage_result(domain, *args):
        evidence = next(arg for arg in args if hasattr(arg, "add_raw"))
        evidence.add_raw(
            source=EvidenceSource.HEURISTICS_AGGREGATED,
            signal=f"{stage} block",
            confidence=100,
            suggested_action="block",
        )
        return VerdictResult(
            flow_id="flow",
            domain=domain,
            action=VerdictAction.DENY,
            confidence=100,
            reason=VerdictReason.HEURISTICS_BLOCK,
            evidence=evidence,
            processing_time_ms=0.0,
        )

    return stage_result


async def _none_async(*_args, **_kwargs):
    return None


def _engine(*, allowed: bool, parental: bool = False, **blocking_stages: bool) -> VerdictEngine:
    """Build the real pipeline with every stage stubbed to 'no opinion'."""
    engine = VerdictEngine.__new__(VerdictEngine)
    engine._safe_mode = False
    engine._total_verdicts = engine._blocked_count = engine._allowed_count = 0
    engine._blocklist_blocks = 0
    engine._avg_processing_ms = 0.0
    engine._min_confidence_to_block = 70
    engine._blocklist = _Lists(allowed=allowed, blocked=blocking_stages.pop("blocklist", False))
    engine._profiles = _Profiles(parental=parental)
    engine._intel_providers = []
    engine._shield_provider = None

    stages = {
        "_check_rewrites": None,
        "_check_schedules": None,
        "_check_device_profile": None,
        "_check_parental_controls": None,
        "_check_streaming_blocker": None,
        "_check_safesearch": None,
        "_check_shadow_blocked": None,
        "_check_nrd": None,
        "_check_ad_genesis": None,
    }
    for name in stages:
        setattr(engine, name, _deny(name) if blocking_stages.pop(name, False) else (lambda *a: None))
    if blocking_stages.pop("_check_heuristics", False):
        sync_deny = _deny("_check_heuristics")

        async def heuristics(domain, client_ip, flow_id, evidence, start_time):
            return sync_deny(domain, evidence)

        engine._check_heuristics = heuristics
    else:
        engine._check_heuristics = _none_async
    assert not blocking_stages, f"unknown stages: {blocking_stages}"
    engine._evaluate_matchers = _none_async
    engine._gather_intel = _none_async
    engine._check_shield = _none_async
    engine._check_frequency = lambda *a: None
    return engine


def _verdict(engine: VerdictEngine) -> VerdictResult:
    ctx = SimpleNamespace(
        flow_id="flow",
        client_ip="192.168.1.50",
        client_mac=None,
        protocol="udp",
        question=SimpleNamespace(name=DOMAIN, rdtype=1),
    )
    return asyncio.run(engine.evaluate(ctx))


NETWORK_WIDE_BLOCKS = [
    "_check_shadow_blocked",
    "blocklist",
    "_check_nrd",
    "_check_heuristics",
    "_check_ad_genesis",
]
DEVICE_RESTRICTIONS = [
    "_check_schedules",
    "_check_device_profile",
    "_check_parental_controls",
    "_check_streaming_blocker",
    "_check_safesearch",
]


@pytest.mark.parametrize("stage", NETWORK_WIDE_BLOCKS)
def test_allowlist_overrides_every_network_wide_block(stage: str) -> None:
    result = _verdict(_engine(allowed=True, **{stage: True}))
    assert result.action == VerdictAction.ALLOW
    assert result.reason == VerdictReason.WHITELIST


@pytest.mark.parametrize("stage", NETWORK_WIDE_BLOCKS)
def test_network_wide_blocks_still_apply_without_the_allowlist(stage: str) -> None:
    assert _verdict(_engine(allowed=False, **{stage: True})).action == VerdictAction.DENY


@pytest.mark.parametrize("stage", DEVICE_RESTRICTIONS)
def test_device_restrictions_stay_in_force_for_allowlisted_domains(stage: str) -> None:
    # Parental-only stages run only for a device under active parental control.
    result = _verdict(_engine(allowed=True, parental=True, **{stage: True}))
    assert result.action == VerdictAction.DENY


def test_shadow_mode_block_is_checked_after_the_allowlist_in_source_order() -> None:
    from pathlib import Path

    source = (
        Path(__file__).parents[2]
        / "easypi_netprotection/verdict/engine_components/pipeline.py"
    ).read_text(encoding="utf-8")
    evaluate = source[source.index("async def evaluate(") :]
    allowlist = evaluate.index("self._blocklist.is_allowed(domain)")
    assert evaluate.index("self._check_shadow_blocked(") > allowlist
    for restriction in ("_check_schedules(", "_check_device_profile(", "_check_parental_controls("):
        assert evaluate.index(restriction) < allowlist
