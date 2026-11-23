"""A word in a domain name is a hint for review, never a block on its own.

The name-based intel provider used to vote "known malicious, deny" for any
domain containing "virus", and "deny" for any containing "tracking" or
"metrics", which blocked virustotal.com, malwarebytes.com and parcel
trackers. Words now match only as whole words and only produce observations.
"""
from __future__ import annotations

import asyncio

import pytest

from easypi_netprotection.intel.domain_intel import DomainCategory, DomainIntelProvider


def _evidence(domain: str):
    return asyncio.run(DomainIntelProvider().analyze(domain, {}))


@pytest.mark.parametrize(
    "domain",
    [
        "virustotal.com",
        "www.virustotal.com",
        "malwarebytes.com",
        "antivirus.kaspersky.com",
        "virus-info.example",
        "tracking.dpd.de",
        "packagetracker.com",
        "metrics.icloud.com",
        "ads.example.com",
        "porn.example",
    ],
)
def test_name_based_intel_never_votes_to_block(domain: str) -> None:
    assert all(item.suggested_action != "deny" for item in _evidence(domain))


@pytest.mark.parametrize(
    ("domain", "category"),
    [
        ("virus-info.example", DomainCategory.MALWARE),
        ("tracking.dpd.de", DomainCategory.TRACKING),
        ("ads.example.com", DomainCategory.ADVERTISING),
        ("doubleclick.net", DomainCategory.ADVERTISING),
        ("sex-shop.example", DomainCategory.ADULT),
    ],
)
def test_whole_words_are_still_recorded_as_hints(domain: str, category: DomainCategory) -> None:
    assert category in DomainIntelProvider().categorize(domain)
    hints = [item for item in _evidence(domain) if item.metadata.get("basis") == "domain_name"]
    assert {item.metadata["category"] for item in hints} >= {category.value}
    assert all(item.suggested_action == "observe" for item in hints)


@pytest.mark.parametrize(
    "domain",
    ["virustotal.com", "malwarebytes.com", "essex.ac.uk", "sussex.ac.uk", "middlesex.gov"],
)
def test_words_inside_other_words_are_not_categories(domain: str) -> None:
    categories = set(DomainIntelProvider().categorize(domain))
    assert not categories & {DomainCategory.MALWARE, DomainCategory.ADULT}


def test_known_safe_domains_are_still_reported_as_safe() -> None:
    assert [item.suggested_action for item in _evidence("github.com")] == ["allow"]


@pytest.mark.parametrize(
    "domain",
    [
        "a7k2-93kd-x81-qq4-z9.xyz",
        "k3j4h5g6-l7k8-j9h0-a1s2-d3f4g5h6j7k8l9z0x1c2v3b4n5m6.com",
        "q1w2-e3r4-t5y6-u7i8-o9p0-a1s2-d3f4-g5h6-j7k8-l9z0x1.top",
    ],
)
def test_machine_generated_names_are_still_blocked(domain: str) -> None:
    denies = [item for item in _evidence(domain) if item.suggested_action == "deny"]
    assert len(denies) == 1
    assert denies[0].metadata["basis"] == "domain_structure"
    assert "looks machine-generated" in denies[0].signal


@pytest.mark.parametrize(
    "domain",
    [
        "shop.xyz",
        "123movies.xyz",
        "a1b2c3d4e5f6g7h8.top",
        "x-y-z-w-v.click",
        "r3---sn-4g5e6nsz.googlevideo.com",
        "1e100.net",
        "virus-malware-trojan.xyz",
    ],
)
def test_one_or_two_structural_signs_do_not_block(domain: str) -> None:
    assert all(item.suggested_action != "deny" for item in _evidence(domain))


def test_structure_blocks_exactly_where_the_old_score_did_for_wordless_names() -> None:
    """Without words, the old rule blocked at score < 20, i.e. penalty > 30."""
    provider = DomainIntelProvider()
    for domain in [
        "a7k2-93kd-x81-qq4-z9.xyz",
        "x9283-77-1234-5532.top",
        "x-y-z-w-v.click",
        "k3j4h5g6-l7k8-j9h0-a1s2-d3f4g5h6j7k8l9z0x1c2v3b4n5m6.com",
        "plain-name.example",
    ]:
        reputation = provider._compute_reputation(domain)
        assert reputation.looks_generated == (reputation.score < 20)


def test_a_structural_block_is_reported_as_the_name_check_not_the_users_blacklist() -> None:
    from easypi_netprotection.verdict.engine_components.decision import VerdictDecisionMixin
    from easypi_netprotection.verdict.evidence import EvidenceChain
    from easypi_netprotection.verdict.outcome import VerdictAction, VerdictReason

    chain = EvidenceChain("flow")
    for item in _evidence("a7k2-93kd-x81-qq4-z9.xyz"):
        chain.add(item)
    from easypi_netprotection.verdict.engine_components.context import get_settings

    decision = VerdictDecisionMixin()
    decision._min_confidence_to_block = get_settings().verdict.min_confidence_to_block
    action, reason, _ = decision._determine_verdict(chain)
    assert action == VerdictAction.DENY
    assert reason == VerdictReason.DOMAIN_ANOMALY
