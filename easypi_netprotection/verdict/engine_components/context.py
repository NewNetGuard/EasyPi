"""
Shared VerdictEngine dependencies

Orchestrates the Verdict Pipeline, coordinating matchers, intel modules,
blocklist filtering, DNS rewrites, heuristics, safe search, and shield
policies to produce final verdicts with full evidence chains.
"""

from __future__ import annotations

# ruff: noqa: F401

import asyncio
import fnmatch
import ipaddress
import json
import logging
import time
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from ...config import get_settings
from ...service_domains import get_domains_for_service
from ...vault.models import Verdict as VerdictModel, EvidenceItem
from ...rewrites import RewriteManager, get_rewrite_manager, RewriteType
from ..evidence import EvidenceChain, EvidenceSource, Evidence
from ..matchers import MatcherRegistry, get_matcher_registry
from ..outcome import VerdictAction, VerdictReason, ConfidenceLevel
from ..blocklist_filter import BlocklistFilter, get_blocklist_filter

# Optional CNAME chain analyzer import
try:
    from ...intel.cname_chain import CNAMEChainAnalyzer, get_cname_analyzer

    CNAME_ANALYZER_AVAILABLE = True
except ImportError:
    CNAME_ANALYZER_AVAILABLE = False
    CNAMEChainAnalyzer = None
    get_cname_analyzer = None

# Optional heuristics engine import
try:
    from ...heuristics import (
        HeuristicsEngine,
        get_heuristics_engine,
    )

    HEURISTICS_AVAILABLE = True
except ImportError:
    HEURISTICS_AVAILABLE = False
    HeuristicsEngine = None
    get_heuristics_engine = None

# Optional profile manager import
try:
    from ...profiles import ProfileManager, get_profile_manager

    PROFILES_AVAILABLE = True
except ImportError:
    PROFILES_AVAILABLE = False
    ProfileManager = None

# Optional safe search import
try:
    from ...safesearch import SafeSearchEnforcer, get_safesearch_enforcer

    SAFESEARCH_AVAILABLE = True
except ImportError:
    SAFESEARCH_AVAILABLE = False
    SafeSearchEnforcer = None

# Optional parental control import
try:
    from ...parental import ParentalController, get_parental_controller

    PARENTAL_AVAILABLE = True
except ImportError:
    PARENTAL_AVAILABLE = False
    ParentalController = None

# Optional streaming blocker import
try:
    from ...gateway.streaming_blocker import get_streaming_blocker, DOH_DOT_DOMAINS

    STREAMING_BLOCKER_AVAILABLE = True
except ImportError:
    STREAMING_BLOCKER_AVAILABLE = False
    get_streaming_blocker = None
    DOH_DOT_DOMAINS = []

# Schedule checker import
try:
    from ..schedule_checker import get_schedule_checker, ScheduleChecker

    SCHEDULE_CHECKER_AVAILABLE = True
except ImportError:
    SCHEDULE_CHECKER_AVAILABLE = False
    get_schedule_checker = None
    ScheduleChecker = None

# Frequency analyzer import (beaconing / burst / C2 callback detection)
try:
    from ...intel.entropy_check import FrequencyAnalyzer

    FREQUENCY_AVAILABLE = True
except ImportError:
    FREQUENCY_AVAILABLE = False
    FrequencyAnalyzer = None

# Ad-Genesis behavioral blocklist — from existing DNS logs (no capture, ACTIVE)
try:
    from ...heuristics.ad_genesis import get_ad_genesis_blocklist

    AD_GENESIS_AVAILABLE = True
except ImportError:
    AD_GENESIS_AVAILABLE = False
    get_ad_genesis_blocklist = None

# Newly-Registered Domain (NRD) feed filter — blocks freshly-registered domains
try:
    from ..nrd_filter import get_nrd_filter

    NRD_AVAILABLE = True
except ImportError:
    NRD_AVAILABLE = False
    get_nrd_filter = None


if TYPE_CHECKING:
    from ...core.resolver import FlowContext


logger = logging.getLogger(__name__)


class IntelProvider(Protocol):
    """Protocol for intel signal providers."""

    async def analyze(
        self,
        domain: str,
        context: dict[str, Any],
    ) -> list[Evidence]:
        """Analyze domain and return evidence items."""
        ...


class ShieldProvider(Protocol):
    """Protocol for shield policy providers."""

    async def evaluate(
        self,
        domain: str,
        device_id: str | None,
        context: dict[str, Any],
    ) -> list[Evidence]:
        """Evaluate shield policies and return evidence."""
        ...


@dataclass
class VerdictResult:
    """Complete verdict with evidence chain."""

    flow_id: str
    domain: str
    action: VerdictAction
    confidence: int
    reason: VerdictReason
    evidence: EvidenceChain
    redirect_target: str | None = None
    processing_time_ms: float = 0.0

    def to_model(self) -> VerdictModel:
        """Convert to Pydantic model for storage/API."""
        return VerdictModel(
            flow_id=self.flow_id,
            domain=self.domain,
            action=self.action.value,
            confidence=self.confidence,
            evidence=[
                EvidenceItem(
                    source=e.source.value,
                    signal=e.signal,
                    confidence=e.confidence,
                    weight=e.weight,
                )
                for e in self.evidence.items
            ],
            redirect_target=self.redirect_target,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "flow_id": self.flow_id,
            "domain": self.domain,
            "action": self.action.value,
            "confidence": self.confidence,
            "confidence_level": ConfidenceLevel.from_score(self.confidence).value,
            "reason": self.reason.value,
            "evidence": self.evidence.to_list(),
            "redirect_target": self.redirect_target,
            "processing_time_ms": round(self.processing_time_ms, 2),
        }


def verdict_runtime():
    """Resolve facade overrides while keeping components acyclic."""
    return sys.modules.get("easypi_netprotection.verdict.engine", sys.modules[__name__])


__all__ = [
    "AD_GENESIS_AVAILABLE",
    "Any",
    "BlocklistFilter",
    "CNAMEChainAnalyzer",
    "CNAME_ANALYZER_AVAILABLE",
    "ConfidenceLevel",
    "DOH_DOT_DOMAINS",
    "Evidence",
    "EvidenceChain",
    "EvidenceItem",
    "EvidenceSource",
    "FREQUENCY_AVAILABLE",
    "FrequencyAnalyzer",
    "HEURISTICS_AVAILABLE",
    "HeuristicsEngine",
    "IntelProvider",
    "MatcherRegistry",
    "NRD_AVAILABLE",
    "PARENTAL_AVAILABLE",
    "PROFILES_AVAILABLE",
    "ParentalController",
    "Path",
    "ProfileManager",
    "Protocol",
    "RewriteManager",
    "RewriteType",
    "SAFESEARCH_AVAILABLE",
    "SCHEDULE_CHECKER_AVAILABLE",
    "STREAMING_BLOCKER_AVAILABLE",
    "SafeSearchEnforcer",
    "ScheduleChecker",
    "ShieldProvider",
    "TYPE_CHECKING",
    "VerdictAction",
    "VerdictModel",
    "VerdictReason",
    "VerdictResult",
    "asyncio",
    "dataclass",
    "fnmatch",
    "get_ad_genesis_blocklist",
    "get_blocklist_filter",
    "get_cname_analyzer",
    "get_domains_for_service",
    "get_heuristics_engine",
    "get_matcher_registry",
    "get_nrd_filter",
    "get_parental_controller",
    "get_profile_manager",
    "get_rewrite_manager",
    "get_safesearch_enforcer",
    "get_schedule_checker",
    "get_settings",
    "get_streaming_blocker",
    "ipaddress",
    "json",
    "logger",
    "logging",
    "sys",
    "time",
    "verdict_runtime",
]
