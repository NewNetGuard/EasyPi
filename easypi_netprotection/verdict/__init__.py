"""
EasyPi NetProtection — Verdict Package.

Decision Engine: Verdict Pipeline, matchers, evidence aggregation.
"""

from .outcome import (
    Verdict,
    VerdictType,
    VerdictAction,
    VerdictReason,
    ConfidenceLevel,
)

from .evidence import (
    Evidence,
    EvidenceSource,
    EvidenceWeight,
    EvidenceChain,
    Signal,
)

from .matchers import (
    BaseMatcher,
    MatchResult,
    MatcherRegistry,
    ExactMatcher,
    WildcardMatcher,
    RegexMatcher,
    IPMatcher,
    ASNMatcher,
)

from .engine import (
    VerdictEngine,
    VerdictResult,
    IntelProvider,
    ShieldProvider,
)

__all__ = [
    # Outcome
    "Verdict",
    "VerdictType",
    "VerdictAction",
    "VerdictReason",
    "ConfidenceLevel",
    
    # Evidence
    "Evidence",
    "EvidenceSource",
    "EvidenceWeight",
    "EvidenceChain",
    "Signal",
    
    # Matchers
    "BaseMatcher",
    "MatchResult",
    "MatcherRegistry",
    "ExactMatcher",
    "WildcardMatcher",
    "RegexMatcher",
    "IPMatcher",
    "ASNMatcher",
    
    # Engine
    "VerdictEngine",
    "VerdictResult",
    "IntelProvider",
    "ShieldProvider",
]
