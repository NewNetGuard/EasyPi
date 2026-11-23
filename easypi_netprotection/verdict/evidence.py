"""
EasyPi NetProtection - Evidence Aggregation

Collects, weighs, and aggregates signals from various sources
into a coherent evidence chain for verdict decisions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceSource(str, Enum):
    """Sources that can produce evidence."""
    
    # Rewrite source (highest priority - overrides everything)
    REWRITE = "rewrite:rule"
    
    # Blocklist source (high priority)
    BLOCKLIST = "blocklist:domain"
    
    # Matcher sources
    MATCHER_EXACT = "matcher:exact"
    MATCHER_WILDCARD = "matcher:wildcard"
    MATCHER_REGEX = "matcher:regex"
    MATCHER_IP = "matcher:ip"
    MATCHER_ASN = "matcher:asn"
    
    # Intel sources
    INTEL_DOMAIN = "intel:domain"
    INTEL_CNAME = "intel:cname_chain"
    INTEL_ENTROPY = "intel:entropy"
    INTEL_ASN = "intel:asn"
    INTEL_TLS = "intel:tls_probe"
    INTEL_REBIND = "intel:rebind"          # DNS rebinding (public domain -> private IP)
    INTEL_FREQUENCY = "intel:frequency"    # Beaconing / burst / high-frequency C2 pattern
    
    # Heuristics sources
    HEURISTICS_DGA = "heuristics:dga"
    HEURISTICS_HOMOGLYPH = "heuristics:homoglyph"
    HEURISTICS_FIRST_SEEN = "heuristics:first_seen"
    HEURISTICS_DOMAIN = "heuristics:domain_analysis"
    HEURISTICS_DEVICE = "heuristics:device_anomaly"
    HEURISTICS_ASN = "heuristics:asn_cluster"
    HEURISTICS_AGGREGATED = "heuristics:aggregated"
    HEURISTICS_AD_GENESIS = "heuristics:ad_genesis"  # behavioral parasitic-ad branch (NAI + co-occurrence)
    
    # Shield sources
    SHIELD_PROFILE = "shield:profile"
    SHIELD_DEVICE = "shield:device"
    SHIELD_SCHEDULE = "shield:schedule"
    SHIELD_ALLOW = "shield:allow"      # Profile whitelist
    SHIELD_DENY = "shield:deny"        # Profile blacklist
    
    # System sources
    SYSTEM_CACHE = "system:cache"
    SYSTEM_SAFE_MODE = "system:safe_mode"
    
    @property
    def category(self) -> str:
        """Get the category of this source."""
        return self.value.split(":")[0]
    
    @property
    def base_weight(self) -> float:
        """Get the base weight for this source type."""
        weights = {
            # Rewrite has absolute priority
            EvidenceSource.REWRITE: 1.0,
            
            # Blocklist has highest weight (curated domain lists)
            EvidenceSource.BLOCKLIST: 1.0,
            
            # Matchers have high weight (explicit rules)
            EvidenceSource.MATCHER_EXACT: 1.0,
            EvidenceSource.MATCHER_WILDCARD: 0.9,
            EvidenceSource.MATCHER_REGEX: 0.85,
            EvidenceSource.MATCHER_IP: 0.95,
            EvidenceSource.MATCHER_ASN: 0.8,
            
            # Intel has variable weight
            EvidenceSource.INTEL_DOMAIN: 0.7,
            EvidenceSource.INTEL_CNAME: 0.75,
            EvidenceSource.INTEL_ENTROPY: 0.6,
            EvidenceSource.INTEL_ASN: 0.5,
            EvidenceSource.INTEL_TLS: 0.65,
            EvidenceSource.INTEL_REBIND: 0.97,
            EvidenceSource.INTEL_FREQUENCY: 0.5,
            
            # Heuristics has moderate weight (multi-signal scoring)
            EvidenceSource.HEURISTICS_DGA: 0.85,
            EvidenceSource.HEURISTICS_HOMOGLYPH: 0.9,
            EvidenceSource.HEURISTICS_FIRST_SEEN: 0.5,
            EvidenceSource.HEURISTICS_DOMAIN: 0.6,
            EvidenceSource.HEURISTICS_DEVICE: 0.4,
            EvidenceSource.HEURISTICS_ASN: 0.5,
            EvidenceSource.HEURISTICS_AGGREGATED: 0.75,
            EvidenceSource.HEURISTICS_AD_GENESIS: 0.85,
            
            # Shield has moderate weight
            EvidenceSource.SHIELD_PROFILE: 0.8,
            EvidenceSource.SHIELD_DEVICE: 0.75,
            EvidenceSource.SHIELD_SCHEDULE: 0.9,
            
            # System has low weight (informational)
            EvidenceSource.SYSTEM_CACHE: 0.3,
            EvidenceSource.SYSTEM_SAFE_MODE: 0.1,
        }
        return weights.get(self, 0.5)


@dataclass
class Signal:
    """
    A single observation from an analyzer.
    
    Signals are raw observations that get converted to Evidence
    when they contribute to a verdict decision.
    """
    
    source: EvidenceSource
    observation: str
    confidence: int  # 0-100
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    def to_evidence(
        self,
        suggested_action: str | None = None,
        weight_modifier: float = 1.0,
    ) -> "Evidence":
        """Convert signal to evidence item."""
        return Evidence(
            source=self.source,
            signal=self.observation,
            confidence=self.confidence,
            weight=self.source.base_weight * weight_modifier,
            suggested_action=suggested_action,
            metadata=self.metadata,
            timestamp=self.timestamp,
        )


class EvidenceWeight(str, Enum):
    """
    Weight categories for evidence importance.
    """
    
    CRITICAL = "critical"    # 1.0 - Absolute evidence
    HIGH = "high"            # 0.8 - Strong evidence
    MEDIUM = "medium"        # 0.6 - Moderate evidence
    LOW = "low"              # 0.4 - Weak evidence
    INFORMATIONAL = "info"   # 0.2 - Just for logging
    
    @property
    def value_float(self) -> float:
        """Get numeric weight value."""
        weights = {
            EvidenceWeight.CRITICAL: 1.0,
            EvidenceWeight.HIGH: 0.8,
            EvidenceWeight.MEDIUM: 0.6,
            EvidenceWeight.LOW: 0.4,
            EvidenceWeight.INFORMATIONAL: 0.2,
        }
        return weights.get(self, 0.5)


@dataclass
class Evidence:
    """
    A piece of evidence contributing to a verdict.
    
    Evidence items are weighted signals that together form
    the basis for the final verdict decision.
    """
    
    source: EvidenceSource
    signal: str
    confidence: int  # 0-100
    weight: float = 1.0  # 0.0-1.0
    suggested_action: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    
    @property
    def weighted_confidence(self) -> float:
        """Calculate confidence adjusted by weight."""
        return self.confidence * self.weight
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source": self.source.value,
            "signal": self.signal,
            "confidence": self.confidence,
            "weight": round(self.weight, 3),
            "suggested_action": self.suggested_action,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Evidence":
        """Create from dictionary."""
        return cls(
            source=EvidenceSource(data["source"]),
            signal=data["signal"],
            confidence=data.get("confidence", 50),
            weight=data.get("weight", 1.0),
            suggested_action=data.get("suggested_action"),
            metadata=data.get("metadata", {}),
        )


class EvidenceChain:
    """
    Aggregates evidence from multiple sources for a single flow.
    
    The chain maintains all evidence items and provides methods
    for analysis and verdict recommendation.
    """
    
    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        self.items: list[Evidence] = []
        self.created_at = time.time()
    
    def add(self, evidence: Evidence) -> None:
        """Add evidence to the chain."""
        self.items.append(evidence)
    
    def add_signal(
        self,
        signal: Signal,
        suggested_action: str | None = None,
        weight_modifier: float = 1.0,
    ) -> Evidence:
        """Convert signal to evidence and add to chain."""
        evidence = signal.to_evidence(suggested_action, weight_modifier)
        self.add(evidence)
        return evidence
    
    def add_raw(
        self,
        source: EvidenceSource | str,
        signal: str,
        confidence: int,
        suggested_action: str | None = None,
        weight: float | None = None,
        metadata: dict | None = None,
    ) -> Evidence:
        """Add evidence from raw values."""
        if isinstance(source, str):
            source = EvidenceSource(source)
        
        evidence = Evidence(
            source=source,
            signal=signal,
            confidence=confidence,
            weight=weight if weight is not None else source.base_weight,
            suggested_action=suggested_action,
            metadata=metadata or {},
        )
        self.add(evidence)
        return evidence
    
    @property
    def total_confidence(self) -> int:
        """Calculate aggregate confidence from all evidence."""
        if not self.items:
            return 0
        
        total_weight = sum(e.weight for e in self.items)
        if total_weight == 0:
            return 0
        
        weighted_sum = sum(e.weighted_confidence for e in self.items)
        base_confidence = weighted_sum / total_weight
        
        # Boost for corroborating evidence
        corroborating = len([e for e in self.items if e.confidence >= 70])
        if corroborating >= 3:
            boost = min(10, (corroborating - 2) * 3)
            base_confidence = min(100, base_confidence + boost)
        
        return int(base_confidence)
    
    @property
    def recommended_action(self) -> str:
        """Determine recommended action from evidence."""
        if not self.items:
            return "observe"
        
        # Count votes by action
        action_scores: dict[str, float] = {}
        
        for e in self.items:
            if e.suggested_action:
                score = action_scores.get(e.suggested_action, 0)
                action_scores[e.suggested_action] = score + e.weighted_confidence
        
        if not action_scores:
            return "observe"
        
        # Allow always wins if confidence is high enough
        if action_scores.get("allow", 0) >= 80:
            return "allow"
        
        # Otherwise, highest score wins
        return max(action_scores, key=lambda k: action_scores[k])
    
    @property
    def primary_reason(self) -> str | None:
        """Get the primary reason (highest confidence signal)."""
        if not self.items:
            return None
        
        blocking = [e for e in self.items if e.suggested_action in ("deny", "redirect")]
        if blocking:
            return max(blocking, key=lambda e: e.weighted_confidence).signal
        
        return max(self.items, key=lambda e: e.weighted_confidence).signal
    
    def get_by_source(self, source: EvidenceSource) -> list[Evidence]:
        """Get all evidence from a specific source."""
        return [e for e in self.items if e.source == source]
    
    def get_by_category(self, category: str) -> list[Evidence]:
        """Get all evidence from a category (matcher, intel, shield, system)."""
        return [e for e in self.items if e.source.category == category]
    
    def get_blocking_evidence(self) -> list[Evidence]:
        """Get evidence that suggests blocking."""
        return [
            e for e in self.items
            if e.suggested_action in ("deny", "redirect")
        ]
    
    def get_allowing_evidence(self) -> list[Evidence]:
        """Get evidence that suggests allowing."""
        return [
            e for e in self.items
            if e.suggested_action in ("allow", "observe")
        ]
    
    def has_conflicting_evidence(self) -> bool:
        """Check if there's conflicting evidence (both allow and deny)."""
        has_allow = any(e.suggested_action == "allow" for e in self.items)
        has_deny = any(e.suggested_action == "deny" for e in self.items)
        return has_allow and has_deny
    
    def to_list(self) -> list[dict[str, Any]]:
        """Convert chain to list of dicts for serialization."""
        return [e.to_dict() for e in self.items]
    
    def summary(self) -> dict[str, Any]:
        """Get a summary of the evidence chain."""
        return {
            "flow_id": self.flow_id,
            "evidence_count": len(self.items),
            "total_confidence": self.total_confidence,
            "recommended_action": self.recommended_action,
            "primary_reason": self.primary_reason,
            "has_conflict": self.has_conflicting_evidence(),
            "sources": list(set(e.source.value for e in self.items)),
            "blocking_count": len(self.get_blocking_evidence()),
            "allowing_count": len(self.get_allowing_evidence()),
        }
    
    def explain(self) -> str:
        """Generate human-readable explanation of the verdict."""
        if not self.items:
            return "No evidence collected, default action applied."
        
        lines = []
        action = self.recommended_action
        confidence = self.total_confidence
        
        if action == "allow":
            lines.append(f"✓ ALLOWED (confidence: {confidence}%)")
        elif action == "deny":
            lines.append(f"✗ BLOCKED (confidence: {confidence}%)")
        elif action == "redirect":
            lines.append(f"↪ REDIRECTED (confidence: {confidence}%)")
        else:
            lines.append(f"◉ OBSERVED (confidence: {confidence}%)")
        
        lines.append("")
        lines.append("Evidence:")
        
        # Sort by weighted confidence
        sorted_items = sorted(
            self.items,
            key=lambda e: e.weighted_confidence,
            reverse=True,
        )
        
        for e in sorted_items[:5]:  # Top 5 evidence items
            action_icon = {
                "allow": "✓",
                "deny": "✗",
                "redirect": "↪",
                "observe": "◉",
            }.get(e.suggested_action or "", "•")
            
            lines.append(
                f"  {action_icon} [{e.source.value}] {e.signal} "
                f"(conf: {e.confidence}%, weight: {e.weight:.2f})"
            )
        
        if len(self.items) > 5:
            lines.append(f"  ... and {len(self.items) - 5} more")
        
        return "\n".join(lines)


def merge_evidence_chains(chains: list[EvidenceChain]) -> EvidenceChain:
    """
    Merge multiple evidence chains into one.
    
    Useful when combining evidence from parallel analysis paths.
    """
    if not chains:
        raise ValueError("No chains to merge")
    
    merged = EvidenceChain(flow_id=chains[0].flow_id)
    
    for chain in chains:
        for evidence in chain.items:
            merged.add(evidence)
    
    return merged
