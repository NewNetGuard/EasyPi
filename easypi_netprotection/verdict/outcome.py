"""
EasyPi NetProtection - Verdict Outcome Models

Defines the possible outcomes of the Verdict Pipeline and their semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from ..time_utils import utc_now
from enum import Enum
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .evidence import Evidence


class VerdictType(str, Enum):
    """Verdict type alias for VerdictAction."""

    ALLOW = "allow"
    DENY = "deny"
    REDIRECT = "redirect"
    OBSERVE = "observe"


class VerdictAction(str, Enum):
    """
    Possible actions for a DNS flow verdict.

    Actions are processed in order of priority:
    1. allow - Explicitly permitted (highest priority)
    2. deny - Blocked, returns NXDOMAIN
    3. redirect - Redirected to specified IP
    4. observe - Allowed but logged for analysis
    """

    ALLOW = "allow"
    DENY = "deny"
    REDIRECT = "redirect"
    OBSERVE = "observe"

    @property
    def is_blocking(self) -> bool:
        """Check if this action blocks the request."""
        return self in (VerdictAction.DENY, VerdictAction.REDIRECT)

    @property
    def is_permissive(self) -> bool:
        """Check if this action allows the request."""
        return self in (VerdictAction.ALLOW, VerdictAction.OBSERVE)

    @property
    def priority(self) -> int:
        """
        Get action priority for conflict resolution.

        Higher priority wins when multiple matchers match.
        ALLOW has highest priority to enable whitelisting.
        """
        priorities = {
            VerdictAction.ALLOW: 100,
            VerdictAction.DENY: 50,
            VerdictAction.REDIRECT: 40,
            VerdictAction.OBSERVE: 10,
        }
        return priorities.get(self, 0)


@dataclass
class Verdict:
    """
    Final verdict for a DNS flow.

    Contains the decision, confidence score, and evidence chain.
    """

    verdict_type: VerdictType = VerdictType.ALLOW
    confidence: int = 100
    evidence: list["Evidence"] = field(default_factory=list)
    reason: str = ""
    redirect_ip: str | None = None
    domain: str = ""
    flow_id: str = ""
    timestamp: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Convert verdict to dictionary."""
        return {
            "verdict": self.verdict_type.value,
            "confidence": self.confidence,
            "evidence": [
                e.to_dict() if hasattr(e, "to_dict") else str(e) for e in self.evidence
            ],
            "reason": self.reason,
            "redirect_ip": self.redirect_ip,
            "domain": self.domain,
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat(),
        }


class VerdictReason(str, Enum):
    """
    Categorized reasons for verdicts.

    Used for analytics and user-facing explanations.
    """

    # Allow reasons
    WHITELIST = "whitelist"
    SAFE_DOMAIN = "safe_domain"
    USER_OVERRIDE = "user_override"
    NO_MATCH = "no_match"

    # Rewrite reasons
    DNS_REWRITE = "dns_rewrite"  # Custom DNS mapping applied
    REWRITE_NXDOMAIN = "rewrite_nxdomain"  # Rewrite to NXDOMAIN
    SAFE_SEARCH = "safe_search"  # Safe Search redirect (Google/Bing/YouTube)

    # Device Profile reasons
    PROFILE_WHITELIST = "profile_whitelist"  # Profile whitelist
    PROFILE_BLACKLIST = "profile_blacklist"  # Profile blacklist
    PROFILE_PASSTHROUGH = "profile_passthrough"  # Profile filter=none
    PROFILE_BLOCKED = "profile_blocked"  # Blocked by profile filter level

    # Deny reasons
    BLACKLIST = "blacklist"  # Domain in the user's own blacklist
    BLOCKLIST = "blocklist"  # Domain in a downloaded blocklist
    NEWLY_REGISTERED = "newly_registered"  # Newly-registered domain feed
    SHADOW_MODE = "shadow_mode"  # Promoted to a block in Shadow Mode
    APP_BLOCKED = "app_blocked"  # Streaming/app blocker for a managed device
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    MALWARE = "malware"
    PHISHING = "phishing"
    ADULT_CONTENT = "adult_content"
    CRYPTOMINING = "cryptomining"

    # Security reasons
    DNS_TUNNELING = "dns_tunneling"
    DGA_DETECTED = "dga_detected"
    CNAME_CLOAKING = "cname_cloaking"
    DNS_REBINDING = "dns_rebinding"  # Public domain resolving to private/reserved IP
    SUSPICIOUS_TLD = "suspicious_tld"

    # Heuristics reasons
    HOMOGLYPH_DETECTED = "homoglyph_detected"  # Brand impersonation (аpple.com)
    HEURISTICS_BLOCK = "heuristics_block"  # Blocked by heuristics engine
    HEURISTICS_OBSERVE = "heuristics_observe"  # Shadow mode observation
    DOMAIN_ANOMALY = "domain_anomaly"  # Suspicious domain structure
    DEVICE_ANOMALY = "device_anomaly"  # Traffic anomaly from device
    ASN_REPUTATION = "asn_reputation"  # Bad ASN/IP reputation

    # Policy reasons
    SCHEDULE_BLOCKED = "schedule_blocked"
    DEVICE_POLICY = "device_policy"
    UNKNOWN_DEVICE = "unknown_device"
    SHIELD_PROFILE = "shield_profile"

    # Parental Control reasons
    PARENTAL_CONTROL = "parental_control"  # Generic parental block
    AGE_RESTRICTED = "age_restricted"  # Blocked by age category
    BEDTIME_BLOCKED = "bedtime_blocked"  # Blocked during bedtime
    DAILY_LIMIT = "daily_limit"  # Daily time limit exceeded

    # System reasons
    SYSTEM_ERROR = "system_error"
    SAFE_MODE = "safe_mode"

    @property
    def category(self) -> str:
        """Get the category of this reason."""
        allow_reasons = {
            VerdictReason.WHITELIST,
            VerdictReason.SAFE_DOMAIN,
            VerdictReason.USER_OVERRIDE,
            VerdictReason.NO_MATCH,
        }
        security_reasons = {
            VerdictReason.DNS_TUNNELING,
            VerdictReason.DGA_DETECTED,
            VerdictReason.CNAME_CLOAKING,
            VerdictReason.DNS_REBINDING,
            VerdictReason.SUSPICIOUS_TLD,
            VerdictReason.MALWARE,
            VerdictReason.PHISHING,
            # Heuristics security
            VerdictReason.HOMOGLYPH_DETECTED,
            VerdictReason.HEURISTICS_BLOCK,
            VerdictReason.DOMAIN_ANOMALY,
            VerdictReason.DEVICE_ANOMALY,
            VerdictReason.ASN_REPUTATION,
        }

        if self in allow_reasons:
            return "allow"
        elif self in security_reasons:
            return "security"
        else:
            return "policy"

    @property
    def severity(self) -> int:
        """
        Get severity level (1-10) for this reason.

        Higher severity = more serious threat.
        """
        severity_map = {
            # Allow - no severity
            VerdictReason.WHITELIST: 0,
            VerdictReason.SAFE_DOMAIN: 0,
            VerdictReason.USER_OVERRIDE: 0,
            VerdictReason.NO_MATCH: 0,
            # Low severity
            VerdictReason.ADVERTISING: 2,
            VerdictReason.TRACKING: 3,
            # Medium severity
            VerdictReason.ADULT_CONTENT: 4,
            VerdictReason.SCHEDULE_BLOCKED: 3,
            VerdictReason.DEVICE_POLICY: 3,
            VerdictReason.SHIELD_PROFILE: 3,
            VerdictReason.BLACKLIST: 5,
            VerdictReason.APP_BLOCKED: 3,
            VerdictReason.NEWLY_REGISTERED: 5,
            VerdictReason.SHADOW_MODE: 7,
            # High severity
            VerdictReason.CRYPTOMINING: 6,
            VerdictReason.SUSPICIOUS_TLD: 6,
            VerdictReason.CNAME_CLOAKING: 7,
            VerdictReason.DNS_REBINDING: 8,
            VerdictReason.DGA_DETECTED: 8,
            VerdictReason.DNS_TUNNELING: 8,
            # Heuristics severity
            VerdictReason.HOMOGLYPH_DETECTED: 8,
            VerdictReason.HEURISTICS_BLOCK: 7,
            VerdictReason.HEURISTICS_OBSERVE: 4,
            VerdictReason.DOMAIN_ANOMALY: 5,
            VerdictReason.DEVICE_ANOMALY: 6,
            VerdictReason.ASN_REPUTATION: 6,
            # Critical severity
            VerdictReason.MALWARE: 9,
            VerdictReason.PHISHING: 9,
            # System
            VerdictReason.SYSTEM_ERROR: 1,
            VerdictReason.SAFE_MODE: 0,
        }
        return severity_map.get(self, 5)


class ConfidenceLevel(str, Enum):
    """
    Confidence levels for verdict decisions.

    Maps to numeric ranges for threshold comparisons.
    """

    CERTAIN = "certain"  # 95-100: Definite match (exact rule, known malware)
    HIGH = "high"  # 80-94: Strong evidence
    MEDIUM = "medium"  # 50-79: Moderate evidence
    LOW = "low"  # 20-49: Weak evidence
    UNCERTAIN = "uncertain"  # 0-19: Very low confidence

    @classmethod
    def from_score(cls, score: int) -> "ConfidenceLevel":
        """Convert numeric score to confidence level."""
        if score >= 95:
            return cls.CERTAIN
        elif score >= 80:
            return cls.HIGH
        elif score >= 50:
            return cls.MEDIUM
        elif score >= 20:
            return cls.LOW
        else:
            return cls.UNCERTAIN

    @property
    def min_score(self) -> int:
        """Get minimum score for this level."""
        ranges = {
            ConfidenceLevel.CERTAIN: 95,
            ConfidenceLevel.HIGH: 80,
            ConfidenceLevel.MEDIUM: 50,
            ConfidenceLevel.LOW: 20,
            ConfidenceLevel.UNCERTAIN: 0,
        }
        return ranges.get(self, 0)

    @property
    def max_score(self) -> int:
        """Get maximum score for this level."""
        ranges = {
            ConfidenceLevel.CERTAIN: 100,
            ConfidenceLevel.HIGH: 94,
            ConfidenceLevel.MEDIUM: 79,
            ConfidenceLevel.LOW: 49,
            ConfidenceLevel.UNCERTAIN: 19,
        }
        return ranges.get(self, 100)


def calculate_confidence(evidences: list[dict]) -> int:
    """
    Calculate aggregate confidence from multiple evidence items.

    Uses weighted combination where stronger signals have more impact.

    Args:
        evidences: List of evidence dicts with 'weight' and 'confidence' keys

    Returns:
        Aggregate confidence score (0-100)
    """
    if not evidences:
        return 0

    total_weight = sum(e.get("weight", 1.0) for e in evidences)
    if total_weight == 0:
        return 0

    weighted_sum = sum(
        e.get("confidence", 50) * e.get("weight", 1.0) for e in evidences
    )

    base_confidence = weighted_sum / total_weight

    # Boost confidence with multiple corroborating signals
    signal_count = len(evidences)
    if signal_count >= 3:
        boost = min(10, (signal_count - 2) * 2)
        base_confidence = min(100, base_confidence + boost)

    return int(base_confidence)


def resolve_action_conflict(actions: list[tuple[VerdictAction, int]]) -> VerdictAction:
    """
    Resolve conflicts between multiple matching actions.

    Uses priority-based resolution:
    1. ALLOW always wins (whitelist override)
    2. Among remaining, highest confidence wins
    3. If tied, use action priority

    Args:
        actions: List of (action, confidence) tuples

    Returns:
        Winning action
    """
    if not actions:
        return VerdictAction.OBSERVE

    # ALLOW always wins if present with high confidence
    for action, confidence in actions:
        if action == VerdictAction.ALLOW and confidence >= 80:
            return VerdictAction.ALLOW

    # Sort by confidence (desc), then action priority (desc)
    sorted_actions = sorted(
        actions,
        key=lambda x: (x[1], x[0].priority),
        reverse=True,
    )

    return sorted_actions[0][0]


def get_response_for_action(
    action: VerdictAction,
    domain: str,
    redirect_ip: str | None = None,
) -> dict[str, Any]:
    """
    Get DNS response parameters for a verdict action.

    Args:
        action: The verdict action
        domain: The queried domain
        redirect_ip: IP to redirect to (for REDIRECT action)

    Returns:
        Dict with response parameters
    """
    if action == VerdictAction.DENY:
        return {
            "response_code": "NXDOMAIN",
            "answers": [],
            "ttl": 60,
            "is_blocked": True,
        }

    elif action == VerdictAction.REDIRECT:
        ip = redirect_ip or "0.0.0.0"
        return {
            "response_code": "NOERROR",
            "answers": [
                {
                    "name": domain + ".",
                    "type": "A",
                    "ttl": 60,
                    "data": ip,
                }
            ],
            "ttl": 60,
            "is_blocked": True,
            "redirect_ip": ip,
        }

    else:  # ALLOW or OBSERVE
        return {
            "is_blocked": False,
            "forward_to_upstream": True,
        }
