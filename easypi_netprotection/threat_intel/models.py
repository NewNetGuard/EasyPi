"""
Threat Intel Models — Data structures for threat intelligence.

Key principles:
- CT/heuristics are SIGNALS only (observe/score), never auto-deny
- Multi-signal threshold for quarantine (not block)
- TTL-based entries with confidence decay over time
- Source weight hierarchy: heuristic < user_report < permissive_list
"""

from __future__ import annotations

from datetime import datetime, timezone
from ..time_utils import utc_now
from enum import Enum, IntEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatCategory(str, Enum):
    """Categories of threats."""
    PHISHING = "phishing"
    MALWARE = "malware"
    DGA = "dga"  # Domain Generation Algorithm
    HOMOGLYPH = "homoglyph"  # Brand impersonation
    NEWREG = "newreg"  # Newly registered domain
    SUSPICIOUS = "suspicious"  # Generic suspicious
    TRACKER = "tracker"
    ADVERTISING = "advertising"
    CRYPTOMINER = "cryptominer"
    COMMAND_CONTROL = "c2"  # Command & Control


class ThreatStatus(str, Enum):
    """Status of a threat entry."""
    ACTIVE = "active"  # Currently flagged
    QUARANTINE = "quarantine"  # In quarantine, pending review
    OBSERVED = "observed"  # Only logging, no action
    CONFIRMED = "confirmed"  # User/admin confirmed threat
    ALLOWLISTED = "allowlisted"  # Manually allowed
    EXPIRED = "expired"  # TTL expired
    DECAYED = "decayed"  # Confidence decayed below threshold


class SourceType(str, Enum):
    """Types of threat intelligence sources."""
    HEURISTIC = "heuristic"  # Our own detection
    CT_LOGS = "ct_logs"  # Certificate Transparency
    USER_REPORT = "user_report"  # Community report
    USER_CONFIRMED = "user_confirmed"  # User verified report
    ADMIN_CONFIRMED = "admin_confirmed"  # Admin verified
    FEED_CC0 = "feed_cc0"  # CC0 licensed feed
    FEED_MIT = "feed_mit"  # MIT licensed feed
    FEED_PERMISSIVE = "feed_permissive"  # Other permissive license
    MANUAL = "manual"  # Manually added


class SourceWeight(IntEnum):
    """
    Weight hierarchy for source reliability.
    Higher = more trusted.
    """
    HEURISTIC = 10  # Lowest - automated detection
    CT_LOGS = 15  # Slightly better - public data
    USER_REPORT = 25  # Community report (unverified)
    USER_CONFIRMED = 40  # User verified the threat
    FEED_PERMISSIVE = 50  # External feed with permissive license
    FEED_MIT = 55  # MIT licensed feed
    FEED_CC0 = 60  # CC0/public domain feed
    ADMIN_CONFIRMED = 80  # Admin verified
    MANUAL = 90  # Manually added by admin

    @classmethod
    def from_source_type(cls, source_type: SourceType) -> int:
        """Get weight for a source type."""
        mapping = {
            SourceType.HEURISTIC: cls.HEURISTIC,
            SourceType.CT_LOGS: cls.CT_LOGS,
            SourceType.USER_REPORT: cls.USER_REPORT,
            SourceType.USER_CONFIRMED: cls.USER_CONFIRMED,
            SourceType.FEED_CC0: cls.FEED_CC0,
            SourceType.FEED_MIT: cls.FEED_MIT,
            SourceType.FEED_PERMISSIVE: cls.FEED_PERMISSIVE,
            SourceType.ADMIN_CONFIRMED: cls.ADMIN_CONFIRMED,
            SourceType.MANUAL: cls.MANUAL,
        }
        return mapping.get(source_type, cls.HEURISTIC)


class HeuristicSignal(BaseModel):
    """Individual heuristic signal."""
    model_config = ConfigDict(frozen=True)

    name: str = Field(..., description="Signal name (e.g., 'homoglyph', 'dga')")
    score: float = Field(..., ge=0, le=100, description="Signal score 0-100")
    details: str = Field(default="", description="Human-readable details")
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatSignals(BaseModel):
    """Collection of signals for a domain."""
    domain: str
    signals: list[HeuristicSignal] = Field(default_factory=list)
    
    # Individual signal scores
    dga_score: float = Field(default=0, ge=0, le=100)
    homoglyph_score: float = Field(default=0, ge=0, le=100)
    entropy_score: float = Field(default=0, ge=0, le=100)
    newreg_score: float = Field(default=0, ge=0, le=100)
    brand_match_score: float = Field(default=0, ge=0, le=100)
    
    # Metadata
    domain_age_days: int | None = Field(default=None)
    matched_brand: str | None = Field(default=None)
    
    @property
    def total_score(self) -> float:
        """Weighted total of all signals."""
        scores = [
            self.dga_score * 0.25,
            self.homoglyph_score * 0.30,  # Brand impersonation is serious
            self.entropy_score * 0.15,
            self.newreg_score * 0.15,
            self.brand_match_score * 0.15,
        ]
        return min(100, sum(scores))
    
    @property
    def signal_count(self) -> int:
        """Number of active signals (score > 0)."""
        count = 0
        if self.dga_score > 20:
            count += 1
        if self.homoglyph_score > 20:
            count += 1
        if self.entropy_score > 50:
            count += 1
        if self.newreg_score > 30:
            count += 1
        if self.brand_match_score > 30:
            count += 1
        return count
    
    def should_quarantine(self, threshold: int = 2) -> bool:
        """
        Check if domain should go to quarantine.
        Requires multiple signals to trigger quarantine (not just one).
        """
        return self.signal_count >= threshold and self.total_score >= 40


class ThreatEntry(BaseModel):
    """
    A threat entry in the database.
    
    Key features:
    - TTL-based expiration
    - Confidence decay over time
    - Source weight consideration
    - Multi-signal aggregation
    """
    id: str = Field(..., description="Unique entry ID")
    domain: str = Field(..., description="Domain name")
    category: ThreatCategory = Field(default=ThreatCategory.SUSPICIOUS)
    status: ThreatStatus = Field(default=ThreatStatus.OBSERVED)
    
    # Scoring
    initial_confidence: float = Field(..., ge=0, le=100, description="Initial confidence score")
    current_confidence: float = Field(..., ge=0, le=100, description="Current (decayed) confidence")
    
    # Source tracking
    source_type: SourceType = Field(default=SourceType.HEURISTIC)
    source_weight: int = Field(default=SourceWeight.HEURISTIC)
    source_details: str = Field(default="", description="Source description")
    
    # Signals
    signals: ThreatSignals | None = Field(default=None)
    signal_count: int = Field(default=0)
    
    # Timestamps
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = Field(default=None, description="TTL expiration")
    last_seen: datetime = Field(default_factory=utc_now)
    
    # Decay settings
    decay_rate: float = Field(default=0.05, description="Confidence decay per day")
    min_confidence: float = Field(default=10, description="Minimum confidence before removal")
    
    # User interaction
    user_reports: int = Field(default=0, description="Number of user reports")
    false_positive_reports: int = Field(default=0, description="FP reports")
    
    # Extra metadata
    metadata: dict[str, Any] = Field(default_factory=dict)
    
    def calculate_decayed_confidence(self, now: datetime | None = None) -> float:
        """Calculate confidence with time decay."""
        if now is None:
            now = utc_now()
        
        days_elapsed = (now - self.created_at).total_seconds() / 86400
        decayed = self.initial_confidence * (1 - self.decay_rate * days_elapsed)
        
        # Apply source weight bonus (higher trust = slower decay)
        weight_bonus = self.source_weight / 100  # 0.1 to 0.9
        decayed = decayed + (self.initial_confidence - decayed) * weight_bonus * 0.3
        
        return max(self.min_confidence, min(100, decayed))
    
    def is_expired(self, now: datetime | None = None) -> bool:
        """Check if entry has expired."""
        if now is None:
            now = utc_now()
        
        if self.expires_at and now >= self.expires_at:
            return True
        
        # Also expire if confidence decayed too much
        return self.calculate_decayed_confidence(now) < self.min_confidence
    
    def should_block(self) -> bool:
        """
        NEVER auto-block from heuristics alone.
        Only block if confirmed by admin or from trusted feed.
        """
        if self.status == ThreatStatus.ALLOWLISTED:
            return False
        
        # Only block if explicitly confirmed
        return self.status == ThreatStatus.CONFIRMED and self.source_weight >= SourceWeight.ADMIN_CONFIRMED
    
    def should_quarantine(self) -> bool:
        """Check if domain should be in quarantine (observe + flag)."""
        if self.status == ThreatStatus.ALLOWLISTED:
            return False
        
        return (
            self.status == ThreatStatus.QUARANTINE
            or (self.signal_count >= 2 and self.current_confidence >= 50)
        )
    
    def to_ui_recommendation(self) -> dict[str, Any]:
        """Generate UI recommendation for user."""
        return {
            "domain": self.domain,
            "status": self.status.value,
            "confidence": round(self.current_confidence, 1),
            "category": self.category.value,
            "signal_count": self.signal_count,
            "recommendation": self._get_recommendation(),
            "action_buttons": self._get_action_buttons(),
            "details": self._get_details(),
        }
    
    def _get_recommendation(self) -> str:
        """Get human-readable recommendation."""
        if self.should_block():
            return "Заблокирован (подтверждённая угроза)"
        elif self.should_quarantine():
            return "Подозрительный домен — рекомендуем проверить"
        elif self.status == ThreatStatus.OBSERVED:
            return "Под наблюдением — активность логируется"
        else:
            return "Информация доступна"
    
    def _get_action_buttons(self) -> list[dict[str, str]]:
        """Get available UI actions."""
        buttons = []
        
        if self.status != ThreatStatus.ALLOWLISTED:
            buttons.append({"action": "allowlist", "label": "Разрешить (allowlist)"})
        
        if self.status == ThreatStatus.QUARANTINE:
            buttons.append({"action": "block", "label": "Заблокировать"})
            buttons.append({"action": "ignore", "label": "Игнорировать"})
        
        if self.status != ThreatStatus.CONFIRMED:
            buttons.append({"action": "report_fp", "label": "Это ошибка (false positive)"})
        
        return buttons
    
    def _get_details(self) -> list[str]:
        """Get human-readable signal details."""
        details = []
        
        if self.signals:
            if self.signals.dga_score > 20:
                details.append(f"DGA-паттерн: {self.signals.dga_score:.0f}%")
            if self.signals.homoglyph_score > 20:
                brand = self.signals.matched_brand or "unknown"
                details.append(f"Похож на бренд '{brand}': {self.signals.homoglyph_score:.0f}%")
            if self.signals.newreg_score > 30:
                age = self.signals.domain_age_days or 0
                details.append(f"Новый домен ({age} дней): {self.signals.newreg_score:.0f}%")
            if self.signals.entropy_score > 50:
                details.append(f"Высокая энтропия: {self.signals.entropy_score:.0f}%")
        
        details.append(f"Источник: {self.source_type.value} (вес: {self.source_weight})")
        
        return details


class QuarantineAction(str, Enum):
    """Actions available for quarantined domains."""
    BLOCK = "block"  # Confirm and block
    ALLOWLIST = "allowlist"  # Add to allowlist
    IGNORE = "ignore"  # Remove from quarantine, don't block
    EXTEND = "extend"  # Extend observation period
    REPORT_FP = "report_fp"  # Report as false positive


class BrandEntry(BaseModel):
    """Protected brand for homoglyph detection."""
    name: str = Field(..., description="Brand name")
    domains: list[str] = Field(default_factory=list, description="Official domains")
    keywords: list[str] = Field(default_factory=list, description="Related keywords")
    protected: bool = Field(default=True, description="Is brand protected")
    owner_verified: bool = Field(default=False, description="Owner verified this entry")


class AllowlistEntry(BaseModel):
    """Manual allowlist entry."""
    id: str
    domain: str  # Can be exact or wildcard pattern
    pattern_type: str = Field(default="exact")  # exact, wildcard, regex
    reason: str = Field(default="")
    added_by: str = Field(default="system")
    added_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = Field(default=None)
    
    def matches(self, domain: str) -> bool:
        """Check if domain matches this allowlist entry."""
        if self.pattern_type == "exact":
            return domain.lower() == self.domain.lower()
        elif self.pattern_type == "wildcard":
            import fnmatch
            return fnmatch.fnmatch(domain.lower(), self.domain.lower())
        elif self.pattern_type == "regex":
            import re
            try:
                return bool(re.match(self.domain, domain, re.IGNORECASE))
            except re.error:
                return False
        return False


class FeedConfig(BaseModel):
    """Configuration for an external threat feed."""
    id: str
    name: str
    url: str
    license: str = Field(default="unknown")  # cc0, mit, apache, unknown
    source_type: SourceType = Field(default=SourceType.FEED_PERMISSIVE)
    enabled: bool = Field(default=True)
    update_interval_hours: int = Field(default=24)
    last_updated: datetime | None = Field(default=None)
    domain_count: int = Field(default=0)
    categories: list[ThreatCategory] = Field(default_factory=list)
    user_license_confirmed: bool = Field(
        default=False,
        description="User confirmed responsibility for license compliance"
    )
    
    def get_source_weight(self) -> int:
        """Get weight based on license."""
        return SourceWeight.from_source_type(self.source_type)
