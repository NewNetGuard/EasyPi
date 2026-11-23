"""
Quarantine System — Management of suspicious domains pending review.

Key principle: OBSERVE + FLAG, never auto-block.
User sees quarantined domains in UI with recommendation to block.

Features:
- Quarantine queue with UI recommendations
- Action history/audit log
- Auto-expiration of old entries
- Bulk actions support
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from ..time_utils import utc_now
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from .models import (
    QuarantineAction,
    ThreatCategory,
    ThreatEntry,
    ThreatSignals,
)


class QuarantineReason(str, Enum):
    """Why domain was quarantined."""
    MULTI_SIGNAL = "multi_signal"  # Multiple heuristic signals
    BRAND_IMPERSONATION = "brand_impersonation"
    NEW_DOMAIN_SUSPICIOUS = "new_domain_suspicious"
    CT_SCAN_HIT = "ct_scan_hit"
    USER_REPORT = "user_report"
    FEED_MATCH = "feed_match"
    MANUAL = "manual"


class QuarantineEntry(BaseModel):
    """Entry in the quarantine queue."""
    id: str = Field(default_factory=lambda: f"q_{uuid.uuid4().hex[:8]}")
    threat_id: str = Field(..., description="Reference to ThreatEntry")
    domain: str
    reason: QuarantineReason
    
    # Signals summary
    confidence: float = Field(default=0, ge=0, le=100)
    signal_count: int = Field(default=0)
    signals: ThreatSignals | None = Field(default=None)
    
    # Metadata
    category: ThreatCategory = Field(default=ThreatCategory.SUSPICIOUS)
    matched_brand: str | None = Field(default=None)
    domain_age_days: int | None = Field(default=None)
    source: str = Field(default="heuristics")
    
    # Timestamps
    quarantined_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = Field(default=None)
    reviewed_at: datetime | None = Field(default=None)
    
    # Review status
    reviewed: bool = Field(default=False)
    action_taken: QuarantineAction | None = Field(default=None)
    reviewed_by: str | None = Field(default=None)
    review_notes: str = Field(default="")
    
    def is_expired(self) -> bool:
        """Check if quarantine entry has expired."""
        if self.expires_at is None:
            return False
        return utc_now() > self.expires_at
    
    def to_ui_card(self) -> dict[str, Any]:
        """Generate UI card for display."""
        return {
            "id": self.id,
            "domain": self.domain,
            "reason": self._format_reason(),
            "confidence": round(self.confidence, 1),
            "signal_count": self.signal_count,
            "details": self._get_details(),
            "category": self.category.value,
            "matched_brand": self.matched_brand,
            "domain_age": self._format_age(),
            "quarantined_at": self.quarantined_at.isoformat(),
            "expires_in": self._format_expiry(),
            "reviewed": self.reviewed,
            "actions": self._get_available_actions(),
            "recommendation": self._get_recommendation(),
            "severity": self._get_severity(),
        }
    
    def _format_reason(self) -> str:
        """Human-readable reason."""
        reasons = {
            QuarantineReason.MULTI_SIGNAL: "Множественные сигналы угрозы",
            QuarantineReason.BRAND_IMPERSONATION: "Возможная имитация бренда",
            QuarantineReason.NEW_DOMAIN_SUSPICIOUS: "Подозрительный новый домен",
            QuarantineReason.CT_SCAN_HIT: "Обнаружен в CT-логах",
            QuarantineReason.USER_REPORT: "Жалоба пользователя",
            QuarantineReason.FEED_MATCH: "Найден в базе угроз",
            QuarantineReason.MANUAL: "Добавлен вручную",
        }
        return reasons.get(self.reason, str(self.reason))
    
    def _get_details(self) -> list[str]:
        """Get signal details for UI."""
        details = []
        
        if self.signals:
            if self.signals.dga_score > 20:
                details.append(f"DGA-паттерн: {self.signals.dga_score:.0f}%")
            if self.signals.homoglyph_score > 20:
                details.append(f"Похож на бренд: {self.signals.homoglyph_score:.0f}%")
            if self.signals.entropy_score > 40:
                details.append(f"Высокая энтропия: {self.signals.entropy_score:.0f}%")
            if self.signals.newreg_score > 30:
                details.append(f"Новый домен: {self.signals.newreg_score:.0f}%")
        
        if self.matched_brand:
            details.append(f"Целевой бренд: {self.matched_brand}")
        
        return details
    
    def _format_age(self) -> str:
        """Format domain age for display."""
        if self.domain_age_days is None:
            return "неизвестно"
        elif self.domain_age_days < 1:
            return "менее 1 дня"
        elif self.domain_age_days < 7:
            return f"{self.domain_age_days} дн."
        elif self.domain_age_days < 30:
            return f"{self.domain_age_days // 7} нед."
        elif self.domain_age_days < 365:
            return f"{self.domain_age_days // 30} мес."
        else:
            return f"{self.domain_age_days // 365} г."
    
    def _format_expiry(self) -> str:
        """Format expiry time for display."""
        if self.expires_at is None:
            return "бессрочно"
        
        delta = self.expires_at - utc_now()
        hours = int(delta.total_seconds() / 3600)
        
        if hours < 0:
            return "истёк"
        elif hours < 24:
            return f"{hours} ч."
        else:
            return f"{hours // 24} дн."
    
    def _get_available_actions(self) -> list[dict[str, str]]:
        """Get available actions for this entry."""
        if self.reviewed:
            return []
        
        return [
            {
                "action": QuarantineAction.BLOCK.value,
                "label": "🚫 Заблокировать",
                "style": "danger",
            },
            {
                "action": QuarantineAction.ALLOWLIST.value,
                "label": "✅ Разрешить",
                "style": "success",
            },
            {
                "action": QuarantineAction.IGNORE.value,
                "label": "👁️ Игнорировать",
                "style": "secondary",
            },
            {
                "action": QuarantineAction.EXTEND.value,
                "label": "⏰ Продлить наблюдение",
                "style": "info",
            },
            {
                "action": QuarantineAction.REPORT_FP.value,
                "label": "❌ Ложное срабатывание",
                "style": "warning",
            },
        ]
    
    def _get_recommendation(self) -> str:
        """Get recommendation text for UI."""
        if self.confidence >= 80:
            return "Рекомендуем заблокировать"
        elif self.confidence >= 60:
            return "Вероятно стоит заблокировать"
        elif self.confidence >= 40:
            return "Требует проверки"
        else:
            return "Низкая угроза"
    
    def _get_severity(self) -> str:
        """Get severity level for UI styling."""
        if self.confidence >= 80:
            return "critical"
        elif self.confidence >= 60:
            return "high"
        elif self.confidence >= 40:
            return "medium"
        else:
            return "low"


class QuarantineManager:
    """
    Manages the quarantine queue.
    
    Key principle: NEVER auto-block. Always require human review.
    """
    
    def __init__(
        self,
        default_ttl_hours: int = 72,
        max_queue_size: int = 1000,
    ):
        """
        Initialize quarantine manager.
        
        Args:
            default_ttl_hours: Default time before auto-expiry
            max_queue_size: Maximum queue size (oldest removed first)
        """
        self.default_ttl_hours = default_ttl_hours
        self.max_queue_size = max_queue_size
        
        self._queue: dict[str, QuarantineEntry] = {}
        self._action_log: list[dict[str, Any]] = []
    
    def add(
        self,
        threat: ThreatEntry,
        reason: QuarantineReason = QuarantineReason.MULTI_SIGNAL,
        ttl_hours: int | None = None,
    ) -> QuarantineEntry:
        """
        Add threat to quarantine queue.
        
        Args:
            threat: ThreatEntry to quarantine
            reason: Why it's being quarantined
            ttl_hours: Custom TTL (None for default)
        
        Returns:
            Created QuarantineEntry
        """
        # Check if already in queue
        existing = self.get_by_domain(threat.domain)
        if existing and not existing.reviewed:
            # Update existing
            existing.confidence = max(existing.confidence, threat.current_confidence)
            existing.signal_count = max(existing.signal_count, threat.signal_count)
            return existing
        
        # Create new entry
        ttl = ttl_hours or self.default_ttl_hours
        
        entry = QuarantineEntry(
            threat_id=threat.id,
            domain=threat.domain,
            reason=reason,
            confidence=threat.current_confidence,
            signal_count=threat.signal_count,
            signals=threat.signals,
            category=threat.category,
            matched_brand=threat.signals.matched_brand if threat.signals else None,
            domain_age_days=threat.signals.domain_age_days if threat.signals else None,
            source=threat.source_type.value,
            expires_at=utc_now() + timedelta(hours=ttl),
        )
        
        # Enforce queue size limit
        if len(self._queue) >= self.max_queue_size:
            self._evict_oldest()
        
        self._queue[entry.id] = entry
        return entry
    
    def add_from_signals(
        self,
        domain: str,
        signals: ThreatSignals,
        source: str = "heuristics",
        ttl_hours: int | None = None,
    ) -> QuarantineEntry | None:
        """
        Add domain to quarantine based on signals.
        
        Only quarantines if signals meet threshold.
        
        Returns:
            QuarantineEntry if quarantined, None otherwise
        """
        if not signals.should_quarantine():
            return None
        
        # Determine reason
        if signals.homoglyph_score > 40:
            reason = QuarantineReason.BRAND_IMPERSONATION
        elif signals.signal_count >= 2:
            reason = QuarantineReason.MULTI_SIGNAL
        elif signals.newreg_score > 50:
            reason = QuarantineReason.NEW_DOMAIN_SUSPICIOUS
        else:
            reason = QuarantineReason.MULTI_SIGNAL
        
        # Determine category
        if signals.homoglyph_score > 40:
            category = ThreatCategory.PHISHING
        elif signals.dga_score > 50:
            category = ThreatCategory.DGA
        else:
            category = ThreatCategory.SUSPICIOUS
        
        ttl = ttl_hours or self.default_ttl_hours
        
        entry = QuarantineEntry(
            threat_id=f"direct_{domain}",
            domain=domain,
            reason=reason,
            confidence=signals.total_score,
            signal_count=signals.signal_count,
            signals=signals,
            category=category,
            matched_brand=signals.matched_brand,
            domain_age_days=signals.domain_age_days,
            source=source,
            expires_at=utc_now() + timedelta(hours=ttl),
        )
        
        # Check existing
        existing = self.get_by_domain(domain)
        if existing and not existing.reviewed:
            existing.confidence = max(existing.confidence, entry.confidence)
            return existing
        
        if len(self._queue) >= self.max_queue_size:
            self._evict_oldest()
        
        self._queue[entry.id] = entry
        return entry
    
    def get(self, entry_id: str) -> QuarantineEntry | None:
        """Get quarantine entry by ID."""
        return self._queue.get(entry_id)
    
    def get_by_domain(self, domain: str) -> QuarantineEntry | None:
        """Get quarantine entry by domain."""
        domain = domain.lower()
        for entry in self._queue.values():
            if entry.domain.lower() == domain:
                return entry
        return None
    
    def get_pending(self, limit: int = 50) -> list[QuarantineEntry]:
        """
        Get pending (unreviewed) entries, sorted by confidence.
        
        Returns entries that need human review.
        """
        pending = [
            e for e in self._queue.values()
            if not e.reviewed and not e.is_expired()
        ]
        
        # Sort by confidence (highest first)
        pending.sort(key=lambda e: e.confidence, reverse=True)
        
        return pending[:limit]
    
    def get_stats(self) -> dict[str, Any]:
        """Get quarantine statistics for dashboard."""
        pending = [e for e in self._queue.values() if not e.reviewed]
        reviewed = [e for e in self._queue.values() if e.reviewed]
        
        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        
        for entry in pending:
            severity = entry._get_severity()
            severity_counts[severity] += 1
        
        # Count by reason
        reason_counts: dict[str, int] = {}
        for entry in pending:
            reason = entry.reason.value
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
        
        return {
            "total_pending": len(pending),
            "total_reviewed": len(reviewed),
            "by_severity": severity_counts,
            "by_reason": reason_counts,
            "oldest_pending_hours": self._get_oldest_age_hours(pending),
        }
    
    def _get_oldest_age_hours(self, entries: list[QuarantineEntry]) -> float:
        """Get age of oldest entry in hours."""
        if not entries:
            return 0
        
        oldest = min(entries, key=lambda e: e.quarantined_at)
        delta = utc_now() - oldest.quarantined_at
        return delta.total_seconds() / 3600
    
    def review(
        self,
        entry_id: str,
        action: QuarantineAction,
        reviewed_by: str = "admin",
        notes: str = "",
    ) -> QuarantineEntry | None:
        """
        Review and act on a quarantine entry.
        
        Args:
            entry_id: ID of entry to review
            action: Action to take
            reviewed_by: Who performed the review
            notes: Optional notes
        
        Returns:
            Updated entry or None if not found
        """
        entry = self._queue.get(entry_id)
        if not entry:
            return None
        
        entry.reviewed = True
        entry.reviewed_at = utc_now()
        entry.action_taken = action
        entry.reviewed_by = reviewed_by
        entry.review_notes = notes
        
        # Log the action
        self._action_log.append({
            "entry_id": entry_id,
            "domain": entry.domain,
            "action": action.value,
            "reviewed_by": reviewed_by,
            "reviewed_at": entry.reviewed_at.isoformat(),
            "notes": notes,
            "confidence": entry.confidence,
        })
        
        return entry
    
    def bulk_review(
        self,
        entry_ids: list[str],
        action: QuarantineAction,
        reviewed_by: str = "admin",
    ) -> int:
        """
        Bulk review multiple entries.
        
        Returns count of successfully reviewed entries.
        """
        count = 0
        for entry_id in entry_ids:
            if self.review(entry_id, action, reviewed_by):
                count += 1
        return count
    
    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        expired_ids = [
            eid for eid, entry in self._queue.items()
            if entry.is_expired()
        ]
        
        for eid in expired_ids:
            del self._queue[eid]
        
        return len(expired_ids)
    
    def cleanup_reviewed(self, older_than_hours: int = 24) -> int:
        """Remove old reviewed entries. Returns count removed."""
        cutoff = utc_now() - timedelta(hours=older_than_hours)
        
        old_ids = [
            eid for eid, entry in self._queue.items()
            if entry.reviewed and entry.reviewed_at and entry.reviewed_at < cutoff
        ]
        
        for eid in old_ids:
            del self._queue[eid]
        
        return len(old_ids)
    
    def _evict_oldest(self) -> None:
        """Remove oldest entry to make room."""
        if not self._queue:
            return
        
        # Prefer removing reviewed entries
        reviewed = [
            (eid, e) for eid, e in self._queue.items() if e.reviewed
        ]
        
        if reviewed:
            oldest = min(reviewed, key=lambda x: x[1].quarantined_at)
            del self._queue[oldest[0]]
        else:
            # Remove oldest unreviewed
            oldest = min(self._queue.items(), key=lambda x: x[1].quarantined_at)
            del self._queue[oldest[0]]
    
    def get_action_log(self, limit: int = 100) -> list[dict[str, Any]]:
        """Get recent action log."""
        return self._action_log[-limit:]
    
    def to_ui_list(self, limit: int = 50) -> list[dict[str, Any]]:
        """Generate UI list of pending entries."""
        pending = self.get_pending(limit)
        return [entry.to_ui_card() for entry in pending]
    
    def is_quarantined(self, domain: str) -> bool:
        """Check if domain is in quarantine."""
        entry = self.get_by_domain(domain)
        return entry is not None and not entry.reviewed and not entry.is_expired()
