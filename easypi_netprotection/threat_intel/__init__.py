"""
EasyPi NetProtection — Threat Intelligence Module

This module provides threat intelligence capabilities with a focus on:
- OBSERVATION, not auto-blocking (signals → quarantine → human review)
- Permissive licenses only (CC0, MIT) for commercial viability
- Rate-limited, resource-friendly scanning
- Multi-signal thresholds with confidence decay

Components:
- ThreatDatabase: SQLite-backed storage with TTL and decay
- HeuristicsEngine: DGA, homoglyph, entropy detection
- CTScanner: Certificate Transparency logs scanning
- QuarantineManager: Pending review queue
- AllowlistManager: Manual allowlist with priority
- BrandProtection: Official domain whitelist
- FeedManager: External feed subscriptions (permissive licenses only)

Key Principles:
1. CT/heuristics are SIGNALS only, never auto-deny
2. Multiple signals required for quarantine (not just one)
3. Quarantine = observe + flag for UI, not block
4. TTL and confidence decay over time
5. Source weight hierarchy: heuristic < user_report < permissive_feed
6. Mandatory allowlist check before any action
"""

from .models import (
    BrandEntry,
    FeedConfig,
    HeuristicSignal,
    QuarantineAction,
    SourceType,
    SourceWeight,
    ThreatCategory,
    ThreatEntry,
    ThreatSignals,
    ThreatStatus,
)
from .threat_db import ThreatDatabase
from .heuristics import HeuristicsEngine, DGAResult, HomoglyphResult, EntropyResult
from .brand_protection import BrandProtection, UserBrandWhitelist
from .ct_scanner import CTScanner, CTEntry, RateLimitConfig, CTScanResult
from .quarantine import QuarantineManager, QuarantineEntry, QuarantineReason
from .allowlist import AllowlistManager, AllowlistEntry
from .feed_manager import FeedManager, FeedParser, FeedFormat, FeedLicense, APPROVED_FEEDS
from .domain_export import DomainExporter, AutoExporter, ExportFormat, ExportCriteria

__all__ = [
    # Models
    "AllowlistEntry",
    "BrandEntry",
    "FeedConfig",
    "HeuristicSignal",
    "QuarantineAction",
    "SourceType",
    "SourceWeight",
    "ThreatCategory",
    "ThreatEntry",
    "ThreatSignals",
    "ThreatStatus",
    # Database
    "ThreatDatabase",
    # Heuristics
    "HeuristicsEngine",
    "DGAResult",
    "HomoglyphResult",
    "EntropyResult",
    # Brand Protection
    "BrandProtection",
    "UserBrandWhitelist",
    # CT Scanner
    "CTScanner",
    "CTEntry",
    "RateLimitConfig",
    "CTScanResult",
    # Quarantine
    "QuarantineManager",
    "QuarantineEntry",
    "QuarantineReason",
    # Allowlist
    "AllowlistManager",
    # Feed Manager
    "FeedManager",
    "FeedParser",
    "FeedFormat",
    "FeedLicense",
    "APPROVED_FEEDS",
    # Domain Export
    "DomainExporter",
    "AutoExporter",
    "ExportFormat",
    "ExportCriteria",
]


class ThreatIntelService:
    """
    Unified Threat Intelligence Service.
    
    Coordinates all threat intel components and provides
    a simple interface for domain checking.
    
    Example:
        service = ThreatIntelService()
        await service.initialize()
        
        # Check a domain
        result = await service.check_domain("suspicious-paypa1.com")
        
        # result = {
        #     "action": "quarantine",  # NOT "block" from heuristics!
        #     "confidence": 75,
        #     "signals": [...],
        #     "recommendation": "Подозрительный домен — рекомендуем проверить",
        #     "ui_card": {...}
        # }
    """
    
    def __init__(
        self,
        db_path: str | None = None,
        cache_dir: str | None = None,
    ):
        """
        Initialize threat intel service.
        
        Args:
            db_path: Path to SQLite database
            cache_dir: Directory for feed caching
        """
        self.threat_db = ThreatDatabase(db_path=db_path)
        self.heuristics = HeuristicsEngine()
        self.brand_protection = BrandProtection()
        self.allowlist = AllowlistManager()
        self.quarantine = QuarantineManager()
        self.ct_scanner = CTScanner(heuristics=self.heuristics)
        self.feed_manager = FeedManager(cache_dir=cache_dir)
        
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize all components."""
        if self._initialized:
            return
        
        await self.threat_db.initialize()
        self._initialized = True
    
    async def check_domain(self, domain: str) -> dict:
        """
        Check domain against all threat intel sources.
        
        IMPORTANT: Heuristics and CT logs produce SIGNALS only.
        They NEVER auto-block. Only quarantine for human review.
        
        Args:
            domain: Domain to check
        
        Returns:
            Dict with action recommendation and details
        """
        await self.initialize()
        domain = domain.lower().strip(".")
        
        # 1. Check allowlist first (highest priority)
        is_allowed, allow_entry = self.allowlist.is_allowed(domain)
        if is_allowed:
            return {
                "action": "allow",
                "reason": "allowlisted",
                "confidence": 0,
                "signals": [],
                "entry": allow_entry,
            }
        
        # 2. Check brand protection (official domains)
        if self.brand_protection.should_skip_detection(domain):
            return {
                "action": "allow",
                "reason": "protected_brand",
                "confidence": 0,
                "signals": [],
            }
        
        # 3. Check existing threat entry
        entry, db_action = await self.threat_db.check_domain(domain)
        
        if entry and entry.should_block():
            # Only block if CONFIRMED (not from heuristics alone)
            return {
                "action": "block",
                "reason": "confirmed_threat",
                "confidence": entry.current_confidence,
                "category": entry.category.value,
                "entry": entry,
            }
        
        # 4. Check feeds (permissive license only)
        in_feed, feed = self.feed_manager.is_in_feed(domain)
        if in_feed and feed:
            # Feed matches go to quarantine for review, not auto-block
            return {
                "action": "quarantine",
                "reason": "feed_match",
                "confidence": 60,
                "feed": feed.name,
                "source_weight": feed.get_source_weight(),
            }
        
        # 5. Run heuristics (SIGNALS ONLY, never auto-block)
        signals = self.heuristics.analyze_domain(domain)
        
        if signals.should_quarantine():
            # Add to quarantine for human review
            q_entry = self.quarantine.add_from_signals(domain, signals)
            
            return {
                "action": "quarantine",  # NOT block!
                "reason": "multi_signal_detection",
                "confidence": signals.total_score,
                "signal_count": signals.signal_count,
                "signals": [s.model_dump() for s in signals.signals],
                "matched_brand": signals.matched_brand,
                "recommendation": "Подозрительный домен — рекомендуем проверить",
                "ui_card": q_entry.to_ui_card() if q_entry else None,
            }
        
        # 6. Check if already in quarantine
        if self.quarantine.is_quarantined(domain):
            q_entry = self.quarantine.get_by_domain(domain)
            return {
                "action": "quarantine",
                "reason": "in_quarantine",
                "confidence": q_entry.confidence if q_entry else 0,
                "ui_card": q_entry.to_ui_card() if q_entry else None,
            }
        
        # 7. Low-confidence signals -> observe only
        if signals.total_score > 20:
            return {
                "action": "observe",
                "reason": "low_confidence_signals",
                "confidence": signals.total_score,
                "signals": [s.model_dump() for s in signals.signals],
            }
        
        # 8. No threats detected
        return {
            "action": "allow",
            "reason": "no_threats",
            "confidence": 0,
            "signals": [],
        }
    
    async def report_domain(
        self,
        domain: str,
        category: ThreatCategory = ThreatCategory.SUSPICIOUS,
        reported_by: str = "user",
        details: str = "",
    ) -> dict:
        """
        Report a domain as potentially malicious.
        
        User reports go to quarantine for review.
        """
        await self.initialize()
        
        # Run heuristics for additional signals
        signals = self.heuristics.analyze_domain(domain)
        
        # Add to threat DB as user report
        entry = await self.threat_db.add_threat(
            domain=domain,
            category=category,
            confidence=50,  # User reports start at 50%
            source_type=SourceType.USER_REPORT,
            signals=signals,
            source_details=f"Reported by {reported_by}: {details}",
        )
        
        # Add to quarantine
        q_entry = self.quarantine.add(
            threat=entry,
            reason=QuarantineReason.USER_REPORT,
        )
        
        return {
            "status": "reported",
            "domain": domain,
            "entry_id": entry.id,
            "quarantine_id": q_entry.id,
            "message": "Спасибо за сообщение. Домен добавлен в очередь на проверку.",
        }
    
    async def confirm_threat(
        self,
        domain: str,
        confirmed_by: str = "admin",
    ) -> bool:
        """Confirm a threat (admin action). This enables blocking."""
        return await self.threat_db.update_status(
            domain=domain,
            new_status=ThreatStatus.CONFIRMED,
            performed_by=confirmed_by,
            reason="Admin confirmed threat",
        )
    
    async def add_to_allowlist(
        self,
        pattern: str,
        reason: str = "",
        added_by: str = "admin",
    ) -> AllowlistEntry:
        """Add domain/pattern to allowlist."""
        return self.allowlist.add(
            pattern=pattern,
            reason=reason,
            added_by=added_by,
        )
    
    def get_quarantine_queue(self, limit: int = 50) -> list[dict]:
        """Get quarantine queue for UI."""
        return self.quarantine.to_ui_list(limit)
    
    async def review_quarantine(
        self,
        entry_id: str,
        action: str,
        reviewed_by: str = "admin",
    ) -> bool:
        """Review and act on quarantine entry."""
        q_action = QuarantineAction(action)
        result = self.quarantine.review(entry_id, q_action, reviewed_by)
        
        if result:
            # Apply the action
            if q_action == QuarantineAction.BLOCK:
                await self.threat_db.update_status(
                    domain=result.domain,
                    new_status=ThreatStatus.CONFIRMED,
                    performed_by=reviewed_by,
                )
            elif q_action == QuarantineAction.ALLOWLIST:
                self.allowlist.add(
                    pattern=result.domain,
                    reason="Approved from quarantine",
                    added_by=reviewed_by,
                )
        
        return result is not None
    
    async def get_stats(self) -> dict:
        """Get comprehensive stats for dashboard."""
        return {
            "threat_db": await self.threat_db.get_stats(),
            "quarantine": self.quarantine.get_stats(),
            "allowlist": self.allowlist.get_stats(),
            "feeds": self.feed_manager.get_stats(),
            "ct_scanner": self.ct_scanner.get_stats(),
        }
    
    async def close(self) -> None:
        """Cleanup resources."""
        await self.threat_db.close()
        await self.ct_scanner.close()
        await self.feed_manager.close()
