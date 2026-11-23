"""
Heuristics Engine - Main integration module.

Combines all heuristic detectors into a single interface
for the verdict engine.

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .first_seen import FirstSeenCache, get_first_seen_cache
from .signal_aggregator import (
    Signal,
    SignalType,
    SignalAggregator,
    AggregatedScore,
    get_signal_aggregator,
)
from .dga_detector import get_dga_detector
from .homoglyph import get_homoglyph_detector
from .domain_analysis import get_domain_analyzer
from .ad_tracker_detector import get_ad_tracker_detector
from ..config import get_settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class HeuristicsResult:
    """Complete heuristics analysis result."""
    domain: str
    final_score: float
    verdict: str  # "allow", "observe", "block"
    is_dga: bool
    is_homoglyph: bool
    matched_brand: Optional[str]
    first_seen_days: Optional[float]
    signals: List[Signal]
    is_ad_tracker: bool = False  # blocked as an unambiguous ad network (reason=advertising)
    is_tracker: bool = False     # blocked as a telemetry/error tracker (reason=tracking)
    analyzed_at: datetime = field(default_factory=utc_now)
    
    def explain(self) -> str:
        """Human-readable explanation."""
        lines = [
            f"Domain: {self.domain}",
            f"Final Score: {self.final_score:.1f}",
            f"Verdict: {self.verdict.upper()}",
            "",
            "Detection Flags:",
        ]
        
        if self.is_dga:
            lines.append("  🤖 DGA-generated domain")
        if self.is_homoglyph:
            lines.append(f"  🎭 Brand impersonation: {self.matched_brand or 'unknown'}")
        if self.first_seen_days is not None and self.first_seen_days < 7:
            lines.append(f"  🆕 New domain ({self.first_seen_days:.1f} days)")
        
        if self.signals:
            lines.append("")
            lines.append("Active Signals:")
            for sig in sorted(self.signals, key=lambda s: -s.effective_weight):
                if sig.effective_weight > 0:
                    lines.append(
                        f"  +{sig.effective_weight:.1f} {sig.signal_type.value}: {sig.reason}"
                    )
                elif sig.effective_weight < 0:
                    lines.append(
                        f"  {sig.effective_weight:.1f} {sig.signal_type.value}: {sig.reason}"
                    )
        
        return "\n".join(lines)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON/API."""
        return {
            "domain": self.domain,
            "final_score": self.final_score,
            "verdict": self.verdict,
            "flags": {
                "is_dga": self.is_dga,
                "is_homoglyph": self.is_homoglyph,
                "matched_brand": self.matched_brand,
                "first_seen_days": self.first_seen_days,
            },
            "signals": [
                {
                    "type": s.signal_type.value,
                    "weight": s.weight,
                    "confidence": s.confidence,
                    "effective_weight": s.effective_weight,
                    "reason": s.reason,
                }
                for s in self.signals
            ],
            "analyzed_at": self.analyzed_at.isoformat(),
        }


class HeuristicsEngine:
    """
    Main heuristics engine that integrates all detectors.
    
    Usage:
        engine = HeuristicsEngine(data_dir="/opt/EasyPi/data/netprotection")
        result = engine.analyze("suspicious-domain.xyz")
        
        if result.verdict == "block":
            # Block the domain
        elif result.verdict == "observe":
            # Log but allow (shadow mode)
        else:
            # Allow normally
    """
    
    def __init__(
        self,
        data_dir: str | Path | None = None,
        observe_threshold: int = 30,
        block_threshold: int = 70,
        enable_persistence: bool = True,
    ):
        """
        Initialize heuristics engine.
        
        Args:
            data_dir: Directory for SQLite databases
            observe_threshold: Score threshold for observation
            block_threshold: Score threshold for blocking
            enable_persistence: Whether to persist signals to DB
        """
        if data_dir is None:
            data_dir = get_settings().NETPROTECTION_DATA_DIR
        else:
            data_dir = Path(data_dir)
        
        self.data_dir = data_dir
        self.observe_threshold = observe_threshold
        self.block_threshold = block_threshold
        self.enable_persistence = enable_persistence
        
        # Initialize components
        if enable_persistence:
            self.first_seen = FirstSeenCache(data_dir / "first_seen.db")
            self.aggregator = SignalAggregator(
                data_dir / "signals.db",
                observe_threshold=observe_threshold,
                block_threshold=block_threshold,
            )
        else:
            # Use singleton instances
            self.first_seen = get_first_seen_cache(data_dir)
            self.aggregator = get_signal_aggregator(data_dir)
        
        # Detectors (stateless singletons)
        self.dga_detector = get_dga_detector()
        self.homoglyph_detector = get_homoglyph_detector()
        self.domain_analyzer = get_domain_analyzer()
        self.ad_tracker_detector = get_ad_tracker_detector()
        
        logger.info(
            f"HeuristicsEngine initialized: "
            f"observe={observe_threshold}, block={block_threshold}"
        )
    
    def analyze(
        self,
        domain: str,
        persist_signals: bool = True,
        quick_mode: bool = False,
        context: dict | None = None,
    ) -> HeuristicsResult:
        """
        Analyze domain using all heuristics.
        
        Args:
            domain: Domain to analyze
            persist_signals: Whether to persist new signals to DB
            quick_mode: Skip expensive analyses for speed
        
        Returns:
            HeuristicsResult with complete analysis
        """
        runtime_settings = self._sync_runtime_settings()
        domain = domain.lower().strip().rstrip('.')
        signals: List[Signal] = []
        
        # 1. First Seen Analysis
        first_seen_record = None
        first_seen_days = None
        if runtime_settings.enable_first_seen_tracking:
            first_seen_record = (
                self.first_seen.record(domain, "domain")
                if persist_signals
                else self.first_seen.lookup(domain)
            )
            if first_seen_record:
                first_seen_days = first_seen_record.age_days

                if first_seen_record.hit_count == 1:
                    signals.append(Signal(
                        signal_type=SignalType.FIRST_SEEN,
                        weight=25,
                        confidence=0.9,
                        reason="First observation in local history",
                        decay_days=30,
                    ))
                elif first_seen_days < 1:
                    signals.append(Signal(
                        signal_type=SignalType.FIRST_SEEN,
                        weight=20,
                        confidence=0.8,
                        reason=f"Observed locally for {first_seen_days:.1f} days",
                        decay_days=30,
                    ))
                elif first_seen_days < runtime_settings.first_seen_new_days:
                    signals.append(Signal(
                        signal_type=SignalType.FIRST_SEEN,
                        weight=10,
                        confidence=0.6,
                        reason=f"Observed locally for {first_seen_days:.1f} days",
                        decay_days=30,
                    ))
        
        # 2. DGA Detection
        dga_result = self.dga_detector.analyze(domain)
        is_dga = runtime_settings.enable_dga_detection and dga_result.score >= runtime_settings.dga_score_threshold

        if is_dga:
            signals.append(Signal(
                signal_type=SignalType.DGA,
                weight=dga_result.risk_weight,
                confidence=dga_result.confidence,
                reason="; ".join(dga_result.reasons[:3]),
                decay_days=90,
            ))
        
        # 3. Homoglyph Detection
        homoglyph_result = self.homoglyph_detector.analyze(domain)
        is_homoglyph = (
            runtime_settings.enable_homoglyph_detection
            and homoglyph_result.score >= runtime_settings.homoglyph_score_threshold
        )
        matched_brand = homoglyph_result.matched_brand
        
        if is_homoglyph:
            signals.append(Signal(
                signal_type=SignalType.HOMOGLYPH,
                weight=homoglyph_result.risk_weight,
                confidence=homoglyph_result.confidence,
                reason=f"Brand: {matched_brand or 'unknown'}; " + 
                       "; ".join(homoglyph_result.reasons[:2]),
                decay_days=90,
            ))
        
        # 4. Domain Structure Analysis
        if runtime_settings.enable_domain_analysis and not quick_mode:
            domain_result = self.domain_analyzer.analyze(domain)
            
            if domain_result.length_score > 0.2:
                signals.append(Signal(
                    signal_type=SignalType.DOMAIN_LENGTH,
                    weight=int(domain_result.length_score * 10),
                    confidence=0.7,
                    reason=f"Domain length: {len(domain)} chars",
                    decay_days=30,
                ))
            
            if domain_result.depth_score > 0.2:
                depth = len(domain.split('.'))
                signals.append(Signal(
                    signal_type=SignalType.DOMAIN_DEPTH,
                    weight=int(domain_result.depth_score * 10),
                    confidence=0.7,
                    reason=f"Subdomain depth: {depth} levels",
                    decay_days=30,
                ))
            
            if domain_result.numbers_score > 0.2:
                signals.append(Signal(
                    signal_type=SignalType.DOMAIN_NUMBERS,
                    weight=int(domain_result.numbers_score * 15),
                    confidence=0.7,
                    reason="Numbers in domain",
                    decay_days=30,
                ))
        
        # 5. Ad/Tracker Detection (behavioral analysis)
        ad_tracker_result = self.ad_tracker_detector.analyze(domain, context=context)
        is_ad_definite = bool(getattr(ad_tracker_result, "is_definite_ad", False))
        is_tracker_definite = bool(getattr(ad_tracker_result, "is_definite_tracker", False))
        is_block_definite = is_ad_definite or is_tracker_definite

        if ad_tracker_result.is_suspicious or is_block_definite:
            # An unambiguous ad network OR telemetry/error tracker is promoted to an
            # outright block (effective_weight >= block_threshold) instead of merely
            # observed. This is the active+visible win: unlisted ad/tracker domains get
            # blocked the moment they're queried (reason=advertising / tracking). FP
            # stays ~0 (curated names; allowlist + CDN exempt; dashboards preserved).
            ad_weight = (
                max(ad_tracker_result.risk_weight, self.block_threshold)
                if is_block_definite else ad_tracker_result.risk_weight
            )
            ad_conf = 1.0 if is_block_definite else ad_tracker_result.confidence
            signals.append(Signal(
                signal_type=SignalType.AD_TRACKER,
                weight=ad_weight,
                confidence=ad_conf,
                reason="; ".join(ad_tracker_result.reasons[:3]) or "ad/tracker domain",
                decay_days=60,
            ))

            indicator_to_signal = {
                "tracking_pixel": SignalType.TRACKING_PIXEL,
                "cookie_sync": SignalType.COOKIE_SYNC,
                "third_party_flood": SignalType.THIRD_PARTY_FLOOD,
            }
            for indicator, signal_type in indicator_to_signal.items():
                indicator_score = ad_tracker_result.indicators.get(indicator)
                if not indicator_score:
                    continue
                signals.append(Signal(
                    signal_type=signal_type,
                    weight=max(int(indicator_score), 1),
                    confidence=ad_tracker_result.confidence,
                    reason="; ".join(ad_tracker_result.reasons[:2]) or indicator.replace("_", " "),
                    decay_days=30,
                ))

        if runtime_settings.enable_device_anomaly and context and context.get("is_device_anomalous"):
            anomaly_score = float(context.get("device_anomaly_score") or 0.0)
            anomaly_reasons = context.get("device_anomaly_reasons") or []
            signals.append(Signal(
                signal_type=SignalType.DEVICE_ANOMALY,
                weight=max(int(anomaly_score * 20), 1),
                confidence=float(context.get("device_anomaly_confidence") or 0.5),
                reason="; ".join(anomaly_reasons[:3]) or "Device traffic anomaly detected",
                decay_days=7,
            ))

        # (The trained ML model now powers DGA/gibberish detection inside the DGA
        # detector — see dga_detector._analyze_language_model — rather than being a
        # separate, overlapping signal here.)

        # Snapshot the freshly-computed signals BEFORE merging history. Only these
        # get persisted below. Re-persisting the historical rows we read back would
        # re-insert them on every query, so a frequently-queried domain's signal count
        # (and thus its summed score) would grow without bound — exponentially.
        fresh_signals = list(signals)

        # 5. Get historical signals from DB (for scoring only — never re-persisted)
        if self.enable_persistence:
            historical_signals = self.aggregator.get_signals(domain)
            # Don't duplicate signal types we just computed
            new_types = {s.signal_type for s in signals}
            for sig in historical_signals:
                if sig.signal_type not in new_types:
                    signals.append(sig)
        
        # 6. Compute final score
        score = AggregatedScore.from_signals(domain, signals)
        final_score = score.total_score

        # Apply custom thresholds
        if final_score < self.observe_threshold:
            verdict = "allow"
        elif final_score < self.block_threshold:
            verdict = "observe"
        else:
            verdict = "block"

        # A curated DEFINITE ad-network / tracker (is_block_definite) is a ~zero-false-
        # positive match: ambiguous tokens and first-party names are excluded, telemetry
        # dashboards are preserved. Block it outright instead of letting the fuzzy
        # aggregated score leave it at "observe" — on the name alone it lands ~1pt under
        # block_threshold. This is what cuts UNLISTED ad networks (rubiconproject,
        # pubmatic, …) automatically, without waiting for a blocklist update.
        if is_block_definite:
            verdict = "block"
            final_score = max(final_score, float(self.block_threshold))
        
        # 7. Persist new signals if enabled (fresh signals only — see snapshot above)
        if persist_signals and self.enable_persistence:
            for sig in fresh_signals:
                # Only persist significant signals
                if sig.effective_weight >= 5:
                    try:
                        self.aggregator.add_signal(
                            domain=domain,
                            signal_type=sig.signal_type,
                            confidence=sig.confidence,
                            reason=sig.reason,
                            weight=sig.weight,
                            decay_days=sig.decay_days,
                        )
                    except Exception as e:
                        logger.warning(f"Failed to persist signal: {e}")
        
        return HeuristicsResult(
            domain=domain,
            final_score=final_score,
            verdict=verdict,
            is_dga=is_dga,
            is_homoglyph=is_homoglyph,
            matched_brand=matched_brand,
            first_seen_days=first_seen_days if first_seen_record and first_seen_record.hit_count > 1 else None,
            signals=signals,
            is_ad_tracker=is_ad_definite,
            is_tracker=is_tracker_definite,
        )

    def _sync_runtime_settings(self):
        """Apply live heuristics settings to the running engine."""
        runtime_settings = get_settings().heuristics
        self.observe_threshold = runtime_settings.observe_threshold
        self.block_threshold = runtime_settings.block_threshold
        if self.enable_persistence:
            self.aggregator.observe_threshold = runtime_settings.observe_threshold
            self.aggregator.block_threshold = runtime_settings.block_threshold
        if hasattr(self.dga_detector, "score_threshold"):
            self.dga_detector.score_threshold = runtime_settings.dga_score_threshold
        if hasattr(self.homoglyph_detector, "score_threshold"):
            self.homoglyph_detector.score_threshold = runtime_settings.homoglyph_score_threshold
        return runtime_settings

    def apply_settings(self, runtime_settings) -> None:
        """Apply settings object pushed from config update flow."""
        self.observe_threshold = runtime_settings.observe_threshold
        self.block_threshold = runtime_settings.block_threshold
        if self.enable_persistence:
            self.aggregator.observe_threshold = runtime_settings.observe_threshold
            self.aggregator.block_threshold = runtime_settings.block_threshold
        if hasattr(self.dga_detector, "score_threshold"):
            self.dga_detector.score_threshold = runtime_settings.dga_score_threshold
        if hasattr(self.homoglyph_detector, "score_threshold"):
            self.homoglyph_detector.score_threshold = runtime_settings.homoglyph_score_threshold
    
    def quick_verdict(self, domain: str) -> str:
        """
        Get quick verdict without full analysis.
        
        Useful for high-throughput scenarios.
        """
        result = self.analyze(domain, persist_signals=False, quick_mode=True)
        return result.verdict
    
    def should_block(self, domain: str) -> bool:
        """Check if domain should be blocked."""
        return self.quick_verdict(domain) == "block"
    
    def should_observe(self, domain: str) -> bool:
        """Check if domain should be observed (shadow mode)."""
        return self.quick_verdict(domain) == "observe"
    
    def add_whitelist_signal(self, domain: str, reason: str = "Manual whitelist") -> None:
        """Add whitelist signal to domain."""
        if self.enable_persistence:
            self.aggregator.add_signal(
                domain=domain,
                signal_type=SignalType.WHITELIST,
                confidence=1.0,
                reason=reason,
                weight=-100,
                decay_days=365,
            )
    
    def add_blocklist_signal(self, domain: str, reason: str = "Manual blocklist") -> None:
        """Add blocklist signal to domain."""
        if self.enable_persistence:
            self.aggregator.add_signal(
                domain=domain,
                signal_type=SignalType.BLOCKLIST,
                confidence=1.0,
                reason=reason,
                weight=100,
                decay_days=365,
            )
    
    def get_observed_domains(self, limit: int = 100) -> List[HeuristicsResult]:
        """Get domains currently in observation mode."""
        if not self.enable_persistence:
            return []
        
        scores = self.aggregator.get_observed_domains(limit=limit)
        results = []
        
        for score in scores:
            # Re-analyze each domain
            result = self.analyze(score.domain, persist_signals=False)
            results.append(result)
        
        return results
    
    def get_stats(self) -> dict:
        """Get engine statistics."""
        stats = {
            "settings": {
                "observe_threshold": self.observe_threshold,
                "block_threshold": self.block_threshold,
                "persistence_enabled": self.enable_persistence,
            },
        }
        
        if self.enable_persistence:
            stats["first_seen"] = self.first_seen.get_stats()
            stats["signals"] = self.aggregator.get_stats()
        
        return stats
    
    def cleanup(self) -> dict:
        """Run cleanup on all databases."""
        results = {}
        
        if self.enable_persistence:
            results["first_seen_removed"] = self.first_seen.cleanup()
            results["signals_removed"] = self.aggregator.cleanup()
        
        return results
    
    def close(self) -> None:
        """Close all database connections."""
        if self.enable_persistence:
            self.first_seen.close()
            self.aggregator.close()


# Singleton instance
_instance: HeuristicsEngine | None = None
_lock = threading.Lock()


def get_heuristics_engine(
    data_dir: str | Path | None = None,
    **kwargs,
) -> HeuristicsEngine:
    """Get singleton HeuristicsEngine instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = HeuristicsEngine(data_dir=data_dir, **kwargs)
    
    return _instance
