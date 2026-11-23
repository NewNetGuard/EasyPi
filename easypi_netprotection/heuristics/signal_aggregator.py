"""
Signal Aggregator - Multi-signal scoring with decay.

Combines multiple heuristic signals into final risk score.
Implements time-based decay for old observations.

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import math
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import List
from ..config import get_settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_fromtimestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


class SignalType(str, Enum):
    """Types of heuristic signals."""
    FIRST_SEEN = "first_seen"       # Domain novelty
    DGA = "dga"                     # DGA detection
    HOMOGLYPH = "homoglyph"         # Brand impersonation
    DOMAIN_LENGTH = "domain_length" # Suspicious length
    DOMAIN_DEPTH = "domain_depth"   # Too many subdomains
    DOMAIN_NUMBERS = "domain_numbers"  # Numbers in domain
    DEVICE_ANOMALY = "device_anomaly"  # Traffic spike
    ASN_CLUSTER = "asn_cluster"     # Bad ASN/IP reputation
    BLOCKLIST = "blocklist"         # Blocklist match
    CNAME_CHAIN = "cname_chain"     # CNAME to blocked domain
    
    # Ad/Tracker detection signals
    AD_TRACKER = "ad_tracker"       # Behavioral ad/tracker detection
    TRACKING_PIXEL = "tracking_pixel"  # Tracking pixel pattern
    COOKIE_SYNC = "cookie_sync"     # Cookie syncing behavior
    THIRD_PARTY_FLOOD = "third_party_flood"  # Too many third-party requests
    
    # Negative signals (reduce score)
    WHITELIST = "whitelist"         # In whitelist
    KNOWN_GOOD = "known_good"       # Known legitimate domain


@dataclass
class Signal:
    """Individual heuristic signal."""
    signal_type: SignalType
    weight: int
    confidence: float  # 0.0 - 1.0
    reason: str
    timestamp: float = field(default_factory=time.time)
    decay_days: int = 30  # Days until signal fully decays
    
    @property
    def effective_weight(self) -> float:
        """Weight after applying confidence and decay."""
        age_days = (time.time() - self.timestamp) / 86400
        
        if age_days >= self.decay_days:
            decay_factor = 0.0
        else:
            # Exponential decay
            decay_factor = math.exp(-3 * age_days / self.decay_days)
        
        return self.weight * self.confidence * decay_factor


@dataclass
class AggregatedScore:
    """Final aggregated risk score."""
    domain: str
    total_score: float
    verdict: str  # "allow", "observe", "block"
    signals: List[Signal]
    computed_at: datetime = field(default_factory=utc_now)
    
    # Thresholds
    OBSERVE_THRESHOLD = 30
    BLOCK_THRESHOLD = 70
    
    @classmethod
    def from_signals(cls, domain: str, signals: List[Signal]) -> "AggregatedScore":
        """Create aggregated score from signals."""
        total = sum(s.effective_weight for s in signals)
        
        if total < cls.OBSERVE_THRESHOLD:
            verdict = "allow"
        elif total < cls.BLOCK_THRESHOLD:
            verdict = "observe"
        else:
            verdict = "block"
        
        return cls(
            domain=domain,
            total_score=total,
            verdict=verdict,
            signals=signals,
        )
    
    def explain(self) -> str:
        """Human-readable explanation of score."""
        lines = [f"Domain: {self.domain}", f"Score: {self.total_score:.1f}"]
        lines.append(f"Verdict: {self.verdict.upper()}")
        lines.append("Signals:")
        
        for sig in sorted(self.signals, key=lambda s: -s.effective_weight):
            if sig.effective_weight != 0:
                lines.append(
                    f"  - {sig.signal_type.value}: "
                    f"+{sig.effective_weight:.1f} ({sig.reason})"
                )
        
        return "\n".join(lines)


class SignalAggregator:
    """
    Aggregates multiple signals into final risk score.
    
    Persistent storage for signal history with decay.
    """
    
    # Default weights for signal types
    DEFAULT_WEIGHTS = {
        SignalType.FIRST_SEEN: 20,
        SignalType.DGA: 35,
        SignalType.HOMOGLYPH: 40,
        SignalType.DOMAIN_LENGTH: 10,
        SignalType.DOMAIN_DEPTH: 10,
        SignalType.DOMAIN_NUMBERS: 15,
        SignalType.DEVICE_ANOMALY: 10,
        SignalType.ASN_CLUSTER: 15,
        SignalType.BLOCKLIST: 100,      # Immediate block
        SignalType.CNAME_CHAIN: 80,     # High confidence block
        SignalType.AD_TRACKER: 25,
        SignalType.TRACKING_PIXEL: 15,
        SignalType.COOKIE_SYNC: 12,
        SignalType.THIRD_PARTY_FLOOD: 10,
        SignalType.WHITELIST: -100,     # Immediate allow
        SignalType.KNOWN_GOOD: -50,     # Strong allow signal
    }
    
    # Default decay days for signal types
    DEFAULT_DECAY = {
        SignalType.FIRST_SEEN: 30,
        SignalType.DGA: 90,
        SignalType.HOMOGLYPH: 90,
        SignalType.DOMAIN_LENGTH: 30,
        SignalType.DOMAIN_DEPTH: 30,
        SignalType.DOMAIN_NUMBERS: 30,
        SignalType.DEVICE_ANOMALY: 7,
        SignalType.ASN_CLUSTER: 14,
        SignalType.BLOCKLIST: 365,
        SignalType.CNAME_CHAIN: 365,
        SignalType.AD_TRACKER: 60,
        SignalType.TRACKING_PIXEL: 30,
        SignalType.COOKIE_SYNC: 30,
        SignalType.THIRD_PARTY_FLOOD: 14,
        SignalType.WHITELIST: 365,
        SignalType.KNOWN_GOOD: 365,
    }
    
    def __init__(
        self,
        db_path: Path | str,
        observe_threshold: int = 30,
        block_threshold: int = 70,
    ):
        self.db_path = Path(db_path)
        self.observe_threshold = observe_threshold
        self.block_threshold = block_threshold
        
        self._local = threading.local()
        self._lock = threading.Lock()
        
        self._init_db()
        logger.info(f"SignalAggregator initialized at {self.db_path}")
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=10.0,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
        return self._local.conn
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS signals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                signal_type TEXT NOT NULL,
                weight INTEGER NOT NULL,
                confidence REAL NOT NULL,
                reason TEXT,
                timestamp REAL NOT NULL,
                decay_days INTEGER NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_signals_domain 
                ON signals(domain);
            CREATE INDEX IF NOT EXISTS idx_signals_timestamp 
                ON signals(timestamp);
            
            -- Cache table for computed scores
            CREATE TABLE IF NOT EXISTS score_cache (
                domain TEXT PRIMARY KEY,
                total_score REAL NOT NULL,
                verdict TEXT NOT NULL,
                computed_at REAL NOT NULL
            );
        """)
        conn.commit()
    
    def add_signal(
        self,
        domain: str,
        signal_type: SignalType,
        confidence: float = 1.0,
        reason: str = "",
        weight: int | None = None,
        decay_days: int | None = None,
    ) -> Signal:
        """
        Add new signal for domain.
        
        Returns the created Signal.
        """
        domain = domain.lower().strip().rstrip('.')
        
        if weight is None:
            weight = self.DEFAULT_WEIGHTS.get(signal_type, 10)
        if decay_days is None:
            decay_days = self.DEFAULT_DECAY.get(signal_type, 30)
        
        signal = Signal(
            signal_type=signal_type,
            weight=weight,
            confidence=confidence,
            reason=reason,
            decay_days=decay_days,
        )
        
        conn = self._get_conn()
        # Keep a single, latest row per (domain, signal_type): re-observing a signal
        # refreshes it instead of appending. Without this, get_signals() returns one
        # row per past observation and from_signals() SUMS them, so a frequently
        # queried domain's score climbs purely from popularity.
        conn.execute(
            "DELETE FROM signals WHERE domain = ? AND signal_type = ?",
            (domain, signal_type.value),
        )
        conn.execute("""
            INSERT INTO signals
            (domain, signal_type, weight, confidence, reason, timestamp, decay_days)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            domain,
            signal_type.value,
            weight,
            confidence,
            reason,
            signal.timestamp,
            decay_days,
        ))
        
        # Invalidate cache
        conn.execute("DELETE FROM score_cache WHERE domain = ?", (domain,))
        conn.commit()
        
        return signal
    
    def get_signals(self, domain: str) -> List[Signal]:
        """Get all active signals for domain."""
        domain = domain.lower().strip().rstrip('.')
        
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT * FROM signals WHERE domain = ?
        """, (domain,))
        
        signals = []
        for row in cursor:
            try:
                signal = Signal(
                    signal_type=SignalType(row['signal_type']),
                    weight=row['weight'],
                    confidence=row['confidence'],
                    reason=row['reason'] or "",
                    timestamp=row['timestamp'],
                    decay_days=row['decay_days'],
                )
                # Only include if not fully decayed
                if signal.effective_weight != 0:
                    signals.append(signal)
            except ValueError:
                # Unknown signal type, skip
                continue
        
        return signals
    
    def compute_score(
        self,
        domain: str,
        additional_signals: List[Signal] | None = None,
        use_cache: bool = True,
        cache_ttl_seconds: int = 300,
    ) -> AggregatedScore:
        """
        Compute aggregated score for domain.
        
        Args:
            domain: Domain to score
            additional_signals: Extra signals to include (not persisted)
            use_cache: Whether to use cached score
            cache_ttl_seconds: Cache TTL in seconds
        """
        domain = domain.lower().strip().rstrip('.')
        now = time.time()
        
        # Check cache
        if use_cache:
            conn = self._get_conn()
            cursor = conn.execute(
                "SELECT * FROM score_cache WHERE domain = ?",
                (domain,)
            )
            row = cursor.fetchone()
            if row and (now - row['computed_at']) < cache_ttl_seconds:
                # Return cached score
                signals = self.get_signals(domain)
                if additional_signals:
                    signals.extend(additional_signals)
                
                return AggregatedScore(
                    domain=domain,
                    total_score=row['total_score'],
                    verdict=row['verdict'],
                    signals=signals,
                    computed_at=utc_fromtimestamp(row['computed_at']),
                )
        
        # Compute fresh score
        signals = self.get_signals(domain)
        if additional_signals:
            signals.extend(additional_signals)
        
        # Create aggregated score
        AggregatedScore.OBSERVE_THRESHOLD = self.observe_threshold
        AggregatedScore.BLOCK_THRESHOLD = self.block_threshold
        score = AggregatedScore.from_signals(domain, signals)
        
        # Update cache
        conn = self._get_conn()
        conn.execute("""
            INSERT OR REPLACE INTO score_cache 
            (domain, total_score, verdict, computed_at)
            VALUES (?, ?, ?, ?)
        """, (domain, score.total_score, score.verdict, now))
        conn.commit()
        
        return score
    
    def quick_verdict(
        self,
        domain: str,
        additional_signals: List[Signal] | None = None,
    ) -> str:
        """
        Get quick verdict without full computation.
        
        Returns: "allow", "observe", or "block"
        """
        return self.compute_score(domain, additional_signals).verdict
    
    def get_observed_domains(
        self,
        limit: int = 100,
        min_score: float | None = None,
        max_score: float | None = None,
    ) -> List[AggregatedScore]:
        """Get domains currently in "observe" state."""
        if min_score is None:
            min_score = self.observe_threshold
        if max_score is None:
            max_score = self.block_threshold
        
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT domain, total_score, verdict, computed_at 
            FROM score_cache 
            WHERE total_score >= ? AND total_score < ?
            ORDER BY total_score DESC
            LIMIT ?
        """, (min_score, max_score, limit))
        
        results = []
        for row in cursor:
            results.append(AggregatedScore(
                domain=row['domain'],
                total_score=row['total_score'],
                verdict=row['verdict'],
                signals=self.get_signals(row['domain']),
                computed_at=utc_fromtimestamp(row['computed_at']),
            ))
        
        return results
    
    def cleanup(self, max_signal_age_days: int = 365) -> int:
        """Remove old signals and cache entries."""
        cutoff = time.time() - (max_signal_age_days * 86400)
        
        conn = self._get_conn()
        
        # Delete old signals
        cursor = conn.execute(
            "DELETE FROM signals WHERE timestamp < ?",
            (cutoff,)
        )
        deleted_signals = cursor.rowcount
        
        # Delete old cache entries (1 day)
        cache_cutoff = time.time() - 86400
        cursor = conn.execute(
            "DELETE FROM score_cache WHERE computed_at < ?",
            (cache_cutoff,)
        )
        deleted_cache = cursor.rowcount
        
        conn.commit()
        
        if deleted_signals > 0 or deleted_cache > 0:
            logger.info(
                f"SignalAggregator cleanup: {deleted_signals} signals, "
                f"{deleted_cache} cache entries"
            )
        
        return deleted_signals + deleted_cache
    
    def get_stats(self) -> dict:
        """Get aggregator statistics."""
        conn = self._get_conn()
        
        stats = {}
        
        # Total signals
        cursor = conn.execute("SELECT COUNT(*) FROM signals")
        stats['total_signals'] = cursor.fetchone()[0]
        
        # Unique domains
        cursor = conn.execute("SELECT COUNT(DISTINCT domain) FROM signals")
        stats['unique_domains'] = cursor.fetchone()[0]
        
        # By signal type
        cursor = conn.execute("""
            SELECT signal_type, COUNT(*) as count 
            FROM signals GROUP BY signal_type
            ORDER BY count DESC
        """)
        stats['by_type'] = {row['signal_type']: row['count'] for row in cursor}
        
        # Cache stats
        cursor = conn.execute("SELECT COUNT(*) FROM score_cache")
        stats['cached_scores'] = cursor.fetchone()[0]
        
        # Verdict distribution
        cursor = conn.execute("""
            SELECT verdict, COUNT(*) as count 
            FROM score_cache GROUP BY verdict
        """)
        stats['verdicts'] = {row['verdict']: row['count'] for row in cursor}
        
        return stats
    
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
_instance: SignalAggregator | None = None
_lock = threading.Lock()


def get_signal_aggregator(data_dir: str | Path | None = None) -> SignalAggregator:
    """Get singleton SignalAggregator instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                if data_dir is None:
                    data_dir = get_settings().NETPROTECTION_DATA_DIR
                else:
                    data_dir = Path(data_dir)
                
                db_path = data_dir / "signals.db"
                _instance = SignalAggregator(db_path)
    
    return _instance
