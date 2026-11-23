"""
Shadow Mode - Observe before block.

Tracks domains that are suspicious but not blocked,
allowing administrators to review before enabling blocking.

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional
from ..config import get_settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_fromtimestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)

# Domain validation regex (RFC 1035 compliant)
DOMAIN_REGEX = re.compile(
    r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.?$'
)

def is_valid_domain(domain: str) -> bool:
    """Validate domain format for security."""
    if not domain or len(domain) > 253:
        return False
    # Remove trailing dot for validation
    domain = domain.rstrip('.')
    if not DOMAIN_REGEX.match(domain):
        return False
    # Check each label
    labels = domain.split('.')
    return all(len(label) <= 63 for label in labels)


class ShadowAction(str, Enum):
    """Actions taken on shadow domains."""
    OBSERVED = "observed"           # Just logged (legacy)
    AUTO_BLOCKED = "auto_blocked"   # Auto-blocked by Shadow Mode
    PROMOTED = "promoted"           # User manually blocked
    DISMISSED = "dismissed"         # User marked as safe
    EXPIRED = "expired"             # Auto-expired after timeout


@dataclass
class ShadowRecord:
    """Record of domain in shadow mode."""
    domain: str
    first_observed: datetime
    last_observed: datetime
    hit_count: int
    max_score: float
    avg_score: float
    action: ShadowAction
    action_at: Optional[datetime]
    action_by: Optional[str]  # Username or "auto"
    notes: str
    
    @property
    def age_days(self) -> float:
        """Days since first observed."""
        delta = utc_now() - self.first_observed
        return delta.total_seconds() / 86400
    
    @property
    def is_active(self) -> bool:
        """True if still being observed."""
        return self.action == ShadowAction.OBSERVED


class ShadowMode:
    """
    Shadow mode manager for observing suspicious domains.
    
    Domains with scores between observe_threshold and block_threshold
    are tracked here for manual review.
    
    Features:
    - Track hit count and score trends
    - Auto-expire after configurable days
    - Admin interface for promote/dismiss
    - Export to blocklist
    """
    
    def __init__(
        self,
        db_path: Path | str,
        observe_threshold: int = 30,
        block_threshold: int = 70,
        auto_expire_days: int = 30,
        auto_promote_hits: int = 100,
        auto_promote_score: float = 65,
    ):
        """
        Initialize shadow mode.
        
        Args:
            db_path: Path to SQLite database
            observe_threshold: Minimum score to enter shadow mode
            block_threshold: Score at which to auto-promote
            auto_expire_days: Days until auto-expire inactive domains
            auto_promote_hits: Hit count to auto-promote (if score >= auto_promote_score)
            auto_promote_score: Score required for auto-promote on high hits
        """
        self.db_path = Path(db_path)
        self.observe_threshold = observe_threshold
        self.block_threshold = block_threshold
        self.auto_expire_days = auto_expire_days
        self.auto_promote_hits = auto_promote_hits
        self.auto_promote_score = auto_promote_score
        
        self._local = threading.local()
        self._lock = threading.Lock()
        
        self._init_db()
        logger.info(f"ShadowMode initialized at {self.db_path}")
    
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
            CREATE TABLE IF NOT EXISTS shadow_domains (
                domain TEXT PRIMARY KEY,
                first_observed REAL NOT NULL,
                last_observed REAL NOT NULL,
                hit_count INTEGER DEFAULT 1,
                max_score REAL NOT NULL,
                total_score REAL NOT NULL,
                action TEXT DEFAULT 'observed',
                action_at REAL,
                action_by TEXT,
                notes TEXT DEFAULT ''
            );
            
            CREATE INDEX IF NOT EXISTS idx_shadow_action 
                ON shadow_domains(action);
            CREATE INDEX IF NOT EXISTS idx_shadow_score 
                ON shadow_domains(max_score);
            CREATE INDEX IF NOT EXISTS idx_shadow_hits 
                ON shadow_domains(hit_count);
            CREATE INDEX IF NOT EXISTS idx_shadow_last_observed
                ON shadow_domains(last_observed);
            
            -- History table for tracking actions
            CREATE TABLE IF NOT EXISTS shadow_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                action TEXT NOT NULL,
                score REAL,
                timestamp REAL NOT NULL,
                actor TEXT,
                notes TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_history_domain 
                ON shadow_history(domain);
            CREATE INDEX IF NOT EXISTS idx_history_timestamp 
                ON shadow_history(timestamp);
        """)
        conn.commit()
    
    def observe(
        self,
        domain: str,
        score: float,
        reasons: List[str] | None = None,
    ) -> ShadowRecord | None:
        """
        Record observation of suspicious domain.
        
        Returns ShadowRecord with current state, or None if invalid domain.
        """
        domain = domain.lower().strip().rstrip('.')
        
        # Validate domain format for security
        if not is_valid_domain(domain):
            logger.warning(f"Shadow Mode: rejected invalid domain format: {domain[:50]}")
            return None
        
        now = time.time()
        
        conn = self._get_conn()
        
        # Check existing record
        cursor = conn.execute(
            "SELECT * FROM shadow_domains WHERE domain = ?",
            (domain,)
        )
        row = cursor.fetchone()
        
        if row:
            # Update existing
            new_max = max(row['max_score'], score)
            new_total = row['total_score'] + score
            new_count = row['hit_count'] + 1
            
            conn.execute("""
                UPDATE shadow_domains 
                SET last_observed = ?, 
                    hit_count = ?,
                    max_score = ?,
                    total_score = ?
                WHERE domain = ?
            """, (now, new_count, new_max, new_total, domain))
            conn.commit()
            
            # Check for auto-promote
            avg_score = new_total / new_count
            if (new_max >= self.block_threshold or 
                (new_count >= self.auto_promote_hits and avg_score >= self.auto_promote_score)):
                self._auto_promote(domain, new_max, "High score/frequency")
            
            return ShadowRecord(
                domain=domain,
                first_observed=self._safe_timestamp_to_datetime(row['first_observed']),
                last_observed=utc_now(),
                hit_count=new_count,
                max_score=new_max,
                avg_score=avg_score,
                action=ShadowAction(row['action']),
                action_at=self._safe_timestamp_to_datetime(row['action_at']) if row['action_at'] else None,
                action_by=row['action_by'],
                notes=row['notes'] or "",
            )
        else:
            # Insert new - OBSERVE for review, never block on sight.
            # A fresh observation lands in the gray zone (observe_threshold..block_threshold).
            # It must stay 'observed' so the only auto-block is heuristics' own
            # block_threshold (>=70, handled in the verdict engine). Blocking here would
            # silently sink high-entropy-but-legitimate hosts (AWS WAF tokens, CDN/bot
            # endpoints) that merely score in the 30s. Promotion to a real block is an
            # explicit admin action (-> action='promoted').
            conn.execute("""
                INSERT INTO shadow_domains
                (domain, first_observed, last_observed, hit_count, max_score, total_score, action)
                VALUES (?, ?, ?, 1, ?, ?, 'observed')
            """, (domain, now, now, score, score))
            conn.commit()

            # Log to history
            self._add_history(domain, "observed", score, "auto",
                             f"Observed by Shadow Mode; Reasons: {'; '.join(reasons or [])}")
            
            return ShadowRecord(
                domain=domain,
                first_observed=utc_now(),
                last_observed=utc_now(),
                hit_count=1,
                max_score=score,
                avg_score=score,
                action=ShadowAction.OBSERVED,
                action_at=None,
                action_by=None,
                notes="",
            )
    
    def get_domain_signals(self, domain: str) -> Dict[str, float]:
        """
        Get signals for a domain from history.
        
        Returns dict of signal_name -> score
        """
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT notes FROM shadow_history 
            WHERE domain = ? AND notes LIKE '%Reasons:%'
            ORDER BY timestamp DESC
            LIMIT 1
        """, (domain.lower().strip().rstrip('.'),))
        
        row = cursor.fetchone()
        if not row or not row['notes']:
            return {}
        
        # Parse "Auto-blocked by Shadow Mode; Reasons: signal1; signal2; ..."
        notes = row['notes']
        signals = {}
        
        if 'Reasons:' in notes:
            reasons_part = notes.split('Reasons:')[1].strip()
            for reason in reasons_part.split(';'):
                reason = reason.strip()
                if reason:
                    # Default score for each signal
                    signals[reason] = 10.0
        
        return signals
    
    def _auto_promote(self, domain: str, score: float, reason: str) -> None:
        """Auto-promote domain to blocklist."""
        self.promote(domain, actor="auto", notes=f"Auto-promote: {reason}")
    
    def _add_history(
        self,
        domain: str,
        action: str,
        score: float | None,
        actor: str,
        notes: str,
    ) -> None:
        """Add entry to history table."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO shadow_history (domain, action, score, timestamp, actor, notes)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (domain, action, score, time.time(), actor, notes))
        conn.commit()
    
    def promote(
        self,
        domain: str,
        actor: str = "admin",
        notes: str = "",
    ) -> bool:
        """
        Promote domain to blocklist.
        
        Returns True if successful.
        """
        domain = domain.lower().strip().rstrip('.')
        
        # Validate domain format
        if not is_valid_domain(domain):
            logger.warning(f"Shadow promote: rejected invalid domain: {domain[:50]}")
            return False
        
        # Sanitize actor and notes (prevent injection)
        actor = str(actor)[:64].replace('<', '').replace('>', '')
        notes = str(notes)[:500].replace('<', '').replace('>', '')
        
        now = time.time()
        
        conn = self._get_conn()
        
        cursor = conn.execute(
            "SELECT * FROM shadow_domains WHERE domain = ?",
            (domain,)
        )
        row = cursor.fetchone()
        
        if not row:
            return False
        
        conn.execute("""
            UPDATE shadow_domains 
            SET action = 'promoted', action_at = ?, action_by = ?, notes = ?
            WHERE domain = ?
        """, (now, actor, notes, domain))
        conn.commit()
        
        self._add_history(domain, "promoted", row['max_score'], actor, notes)
        logger.info(f"Shadow domain promoted: {domain} by {actor}")
        
        return True
    
    def dismiss(
        self,
        domain: str,
        actor: str = "admin",
        notes: str = "",
    ) -> bool:
        """
        Dismiss domain as safe.
        
        Returns True if successful.
        """
        domain = domain.lower().strip().rstrip('.')
        
        # Validate domain format
        if not is_valid_domain(domain):
            logger.warning(f"Shadow dismiss: rejected invalid domain: {domain[:50]}")
            return False
        
        # Sanitize actor and notes (prevent injection)
        actor = str(actor)[:64].replace('<', '').replace('>', '')
        notes = str(notes)[:500].replace('<', '').replace('>', '')
        
        now = time.time()
        
        conn = self._get_conn()
        
        cursor = conn.execute(
            "SELECT * FROM shadow_domains WHERE domain = ?",
            (domain,)
        )
        row = cursor.fetchone()
        
        if not row:
            return False
        
        conn.execute("""
            UPDATE shadow_domains 
            SET action = 'dismissed', action_at = ?, action_by = ?, notes = ?
            WHERE domain = ?
        """, (now, actor, notes, domain))
        conn.commit()
        
        self._add_history(domain, "dismissed", row['max_score'], actor, notes)
        logger.info(f"Shadow domain dismissed: {domain} by {actor}")
        
        return True
    
    def get_record(self, domain: str) -> Optional[ShadowRecord]:
        """Get shadow record for domain."""
        domain = domain.lower().strip().rstrip('.')
        
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM shadow_domains WHERE domain = ?",
            (domain,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        avg_score = row['total_score'] / row['hit_count'] if row['hit_count'] > 0 else 0
        
        return ShadowRecord(
            domain=domain,
            first_observed=self._safe_timestamp_to_datetime(row['first_observed']),
            last_observed=self._safe_timestamp_to_datetime(row['last_observed']),
            hit_count=row['hit_count'],
            max_score=row['max_score'],
            avg_score=avg_score,
            action=ShadowAction(row['action']),
            action_at=self._safe_timestamp_to_datetime(row['action_at']) if row['action_at'] else None,
            action_by=row['action_by'],
            notes=row['notes'] or "",
        )
    
    def increment_hit_count(self, domain: str) -> bool:
        """
        Increment hit count and update last_observed for a domain.
        
        Used when shadow-blocked domain is accessed again.
        Returns True if updated, False if domain not found.
        """
        domain = domain.lower().strip().rstrip('.')
        now = time.time()
        
        try:
            conn = self._get_conn()
            cursor = conn.execute("""
                UPDATE shadow_domains 
                SET hit_count = hit_count + 1,
                    last_observed = ?
                WHERE domain = ?
            """, (now, domain))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            logger.debug(f"Failed to increment hit count for {domain}: {e}")
            return False
    
    def is_observed(self, domain: str) -> bool:
        """Check if domain is currently in shadow mode."""
        record = self.get_record(domain)
        return record is not None and record.is_active
    
    def is_promoted(self, domain: str) -> bool:
        """Check if domain was promoted to blocklist."""
        record = self.get_record(domain)
        return record is not None and record.action == ShadowAction.PROMOTED
    
    def _safe_timestamp_to_datetime(self, ts: float | None) -> datetime:
        """Convert timestamp to datetime, handling invalid values."""
        if ts is None or ts <= 0:
            return utc_now()
        try:
            # Sanity check: timestamp should be after 2020 and before 2100
            if ts < 1577836800 or ts > 4102444800:  # 2020-01-01 to 2100-01-01
                return utc_now()
            return utc_fromtimestamp(ts)
        except (ValueError, OSError):
            return utc_now()
    
    def list_active(
        self,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "max_score",
        sort_desc: bool = True,
    ) -> List[ShadowRecord]:
        """
        List active shadow domains.
        
        Args:
            limit: Max results to return
            offset: Offset for pagination
            sort_by: Column to sort by (max_score, hit_count, last_observed)
            sort_desc: Sort descending if True
        """
        valid_sorts = {'max_score', 'hit_count', 'last_observed', 'first_observed'}
        if sort_by not in valid_sorts:
            sort_by = 'max_score'
        
        order = "DESC" if sort_desc else "ASC"
        
        conn = self._get_conn()
        cursor = conn.execute(f"""
            SELECT * FROM shadow_domains 
            WHERE action IN ('observed', 'auto_blocked')
            ORDER BY {sort_by} {order}
            LIMIT ? OFFSET ?
        """, (limit, offset))
        
        results = []
        for row in cursor:
            avg_score = row['total_score'] / row['hit_count'] if row['hit_count'] > 0 else 0
            results.append(ShadowRecord(
                domain=row['domain'],
                first_observed=self._safe_timestamp_to_datetime(row['first_observed']),
                last_observed=self._safe_timestamp_to_datetime(row['last_observed']),
                hit_count=row['hit_count'],
                max_score=row['max_score'],
                avg_score=avg_score,
                action=ShadowAction(row['action']),
                action_at=self._safe_timestamp_to_datetime(row['action_at']) if row['action_at'] else None,
                action_by=row['action_by'],
                notes=row['notes'] or "",
            ))
        
        return results
    
    def list_promoted(self, limit: int = 100) -> List[ShadowRecord]:
        """List domains that were promoted to blocklist."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT * FROM shadow_domains 
            WHERE action = 'promoted'
            ORDER BY action_at DESC
            LIMIT ?
        """, (limit,))
        
        results = []
        for row in cursor:
            avg_score = row['total_score'] / row['hit_count'] if row['hit_count'] > 0 else 0
            results.append(ShadowRecord(
                domain=row['domain'],
                first_observed=self._safe_timestamp_to_datetime(row['first_observed']),
                last_observed=self._safe_timestamp_to_datetime(row['last_observed']),
                hit_count=row['hit_count'],
                max_score=row['max_score'],
                avg_score=avg_score,
                action=ShadowAction(row['action']),
                action_at=self._safe_timestamp_to_datetime(row['action_at']) if row['action_at'] else None,
                action_by=row['action_by'],
                notes=row['notes'] or "",
            ))
        
        return results
    
    def export_promoted_domains(self) -> List[str]:
        """Export all promoted domains for blocklist integration."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT domain FROM shadow_domains 
            WHERE action = 'promoted'
            ORDER BY domain
        """)
        
        return [row['domain'] for row in cursor]
    
    def cleanup_expired(self) -> int:
        """
        Expire old inactive shadow domains.
        
        Returns number of expired domains.
        """
        cutoff = time.time() - (self.auto_expire_days * 86400)
        now = time.time()
        
        conn = self._get_conn()
        
        # Find domains to expire
        cursor = conn.execute("""
            SELECT domain, max_score FROM shadow_domains 
            WHERE action = 'observed' AND last_observed < ?
        """, (cutoff,))
        
        to_expire = cursor.fetchall()
        
        # Update each
        for row in to_expire:
            conn.execute("""
                UPDATE shadow_domains 
                SET action = 'expired', action_at = ?, action_by = 'auto'
                WHERE domain = ?
            """, (now, row['domain']))
            self._add_history(row['domain'], "expired", row['max_score'], "auto", 
                            f"Auto-expired after {self.auto_expire_days} days")
        
        conn.commit()
        
        if to_expire:
            logger.info(f"Shadow mode: expired {len(to_expire)} inactive domains")
        
        return len(to_expire)
    
    def get_stats(self) -> dict:
        """Get shadow mode statistics."""
        conn = self._get_conn()
        
        stats = {}
        
        # Total by action
        cursor = conn.execute("""
            SELECT action, COUNT(*) as count 
            FROM shadow_domains GROUP BY action
        """)
        stats['by_action'] = {row['action']: row['count'] for row in cursor}
        
        # Active count
        stats['active_count'] = stats['by_action'].get('observed', 0)
        stats['promoted_count'] = stats['by_action'].get('promoted', 0)
        stats['dismissed_count'] = stats['by_action'].get('dismissed', 0)
        stats['expired_count'] = stats['by_action'].get('expired', 0)

        cursor = conn.execute("""
            SELECT COUNT(*) FROM shadow_domains
            WHERE action = 'promoted' AND action_by = 'auto'
        """)
        stats['auto_promoted_count'] = cursor.fetchone()[0]
        
        # High priority (score > 50 and active)
        cursor = conn.execute("""
            SELECT COUNT(*) FROM shadow_domains 
            WHERE action = 'observed' AND max_score >= 50
        """)
        stats['high_priority_count'] = cursor.fetchone()[0]
        
        # Recent activity (last 24 hours)
        day_ago = time.time() - 86400
        cursor = conn.execute("""
            SELECT COUNT(*) FROM shadow_domains 
            WHERE last_observed > ?
        """, (day_ago,))
        stats['active_last_24h'] = cursor.fetchone()[0]
        
        return stats
    
    def get_history(
        self,
        domain: str | None = None,
        limit: int = 100,
    ) -> List[dict]:
        """Get action history."""
        conn = self._get_conn()
        
        if domain:
            cursor = conn.execute("""
                SELECT * FROM shadow_history 
                WHERE domain = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (domain.lower().strip().rstrip('.'), limit))
        else:
            cursor = conn.execute("""
                SELECT * FROM shadow_history 
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        results = []
        for row in cursor:
            results.append({
                'domain': row['domain'],
                'action': row['action'],
                'score': row['score'],
                'timestamp': utc_fromtimestamp(row['timestamp']),
                'actor': row['actor'],
                'notes': row['notes'],
            })
        
        return results
    
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def apply_settings(
        self,
        *,
        observe_threshold: int | None = None,
        block_threshold: int | None = None,
        auto_expire_days: int | None = None,
        auto_promote_hits: int | None = None,
    ) -> None:
        """Apply live runtime settings without recreating the singleton."""
        if observe_threshold is not None:
            self.observe_threshold = observe_threshold
        if block_threshold is not None:
            self.block_threshold = block_threshold
        if auto_expire_days is not None:
            self.auto_expire_days = auto_expire_days
        if auto_promote_hits is not None:
            self.auto_promote_hits = auto_promote_hits


# Singleton instance
_instance: ShadowMode | None = None
_lock = threading.Lock()


def get_shadow_mode(data_dir: str | Path | None = None) -> ShadowMode:
    """Get singleton ShadowMode instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                if data_dir is None:
                    data_dir = get_settings().NETPROTECTION_DATA_DIR
                else:
                    data_dir = Path(data_dir)
                
                db_path = data_dir / "shadow_mode.db"
                _instance = ShadowMode(db_path)
    if _instance is not None:
        heuristics_settings = get_settings().heuristics
        _instance.apply_settings(
            observe_threshold=heuristics_settings.observe_threshold,
            block_threshold=heuristics_settings.block_threshold,
            auto_expire_days=heuristics_settings.shadow_auto_expire_days,
            auto_promote_hits=heuristics_settings.shadow_auto_promote_hits,
        )
    return _instance


class ShadowModeManager:
    """
    Manager wrapper for Shadow Mode API.
    
    Provides interface for backend API endpoints.
    """
    
    def __init__(self, data_dir: str | Path | None = None):
        self._shadow = get_shadow_mode(data_dir)
    
    def get_observed_domains(
        self,
        status: str | None = None,
        min_score: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ):
        """Get observed domains with filtering."""
        if status == 'observing' or status is None:
            domains = self._shadow.list_active(limit=limit, offset=offset)
        elif status == 'promoted':
            domains = self._shadow.list_promoted(limit=limit)
        elif status == 'dismissed':
            # Need to get dismissed domains
            conn = self._shadow._get_conn()
            cursor = conn.execute("""
                SELECT * FROM shadow_domains 
                WHERE action = 'dismissed'
                ORDER BY action_at DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            domains = self._rows_to_records(cursor.fetchall())
        else:
            domains = self._shadow.list_active(limit=limit, offset=offset)
        
        # Filter by min_score if provided
        if min_score is not None:
            domains = [d for d in domains if d.max_score >= min_score]
        
        # Convert to API-friendly format
        return [
            ObservedDomain(
                domain=d.domain,
                score=d.max_score,
                first_seen=d.first_observed,
                last_seen=d.last_observed,
                hit_count=d.hit_count,
                signals=self._get_signals(d.domain),
                status=d.action.value,
                reviewed_by=d.action_by,
                reviewed_at=d.action_at,
            )
            for d in domains
        ]
    
    def _rows_to_records(self, rows) -> List[ShadowRecord]:
        """Convert database rows to ShadowRecord objects."""
        results = []
        for row in rows:
            avg_score = row['total_score'] / row['hit_count'] if row['hit_count'] > 0 else 0
            results.append(ShadowRecord(
                domain=row['domain'],
                first_observed=self._safe_timestamp_to_datetime(row['first_observed']),
                last_observed=self._safe_timestamp_to_datetime(row['last_observed']),
                hit_count=row['hit_count'],
                max_score=row['max_score'],
                avg_score=avg_score,
                action=ShadowAction(row['action']),
                action_at=self._safe_timestamp_to_datetime(row['action_at']) if row['action_at'] else None,
                action_by=row['action_by'],
                notes=row['notes'] or "",
            ))
        return results
    
    def _get_signals(self, domain: str) -> Dict:
        """Get heuristic signals for domain."""
        try:
            from easypi_netprotection.heuristics.signal_aggregator import get_signal_aggregator
            aggregator = get_signal_aggregator()
            if aggregator:
                result = aggregator.get_domain_signals(domain)
                return result.get('signals', {})
        except Exception:
            pass
        return {}
    
    def count_observed(
        self,
        status: str | None = None,
        min_score: float | None = None,
    ) -> int:
        """Count observed domains."""
        stats = self._shadow.get_stats()
        if status == 'observing':
            return stats.get('active_count', 0)
        elif status == 'promoted':
            return stats.get('promoted_count', 0)
        elif status == 'dismissed':
            return stats.get('dismissed_count', 0)
        return sum([
            stats.get('active_count', 0),
            stats.get('promoted_count', 0),
            stats.get('dismissed_count', 0),
        ])
    
    def get_stats(self) -> Dict:
        """Get shadow mode statistics."""
        stats = self._shadow.get_stats()
        return {
            'observing': stats.get('active_count', 0),
            'promoted': stats.get('promoted_count', 0),
            'dismissed': stats.get('dismissed_count', 0),
            'expired': stats.get('expired_count', 0),
            'pending_review': stats.get('high_priority_count', 0),
            'auto_promoted': stats.get('auto_promoted_count', 0),
        }
    
    def promote_to_blocklist(
        self,
        domain: str,
        reason: str = "Manual review",
        reviewed_by: str = "admin",
    ) -> bool:
        """Promote domain to blocklist."""
        return self._shadow.promote(domain, actor=reviewed_by, notes=reason)
    
    def dismiss_domain(
        self,
        domain: str,
        reason: str = "Deemed safe",
        reviewed_by: str = "admin",
    ) -> bool:
        """Dismiss domain as safe."""
        return self._shadow.dismiss(domain, actor=reviewed_by, notes=reason)
    
    def extend_observation(
        self,
        domain: str,
        days: int = 30,
        reason: str = "Extended review",
    ) -> bool:
        """Extend observation period for domain."""
        # Reset last_observed to extend observation
        conn = self._shadow._get_conn()
        cursor = conn.execute(
            "SELECT * FROM shadow_domains WHERE domain = ?",
            (domain.lower().strip().rstrip('.'),)
        )
        row = cursor.fetchone()
        if not row:
            return False
        
        import time
        conn.execute(
            "UPDATE shadow_domains SET last_observed = ?, notes = ? WHERE domain = ?",
            (time.time(), reason, domain.lower().strip().rstrip('.'))
        )
        conn.commit()
        return True


@dataclass
class ObservedDomain:
    """Domain under observation for API response."""
    domain: str
    score: float
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    signals: Dict
    status: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
