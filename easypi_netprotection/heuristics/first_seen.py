"""
First Seen Cache - Domain/IP novelty tracking.

Tracks when domains and IPs were first observed.
New domains (< 7 days) get higher risk score.

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from ..config import get_settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_fromtimestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


@dataclass
class FirstSeenRecord:
    """Record of when entity was first seen."""
    entity: str  # domain or IP
    entity_type: str  # 'domain' or 'ip'
    first_seen: datetime
    last_seen: datetime
    hit_count: int
    
    @property
    def age_days(self) -> float:
        """Days since first seen."""
        delta = utc_now() - self.first_seen
        return delta.total_seconds() / 86400
    
    @property
    def is_new(self) -> bool:
        """True if first seen within 7 days."""
        return self.age_days < 7


class FirstSeenCache:
    """
    SQLite-backed cache for tracking first-seen timestamps.
    
    Thread-safe with connection pooling.
    """
    
    # Risk thresholds (days)
    NEW_THRESHOLD_DAYS = 7
    VERY_NEW_THRESHOLD_DAYS = 1
    
    def __init__(
        self,
        db_path: Path | str,
        max_entries: int = 500000,
        cleanup_interval_hours: int = 24,
    ):
        self.db_path = Path(db_path)
        self.max_entries = max_entries
        self.cleanup_interval = cleanup_interval_hours * 3600
        
        self._local = threading.local()
        self._lock = threading.Lock()
        self._last_cleanup = 0.0
        
        self._init_db()
        logger.info(f"FirstSeenCache initialized at {self.db_path}")
    
    def _get_conn(self) -> sqlite3.Connection:
        """Get thread-local connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                timeout=10.0,
                check_same_thread=False,
            )
            self._local.conn.row_factory = sqlite3.Row
            # Performance settings
            self._local.conn.execute("PRAGMA journal_mode=WAL")
            self._local.conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn.execute("PRAGMA cache_size=10000")
        return self._local.conn
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = self._get_conn()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS first_seen (
                entity TEXT PRIMARY KEY,
                entity_type TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                hit_count INTEGER DEFAULT 1
            );
            
            CREATE INDEX IF NOT EXISTS idx_first_seen_type 
                ON first_seen(entity_type);
            CREATE INDEX IF NOT EXISTS idx_first_seen_date 
                ON first_seen(first_seen);
            CREATE INDEX IF NOT EXISTS idx_last_seen_date 
                ON first_seen(last_seen);
        """)
        conn.commit()
    
    def record(
        self,
        entity: str,
        entity_type: str = "domain",
    ) -> FirstSeenRecord:
        """
        Record observation of entity.
        
        Returns FirstSeenRecord with age information.
        """
        entity = entity.lower().strip().rstrip('.')
        now = time.time()
        
        conn = self._get_conn()
        
        # Try to get existing record
        cursor = conn.execute(
            "SELECT * FROM first_seen WHERE entity = ?",
            (entity,)
        )
        row = cursor.fetchone()
        
        if row:
            # Update existing
            conn.execute("""
                UPDATE first_seen 
                SET last_seen = ?, hit_count = hit_count + 1
                WHERE entity = ?
            """, (now, entity))
            conn.commit()
            
            return FirstSeenRecord(
                entity=entity,
                entity_type=row['entity_type'],
                first_seen=utc_fromtimestamp(row['first_seen']),
                last_seen=utc_now(),
                hit_count=row['hit_count'] + 1,
            )
        else:
            # Insert new
            conn.execute("""
                INSERT INTO first_seen (entity, entity_type, first_seen, last_seen, hit_count)
                VALUES (?, ?, ?, ?, 1)
            """, (entity, entity_type, now, now))
            conn.commit()
            
            return FirstSeenRecord(
                entity=entity,
                entity_type=entity_type,
                first_seen=utc_now(),
                last_seen=utc_now(),
                hit_count=1,
            )
    
    def lookup(self, entity: str) -> Optional[FirstSeenRecord]:
        """
        Look up entity without recording.
        
        Returns None if never seen.
        """
        entity = entity.lower().strip().rstrip('.')
        
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM first_seen WHERE entity = ?",
            (entity,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return FirstSeenRecord(
            entity=entity,
            entity_type=row['entity_type'],
            first_seen=utc_fromtimestamp(row['first_seen']),
            last_seen=utc_fromtimestamp(row['last_seen']),
            hit_count=row['hit_count'],
        )
    
    def get_risk_score(self, entity: str, entity_type: str = "domain") -> int:
        """
        Get risk score based on novelty.
        
        Returns:
            0 - Known entity (> 7 days)
            10 - Somewhat new (1-7 days)
            20 - Very new (< 1 day)
            25 - Never seen before
        """
        record = self.record(entity, entity_type)
        
        if record.hit_count == 1:
            # First time ever
            return 25
        elif record.age_days < self.VERY_NEW_THRESHOLD_DAYS:
            return 20
        elif record.age_days < self.NEW_THRESHOLD_DAYS:
            return 10
        else:
            return 0
    
    def get_stats(self) -> dict:
        """Get cache statistics."""
        conn = self._get_conn()
        
        stats = {}
        
        # Total entries
        cursor = conn.execute("SELECT COUNT(*) FROM first_seen")
        stats['total_entries'] = cursor.fetchone()[0]
        
        # By type
        cursor = conn.execute("""
            SELECT entity_type, COUNT(*) as count 
            FROM first_seen GROUP BY entity_type
        """)
        stats['by_type'] = {row['entity_type']: row['count'] for row in cursor}
        
        # New entities (< 7 days)
        week_ago = time.time() - (7 * 86400)
        cursor = conn.execute(
            "SELECT COUNT(*) FROM first_seen WHERE first_seen > ?",
            (week_ago,)
        )
        stats['new_last_7_days'] = cursor.fetchone()[0]
        
        # Very new (< 1 day)
        day_ago = time.time() - 86400
        cursor = conn.execute(
            "SELECT COUNT(*) FROM first_seen WHERE first_seen > ?",
            (day_ago,)
        )
        stats['new_last_24_hours'] = cursor.fetchone()[0]
        
        return stats
    
    def cleanup(self, max_age_days: int = 90) -> int:
        """
        Remove old entries to keep cache size manageable.
        
        Returns number of removed entries.
        """
        now = time.time()
        
        # Rate limit cleanup
        if now - self._last_cleanup < self.cleanup_interval:
            return 0
        
        self._last_cleanup = now
        cutoff = now - (max_age_days * 86400)
        
        conn = self._get_conn()
        
        with self._lock:
            # Delete old entries
            cursor = conn.execute(
                "DELETE FROM first_seen WHERE last_seen < ?",
                (cutoff,)
            )
            deleted = cursor.rowcount
            
            # If still too many, delete oldest
            cursor = conn.execute("SELECT COUNT(*) FROM first_seen")
            count = cursor.fetchone()[0]
            
            if count > self.max_entries:
                excess = count - self.max_entries
                conn.execute("""
                    DELETE FROM first_seen WHERE entity IN (
                        SELECT entity FROM first_seen 
                        ORDER BY last_seen ASC LIMIT ?
                    )
                """, (excess,))
                deleted += excess
            
            conn.commit()
            
            if deleted > 0:
                logger.info(f"FirstSeenCache cleanup: removed {deleted} entries")
            
            return deleted
    
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
_instance: FirstSeenCache | None = None
_lock = threading.Lock()


def get_first_seen_cache(data_dir: str | Path | None = None) -> FirstSeenCache:
    """Get singleton FirstSeenCache instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                if data_dir is None:
                    data_dir = get_settings().NETPROTECTION_DATA_DIR
                else:
                    data_dir = Path(data_dir)
                
                db_path = data_dir / "first_seen.db"
                _instance = FirstSeenCache(db_path)
    
    return _instance
