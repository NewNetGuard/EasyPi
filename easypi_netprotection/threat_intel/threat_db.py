"""
Threat Database — SQLite-backed storage with TTL and confidence decay.

Features:
- TTL-based expiration for all entries
- Automatic confidence decay over time
- Source weight consideration in scoring
- Efficient lookups with indexing
- Automatic cleanup of expired entries
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from ..time_utils import utc_now
from pathlib import Path
from typing import Generator

from .models import (
    AllowlistEntry,
    BrandEntry,
    SourceType,
    SourceWeight,
    ThreatCategory,
    ThreatEntry,
    ThreatSignals,
    ThreatStatus,
)


class ThreatDatabase:
    """
    SQLite-backed threat intelligence database.
    
    Key features:
    - TTL expiration with configurable defaults
    - Confidence decay over time
    - Source weight hierarchy
    - Deduplication
    - Efficient batch operations
    """
    
    # Default TTLs by source type (in days)
    DEFAULT_TTL = {
        SourceType.HEURISTIC: 7,  # Short TTL for automated detection
        SourceType.CT_LOGS: 14,
        SourceType.USER_REPORT: 30,
        SourceType.USER_CONFIRMED: 90,
        SourceType.FEED_CC0: 30,
        SourceType.FEED_MIT: 30,
        SourceType.FEED_PERMISSIVE: 30,
        SourceType.ADMIN_CONFIRMED: 365,
        SourceType.MANUAL: 365,
    }
    
    def __init__(
        self,
        db_path: str | Path | None = None,
        decay_rate: float = 0.05,
        min_confidence: float = 10.0,
        cleanup_interval: int = 3600,  # 1 hour
    ):
        """
        Initialize threat database.
        
        Args:
            db_path: Path to SQLite database (None for in-memory)
            decay_rate: Confidence decay rate per day (default 5%)
            min_confidence: Minimum confidence before removal
            cleanup_interval: Seconds between cleanup runs
        """
        self.db_path = str(db_path) if db_path else ":memory:"
        self.decay_rate = decay_rate
        self.min_confidence = min_confidence
        self.cleanup_interval = cleanup_interval
        
        self._conn: sqlite3.Connection | None = None
        self._cleanup_task: asyncio.Task | None = None
        self._initialized = False
    
    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with proper settings."""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES,
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        
        try:
            yield self._conn
        except Exception:
            self._conn.rollback()
            raise
    
    async def initialize(self) -> None:
        """Initialize database schema."""
        if self._initialized:
            return
        
        with self._get_connection() as conn:
            # Threats table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT NOT NULL,
                    initial_confidence REAL NOT NULL,
                    current_confidence REAL NOT NULL,
                    source_type TEXT NOT NULL,
                    source_weight INTEGER NOT NULL,
                    source_details TEXT DEFAULT '',
                    signals_json TEXT,
                    signal_count INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    last_seen TEXT NOT NULL,
                    decay_rate REAL DEFAULT 0.05,
                    min_confidence REAL DEFAULT 10,
                    user_reports INTEGER DEFAULT 0,
                    false_positive_reports INTEGER DEFAULT 0,
                    metadata_json TEXT DEFAULT '{}'
                )
            """)
            
            # Indexes for efficient lookups
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_domain ON threats(domain)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_category ON threats(category)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_expires ON threats(expires_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_threats_confidence ON threats(current_confidence)")
            
            # Allowlist table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS allowlist (
                    id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    pattern_type TEXT DEFAULT 'exact',
                    reason TEXT DEFAULT '',
                    added_by TEXT DEFAULT 'system',
                    added_at TEXT NOT NULL,
                    expires_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_allowlist_domain ON allowlist(domain)")
            
            # Brands table (for homoglyph protection)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS brands (
                    name TEXT PRIMARY KEY,
                    domains_json TEXT NOT NULL,
                    keywords_json TEXT NOT NULL,
                    protected INTEGER DEFAULT 1,
                    owner_verified INTEGER DEFAULT 0
                )
            """)
            
            # Feeds table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS feeds (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    url TEXT NOT NULL,
                    license TEXT DEFAULT 'unknown',
                    source_type TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    update_interval_hours INTEGER DEFAULT 24,
                    last_updated TEXT,
                    domain_count INTEGER DEFAULT 0,
                    categories_json TEXT DEFAULT '[]'
                )
            """)
            
            # Quarantine log (for UI)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS quarantine_log (
                    id TEXT PRIMARY KEY,
                    threat_id TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    action TEXT NOT NULL,
                    performed_by TEXT DEFAULT 'system',
                    performed_at TEXT NOT NULL,
                    reason TEXT DEFAULT '',
                    FOREIGN KEY (threat_id) REFERENCES threats(id)
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_quarantine_threat ON quarantine_log(threat_id)")
            
            conn.commit()
        
        self._initialized = True
    
    async def start_cleanup_task(self) -> None:
        """Start background cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop_cleanup_task(self) -> None:
        """Stop background cleanup task."""
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def _cleanup_loop(self) -> None:
        """Background loop for cleanup and decay updates."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired()
                await self.update_decayed_confidence()
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error but continue
                pass
    
    # --------------------------
    # Threat Entry Operations
    # --------------------------
    
    async def add_threat(
        self,
        domain: str,
        category: ThreatCategory,
        confidence: float,
        source_type: SourceType,
        signals: ThreatSignals | None = None,
        ttl_days: int | None = None,
        source_details: str = "",
        metadata: dict | None = None,
    ) -> ThreatEntry:
        """
        Add a new threat entry or update existing one.
        
        Note: Heuristics and CT logs always create OBSERVED entries,
        never auto-block.
        """
        await self.initialize()
        
        # Check allowlist first
        if await self.is_allowlisted(domain):
            # Return a dummy entry with allowlisted status
            return ThreatEntry(
                id=f"allowlisted_{domain}",
                domain=domain,
                category=category,
                status=ThreatStatus.ALLOWLISTED,
                initial_confidence=0,
                current_confidence=0,
                source_type=source_type,
                source_weight=0,
            )
        
        # Determine TTL
        if ttl_days is None:
            ttl_days = self.DEFAULT_TTL.get(source_type, 30)
        
        # Determine initial status based on source
        if source_type in (SourceType.HEURISTIC, SourceType.CT_LOGS):
            # NEVER auto-block from heuristics/CT
            if signals and signals.should_quarantine():
                status = ThreatStatus.QUARANTINE
            else:
                status = ThreatStatus.OBSERVED
        elif source_type in (SourceType.ADMIN_CONFIRMED, SourceType.MANUAL):
            status = ThreatStatus.CONFIRMED
        else:
            status = ThreatStatus.ACTIVE
        
        source_weight = SourceWeight.from_source_type(source_type)
        
        # Check for existing entry
        existing = await self.get_threat(domain)
        
        now = utc_now()
        
        if existing:
            # Update existing entry with combined signals
            return await self._update_existing_threat(
                existing, category, confidence, source_type, 
                source_weight, signals, ttl_days, source_details
            )
        
        # Create new entry
        entry = ThreatEntry(
            id=f"threat_{uuid.uuid4().hex[:12]}",
            domain=domain.lower(),
            category=category,
            status=status,
            initial_confidence=confidence,
            current_confidence=confidence,
            source_type=source_type,
            source_weight=source_weight,
            source_details=source_details,
            signals=signals,
            signal_count=signals.signal_count if signals else 0,
            created_at=now,
            updated_at=now,
            expires_at=now + timedelta(days=ttl_days),
            last_seen=now,
            decay_rate=self.decay_rate,
            min_confidence=self.min_confidence,
            metadata=metadata or {},
        )
        
        await self._insert_threat(entry)
        return entry
    
    async def _update_existing_threat(
        self,
        existing: ThreatEntry,
        category: ThreatCategory,
        confidence: float,
        source_type: SourceType,
        source_weight: int,
        signals: ThreatSignals | None,
        ttl_days: int,
        source_details: str,
    ) -> ThreatEntry:
        """Update an existing threat entry."""
        now = utc_now()
        
        # Take higher confidence and better source
        new_confidence = max(existing.current_confidence, confidence)
        new_weight = max(existing.source_weight, source_weight)
        
        # Combine signal counts
        new_signal_count = existing.signal_count
        if signals:
            new_signal_count = max(new_signal_count, signals.signal_count)
        
        # Upgrade status if needed
        new_status = existing.status
        if source_weight > existing.source_weight:
            if source_type in (SourceType.ADMIN_CONFIRMED, SourceType.MANUAL):
                new_status = ThreatStatus.CONFIRMED
            elif source_type == SourceType.USER_CONFIRMED:
                new_status = ThreatStatus.ACTIVE
        
        # Check quarantine threshold
        if (
            new_status == ThreatStatus.OBSERVED
            and signals
            and signals.should_quarantine()
        ):
            new_status = ThreatStatus.QUARANTINE
        
        # Extend TTL
        new_expires = now + timedelta(days=ttl_days)
        if existing.expires_at and existing.expires_at > new_expires:
            new_expires = existing.expires_at
        
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE threats SET
                    category = ?,
                    status = ?,
                    current_confidence = ?,
                    source_type = CASE WHEN ? > source_weight THEN ? ELSE source_type END,
                    source_weight = ?,
                    signal_count = ?,
                    updated_at = ?,
                    expires_at = ?,
                    last_seen = ?,
                    user_reports = user_reports + ?
                WHERE id = ?
            """, (
                category.value,
                new_status.value,
                new_confidence,
                source_weight, source_type.value,
                new_weight,
                new_signal_count,
                now.isoformat(),
                new_expires.isoformat(),
                now.isoformat(),
                1 if source_type == SourceType.USER_REPORT else 0,
                existing.id,
            ))
            conn.commit()
        
        return await self.get_threat(existing.domain)  # type: ignore
    
    async def _insert_threat(self, entry: ThreatEntry) -> None:
        """Insert a new threat entry."""
        with self._get_connection() as conn:
            signals_json = entry.signals.model_dump_json() if entry.signals else None
            
            conn.execute("""
                INSERT INTO threats (
                    id, domain, category, status, initial_confidence, current_confidence,
                    source_type, source_weight, source_details, signals_json, signal_count,
                    created_at, updated_at, expires_at, last_seen,
                    decay_rate, min_confidence, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.id,
                entry.domain,
                entry.category.value,
                entry.status.value,
                entry.initial_confidence,
                entry.current_confidence,
                entry.source_type.value,
                entry.source_weight,
                entry.source_details,
                signals_json,
                entry.signal_count,
                entry.created_at.isoformat(),
                entry.updated_at.isoformat(),
                entry.expires_at.isoformat() if entry.expires_at else None,
                entry.last_seen.isoformat(),
                entry.decay_rate,
                entry.min_confidence,
                json.dumps(entry.metadata),
            ))
            conn.commit()
    
    async def get_threat(self, domain: str) -> ThreatEntry | None:
        """Get threat entry for a domain."""
        await self.initialize()
        
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM threats WHERE domain = ? AND status != 'expired'",
                (domain.lower(),)
            ).fetchone()
            
            if row:
                return self._row_to_entry(row)
        
        return None
    
    async def get_threat_by_id(self, threat_id: str) -> ThreatEntry | None:
        """Get threat entry by ID."""
        await self.initialize()
        
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM threats WHERE id = ?",
                (threat_id,)
            ).fetchone()
            
            if row:
                return self._row_to_entry(row)
        
        return None
    
    async def update_threat_status(
        self,
        threat_id: str,
        new_status: ThreatStatus,
        reason: str = "",
        performed_by: str = "system",
    ) -> ThreatEntry | None:
        """
        Update threat status (confirm, reject, allowlist).
        
        Args:
            threat_id: Threat entry ID
            new_status: New status to set
            reason: Reason for status change
            performed_by: Who performed the action
        
        Returns:
            Updated ThreatEntry or None if not found
        """
        await self.initialize()
        
        now = utc_now()
        
        with self._get_connection() as conn:
            # Update status
            result = conn.execute("""
                UPDATE threats SET
                    status = ?,
                    updated_at = ?,
                    source_type = CASE 
                        WHEN ? = 'confirmed' THEN 'admin_confirmed'
                        ELSE source_type
                    END,
                    source_weight = CASE
                        WHEN ? = 'confirmed' THEN 80
                        ELSE source_weight
                    END
                WHERE id = ?
            """, (
                new_status.value,
                now.isoformat(),
                new_status.value,
                new_status.value,
                threat_id,
            ))
            
            if result.rowcount == 0:
                return None
            
            # Log the action
            conn.execute("""
                INSERT INTO quarantine_log (id, threat_id, domain, action, performed_by, performed_at, reason)
                SELECT ?, id, domain, ?, ?, ?, ?
                FROM threats WHERE id = ?
            """, (
                f"log_{uuid.uuid4().hex[:12]}",
                f"status_change:{new_status.value}",
                performed_by,
                now.isoformat(),
                reason,
                threat_id,
            ))
            
            conn.commit()
        
        return await self.get_threat_by_id(threat_id)
    
    def _row_to_entry(self, row: sqlite3.Row) -> ThreatEntry:
        """Convert database row to ThreatEntry."""
        signals = None
        if row["signals_json"]:
            signals = ThreatSignals.model_validate_json(row["signals_json"])
        
        return ThreatEntry(
            id=row["id"],
            domain=row["domain"],
            category=ThreatCategory(row["category"]),
            status=ThreatStatus(row["status"]),
            initial_confidence=row["initial_confidence"],
            current_confidence=row["current_confidence"],
            source_type=SourceType(row["source_type"]),
            source_weight=row["source_weight"],
            source_details=row["source_details"],
            signals=signals,
            signal_count=row["signal_count"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]),
            decay_rate=row["decay_rate"],
            min_confidence=row["min_confidence"],
            user_reports=row["user_reports"],
            false_positive_reports=row["false_positive_reports"],
            metadata=json.loads(row["metadata_json"]),
        )
    
    async def check_domain(self, domain: str) -> tuple[ThreatEntry | None, str]:
        """
        Check domain and return recommendation.
        
        Returns:
            Tuple of (ThreatEntry or None, action recommendation)
            Actions: "allow", "observe", "quarantine", "block"
        """
        # Check allowlist first
        if await self.is_allowlisted(domain):
            return None, "allow"
        
        entry = await self.get_threat(domain)
        
        if entry is None:
            return None, "allow"
        
        # Update confidence with decay
        entry.current_confidence = entry.calculate_decayed_confidence()
        
        if entry.is_expired():
            return entry, "allow"  # Expired = allow
        
        if entry.should_block():
            return entry, "block"
        
        if entry.should_quarantine():
            return entry, "quarantine"
        
        return entry, "observe"
    
    async def get_quarantined(self, limit: int = 100) -> list[ThreatEntry]:
        """Get all quarantined entries for UI review."""
        await self.initialize()
        
        entries = []
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM threats
                WHERE status = 'quarantine'
                ORDER BY current_confidence DESC, updated_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            
            for row in rows:
                entries.append(self._row_to_entry(row))
        
        return entries
    
    async def get_observed(self, limit: int = 100) -> list[ThreatEntry]:
        """Get all observed entries."""
        await self.initialize()
        
        entries = []
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM threats
                WHERE status = 'observed'
                ORDER BY current_confidence DESC, updated_at DESC
                LIMIT ?
            """, (limit,)).fetchall()
            
            for row in rows:
                entries.append(self._row_to_entry(row))
        
        return entries
    
    async def update_status(
        self,
        domain: str,
        new_status: ThreatStatus,
        performed_by: str = "system",
        reason: str = "",
    ) -> bool:
        """Update threat status (e.g., from quarantine to confirmed)."""
        entry = await self.get_threat(domain)
        if not entry:
            return False
        
        now = utc_now()
        
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE threats SET status = ?, updated_at = ?
                WHERE domain = ?
            """, (new_status.value, now.isoformat(), domain.lower()))
            
            # Log the action
            conn.execute("""
                INSERT INTO quarantine_log (id, threat_id, domain, action, performed_by, performed_at, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                f"qlog_{uuid.uuid4().hex[:8]}",
                entry.id,
                domain,
                new_status.value,
                performed_by,
                now.isoformat(),
                reason,
            ))
            
            conn.commit()
        
        return True
    
    async def report_false_positive(self, domain: str, reported_by: str = "user") -> bool:
        """Report a false positive."""
        entry = await self.get_threat(domain)
        if not entry:
            return False
        
        now = utc_now()
        
        with self._get_connection() as conn:
            # Increase FP count and decrease confidence
            new_confidence = max(0, entry.current_confidence - 15)
            
            conn.execute("""
                UPDATE threats SET
                    false_positive_reports = false_positive_reports + 1,
                    current_confidence = ?,
                    updated_at = ?
                WHERE domain = ?
            """, (new_confidence, now.isoformat(), domain.lower()))
            
            # If too many FP reports, move to observed
            if entry.false_positive_reports + 1 >= 3:
                conn.execute("""
                    UPDATE threats SET status = 'observed'
                    WHERE domain = ? AND status != 'confirmed'
                """, (domain.lower(),))
            
            conn.commit()
        
        return True
    
    # --------------------------
    # Allowlist Operations
    # --------------------------
    
    async def add_to_allowlist(
        self,
        domain: str,
        pattern_type: str = "exact",
        reason: str = "",
        added_by: str = "system",
        expires_days: int | None = None,
    ) -> AllowlistEntry:
        """Add domain to allowlist."""
        await self.initialize()
        
        now = utc_now()
        expires_at = now + timedelta(days=expires_days) if expires_days else None
        
        entry = AllowlistEntry(
            id=f"allow_{uuid.uuid4().hex[:8]}",
            domain=domain.lower(),
            pattern_type=pattern_type,
            reason=reason,
            added_by=added_by,
            added_at=now,
            expires_at=expires_at,
        )
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO allowlist (id, domain, pattern_type, reason, added_by, added_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                entry.id,
                entry.domain,
                entry.pattern_type,
                entry.reason,
                entry.added_by,
                entry.added_at.isoformat(),
                entry.expires_at.isoformat() if entry.expires_at else None,
            ))
            
            # Also update any existing threat entry
            conn.execute("""
                UPDATE threats SET status = 'allowlisted'
                WHERE domain = ?
            """, (domain.lower(),))
            
            conn.commit()
        
        return entry
    
    async def remove_from_allowlist(self, domain: str) -> bool:
        """Remove domain from allowlist."""
        with self._get_connection() as conn:
            result = conn.execute(
                "DELETE FROM allowlist WHERE domain = ?",
                (domain.lower(),)
            )
            conn.commit()
            return result.rowcount > 0
    
    async def is_allowlisted(self, domain: str) -> bool:
        """Check if domain is allowlisted."""
        await self.initialize()
        
        with self._get_connection() as conn:
            # Check exact match first
            row = conn.execute(
                "SELECT * FROM allowlist WHERE domain = ? AND pattern_type = 'exact'",
                (domain.lower(),)
            ).fetchone()
            
            if row:
                # Check expiration
                if row["expires_at"]:
                    expires = datetime.fromisoformat(row["expires_at"])
                    if utc_now() > expires:
                        return False
                return True
            
            # Check wildcard patterns
            rows = conn.execute(
                "SELECT * FROM allowlist WHERE pattern_type != 'exact'"
            ).fetchall()
            
            for row in rows:
                entry = AllowlistEntry(
                    id=row["id"],
                    domain=row["domain"],
                    pattern_type=row["pattern_type"],
                    reason=row["reason"],
                    added_by=row["added_by"],
                    added_at=datetime.fromisoformat(row["added_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                )
                
                if entry.expires_at and utc_now() > entry.expires_at:
                    continue
                
                if entry.matches(domain):
                    return True
        
        return False
    
    async def get_allowlist(self) -> list[AllowlistEntry]:
        """Get all allowlist entries."""
        await self.initialize()
        
        entries = []
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM allowlist ORDER BY added_at DESC").fetchall()
            
            for row in rows:
                entries.append(AllowlistEntry(
                    id=row["id"],
                    domain=row["domain"],
                    pattern_type=row["pattern_type"],
                    reason=row["reason"],
                    added_by=row["added_by"],
                    added_at=datetime.fromisoformat(row["added_at"]),
                    expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
                ))
        
        return entries
    
    # --------------------------
    # Brand Operations
    # --------------------------
    
    async def add_brand(self, brand: BrandEntry) -> None:
        """Add protected brand."""
        await self.initialize()
        
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO brands (name, domains_json, keywords_json, protected, owner_verified)
                VALUES (?, ?, ?, ?, ?)
            """, (
                brand.name.lower(),
                json.dumps(brand.domains),
                json.dumps(brand.keywords),
                1 if brand.protected else 0,
                1 if brand.owner_verified else 0,
            ))
            conn.commit()
    
    async def get_brands(self) -> list[BrandEntry]:
        """Get all protected brands."""
        await self.initialize()
        
        brands = []
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM brands WHERE protected = 1").fetchall()
            
            for row in rows:
                brands.append(BrandEntry(
                    name=row["name"],
                    domains=json.loads(row["domains_json"]),
                    keywords=json.loads(row["keywords_json"]),
                    protected=bool(row["protected"]),
                    owner_verified=bool(row["owner_verified"]),
                ))
        
        return brands
    
    # --------------------------
    # Cleanup Operations
    # --------------------------
    
    async def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count of removed entries."""
        await self.initialize()
        
        now = utc_now().isoformat()
        
        with self._get_connection() as conn:
            result = conn.execute("""
                UPDATE threats SET status = 'expired'
                WHERE expires_at IS NOT NULL AND expires_at < ?
                AND status NOT IN ('confirmed', 'allowlisted')
            """, (now,))
            
            # Also clean up old expired entries (older than 30 days)
            old_date = (utc_now() - timedelta(days=30)).isoformat()
            conn.execute("""
                DELETE FROM threats
                WHERE status = 'expired' AND updated_at < ?
            """, (old_date,))
            
            conn.commit()
            return result.rowcount
    
    async def update_decayed_confidence(self) -> int:
        """Update confidence for all entries with decay. Returns updated count."""
        await self.initialize()
        
        now = utc_now()
        updated = 0
        
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT id, initial_confidence, created_at, decay_rate, min_confidence, source_weight
                FROM threats
                WHERE status NOT IN ('expired', 'allowlisted', 'confirmed')
            """).fetchall()
            
            for row in rows:
                created = datetime.fromisoformat(row["created_at"])
                days_elapsed = (now - created).total_seconds() / 86400
                
                initial = row["initial_confidence"]
                decay = row["decay_rate"]
                min_conf = row["min_confidence"]
                weight = row["source_weight"]
                
                # Calculate decay with source weight bonus
                decayed = initial * (1 - decay * days_elapsed)
                weight_bonus = weight / 100
                decayed = decayed + (initial - decayed) * weight_bonus * 0.3
                new_confidence = max(min_conf, min(100, decayed))
                
                conn.execute("""
                    UPDATE threats SET current_confidence = ?
                    WHERE id = ?
                """, (new_confidence, row["id"]))
                updated += 1
            
            conn.commit()
        
        return updated
    
    async def get_stats(self) -> dict:
        """Get database statistics."""
        await self.initialize()
        
        with self._get_connection() as conn:
            stats = {}
            
            # Total threats by status
            for status in ThreatStatus:
                count = conn.execute(
                    "SELECT COUNT(*) FROM threats WHERE status = ?",
                    (status.value,)
                ).fetchone()[0]
                stats[f"threats_{status.value}"] = count
            
            # Total allowlist
            stats["allowlist_count"] = conn.execute(
                "SELECT COUNT(*) FROM allowlist"
            ).fetchone()[0]
            
            # Total brands
            stats["brand_count"] = conn.execute(
                "SELECT COUNT(*) FROM brands"
            ).fetchone()[0]
            
            # Average confidence
            avg = conn.execute(
                "SELECT AVG(current_confidence) FROM threats WHERE status NOT IN ('expired', 'allowlisted')"
            ).fetchone()[0]
            stats["avg_confidence"] = round(avg, 1) if avg else 0
            
        return stats
    
    async def close(self) -> None:
        """Close database connection."""
        await self.stop_cleanup_task()
        if self._conn:
            self._conn.close()
            self._conn = None
