from __future__ import annotations

import json
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from ..time_utils import utc_now
from pathlib import Path
from typing import Generator

from ..config import get_settings
from .models import (
    Device,
    DeviceUpdate,
    FlowRecord,
    Matcher,
    MatcherCreate,
    MatcherUpdate,
    Schedule,
    ShieldProfile,
)


SCHEMA_VERSION = 1

SCHEMA_SQL = """
-- Matchers table
CREATE TABLE IF NOT EXISTS matchers (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER DEFAULT 100,
    enabled INTEGER DEFAULT 1,
    tags TEXT DEFAULT '[]',
    comment TEXT DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    hit_count INTEGER DEFAULT 0,
    last_hit_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_matchers_enabled ON matchers(enabled);
CREATE INDEX IF NOT EXISTS idx_matchers_priority ON matchers(priority DESC);
CREATE INDEX IF NOT EXISTS idx_matchers_kind ON matchers(kind);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    mac_address TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    hostname TEXT,
    kind TEXT DEFAULT 'unknown',
    vendor TEXT,
    shield_profile TEXT DEFAULT 'balanced',
    custom_matchers TEXT DEFAULT '[]',
    friendly_name TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    total_flows INTEGER DEFAULT 0,
    blocked_flows INTEGER DEFAULT 0,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address);
CREATE INDEX IF NOT EXISTS idx_devices_active ON devices(is_active);

-- Shield profiles table
CREATE TABLE IF NOT EXISTS shield_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    preset TEXT DEFAULT 'custom',
    description TEXT DEFAULT '',
    block_advertising INTEGER DEFAULT 1,
    block_tracking INTEGER DEFAULT 1,
    block_malware INTEGER DEFAULT 1,
    block_phishing INTEGER DEFAULT 1,
    block_adult INTEGER DEFAULT 0,
    block_social INTEGER DEFAULT 0,
    block_gaming INTEGER DEFAULT 0,
    block_streaming INTEGER DEFAULT 0,
    enforce_safesearch INTEGER DEFAULT 0,
    enforce_youtube_restricted INTEGER DEFAULT 0,
    custom_matchers TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Schedules table
CREATE TABLE IF NOT EXISTS schedules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    device_ids TEXT DEFAULT '[]',
    days TEXT DEFAULT '["mon","tue","wed","thu","fri","sat","sun"]',
    start_time TEXT DEFAULT '00:00',
    end_time TEXT DEFAULT '23:59',
    action TEXT DEFAULT 'deny',
    override_profile TEXT,
    enabled INTEGER DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled);

-- Flow records (Chronicle)
CREATE TABLE IF NOT EXISTS flow_records (
    id TEXT PRIMARY KEY,
    flow_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    query_type TEXT DEFAULT 'A',
    device_id TEXT,
    device_ip_hash TEXT,
    action TEXT NOT NULL,
    confidence INTEGER,
    primary_evidence TEXT,
    response_ip TEXT,
    response_code TEXT DEFAULT 'NOERROR',
    upstream_used TEXT,
    cached INTEGER DEFAULT 0,
    processing_time_ms REAL DEFAULT 0,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flow_records(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_flows_domain ON flow_records(domain);
CREATE INDEX IF NOT EXISTS idx_flows_device ON flow_records(device_id);
CREATE INDEX IF NOT EXISTS idx_flows_action ON flow_records(action);

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_info (
    key TEXT PRIMARY KEY,
    value TEXT
);

INSERT OR IGNORE INTO schema_info (key, value) VALUES ('version', '1');
"""


class VaultRepository:
    """SQLite-based persistence layer for NetProtection."""
    
    def __init__(self, db_path: Path | str | None = None):
        settings = get_settings()
        self.db_path = Path(db_path) if db_path else settings.vault.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._connect() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
    
    async def initialize(self) -> None:
        """Async initialization method for compatibility with bootstrap."""
        # Already initialized in __init__, this is for async bootstrap compatibility
        pass
    
    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(
            self.db_path,
            timeout=10.0,
            isolation_level="DEFERRED",
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
        finally:
            conn.close()
    
    def create_backup(self) -> Path:
        """Create a backup of the database."""
        settings = get_settings()
        backup_dir = self.db_path.parent / "backups"
        backup_dir.mkdir(exist_ok=True)
        
        timestamp = utc_now().strftime("%Y%m%d_%H%M%S")
        backup_path = backup_dir / f"netprotection_{timestamp}.db"
        
        shutil.copy2(self.db_path, backup_path)
        
        # Clean old backups
        backups = sorted(backup_dir.glob("netprotection_*.db"), reverse=True)
        for old_backup in backups[settings.vault.max_backups:]:
            old_backup.unlink()
        
        return backup_path
    
    # -------------------------------------------------------------------------
    # Matchers CRUD
    # -------------------------------------------------------------------------
    
    def get_matchers(
        self,
        enabled_only: bool = False,
        kind: str | None = None,
        tags: list[str] | None = None,
    ) -> list[Matcher]:
        """Retrieve matchers with optional filtering."""
        query = "SELECT * FROM matchers WHERE 1=1"
        params: list = []
        
        if enabled_only:
            query += " AND enabled = 1"
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        
        query += " ORDER BY priority DESC, created_at ASC"
        
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        
        matchers = []
        for row in rows:
            data = dict(row)
            data["tags"] = json.loads(data["tags"])
            data["enabled"] = bool(data["enabled"])
            
            # Filter by tags if specified
            if tags and not any(t in data["tags"] for t in tags):
                continue
            
            matchers.append(Matcher(**data))
        
        return matchers
    
    def get_matcher(self, matcher_id: str) -> Matcher | None:
        """Retrieve a single matcher by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM matchers WHERE id = ?",
                (matcher_id,),
            ).fetchone()
        
        if not row:
            return None
        
        data = dict(row)
        data["tags"] = json.loads(data["tags"])
        data["enabled"] = bool(data["enabled"])
        return Matcher(**data)
    
    def create_matcher(self, create: MatcherCreate) -> Matcher:
        """Create a new matcher."""
        matcher = Matcher(
            kind=create.kind,
            pattern=create.pattern,
            action=create.action,
            priority=create.priority,
            enabled=create.enabled,
            tags=create.tags,
            comment=create.comment,
        )
        
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO matchers 
                (id, kind, pattern, action, priority, enabled, tags, comment, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    matcher.id,
                    matcher.kind.value,
                    matcher.pattern,
                    matcher.action.value,
                    matcher.priority,
                    int(matcher.enabled),
                    json.dumps(matcher.tags),
                    matcher.comment,
                    matcher.created_at.isoformat(),
                    matcher.updated_at.isoformat(),
                ),
            )
            conn.commit()
        
        return matcher
    
    def update_matcher(self, matcher_id: str, update: MatcherUpdate) -> Matcher | None:
        """Update an existing matcher."""
        existing = self.get_matcher(matcher_id)
        if not existing:
            return None
        
        updates = update.model_dump(exclude_unset=True)
        if not updates:
            return existing
        
        updates["updated_at"] = utc_now()
        
        # Whitelist allowed columns to prevent SQL injection
        ALLOWED_COLUMNS = {
            "pattern", "kind", "action", "priority", "enabled",
            "tags", "redirect_ip", "comment", "updated_at"
        }
        
        set_clauses = []
        params = []
        
        for key, value in updates.items():
            if key not in ALLOWED_COLUMNS:
                continue  # Skip unknown columns
            if key == "tags":
                value = json.dumps(value)
            elif key == "enabled":
                value = int(value)
            elif key in ("kind", "action"):
                value = value.value if hasattr(value, "value") else value
            elif isinstance(value, datetime):
                value = value.isoformat()
            
            set_clauses.append(f"{key} = ?")
            params.append(value)
        
        params.append(matcher_id)
        
        with self._connect() as conn:
            conn.execute(
                f"UPDATE matchers SET {', '.join(set_clauses)} WHERE id = ?",
                params,
            )
            conn.commit()
        
        return self.get_matcher(matcher_id)
    
    def delete_matcher(self, matcher_id: str) -> bool:
        """Delete a matcher."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM matchers WHERE id = ?",
                (matcher_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
    
    def increment_matcher_hit(self, matcher_id: str) -> None:
        """Increment hit count for a matcher."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE matchers 
                SET hit_count = hit_count + 1, last_hit_at = ?
                WHERE id = ?
                """,
                (utc_now().isoformat(), matcher_id),
            )
            conn.commit()
    
    # -------------------------------------------------------------------------
    # Devices CRUD
    # -------------------------------------------------------------------------
    
    def get_devices(self, active_only: bool = False) -> list[Device]:
        """Retrieve all devices."""
        query = "SELECT * FROM devices"
        if active_only:
            query += " WHERE is_active = 1"
        query += " ORDER BY last_seen DESC"
        
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        
        devices = []
        for row in rows:
            data = dict(row)
            data["custom_matchers"] = json.loads(data["custom_matchers"])
            data["is_active"] = bool(data["is_active"])
            devices.append(Device(**data))
        
        return devices
    
    def get_device(self, device_id: str) -> Device | None:
        """Retrieve a device by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ?",
                (device_id,),
            ).fetchone()
        
        if not row:
            return None
        
        data = dict(row)
        data["custom_matchers"] = json.loads(data["custom_matchers"])
        data["is_active"] = bool(data["is_active"])
        return Device(**data)
    
    def get_device_by_mac(self, mac_address: str) -> Device | None:
        """Retrieve a device by MAC address."""
        # Normalize MAC
        clean = mac_address.replace(":", "").replace("-", "").replace(".", "").lower()
        normalized = ":".join(clean[i:i+2] for i in range(0, 12, 2))
        
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE mac_address = ?",
                (normalized,),
            ).fetchone()
        
        if not row:
            return None
        
        data = dict(row)
        data["custom_matchers"] = json.loads(data["custom_matchers"])
        data["is_active"] = bool(data["is_active"])
        return Device(**data)
    
    def upsert_device(self, device: Device) -> Device:
        """Insert or update a device."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO devices 
                (id, mac_address, ip_address, hostname, kind, vendor, shield_profile,
                 custom_matchers, friendly_name, first_seen, last_seen, total_flows,
                 blocked_flows, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(mac_address) DO UPDATE SET
                    ip_address = excluded.ip_address,
                    hostname = COALESCE(excluded.hostname, hostname),
                    last_seen = excluded.last_seen,
                    total_flows = total_flows + 1,
                    is_active = 1
                """,
                (
                    device.id,
                    device.mac_address,
                    device.ip_address,
                    device.hostname,
                    device.kind.value,
                    device.vendor,
                    device.shield_profile.value,
                    json.dumps(device.custom_matchers),
                    device.friendly_name,
                    device.first_seen.isoformat(),
                    device.last_seen.isoformat(),
                    device.total_flows,
                    device.blocked_flows,
                    int(device.is_active),
                ),
            )
            conn.commit()
        
        return self.get_device_by_mac(device.mac_address) or device
    
    def update_device(self, device_id: str, update: DeviceUpdate) -> Device | None:
        """Update device settings."""
        existing = self.get_device(device_id)
        if not existing:
            return None
        
        updates = update.model_dump(exclude_unset=True)
        if not updates:
            return existing
        
        # Whitelist allowed columns to prevent SQL injection
        ALLOWED_COLUMNS = {
            "name", "kind", "shield_profile", "custom_matchers",
            "blocked", "is_active"
        }
        
        set_clauses = []
        params = []
        
        for key, value in updates.items():
            if key not in ALLOWED_COLUMNS:
                continue  # Skip unknown columns
            if key == "custom_matchers":
                value = json.dumps(value)
            elif key in ("kind", "shield_profile"):
                value = value.value if hasattr(value, "value") else value
            
            set_clauses.append(f"{key} = ?")
            params.append(value)
        
        params.append(device_id)
        
        with self._connect() as conn:
            conn.execute(
                f"UPDATE devices SET {', '.join(set_clauses)} WHERE id = ?",
                params,
            )
            conn.commit()
        
        return self.get_device(device_id)
    
    def increment_device_blocked(self, device_id: str) -> None:
        """Increment blocked flow count for a device."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE devices SET blocked_flows = blocked_flows + 1 WHERE id = ?",
                (device_id,),
            )
            conn.commit()
    
    # -------------------------------------------------------------------------
    # Shield Profiles CRUD
    # -------------------------------------------------------------------------
    
    def get_shield_profiles(self) -> list[ShieldProfile]:
        """Retrieve all shield profiles."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM shield_profiles ORDER BY name"
            ).fetchall()
        
        profiles = []
        for row in rows:
            data = dict(row)
            data["custom_matchers"] = json.loads(data["custom_matchers"])
            # Convert integer booleans
            for key in data:
                if key.startswith("block_") or key.startswith("enforce_"):
                    data[key] = bool(data[key])
            profiles.append(ShieldProfile(**data))
        
        return profiles
    
    def get_shield_profile(self, profile_id: str) -> ShieldProfile | None:
        """Retrieve a shield profile by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM shield_profiles WHERE id = ?",
                (profile_id,),
            ).fetchone()
        
        if not row:
            return None
        
        data = dict(row)
        data["custom_matchers"] = json.loads(data["custom_matchers"])
        for key in data:
            if key.startswith("block_") or key.startswith("enforce_"):
                data[key] = bool(data[key])
        
        return ShieldProfile(**data)
    
    def save_shield_profile(self, profile: ShieldProfile) -> ShieldProfile:
        """Save or update a shield profile."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO shield_profiles
                (id, name, preset, description, block_advertising, block_tracking,
                 block_malware, block_phishing, block_adult, block_social,
                 block_gaming, block_streaming, enforce_safesearch,
                 enforce_youtube_restricted, custom_matchers, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.id,
                    profile.name,
                    profile.preset.value,
                    profile.description,
                    int(profile.block_advertising),
                    int(profile.block_tracking),
                    int(profile.block_malware),
                    int(profile.block_phishing),
                    int(profile.block_adult),
                    int(profile.block_social),
                    int(profile.block_gaming),
                    int(profile.block_streaming),
                    int(profile.enforce_safesearch),
                    int(profile.enforce_youtube_restricted),
                    json.dumps(profile.custom_matchers),
                    profile.created_at.isoformat(),
                    profile.updated_at.isoformat(),
                ),
            )
            conn.commit()
        
        return profile
    
    def delete_shield_profile(self, profile_id: str) -> bool:
        """Delete a shield profile."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM shield_profiles WHERE id = ?",
                (profile_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
    
    # -------------------------------------------------------------------------
    # Schedules CRUD
    # -------------------------------------------------------------------------
    
    def get_schedules(self, enabled_only: bool = False) -> list[Schedule]:
        """Retrieve all schedules."""
        query = "SELECT * FROM schedules"
        if enabled_only:
            query += " WHERE enabled = 1"
        
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        
        schedules = []
        for row in rows:
            data = dict(row)
            data["device_ids"] = json.loads(data["device_ids"])
            data["days"] = json.loads(data["days"])
            data["enabled"] = bool(data["enabled"])
            schedules.append(Schedule(**data))
        
        return schedules
    
    def save_schedule(self, schedule: Schedule) -> Schedule:
        """Save or update a schedule."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO schedules
                (id, name, device_ids, days, start_time, end_time, action,
                 override_profile, enabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    schedule.id,
                    schedule.name,
                    json.dumps(schedule.device_ids),
                    json.dumps(schedule.days),
                    schedule.start_time,
                    schedule.end_time,
                    schedule.action.value,
                    schedule.override_profile.value if schedule.override_profile else None,
                    int(schedule.enabled),
                    schedule.created_at.isoformat(),
                ),
            )
            conn.commit()
        
        return schedule
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM schedules WHERE id = ?",
                (schedule_id,),
            )
            conn.commit()
            return cursor.rowcount > 0
    
    # -------------------------------------------------------------------------
    # Flow Records (Chronicle)
    # -------------------------------------------------------------------------
    
    def record_flow(self, flow: FlowRecord) -> None:
        """Record a flow entry."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO flow_records
                (id, flow_id, domain, query_type, device_id, device_ip_hash,
                 action, confidence, primary_evidence, response_ip, response_code,
                 upstream_used, cached, processing_time_ms, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    flow.id,
                    flow.flow_id,
                    flow.domain,
                    flow.query_type,
                    flow.device_id,
                    flow.device_ip_hash,
                    flow.action.value,
                    flow.confidence,
                    flow.primary_evidence,
                    flow.response_ip,
                    flow.response_code,
                    flow.upstream_used,
                    int(flow.cached),
                    flow.processing_time_ms,
                    flow.timestamp.isoformat(),
                ),
            )
            conn.commit()
    
    def get_recent_flows(
        self,
        limit: int = 100,
        offset: int = 0,
        device_id: str | None = None,
        action: str | None = None,
        domain_contains: str | None = None,
    ) -> list[FlowRecord]:
        """Retrieve recent flow records."""
        query = "SELECT * FROM flow_records WHERE 1=1"
        params: list = []
        
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        if domain_contains:
            query += " AND domain LIKE ?"
            params.append(f"%{domain_contains}%")
        
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        
        flows = []
        for row in rows:
            data = dict(row)
            data["cached"] = bool(data["cached"])
            flows.append(FlowRecord(**data))
        
        return flows
    
    def get_flow_by_id(self, flow_id: str) -> FlowRecord | None:
        """Retrieve a flow record by flow_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM flow_records WHERE flow_id = ?",
                (flow_id,),
            ).fetchone()
        
        if not row:
            return None
        
        data = dict(row)
        data["cached"] = bool(data["cached"])
        return FlowRecord(**data)
    
    def cleanup_old_flows(self, retention_days: int | None = None) -> int:
        """Delete flow records older than retention period."""
        if retention_days is None:
            retention_days = get_settings().chronicle.retention_days
        
        cutoff = utc_now() - timedelta(days=retention_days)
        
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM flow_records WHERE timestamp < ?",
                (cutoff.isoformat(),),
            )
            conn.commit()
            return cursor.rowcount
    
    def get_flow_stats(
        self,
        hours: int = 24,
    ) -> dict:
        """Get aggregated flow statistics."""
        cutoff = utc_now() - timedelta(hours=hours)
        
        with self._connect() as conn:
            # Total counts
            row = conn.execute(
                """
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN action = 'allow' THEN 1 ELSE 0 END) as allowed,
                    SUM(CASE WHEN action = 'deny' THEN 1 ELSE 0 END) as denied,
                    SUM(CASE WHEN action = 'redirect' THEN 1 ELSE 0 END) as redirected,
                    SUM(CASE WHEN cached = 1 THEN 1 ELSE 0 END) as cached,
                    AVG(processing_time_ms) as avg_time,
                    COUNT(DISTINCT domain) as unique_domains,
                    COUNT(DISTINCT device_id) as unique_devices
                FROM flow_records
                WHERE timestamp > ?
                """,
                (cutoff.isoformat(),),
            ).fetchone()
            
            # Top blocked domains
            top_blocked = conn.execute(
                """
                SELECT domain, COUNT(*) as count
                FROM flow_records
                WHERE timestamp > ? AND action = 'deny'
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff.isoformat(),),
            ).fetchall()
            
            # Top allowed domains
            top_allowed = conn.execute(
                """
                SELECT domain, COUNT(*) as count
                FROM flow_records
                WHERE timestamp > ? AND action = 'allow'
                GROUP BY domain
                ORDER BY count DESC
                LIMIT 10
                """,
                (cutoff.isoformat(),),
            ).fetchall()
        
        return {
            "total_flows": row["total"] or 0,
            "allowed_flows": row["allowed"] or 0,
            "denied_flows": row["denied"] or 0,
            "redirected_flows": row["redirected"] or 0,
            "cached_responses": row["cached"] or 0,
            "avg_response_time_ms": round(row["avg_time"] or 0, 2),
            "unique_domains": row["unique_domains"] or 0,
            "unique_devices": row["unique_devices"] or 0,
            "top_blocked_domains": [(r["domain"], r["count"]) for r in top_blocked],
            "top_allowed_domains": [(r["domain"], r["count"]) for r in top_allowed],
        }


# Singleton instance
_repository: VaultRepository | None = None


def get_repository() -> VaultRepository:
    """Get cached repository instance."""
    global _repository
    if _repository is None:
        _repository = VaultRepository()
    return _repository
