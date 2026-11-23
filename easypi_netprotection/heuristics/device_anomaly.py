"""
Device Anomaly Detector - Traffic spike detection.

Detects unusual DNS query patterns per device/IP:
- Sudden traffic spikes
- New domain floods
- Unusual query patterns

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from ..config import get_settings

logger = logging.getLogger(__name__)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_fromtimestamp(timestamp: float) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


@dataclass
class DeviceStats:
    """Statistics for a single device."""
    device_id: str  # IP or MAC hash
    queries_1min: int = 0
    queries_5min: int = 0
    queries_1hour: int = 0
    unique_domains_1hour: int = 0
    avg_queries_per_hour: float = 0.0
    last_seen: datetime = field(default_factory=utc_now)
    
    @property
    def is_spike_1min(self) -> bool:
        """Check if 1-minute rate is anomalous."""
        # More than 100 queries/min is suspicious
        return self.queries_1min > 100
    
    @property
    def is_spike_5min(self) -> bool:
        """Check if 5-minute rate is anomalous."""
        # More than 300 queries/5min is suspicious
        return self.queries_5min > 300
    
    @property
    def is_domain_flood(self) -> bool:
        """Check for excessive unique domains."""
        # More than 500 unique domains/hour is suspicious
        return self.unique_domains_1hour > 500


@dataclass
class AnomalyResult:
    """Result of device anomaly detection."""
    device_id: str
    is_anomalous: bool
    anomaly_type: str  # "spike", "flood", "pattern", "normal"
    score: float  # 0.0 - 1.0
    confidence: float
    stats: DeviceStats
    reasons: List[str]
    
    @property
    def risk_weight(self) -> int:
        """Risk weight for signal aggregator."""
        if not self.is_anomalous:
            return 0
        
        # Scale from 0 to 10
        return int(10 * self.score * self.confidence)


class DeviceAnomalyDetector:
    """
    Detects anomalous DNS query patterns per device.
    
    Uses time-bucketed counters for efficient tracking.
    """
    
    # Thresholds
    SPIKE_1MIN_THRESHOLD = 100
    SPIKE_5MIN_THRESHOLD = 300
    SPIKE_1HOUR_THRESHOLD = 2000
    DOMAIN_FLOOD_THRESHOLD = 500
    
    # Standard deviation multiplier for dynamic threshold
    STDDEV_MULTIPLIER = 3.0
    
    def __init__(
        self,
        db_path: Path | str,
        bucket_duration_sec: int = 60,
        history_hours: int = 24,
    ):
        """
        Initialize device anomaly detector.
        
        Args:
            db_path: Path to SQLite database
            bucket_duration_sec: Duration of time buckets
            history_hours: Hours of history to maintain
        """
        self.db_path = Path(db_path)
        self.bucket_duration = bucket_duration_sec
        self.history_hours = history_hours
        
        # In-memory counters for current buckets
        self._current_bucket = 0
        self._query_counts: Dict[str, int] = defaultdict(int)
        self._unique_domains: Dict[str, set] = defaultdict(set)
        
        self._local = threading.local()
        self._lock = threading.Lock()
        
        self._init_db()
        logger.info(f"DeviceAnomalyDetector initialized at {self.db_path}")
    
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
            -- Time-bucketed query counts per device
            CREATE TABLE IF NOT EXISTS device_buckets (
                device_id TEXT NOT NULL,
                bucket_time INTEGER NOT NULL,
                query_count INTEGER DEFAULT 0,
                unique_domains INTEGER DEFAULT 0,
                PRIMARY KEY (device_id, bucket_time)
            );
            
            CREATE INDEX IF NOT EXISTS idx_buckets_device 
                ON device_buckets(device_id);
            CREATE INDEX IF NOT EXISTS idx_buckets_time 
                ON device_buckets(bucket_time);
            
            -- Device baseline statistics
            CREATE TABLE IF NOT EXISTS device_baselines (
                device_id TEXT PRIMARY KEY,
                avg_queries_per_hour REAL DEFAULT 0,
                stddev_queries_per_hour REAL DEFAULT 0,
                avg_unique_domains_per_hour REAL DEFAULT 0,
                sample_count INTEGER DEFAULT 0,
                last_updated REAL
            );
            
            -- Detected anomalies log
            CREATE TABLE IF NOT EXISTS anomaly_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                anomaly_type TEXT NOT NULL,
                score REAL NOT NULL,
                details TEXT,
                timestamp REAL NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_anomaly_device 
                ON anomaly_log(device_id);
            CREATE INDEX IF NOT EXISTS idx_anomaly_time 
                ON anomaly_log(timestamp);
        """)
        conn.commit()
    
    def _get_bucket_time(self, timestamp: float | None = None) -> int:
        """Get bucket time for timestamp."""
        if timestamp is None:
            timestamp = time.time()
        return int(timestamp // self.bucket_duration) * self.bucket_duration
    
    def record_query(
        self,
        device_id: str,
        domain: str,
        timestamp: float | None = None,
    ) -> None:
        """
        Record DNS query from device.
        
        Args:
            device_id: Device identifier (IP hash, MAC, etc.)
            domain: Queried domain
            timestamp: Query timestamp (default: now)
        """
        if timestamp is None:
            timestamp = time.time()
        
        bucket_time = self._get_bucket_time(timestamp)
        
        with self._lock:
            # Update in-memory counters
            key = f"{device_id}:{bucket_time}"
            self._query_counts[key] += 1
            
            domain_key = f"{device_id}:{bucket_time}"
            if domain_key not in self._unique_domains:
                self._unique_domains[domain_key] = set()
            self._unique_domains[domain_key].add(domain.lower())
            
            # Flush to DB if bucket changed
            if bucket_time != self._current_bucket:
                self._flush_buckets()
                self._current_bucket = bucket_time
    
    def _flush_buckets(self) -> None:
        """Flush in-memory counters to database."""
        if not self._query_counts:
            return
        
        conn = self._get_conn()
        
        # Aggregate by device and bucket
        aggregated: Dict[Tuple[str, int], Tuple[int, int]] = {}
        
        for key, count in self._query_counts.items():
            device_id, bucket_str = key.rsplit(':', 1)
            bucket_time = int(bucket_str)
            
            unique_count = len(self._unique_domains.get(key, set()))
            
            agg_key = (device_id, bucket_time)
            if agg_key in aggregated:
                old_count, old_unique = aggregated[agg_key]
                aggregated[agg_key] = (old_count + count, old_unique + unique_count)
            else:
                aggregated[agg_key] = (count, unique_count)
        
        # Insert/update database
        for (device_id, bucket_time), (count, unique) in aggregated.items():
            conn.execute("""
                INSERT INTO device_buckets (device_id, bucket_time, query_count, unique_domains)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(device_id, bucket_time) DO UPDATE SET
                    query_count = query_count + excluded.query_count,
                    unique_domains = unique_domains + excluded.unique_domains
            """, (device_id, bucket_time, count, unique))
        
        conn.commit()
        
        # Clear in-memory counters
        self._query_counts.clear()
        self._unique_domains.clear()
    
    def get_device_stats(
        self,
        device_id: str,
        window_minutes: int = 60,
    ) -> DeviceStats:
        """
        Get statistics for device over time window.
        
        Args:
            device_id: Device identifier
            window_minutes: Time window in minutes
        """
        # Flush current data first
        with self._lock:
            self._flush_buckets()
        
        now = time.time()
        conn = self._get_conn()
        
        # Get counts for different windows
        windows = {
            '1min': now - 60,
            '5min': now - 300,
            '1hour': now - 3600,
        }
        
        results = {}
        for name, cutoff in windows.items():
            cursor = conn.execute("""
                SELECT SUM(query_count) as total, SUM(unique_domains) as unique
                FROM device_buckets
                WHERE device_id = ? AND bucket_time >= ?
            """, (device_id, cutoff))
            row = cursor.fetchone()
            results[name] = (row['total'] or 0, row['unique'] or 0)
        
        # Get baseline
        cursor = conn.execute(
            "SELECT * FROM device_baselines WHERE device_id = ?",
            (device_id,)
        )
        baseline = cursor.fetchone()
        avg_per_hour = baseline['avg_queries_per_hour'] if baseline else 0
        
        return DeviceStats(
            device_id=device_id,
            queries_1min=results['1min'][0],
            queries_5min=results['5min'][0],
            queries_1hour=results['1hour'][0],
            unique_domains_1hour=results['1hour'][1],
            avg_queries_per_hour=avg_per_hour,
            last_seen=utc_now(),
        )
    
    def analyze(
        self,
        device_id: str,
        domain: str | None = None,
    ) -> AnomalyResult:
        """
        Analyze device for anomalies.
        
        Args:
            device_id: Device identifier
            domain: Optional domain being queried (for context)
        
        Returns:
            AnomalyResult with detection details
        """
        stats = self.get_device_stats(device_id)
        
        reasons = []
        score = 0.0
        anomaly_type = "normal"
        
        # Check 1-minute spike
        if stats.queries_1min > self.SPIKE_1MIN_THRESHOLD:
            spike_ratio = stats.queries_1min / self.SPIKE_1MIN_THRESHOLD
            score += min(0.4 * spike_ratio, 0.6)
            reasons.append(f"1-min spike: {stats.queries_1min} queries")
            anomaly_type = "spike"
        
        # Check 5-minute spike
        if stats.queries_5min > self.SPIKE_5MIN_THRESHOLD:
            spike_ratio = stats.queries_5min / self.SPIKE_5MIN_THRESHOLD
            score += min(0.3 * spike_ratio, 0.4)
            reasons.append(f"5-min spike: {stats.queries_5min} queries")
            if anomaly_type == "normal":
                anomaly_type = "spike"
        
        # Check domain flood
        if stats.unique_domains_1hour > self.DOMAIN_FLOOD_THRESHOLD:
            flood_ratio = stats.unique_domains_1hour / self.DOMAIN_FLOOD_THRESHOLD
            score += min(0.4 * flood_ratio, 0.5)
            reasons.append(f"Domain flood: {stats.unique_domains_1hour} unique domains")
            anomaly_type = "flood"
        
        # Check against baseline (if available)
        if stats.avg_queries_per_hour > 0:
            baseline = self._get_baseline(device_id)
            if baseline and baseline['stddev'] > 0:
                # Z-score calculation
                zscore = (stats.queries_1hour - baseline['avg']) / baseline['stddev']
                if zscore > self.STDDEV_MULTIPLIER:
                    score += min(0.3 * (zscore / self.STDDEV_MULTIPLIER), 0.4)
                    reasons.append(f"Baseline deviation: {zscore:.1f} σ")
                    if anomaly_type == "normal":
                        anomaly_type = "pattern"
        
        # Normalize score
        score = min(score, 1.0)
        
        is_anomalous = score >= 0.3
        confidence = 0.7 if stats.queries_1hour > 100 else 0.5
        
        # Log significant anomalies
        if is_anomalous and score >= 0.5:
            self._log_anomaly(device_id, anomaly_type, score, reasons)
        
        return AnomalyResult(
            device_id=device_id,
            is_anomalous=is_anomalous,
            anomaly_type=anomaly_type,
            score=score,
            confidence=confidence,
            stats=stats,
            reasons=reasons if reasons else ["Normal traffic pattern"],
        )
    
    def _get_baseline(self, device_id: str) -> Optional[dict]:
        """Get baseline statistics for device."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM device_baselines WHERE device_id = ?",
            (device_id,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return {
            'avg': row['avg_queries_per_hour'],
            'stddev': row['stddev_queries_per_hour'],
            'samples': row['sample_count'],
        }
    
    def _log_anomaly(
        self,
        device_id: str,
        anomaly_type: str,
        score: float,
        reasons: List[str],
    ) -> None:
        """Log detected anomaly."""
        conn = self._get_conn()
        conn.execute("""
            INSERT INTO anomaly_log (device_id, anomaly_type, score, details, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (device_id, anomaly_type, score, "; ".join(reasons), time.time()))
        conn.commit()
    
    def update_baselines(self) -> int:
        """
        Update device baselines from historical data.
        
        Should be called periodically (e.g., hourly).
        Returns number of devices updated.
        """
        # Flush current data
        with self._lock:
            self._flush_buckets()
        
        conn = self._get_conn()
        now = time.time()
        
        # Calculate baselines from last 24 hours
        cutoff = now - (24 * 3600)
        
        cursor = conn.execute("""
            SELECT 
                device_id,
                AVG(query_count * 60.0 / ?) as avg_per_hour,
                -- SQLite doesn't have STDDEV, calculate manually
                COUNT(*) as sample_count
            FROM device_buckets
            WHERE bucket_time >= ?
            GROUP BY device_id
            HAVING COUNT(*) >= 10
        """, (self.bucket_duration, cutoff))
        
        updated = 0
        for row in cursor:
            device_id = row['device_id']
            avg = row['avg_per_hour'] or 0
            samples = row['sample_count']
            
            # Calculate stddev with separate query
            stddev_cursor = conn.execute("""
                SELECT AVG((query_count * 60.0 / ? - ?) * (query_count * 60.0 / ? - ?)) as variance
                FROM device_buckets
                WHERE device_id = ? AND bucket_time >= ?
            """, (self.bucket_duration, avg, self.bucket_duration, avg, device_id, cutoff))
            stddev_row = stddev_cursor.fetchone()
            variance = stddev_row['variance'] or 0
            stddev = variance ** 0.5
            
            conn.execute("""
                INSERT INTO device_baselines 
                (device_id, avg_queries_per_hour, stddev_queries_per_hour, sample_count, last_updated)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    avg_queries_per_hour = excluded.avg_queries_per_hour,
                    stddev_queries_per_hour = excluded.stddev_queries_per_hour,
                    sample_count = excluded.sample_count,
                    last_updated = excluded.last_updated
            """, (device_id, avg, stddev, samples, now))
            updated += 1
        
        conn.commit()
        
        if updated > 0:
            logger.info(f"Updated baselines for {updated} devices")
        
        return updated
    
    def cleanup(self, max_age_hours: int | None = None) -> int:
        """
        Remove old bucket data.
        
        Returns number of removed entries.
        """
        if max_age_hours is None:
            max_age_hours = self.history_hours
        
        cutoff = time.time() - (max_age_hours * 3600)
        
        conn = self._get_conn()
        
        cursor = conn.execute(
            "DELETE FROM device_buckets WHERE bucket_time < ?",
            (cutoff,)
        )
        deleted_buckets = cursor.rowcount
        
        # Also cleanup old anomaly logs (keep 7 days)
        anomaly_cutoff = time.time() - (7 * 24 * 3600)
        cursor = conn.execute(
            "DELETE FROM anomaly_log WHERE timestamp < ?",
            (anomaly_cutoff,)
        )
        deleted_logs = cursor.rowcount
        
        conn.commit()
        
        if deleted_buckets > 0 or deleted_logs > 0:
            logger.info(f"DeviceAnomaly cleanup: {deleted_buckets} buckets, {deleted_logs} logs")
        
        return deleted_buckets + deleted_logs
    
    def get_stats(self) -> dict:
        """Get detector statistics."""
        conn = self._get_conn()
        
        stats = {}
        
        # Active devices (last hour)
        hour_ago = time.time() - 3600
        cursor = conn.execute("""
            SELECT COUNT(DISTINCT device_id) FROM device_buckets
            WHERE bucket_time >= ?
        """, (hour_ago,))
        stats['active_devices_1h'] = cursor.fetchone()[0]
        
        # Total buckets
        cursor = conn.execute("SELECT COUNT(*) FROM device_buckets")
        stats['total_buckets'] = cursor.fetchone()[0]
        
        # Baselines
        cursor = conn.execute("SELECT COUNT(*) FROM device_baselines")
        stats['devices_with_baseline'] = cursor.fetchone()[0]
        
        # Recent anomalies
        day_ago = time.time() - 86400
        cursor = conn.execute("""
            SELECT anomaly_type, COUNT(*) as count
            FROM anomaly_log
            WHERE timestamp >= ?
            GROUP BY anomaly_type
        """, (day_ago,))
        stats['anomalies_24h'] = {row['anomaly_type']: row['count'] for row in cursor}
        
        return stats
    
    def get_recent_anomalies(
        self,
        limit: int = 100,
        device_id: str | None = None,
    ) -> List[dict]:
        """Get recent anomaly events."""
        conn = self._get_conn()
        
        if device_id:
            cursor = conn.execute("""
                SELECT * FROM anomaly_log
                WHERE device_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """, (device_id, limit))
        else:
            cursor = conn.execute("""
                SELECT * FROM anomaly_log
                ORDER BY timestamp DESC
                LIMIT ?
            """, (limit,))
        
        results = []
        for row in cursor:
            results.append({
                'device_id': row['device_id'],
                'anomaly_type': row['anomaly_type'],
                'score': row['score'],
                'details': row['details'],
                'timestamp': utc_fromtimestamp(row['timestamp']),
            })
        
        return results
    
    def close(self) -> None:
        """Close database connection."""
        # Flush remaining data
        with self._lock:
            self._flush_buckets()
        
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
_instance: DeviceAnomalyDetector | None = None
_lock = threading.Lock()


def get_device_anomaly_detector(
    data_dir: str | Path | None = None,
) -> DeviceAnomalyDetector:
    """Get singleton DeviceAnomalyDetector instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                if data_dir is None:
                    data_dir = get_settings().NETPROTECTION_DATA_DIR
                else:
                    data_dir = Path(data_dir)
                
                db_path = data_dir / "device_anomaly.db"
                _instance = DeviceAnomalyDetector(db_path)
    
    return _instance
