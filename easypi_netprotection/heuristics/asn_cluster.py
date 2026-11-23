"""
ASN Cluster Analyzer - IP/ASN reputation tracking.

Tracks and analyzes IP addresses and their ASN (Autonomous System Number)
to identify clusters of malicious infrastructure.

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set
from ..config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class ASNInfo:
    """Information about an Autonomous System."""
    asn: int
    name: str
    country: str
    total_ips_seen: int
    blocked_ips: int
    suspicious_ips: int
    block_ratio: float
    first_seen: datetime
    last_seen: datetime
    
    @property
    def is_suspicious(self) -> bool:
        """Check if ASN has high block ratio."""
        # Suspicious if >30% of seen IPs were blocked
        return self.block_ratio > 0.3 and self.total_ips_seen >= 10
    
    @property
    def is_hostile(self) -> bool:
        """Check if ASN is predominantly malicious."""
        # Hostile if >70% blocked and significant sample
        return self.block_ratio > 0.7 and self.total_ips_seen >= 50


@dataclass
class IPReputation:
    """Reputation information for an IP address."""
    ip: str
    asn: Optional[int]
    asn_name: Optional[str]
    country: Optional[str]
    hit_count: int
    blocked_count: int
    suspicious_count: int
    domains_seen: int
    first_seen: datetime
    last_seen: datetime
    
    @property
    def block_ratio(self) -> float:
        """Ratio of blocked queries."""
        if self.hit_count == 0:
            return 0.0
        return self.blocked_count / self.hit_count
    
    @property
    def is_suspicious(self) -> bool:
        """Check if IP has suspicious activity."""
        return self.block_ratio > 0.5 and self.hit_count >= 5


@dataclass
class ASNClusterResult:
    """Result of ASN cluster analysis."""
    ip: str
    asn: Optional[int]
    is_suspicious: bool
    score: float  # 0.0 - 1.0
    confidence: float
    ip_reputation: Optional[IPReputation]
    asn_info: Optional[ASNInfo]
    reasons: List[str]
    
    @property
    def risk_weight(self) -> int:
        """Risk weight for signal aggregator."""
        if not self.is_suspicious:
            return 0
        
        # Scale from 0 to 15
        return int(15 * self.score * self.confidence)


class ASNClusterAnalyzer:
    """
    Analyzes IP addresses and ASN clusters for malicious patterns.
    
    Features:
    - Track IP reputation across DNS responses
    - Aggregate by ASN to find malicious networks
    - Identify hosting providers used by malware
    - Geographic analysis
    """
    
    # Known hosting providers often abused (higher scrutiny)
    ABUSED_ASNS: Dict[int, str] = {
        # Bulletproof hosting
        49505: "Selectel",
        44094: "WEBZILLA",
        202425: "IP Volume",
        # Free hosting abuse
        13335: "Cloudflare (free tier abuse)",
        # VPN/Proxy providers
        9009: "M247",
        # Known bad actors
        48666: "Marosnet",
        35913: "DediPath",
    }
    
    # ASNs to never block (major legitimate providers)
    SAFE_ASNS: Set[int] = {
        # Google
        15169, 396982,
        # Amazon
        16509, 14618,
        # Microsoft
        8075, 8068,
        # Apple
        714, 6185,
        # Akamai
        20940, 16625,
        # Fastly
        54113,
    }
    
    def __init__(
        self,
        db_path: Path | str,
        suspicious_threshold: float = 0.3,
        hostile_threshold: float = 0.7,
    ):
        """
        Initialize ASN cluster analyzer.
        
        Args:
            db_path: Path to SQLite database
            suspicious_threshold: Block ratio threshold for suspicious
            hostile_threshold: Block ratio threshold for hostile
        """
        self.db_path = Path(db_path)
        self.suspicious_threshold = suspicious_threshold
        self.hostile_threshold = hostile_threshold
        
        self._local = threading.local()
        self._lock = threading.Lock()
        
        self._init_db()
        logger.info(f"ASNClusterAnalyzer initialized at {self.db_path}")
    
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
            -- IP reputation tracking
            CREATE TABLE IF NOT EXISTS ip_reputation (
                ip TEXT PRIMARY KEY,
                asn INTEGER,
                asn_name TEXT,
                country TEXT,
                hit_count INTEGER DEFAULT 0,
                blocked_count INTEGER DEFAULT 0,
                suspicious_count INTEGER DEFAULT 0,
                domains_seen INTEGER DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            );
            
            CREATE INDEX IF NOT EXISTS idx_ip_asn ON ip_reputation(asn);
            CREATE INDEX IF NOT EXISTS idx_ip_blocked ON ip_reputation(blocked_count);
            
            -- ASN aggregate statistics
            CREATE TABLE IF NOT EXISTS asn_stats (
                asn INTEGER PRIMARY KEY,
                name TEXT,
                country TEXT,
                total_ips INTEGER DEFAULT 0,
                blocked_ips INTEGER DEFAULT 0,
                suspicious_ips INTEGER DEFAULT 0,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL
            );
            
            -- IP to domain mapping (for clustering)
            CREATE TABLE IF NOT EXISTS ip_domains (
                ip TEXT NOT NULL,
                domain TEXT NOT NULL,
                first_seen REAL NOT NULL,
                last_seen REAL NOT NULL,
                hit_count INTEGER DEFAULT 1,
                was_blocked INTEGER DEFAULT 0,
                PRIMARY KEY (ip, domain)
            );
            
            CREATE INDEX IF NOT EXISTS idx_ip_domains_domain ON ip_domains(domain);
        """)
        conn.commit()
    
    def record_response(
        self,
        ip: str,
        domain: str,
        was_blocked: bool,
        was_suspicious: bool = False,
        asn: int | None = None,
        asn_name: str | None = None,
        country: str | None = None,
    ) -> None:
        """
        Record DNS response for reputation tracking.
        
        Args:
            ip: IP address from DNS response
            domain: Domain that was queried
            was_blocked: Whether the response was blocked
            was_suspicious: Whether marked suspicious (not blocked)
            asn: ASN number (if known)
            asn_name: ASN name (if known)
            country: Country code (if known)
        """
        now = time.time()
        
        conn = self._get_conn()
        
        # Update IP reputation
        cursor = conn.execute(
            "SELECT * FROM ip_reputation WHERE ip = ?",
            (ip,)
        )
        existing = cursor.fetchone()
        
        if existing:
            conn.execute("""
                UPDATE ip_reputation SET
                    hit_count = hit_count + 1,
                    blocked_count = blocked_count + ?,
                    suspicious_count = suspicious_count + ?,
                    last_seen = ?,
                    asn = COALESCE(?, asn),
                    asn_name = COALESCE(?, asn_name),
                    country = COALESCE(?, country)
                WHERE ip = ?
            """, (
                1 if was_blocked else 0,
                1 if was_suspicious else 0,
                now,
                asn,
                asn_name,
                country,
                ip,
            ))
        else:
            conn.execute("""
                INSERT INTO ip_reputation 
                (ip, asn, asn_name, country, hit_count, blocked_count, 
                 suspicious_count, domains_seen, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, ?, ?, 1, ?, ?)
            """, (
                ip, asn, asn_name, country,
                1 if was_blocked else 0,
                1 if was_suspicious else 0,
                now, now,
            ))
        
        # Update IP-domain mapping
        conn.execute("""
            INSERT INTO ip_domains (ip, domain, first_seen, last_seen, hit_count, was_blocked)
            VALUES (?, ?, ?, ?, 1, ?)
            ON CONFLICT(ip, domain) DO UPDATE SET
                last_seen = excluded.last_seen,
                hit_count = hit_count + 1,
                was_blocked = was_blocked OR excluded.was_blocked
        """, (ip, domain.lower(), now, now, 1 if was_blocked else 0))
        
        # Update domain count for IP
        cursor = conn.execute(
            "SELECT COUNT(DISTINCT domain) FROM ip_domains WHERE ip = ?",
            (ip,)
        )
        domain_count = cursor.fetchone()[0]
        conn.execute(
            "UPDATE ip_reputation SET domains_seen = ? WHERE ip = ?",
            (domain_count, ip)
        )
        
        # Update ASN stats if we have ASN info
        if asn is not None:
            self._update_asn_stats(asn, asn_name, country, was_blocked, was_suspicious)
        
        conn.commit()
    
    def _update_asn_stats(
        self,
        asn: int,
        name: str | None,
        country: str | None,
        was_blocked: bool,
        was_suspicious: bool,
    ) -> None:
        """Update ASN aggregate statistics."""
        now = time.time()
        conn = self._get_conn()
        
        cursor = conn.execute(
            "SELECT * FROM asn_stats WHERE asn = ?",
            (asn,)
        )
        existing = cursor.fetchone()
        
        if existing:
            conn.execute("""
                UPDATE asn_stats SET
                    total_ips = (
                        SELECT COUNT(DISTINCT ip) FROM ip_reputation WHERE asn = ?
                    ),
                    blocked_ips = (
                        SELECT COUNT(DISTINCT ip) FROM ip_reputation 
                        WHERE asn = ? AND blocked_count > 0
                    ),
                    suspicious_ips = (
                        SELECT COUNT(DISTINCT ip) FROM ip_reputation 
                        WHERE asn = ? AND suspicious_count > 0
                    ),
                    last_seen = ?,
                    name = COALESCE(?, name),
                    country = COALESCE(?, country)
                WHERE asn = ?
            """, (asn, asn, asn, now, name, country, asn))
        else:
            conn.execute("""
                INSERT INTO asn_stats 
                (asn, name, country, total_ips, blocked_ips, suspicious_ips, first_seen, last_seen)
                VALUES (?, ?, ?, 1, ?, ?, ?, ?)
            """, (
                asn, name, country,
                1 if was_blocked else 0,
                1 if was_suspicious else 0,
                now, now,
            ))
    
    def get_ip_reputation(self, ip: str) -> Optional[IPReputation]:
        """Get reputation for IP address."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM ip_reputation WHERE ip = ?",
            (ip,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        return IPReputation(
            ip=row['ip'],
            asn=row['asn'],
            asn_name=row['asn_name'],
            country=row['country'],
            hit_count=row['hit_count'],
            blocked_count=row['blocked_count'],
            suspicious_count=row['suspicious_count'],
            domains_seen=row['domains_seen'],
            first_seen=datetime.utcfromtimestamp(row['first_seen']),
            last_seen=datetime.utcfromtimestamp(row['last_seen']),
        )
    
    def get_asn_info(self, asn: int) -> Optional[ASNInfo]:
        """Get information for ASN."""
        conn = self._get_conn()
        cursor = conn.execute(
            "SELECT * FROM asn_stats WHERE asn = ?",
            (asn,)
        )
        row = cursor.fetchone()
        
        if not row:
            return None
        
        total = row['total_ips'] or 1  # Avoid division by zero
        block_ratio = (row['blocked_ips'] or 0) / total
        
        return ASNInfo(
            asn=row['asn'],
            name=row['name'] or f"AS{row['asn']}",
            country=row['country'] or "Unknown",
            total_ips_seen=row['total_ips'],
            blocked_ips=row['blocked_ips'],
            suspicious_ips=row['suspicious_ips'],
            block_ratio=block_ratio,
            first_seen=datetime.utcfromtimestamp(row['first_seen']),
            last_seen=datetime.utcfromtimestamp(row['last_seen']),
        )
    
    def analyze(
        self,
        ip: str,
        asn: int | None = None,
    ) -> ASNClusterResult:
        """
        Analyze IP/ASN for suspicious patterns.
        
        Args:
            ip: IP address to analyze
            asn: Optional ASN (if not stored, will look up)
        
        Returns:
            ASNClusterResult with analysis details
        """
        reasons = []
        score = 0.0
        
        # Get IP reputation
        ip_rep = self.get_ip_reputation(ip)
        
        # Get ASN info
        asn_to_use = asn
        if asn_to_use is None and ip_rep:
            asn_to_use = ip_rep.asn
        
        asn_info = None
        if asn_to_use:
            asn_info = self.get_asn_info(asn_to_use)
        
        # Analyze IP reputation
        if ip_rep:
            if ip_rep.block_ratio > self.hostile_threshold:
                score += 0.5
                reasons.append(f"IP hostile: {ip_rep.block_ratio:.0%} blocked")
            elif ip_rep.block_ratio > self.suspicious_threshold:
                score += 0.3
                reasons.append(f"IP suspicious: {ip_rep.block_ratio:.0%} blocked")
            
            # Many domains on one IP
            if ip_rep.domains_seen > 100:
                score += 0.1
                reasons.append(f"High domain count: {ip_rep.domains_seen}")
        
        # Analyze ASN reputation
        if asn_info:
            # Check known bad ASNs
            if asn_info.asn in self.ABUSED_ASNS:
                score += 0.2
                reasons.append(f"Known abused ASN: {self.ABUSED_ASNS[asn_info.asn]}")
            
            # Check safe ASNs (reduce score)
            if asn_info.asn in self.SAFE_ASNS:
                score = max(0, score - 0.3)
                reasons.append(f"Trusted ASN: {asn_info.name}")
            
            # Check ASN block ratio
            if asn_info.is_hostile:
                score += 0.4
                reasons.append(f"Hostile ASN: {asn_info.block_ratio:.0%} blocked")
            elif asn_info.is_suspicious:
                score += 0.2
                reasons.append(f"Suspicious ASN: {asn_info.block_ratio:.0%} blocked")
        
        # Normalize score
        score = max(0, min(score, 1.0))
        
        is_suspicious = score >= 0.3
        
        # Confidence based on data quality
        confidence = 0.5
        if ip_rep and ip_rep.hit_count >= 10:
            confidence = 0.7
        if asn_info and asn_info.total_ips_seen >= 50:
            confidence = 0.8
        
        return ASNClusterResult(
            ip=ip,
            asn=asn_to_use,
            is_suspicious=is_suspicious,
            score=score,
            confidence=confidence,
            ip_reputation=ip_rep,
            asn_info=asn_info,
            reasons=reasons if reasons else ["No reputation data"],
        )
    
    def get_hostile_asns(self, limit: int = 50) -> List[ASNInfo]:
        """Get ASNs with highest block ratios."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT *, 
                   CAST(blocked_ips AS REAL) / NULLIF(total_ips, 0) as block_ratio
            FROM asn_stats
            WHERE total_ips >= 10
            ORDER BY block_ratio DESC
            LIMIT ?
        """, (limit,))
        
        results = []
        for row in cursor:
            total = row['total_ips'] or 1
            block_ratio = (row['blocked_ips'] or 0) / total
            
            results.append(ASNInfo(
                asn=row['asn'],
                name=row['name'] or f"AS{row['asn']}",
                country=row['country'] or "Unknown",
                total_ips_seen=row['total_ips'],
                blocked_ips=row['blocked_ips'],
                suspicious_ips=row['suspicious_ips'],
                block_ratio=block_ratio,
                first_seen=datetime.utcfromtimestamp(row['first_seen']),
                last_seen=datetime.utcfromtimestamp(row['last_seen']),
            ))
        
        return results
    
    def get_ip_cluster(self, ip: str) -> List[str]:
        """Get domains sharing the same IP."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT domain, hit_count, was_blocked
            FROM ip_domains
            WHERE ip = ?
            ORDER BY hit_count DESC
            LIMIT 100
        """, (ip,))
        
        return [row['domain'] for row in cursor]
    
    def get_domain_ips(self, domain: str) -> List[str]:
        """Get IPs that have served a domain."""
        conn = self._get_conn()
        cursor = conn.execute("""
            SELECT ip, hit_count
            FROM ip_domains
            WHERE domain = ?
            ORDER BY hit_count DESC
            LIMIT 100
        """, (domain.lower(),))
        
        return [row['ip'] for row in cursor]
    
    def cleanup(self, max_age_days: int = 90) -> int:
        """Remove old IP reputation data."""
        cutoff = time.time() - (max_age_days * 86400)
        
        conn = self._get_conn()
        
        # Clean up IP domains first
        cursor = conn.execute(
            "DELETE FROM ip_domains WHERE last_seen < ?",
            (cutoff,)
        )
        deleted_mappings = cursor.rowcount
        
        # Clean up IP reputation
        cursor = conn.execute(
            "DELETE FROM ip_reputation WHERE last_seen < ?",
            (cutoff,)
        )
        deleted_ips = cursor.rowcount
        
        conn.commit()
        
        if deleted_ips > 0 or deleted_mappings > 0:
            logger.info(
                f"ASN cleanup: {deleted_ips} IPs, {deleted_mappings} mappings"
            )
        
        return deleted_ips + deleted_mappings
    
    def get_stats(self) -> dict:
        """Get analyzer statistics."""
        conn = self._get_conn()
        
        stats = {}
        
        # Total IPs tracked
        cursor = conn.execute("SELECT COUNT(*) FROM ip_reputation")
        stats['total_ips'] = cursor.fetchone()[0]
        
        # Suspicious IPs
        cursor = conn.execute("""
            SELECT COUNT(*) FROM ip_reputation 
            WHERE blocked_count > hit_count * 0.3 AND hit_count >= 5
        """)
        stats['suspicious_ips'] = cursor.fetchone()[0]
        
        # Total ASNs
        cursor = conn.execute("SELECT COUNT(*) FROM asn_stats")
        stats['total_asns'] = cursor.fetchone()[0]
        
        # Suspicious ASNs
        cursor = conn.execute("""
            SELECT COUNT(*) FROM asn_stats 
            WHERE blocked_ips > total_ips * 0.3 AND total_ips >= 10
        """)
        stats['suspicious_asns'] = cursor.fetchone()[0]
        
        # Top countries by IP count
        cursor = conn.execute("""
            SELECT country, COUNT(*) as count
            FROM ip_reputation
            WHERE country IS NOT NULL
            GROUP BY country
            ORDER BY count DESC
            LIMIT 10
        """)
        stats['top_countries'] = {row['country']: row['count'] for row in cursor}
        
        return stats
    
    def close(self) -> None:
        """Close database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Singleton instance
_instance: ASNClusterAnalyzer | None = None
_lock = threading.Lock()


def get_asn_cluster_analyzer(
    data_dir: str | Path | None = None,
) -> ASNClusterAnalyzer:
    """Get singleton ASNClusterAnalyzer instance."""
    global _instance
    
    if _instance is None:
        with _lock:
            if _instance is None:
                if data_dir is None:
                    data_dir = get_settings().NETPROTECTION_DATA_DIR
                else:
                    data_dir = Path(data_dir)
                
                db_path = data_dir / "asn_cluster.db"
                _instance = ASNClusterAnalyzer(db_path)
    
    return _instance
