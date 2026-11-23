"""
EasyPi NetProtection — Flow Log Module.

Журнал DNS-потоков с анонимизацией и автоматической ротацией.
Хранение истории запросов с ограниченным сроком хранения.

Security features:
- Stable salt from env/file with rotation support
- Privacy controls for evidence/response data
- DoS protection with backpressure
- Database size limits and auto-maintenance
- Fail-open on errors (DNS continues)
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Callable
from collections import deque
from ..config import get_settings

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

DEFAULT_RETENTION_DAYS = 7
MAX_RETENTION_DAYS = 90  # Hard limit to prevent abuse
DEFAULT_BATCH_SIZE = 100
DEFAULT_FLUSH_INTERVAL = 5.0  # seconds
MAX_IN_MEMORY_ENTRIES = 10000
DEFAULT_BUFFER_BACKPRESSURE = 0.8
DEFAULT_DB_MAX_SIZE_MB = 500
DEFAULT_VACUUM_INTERVAL_HOURS = 24


# ════════════════════════════════════════════════════════════════════════════════
# SALT MANAGEMENT
# ════════════════════════════════════════════════════════════════════════════════

class SaltManager:
    """
    Manages salt for IP anonymization with rotation support.
    
    Features:
    - Loads salt from environment variable or file
    - Stable across restarts
    - Supports rotation with double-window for correlation
    """
    
    ENV_VAR = "NETPROTECTION_CHRONICLE__HASH_SALT"
    
    def __init__(
        self,
        salt_file: Path | str | None = None,
        rotation_days: int = 30,
        double_window: bool = True,
    ):
        if salt_file is None:
            salt_file = get_settings().NETPROTECTION_DATA_DIR / ".salt"
        self._salt_file = Path(salt_file)
        self._rotation_days = rotation_days
        self._double_window = double_window
        
        self._current_salt: str = ""
        self._previous_salt: str = ""
        self._salt_created: datetime | None = None
        
        self._load_or_create()
    
    def _load_or_create(self) -> None:
        """Load salt from env/file or create new one."""
        # Priority 1: Environment variable
        env_salt = os.environ.get(self.ENV_VAR, "").strip()
        if env_salt:
            self._current_salt = env_salt
            logger.info("Salt loaded from environment variable")
            return
        
        # Priority 2: Salt file
        if self._salt_file.exists():
            try:
                data = self._salt_file.read_text().strip()
                lines = data.split("\n")
                
                if len(lines) >= 1:
                    self._current_salt = lines[0].strip()
                if len(lines) >= 2:
                    self._previous_salt = lines[1].strip()
                if len(lines) >= 3:
                    try:
                        self._salt_created = datetime.fromisoformat(lines[2].strip())
                    except ValueError:
                        pass
                
                if self._current_salt:
                    logger.info("Salt loaded from file: %s", self._salt_file)
                    return
            except Exception as e:
                logger.warning("Failed to load salt from file: %s", e)
        
        # Priority 3: Generate new salt and save
        self._generate_new_salt()
    
    def _generate_new_salt(self) -> None:
        """Generate a new salt and persist it."""
        self._previous_salt = self._current_salt
        self._current_salt = secrets.token_hex(32)
        self._salt_created = datetime.now()
        self._save_to_file()
        logger.info("New salt generated and saved to: %s", self._salt_file)
    
    def _save_to_file(self) -> None:
        """Save salt to file with secure permissions."""
        try:
            self._salt_file.parent.mkdir(parents=True, exist_ok=True)
            
            data = f"{self._current_salt}\n{self._previous_salt}\n"
            if self._salt_created:
                data += self._salt_created.isoformat()
            
            self._salt_file.write_text(data)
            
            # Set restrictive permissions (Unix only)
            try:
                os.chmod(self._salt_file, 0o600)
            except (OSError, AttributeError):
                pass  # Windows doesn't support this
                
        except Exception as e:
            logger.error("Failed to save salt to file: %s", e)
    
    def rotate_if_needed(self) -> bool:
        """
        Check if salt needs rotation and rotate if so.
        
        Returns:
            True if salt was rotated
        """
        if not self._salt_created:
            return False
        
        age_days = (datetime.now() - self._salt_created).days
        
        if age_days >= self._rotation_days:
            logger.info("Rotating salt (age: %d days, threshold: %d)", age_days, self._rotation_days)
            self._generate_new_salt()
            return True
        
        return False
    
    @property
    def current(self) -> str:
        """Current salt for hashing."""
        return self._current_salt
    
    @property
    def previous(self) -> str:
        """Previous salt (for double-window correlation)."""
        return self._previous_salt if self._double_window else ""
    
    def hash_with_both(self, value: str) -> tuple[str, str]:
        """
        Hash value with both current and previous salts.
        
        Returns:
            (current_hash, previous_hash) - previous may be empty
        """
        current_hash = self._hash(value, self._current_salt)
        previous_hash = ""
        
        if self._double_window and self._previous_salt:
            previous_hash = self._hash(value, self._previous_salt)
        
        return current_hash, previous_hash
    
    def _hash(self, value: str, salt: str) -> str:
        """Hash value with salt."""
        if not value:
            return "unknown"
        data = f"{salt}:{value}".encode()
        return hashlib.sha256(data).hexdigest()[:12]


# The verdict engine's decisive reason is stored in the categories column as
# "reason:<VerdictReason value>", e.g. "reason:shadow_mode".
FLOW_REASON_PREFIX = "reason:"

# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class FlowStatus(str, Enum):
    """Статус обработки Flow."""
    
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    REDIRECTED = "redirected"
    CACHED = "cached"
    UPSTREAM = "upstream"
    FAILED = "failed"


class QueryType(str, Enum):
    """Тип DNS-запроса."""
    
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    TXT = "TXT"
    NS = "NS"
    SOA = "SOA"
    PTR = "PTR"
    SRV = "SRV"
    HTTPS = "HTTPS"
    SVCB = "SVCB"
    ANY = "ANY"
    OTHER = "OTHER"


# ════════════════════════════════════════════════════════════════════════════════
# ANONYMIZATION
# ════════════════════════════════════════════════════════════════════════════════

class IPAnonymizer:
    """
    Анонимизатор IP-адресов.
    
    Методы:
    - Хеширование с солью (необратимое)
    - Обрезание IPv6 до /64
    - Полное удаление
    
    Security:
    - Uses SaltManager for stable, rotatable salt
    - Supports double-window correlation
    """
    
    def __init__(
        self,
        salt: str | None = None,
        salt_manager: SaltManager | None = None,
    ):
        if salt_manager:
            self._salt_manager = salt_manager
            self._salt = salt_manager.current
        else:
            self._salt = salt or secrets.token_hex(16)
            self._salt_manager = None
    
    @property
    def salt(self) -> str:
        """Соль для хеширования (для восстановления при перезапуске)."""
        if self._salt_manager:
            return self._salt_manager.current
        return self._salt
    
    def hash_ip(self, ip: str) -> str:
        """
        Хеширование IP-адреса.
        
        Результат: первые 12 символов SHA-256.
        Необратимое, но консистентное в рамках одной соли.
        """
        if not ip:
            return "unknown"
        
        salt = self._salt_manager.current if self._salt_manager else self._salt
        data = f"{salt}:{ip}".encode()
        hash_bytes = hashlib.sha256(data).hexdigest()
        return hash_bytes[:12]
    
    def hash_ip_with_previous(self, ip: str) -> tuple[str, str]:
        """
        Hash IP with both current and previous salt (double-window).
        
        Returns:
            (current_hash, previous_hash)
        """
        if self._salt_manager:
            return self._salt_manager.hash_with_both(ip)
        return self.hash_ip(ip), ""
    
    def truncate_ipv6(self, ip: str) -> str:
        """
        Обрезание IPv6 до /64.
        
        Сохраняет network prefix, убирает interface identifier.
        """
        if ":" not in ip:
            # IPv4 — возвращаем как есть или хешируем
            return self.hash_ip(ip)
        
        # IPv6: оставляем первые 4 группы
        parts = ip.split(":")
        if len(parts) >= 4:
            truncated = ":".join(parts[:4]) + "::/64"
            return truncated
        
        return self.hash_ip(ip)
    
    def anonymize(self, ip: str, method: str = "hash") -> str:
        """
        Анонимизация IP-адреса.
        
        Args:
            ip: IP-адрес
            method: "hash", "truncate", "remove"
        """
        if method == "remove":
            return "redacted"
        elif method == "truncate":
            return self.truncate_ipv6(ip)
        else:
            return self.hash_ip(ip)


# ════════════════════════════════════════════════════════════════════════════════
# FLOW ENTRY
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class FlowEntry:
    """
    Запись о DNS-потоке.
    
    Содержит анонимизированную информацию о запросе.
    """
    
    # Идентификация
    flow_id: str
    timestamp: datetime
    
    # Запрос
    domain: str
    query_type: QueryType
    
    # Клиент (анонимизировано)
    client_id: str  # Хешированный IP или device_id
    device_id: str | None = None
    
    # Результат
    status: FlowStatus = FlowStatus.ALLOWED
    verdict: str = "allow"  # allow, deny, redirect, observe
    confidence: int = 100
    
    # Ответ
    response_ips: list[str] = field(default_factory=list)
    response_code: str = "NOERROR"  # NOERROR, NXDOMAIN, SERVFAIL, etc.
    
    # Производительность
    latency_ms: float = 0.0
    cached: bool = False
    upstream_used: str | None = None
    
    # Evidence summary (без полных данных)
    evidence_summary: str = ""
    matcher_id: str | None = None
    
    # Категории
    categories: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация для JSON/API."""
        return {
            "flow_id": self.flow_id,
            "timestamp": self.timestamp.isoformat(),
            "domain": self.domain,
            "query_type": self.query_type.value,
            "client_id": self.client_id,
            "device_id": self.device_id,
            "status": self.status.value,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "response_ips": self.response_ips,
            "response_code": self.response_code,
            "latency_ms": self.latency_ms,
            "cached": self.cached,
            "upstream_used": self.upstream_used,
            "evidence_summary": self.evidence_summary,
            "matcher_id": self.matcher_id,
            "categories": self.categories,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FlowEntry":
        """Десериализация."""
        return cls(
            flow_id=data["flow_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            domain=data["domain"],
            query_type=QueryType(data.get("query_type", "A")),
            client_id=data["client_id"],
            device_id=data.get("device_id"),
            status=FlowStatus(data.get("status", "allowed")),
            verdict=data.get("verdict", "allow"),
            confidence=data.get("confidence", 100),
            response_ips=data.get("response_ips", []),
            response_code=data.get("response_code", "NOERROR"),
            latency_ms=data.get("latency_ms", 0.0),
            cached=data.get("cached", False),
            upstream_used=data.get("upstream_used"),
            evidence_summary=data.get("evidence_summary", ""),
            matcher_id=data.get("matcher_id"),
            categories=data.get("categories", []),
        )
    
    def to_sql_tuple(self) -> tuple:
        """Кортеж для SQL INSERT."""
        return (
            self.flow_id,
            self.timestamp.isoformat(),
            self.domain,
            self.query_type.value,
            self.client_id,
            self.device_id,
            self.status.value,
            self.verdict,
            self.confidence,
            ",".join(self.response_ips),
            self.response_code,
            self.latency_ms,
            1 if self.cached else 0,
            self.upstream_used,
            self.evidence_summary,
            self.matcher_id,
            ",".join(self.categories),
        )


# ════════════════════════════════════════════════════════════════════════════════
# FLOW LOG STORAGE
# ════════════════════════════════════════════════════════════════════════════════

class FlowLogStorage:
    """
    SQLite хранилище для Flow Log.
    
    Особенности:
    - WAL mode для производительности
    - Автоматическая ротация по времени
    - Индексы для быстрого поиска
    - Size limits and auto-maintenance
    - Fail-open error handling
    """
    
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS flow_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        flow_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        domain TEXT NOT NULL,
        query_type TEXT NOT NULL,
        client_id TEXT NOT NULL,
        device_id TEXT,
        status TEXT NOT NULL,
        verdict TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        response_ips TEXT,
        response_code TEXT,
        latency_ms REAL,
        cached INTEGER,
        upstream_used TEXT,
        evidence_summary TEXT,
        matcher_id TEXT,
        categories TEXT
    );
    
    CREATE INDEX IF NOT EXISTS idx_flow_timestamp ON flow_log(timestamp);
    CREATE INDEX IF NOT EXISTS idx_flow_domain ON flow_log(domain);
    CREATE INDEX IF NOT EXISTS idx_flow_client ON flow_log(client_id);
    CREATE INDEX IF NOT EXISTS idx_flow_device ON flow_log(device_id);
    CREATE INDEX IF NOT EXISTS idx_flow_status ON flow_log(status);
    CREATE INDEX IF NOT EXISTS idx_flow_verdict ON flow_log(verdict);
    
    -- Metadata table for tracking DB state
    CREATE TABLE IF NOT EXISTS flow_log_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """
    
    def __init__(
        self,
        db_path: Path,
        max_size_mb: int = DEFAULT_DB_MAX_SIZE_MB,
        fail_open: bool = True,
    ):
        self._db_path = db_path
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()
        
        # Size and error management
        self._max_size_bytes = max_size_mb * 1024 * 1024
        self._fail_open = fail_open
        self._consecutive_failures = 0
        self._disabled = False
        self._last_vacuum: datetime | None = None
        
        # Metrics
        self._total_inserts = 0
        self._total_errors = 0
    
    async def initialize(self) -> None:
        """Инициализация базы данных."""
        async with self._lock:
            try:
                self._conn = sqlite3.connect(
                    str(self._db_path),
                    check_same_thread=False,
                    timeout=10.0,
                )
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.execute("PRAGMA cache_size=10000")
                self._conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
                self._conn.executescript(self.SCHEMA)
                self._conn.commit()
                self._disabled = False
                self._consecutive_failures = 0
                logger.info("FlowLogStorage initialized: %s", self._db_path)
            except Exception as e:
                logger.error("Failed to initialize FlowLogStorage: %s", e)
                self._total_errors += 1
                if not self._fail_open:
                    raise
    
    async def close(self) -> None:
        """Закрытие соединения."""
        async with self._lock:
            if self._conn:
                try:
                    self._conn.close()
                except Exception as e:
                    logger.warning("Error closing connection: %s", e)
                self._conn = None
    
    def _handle_error(self, error: Exception, operation: str) -> None:
        """Handle errors with fail-open logic."""
        self._total_errors += 1
        self._consecutive_failures += 1
        
        logger.error("FlowLogStorage %s failed (%d consecutive): %s",
                     operation, self._consecutive_failures, error)
        
        # Disable after too many failures
        if self._consecutive_failures >= 10:
            self._disabled = True
            logger.warning("FlowLogStorage disabled due to consecutive failures")
    
    def _reset_failure_count(self) -> None:
        """Reset failure counter on success."""
        if self._consecutive_failures > 0:
            self._consecutive_failures = 0
            if self._disabled:
                self._disabled = False
                logger.info("FlowLogStorage re-enabled after successful operation")
    
    async def insert_batch(self, entries: list[FlowEntry]) -> int:
        """
        Вставка пакета записей.
        
        Returns:
            Количество вставленных записей (0 on failure, fail-open)
        """
        if not entries or not self._conn or self._disabled:
            return 0
        
        async with self._lock:
            try:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO flow_log (
                        flow_id, timestamp, domain, query_type, client_id,
                        device_id, status, verdict, confidence, response_ips,
                        response_code, latency_ms, cached, upstream_used,
                        evidence_summary, matcher_id, categories
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [e.to_sql_tuple() for e in entries],
                )
                self._conn.commit()
                self._total_inserts += len(entries)
                self._reset_failure_count()
                return len(entries)
            except Exception as e:
                self._handle_error(e, "insert_batch")
                if not self._fail_open:
                    raise
                return 0
    
    async def get_db_size_bytes(self) -> int:
        """Get current database file size."""
        try:
            if self._db_path.exists():
                # Include WAL file size
                size = self._db_path.stat().st_size
                wal_path = Path(str(self._db_path) + "-wal")
                if wal_path.exists():
                    size += wal_path.stat().st_size
                return size
        except Exception:
            pass
        return 0
    
    async def check_size_limit(self) -> bool:
        """
        Check if database exceeds size limit.
        
        Returns:
            True if over limit
        """
        current_size = await self.get_db_size_bytes()
        return current_size > self._max_size_bytes
    
    async def get_storage_stats(self) -> dict[str, Any]:
        """Get storage statistics."""
        size_bytes = await self.get_db_size_bytes()
        return {
            "db_path": str(self._db_path),
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / (1024 * 1024), 2),
            "max_size_mb": self._max_size_bytes // (1024 * 1024),
            "over_limit": size_bytes > self._max_size_bytes,
            "total_inserts": self._total_inserts,
            "total_errors": self._total_errors,
            "consecutive_failures": self._consecutive_failures,
            "disabled": self._disabled,
            "last_vacuum": self._last_vacuum.isoformat() if self._last_vacuum else None,
        }
    
    async def query(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        domain: str | None = None,
        client_id: str | None = None,
        device_id: str | None = None,
        status: FlowStatus | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[FlowEntry]:
        """
        Запрос записей с фильтрацией.
        """
        if not self._conn:
            return []
        
        conditions = []
        params: list[Any] = []
        
        if domain:
            conditions.append("domain LIKE ?")
            params.append(f"%{domain}%")
        
        if client_id:
            conditions.append("client_id = ?")
            params.append(client_id)
        
        if device_id:
            conditions.append("device_id = ?")
            params.append(device_id)
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        
        if until:
            conditions.append("timestamp <= ?")
            params.append(until.isoformat())
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        query = f"""
            SELECT flow_id, timestamp, domain, query_type, client_id,
                   device_id, status, verdict, confidence, response_ips,
                   response_code, latency_ms, cached, upstream_used,
                   evidence_summary, matcher_id, categories
            FROM flow_log
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        
        async with self._lock:
            cursor = self._conn.execute(query, params)
            rows = cursor.fetchall()
        
        entries = []
        for row in rows:
            entries.append(FlowEntry(
                flow_id=row[0],
                timestamp=datetime.fromisoformat(row[1]),
                domain=row[2],
                query_type=QueryType(row[3]) if row[3] else QueryType.A,
                client_id=row[4],
                device_id=row[5],
                status=FlowStatus(row[6]) if row[6] else FlowStatus.ALLOWED,
                verdict=row[7] or "allow",
                confidence=row[8] or 100,
                response_ips=row[9].split(",") if row[9] else [],
                response_code=row[10] or "NOERROR",
                latency_ms=row[11] or 0.0,
                cached=bool(row[12]),
                upstream_used=row[13],
                evidence_summary=row[14] or "",
                matcher_id=row[15],
                categories=row[16].split(",") if row[16] else [],
            ))
        
        return entries
    
    async def get_by_flow_id(self, flow_id: str) -> FlowEntry | None:
        """Получение записи по flow_id."""
        if not self._conn:
            return None
        
        async with self._lock:
            cursor = self._conn.execute(
                """
                SELECT flow_id, timestamp, domain, query_type, client_id,
                       device_id, status, verdict, confidence, response_ips,
                       response_code, latency_ms, cached, upstream_used,
                       evidence_summary, matcher_id, categories
                FROM flow_log
                WHERE flow_id = ?
                """,
                (flow_id,),
            )
            row = cursor.fetchone()
        
        if not row:
            return None
        
        return FlowEntry(
            flow_id=row[0],
            timestamp=datetime.fromisoformat(row[1]),
            domain=row[2],
            query_type=QueryType(row[3]) if row[3] else QueryType.A,
            client_id=row[4],
            device_id=row[5],
            status=FlowStatus(row[6]) if row[6] else FlowStatus.ALLOWED,
            verdict=row[7] or "allow",
            confidence=row[8] or 100,
            response_ips=row[9].split(",") if row[9] else [],
            response_code=row[10] or "NOERROR",
            latency_ms=row[11] or 0.0,
            cached=bool(row[12]),
            upstream_used=row[13],
            evidence_summary=row[14] or "",
            matcher_id=row[15],
            categories=row[16].split(",") if row[16] else [],
        )
    
    async def count(
        self,
        *,
        status: FlowStatus | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
    ) -> int:
        """Подсчёт записей."""
        if not self._conn:
            return 0
        
        conditions = []
        params: list[Any] = []
        
        if status:
            conditions.append("status = ?")
            params.append(status.value)
        
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        async with self._lock:
            cursor = self._conn.execute(
                f"SELECT COUNT(*) FROM flow_log WHERE {where_clause}",
                params,
            )
            result = cursor.fetchone()
        
        return result[0] if result else 0
    
    async def cleanup_old_entries(self, retention_days: int) -> int:
        """
        Удаление старых записей.
        
        Args:
            retention_days: Days to retain (capped at MAX_RETENTION_DAYS)
        
        Returns:
            Количество удалённых записей
        """
        if not self._conn or self._disabled:
            return 0
        
        # Cap retention to prevent abuse
        retention_days = min(retention_days, MAX_RETENTION_DAYS)
        cutoff = datetime.now() - timedelta(days=retention_days)
        
        async with self._lock:
            try:
                cursor = self._conn.execute(
                    "DELETE FROM flow_log WHERE timestamp < ?",
                    (cutoff.isoformat(),),
                )
                deleted = cursor.rowcount
                self._conn.commit()
                self._reset_failure_count()
                
                if deleted > 0:
                    logger.info("Cleaned up %d old flow entries", deleted)
                
                return deleted
            except Exception as e:
                self._handle_error(e, "cleanup_old_entries")
                if not self._fail_open:
                    raise
                return 0
    
    async def emergency_cleanup(self, keep_entries: int = 10000) -> int:
        """
        Emergency cleanup when DB is over size limit.
        
        Keeps only the most recent entries.
        
        Returns:
            Number of entries deleted
        """
        if not self._conn:
            return 0
        
        async with self._lock:
            try:
                # Get total count
                cursor = self._conn.execute("SELECT COUNT(*) FROM flow_log")
                total = cursor.fetchone()[0]
                
                if total <= keep_entries:
                    return 0
                
                # Delete oldest entries
                to_delete = total - keep_entries
                cursor = self._conn.execute(
                    """
                    DELETE FROM flow_log WHERE id IN (
                        SELECT id FROM flow_log ORDER BY timestamp ASC LIMIT ?
                    )
                    """,
                    (to_delete,),
                )
                deleted = cursor.rowcount
                self._conn.commit()
                
                logger.warning("Emergency cleanup: deleted %d entries, kept %d", deleted, keep_entries)
                return deleted
            except Exception as e:
                self._handle_error(e, "emergency_cleanup")
                return 0
    
    async def vacuum(self) -> None:
        """Оптимизация базы данных."""
        if not self._conn or self._disabled:
            return
        
        async with self._lock:
            try:
                self._conn.execute("PRAGMA incremental_vacuum")
                self._conn.execute("ANALYZE")
                self._last_vacuum = datetime.now()
                self._reset_failure_count()
                logger.debug("Database vacuumed and analyzed")
            except Exception as e:
                self._handle_error(e, "vacuum")
    
    async def full_vacuum(self) -> None:
        """Full database vacuum (more aggressive, blocks writes)."""
        if not self._conn or self._disabled:
            return
        
        async with self._lock:
            try:
                self._conn.execute("VACUUM")
                self._conn.execute("ANALYZE")
                self._last_vacuum = datetime.now()
                self._reset_failure_count()
                logger.info("Full database vacuum completed")
            except Exception as e:
                self._handle_error(e, "full_vacuum")


# ════════════════════════════════════════════════════════════════════════════════
# FLOW LOGGER
# ════════════════════════════════════════════════════════════════════════════════

class FlowLogger:
    """
    Асинхронный логгер DNS-потоков.
    
    Особенности:
    - Буферизация записей в памяти
    - Периодический сброс в БД
    - Автоматическая ротация
    - Анонимизация IP
    
    Security features:
    - DoS protection with backpressure/drop
    - Privacy controls for evidence/response data
    - Database size monitoring and maintenance
    - Fail-open error handling
    """
    
    def __init__(
        self,
        storage: FlowLogStorage,
        anonymizer: IPAnonymizer | None = None,
        *,
        enabled: bool = True,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        batch_size: int = DEFAULT_BATCH_SIZE,
        flush_interval: float = DEFAULT_FLUSH_INTERVAL,
        # DoS protection
        buffer_max_size: int = MAX_IN_MEMORY_ENTRIES,
        backpressure_threshold: float = DEFAULT_BUFFER_BACKPRESSURE,
        drop_on_overflow: bool = True,
        # Privacy controls
        store_evidence: bool = True,
        evidence_max_length: int = 500,
        store_response_ips: bool = True,
        response_ips_max_count: int = 10,
        # Maintenance
        vacuum_interval_hours: int = DEFAULT_VACUUM_INTERVAL_HOURS,
        db_max_size_mb: int = DEFAULT_DB_MAX_SIZE_MB,
        # Failure handling
        fail_open: bool = True,
        max_consecutive_failures: int = 10,
        # Callbacks
        on_backpressure: Callable[[], None] | None = None,
        on_overflow_drop: Callable[[int], None] | None = None,
    ):
        self._storage = storage
        self._anonymizer = anonymizer or IPAnonymizer()
        self._enabled = enabled
        self._retention_days = min(retention_days, MAX_RETENTION_DAYS)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        
        # DoS protection
        self._buffer_max_size = buffer_max_size
        self._backpressure_threshold = backpressure_threshold
        self._drop_on_overflow = drop_on_overflow
        self._backpressure_active = False
        
        # Privacy controls
        self._store_evidence = store_evidence
        self._evidence_max_length = evidence_max_length
        self._store_response_ips = store_response_ips
        self._response_ips_max_count = response_ips_max_count
        
        # Maintenance
        self._vacuum_interval_hours = vacuum_interval_hours
        self._db_max_size_mb = db_max_size_mb
        
        # Failure handling
        self._fail_open = fail_open
        self._max_consecutive_failures = max_consecutive_failures
        self._consecutive_failures = 0
        self._logging_disabled = False
        
        # Callbacks
        self._on_backpressure = on_backpressure
        self._on_overflow_drop = on_overflow_drop
        
        # Буфер в памяти
        self._buffer: deque[FlowEntry] = deque(maxlen=buffer_max_size)
        self._pending: list[FlowEntry] = []
        
        # Фоновые задачи
        self._flush_task: asyncio.Task | None = None
        self._cleanup_task: asyncio.Task | None = None
        self._maintenance_task: asyncio.Task | None = None
        self._running = False
        
        # Статистика
        self._total_logged = 0
        self._total_flushed = 0
        self._total_dropped = 0
        self._total_errors = 0
    
    @property
    def anonymizer(self) -> IPAnonymizer:
        """Доступ к анонимайзеру."""
        return self._anonymizer
    
    @property
    def enabled(self) -> bool:
        """Whether logging is enabled."""
        return self._enabled and not self._logging_disabled
    
    @enabled.setter
    def enabled(self, value: bool) -> None:
        """Enable/disable logging."""
        self._enabled = value
        if value:
            self._logging_disabled = False
            self._consecutive_failures = 0
        logger.info("FlowLogger %s", "enabled" if value else "disabled")
    
    async def start(self) -> None:
        """Запуск логгера."""
        if not self._enabled:
            logger.info("FlowLogger is disabled, not starting")
            return
        
        await self._storage.initialize()
        self._running = True
        
        self._flush_task = asyncio.create_task(self._flush_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._maintenance_task = asyncio.create_task(self._maintenance_loop())
        
        logger.info("FlowLogger started (retention=%d days, buffer=%d)",
                    self._retention_days, self._buffer_max_size)
    
    async def stop(self) -> None:
        """Остановка логгера."""
        self._running = False
        
        # Сбрасываем оставшиеся записи
        await self._flush()
        
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
        
        await self._storage.close()
        logger.info("FlowLogger stopped")

    async def close(self) -> None:
        """Compatibility alias for shutdown callers."""
        await self.stop()
    
    def _check_backpressure(self) -> bool:
        """
        Check if backpressure should be applied.
        
        Returns:
            True if at backpressure threshold
        """
        current_fill = len(self._pending) / self._buffer_max_size
        
        if current_fill >= self._backpressure_threshold:
            if not self._backpressure_active:
                self._backpressure_active = True
                logger.warning("FlowLogger backpressure activated (buffer %.1f%% full)",
                               current_fill * 100)
                if self._on_backpressure:
                    try:
                        self._on_backpressure()
                    except Exception:
                        pass
            return True
        
        if self._backpressure_active and current_fill < self._backpressure_threshold * 0.8:
            self._backpressure_active = False
            logger.info("FlowLogger backpressure released")
        
        return False
    
    def _apply_privacy_controls(self, entry: FlowEntry) -> FlowEntry:
        """
        Apply privacy controls to entry.
        
        Trims or removes evidence_summary and response_ips based on config.
        """
        # Evidence summary
        if not self._store_evidence:
            entry.evidence_summary = ""
        elif self._evidence_max_length > 0 and len(entry.evidence_summary) > self._evidence_max_length:
            entry.evidence_summary = entry.evidence_summary[:self._evidence_max_length] + "..."
        
        # Response IPs
        if not self._store_response_ips:
            entry.response_ips = []
        elif self._response_ips_max_count > 0 and len(entry.response_ips) > self._response_ips_max_count:
            entry.response_ips = entry.response_ips[:self._response_ips_max_count]
        
        return entry
    
    def log(self, entry: FlowEntry) -> bool:
        """
        Добавление записи в лог (неблокирующее).
        
        Запись добавляется в буфер и будет сброшена в БД
        при следующем flush.
        
        Returns:
            True if logged, False if dropped (DoS protection)
        """
        # Check if logging is enabled
        if not self.enabled:
            return False
        
        # Apply privacy controls
        entry = self._apply_privacy_controls(entry)
        
        # Check backpressure
        self._check_backpressure()
        
        # Check for overflow
        if len(self._pending) >= self._buffer_max_size:
            if self._drop_on_overflow:
                # Drop oldest entries
                dropped = len(self._pending) // 10  # Drop 10%
                self._pending = self._pending[dropped:]
                self._total_dropped += dropped
                
                if self._on_overflow_drop:
                    try:
                        self._on_overflow_drop(dropped)
                    except Exception:
                        pass
                
                logger.warning("FlowLogger overflow: dropped %d oldest entries", dropped)
            else:
                # Block (not recommended for DNS)
                self._total_dropped += 1
                return False
        
        self._buffer.append(entry)
        self._pending.append(entry)
        self._total_logged += 1
        
        # Если накопилось много — сбрасываем немедленно
        if len(self._pending) >= self._batch_size:
            asyncio.create_task(self._flush())
        
        return True
    
    def log_flow(
        self,
        flow_id: str,
        domain: str,
        client_ip: str,
        *,
        query_type: QueryType = QueryType.A,
        device_id: str | None = None,
        status: FlowStatus = FlowStatus.ALLOWED,
        verdict: str = "allow",
        confidence: int = 100,
        response_ips: list[str] | None = None,
        response_code: str = "NOERROR",
        latency_ms: float = 0.0,
        cached: bool = False,
        upstream_used: str | None = None,
        evidence_summary: str = "",
        matcher_id: str | None = None,
        categories: list[str] | None = None,
    ) -> FlowEntry | None:
        """
        Логирование DNS-потока с автоматической анонимизацией.
        
        Returns:
            Созданная запись, или None if logging disabled/dropped
        """
        if not self.enabled:
            return None
        
        entry = FlowEntry(
            flow_id=flow_id,
            timestamp=datetime.now(),
            domain=domain,
            query_type=query_type,
            client_id=self._anonymizer.anonymize(client_ip),
            device_id=device_id,
            status=status,
            verdict=verdict,
            confidence=confidence,
            response_ips=response_ips or [],
            response_code=response_code,
            latency_ms=latency_ms,
            cached=cached,
            upstream_used=upstream_used,
            evidence_summary=evidence_summary,
            matcher_id=matcher_id,
            categories=categories or [],
        )
        
        if self.log(entry):
            return entry
        return None
    
    async def _flush(self) -> None:
        """Сброс буфера в БД (fail-open)."""
        if not self._pending:
            return
        
        entries = self._pending[:]
        self._pending.clear()
        
        try:
            count = await self._storage.insert_batch(entries)
            self._total_flushed += count
            
            if count > 0:
                logger.debug("Flushed %d flow entries", count)
                self._consecutive_failures = 0
        except Exception as e:
            self._total_errors += 1
            self._consecutive_failures += 1
            
            logger.error("FlowLogger flush failed (%d consecutive): %s",
                         self._consecutive_failures, e)
            
            # Disable logging after too many failures (fail-open)
            if self._consecutive_failures >= self._max_consecutive_failures:
                self._logging_disabled = True
                logger.warning("FlowLogger auto-disabled due to %d consecutive failures",
                               self._consecutive_failures)
    
    async def _flush_loop(self) -> None:
        """Периодический сброс буфера."""
        while self._running:
            await asyncio.sleep(self._flush_interval)
            try:
                await self._flush()
            except Exception as e:
                logger.error("Flush loop error: %s", e)
    
    async def _cleanup_loop(self) -> None:
        """Периодическая очистка старых записей."""
        while self._running:
            # Очистка раз в час
            await asyncio.sleep(3600)
            try:
                await self._storage.cleanup_old_entries(self._retention_days)
            except Exception as e:
                logger.error("Cleanup loop error: %s", e)
    
    async def _maintenance_loop(self) -> None:
        """
        Periodic maintenance: VACUUM, size checks, salt rotation.
        """
        vacuum_interval_sec = self._vacuum_interval_hours * 3600
        
        while self._running:
            await asyncio.sleep(vacuum_interval_sec)
            
            try:
                # Check database size
                if await self._storage.check_size_limit():
                    logger.warning("Database over size limit, triggering emergency cleanup")
                    await self._storage.emergency_cleanup()
                
                # Run vacuum
                await self._storage.vacuum()
                
                # Check salt rotation (if using SaltManager)
                if hasattr(self._anonymizer, '_salt_manager') and self._anonymizer._salt_manager:
                    if self._anonymizer._salt_manager.rotate_if_needed():
                        logger.info("Salt rotated")
                
            except Exception as e:
                logger.error("Maintenance loop error: %s", e)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Query API
    # ─────────────────────────────────────────────────────────────────────────
    
    async def query(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        domain: str | None = None,
        client_id: str | None = None,
        device_id: str | None = None,
        status: FlowStatus | None = None,
        verdict: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[FlowEntry]:
        """Запрос записей из хранилища."""
        return await self._storage.query(
            limit=limit,
            offset=offset,
            domain=domain,
            client_id=client_id,
            device_id=device_id,
            status=status,
            verdict=verdict,
            since=since,
            until=until,
        )
    
    async def get_flow(self, flow_id: str) -> FlowEntry | None:
        """Получение записи по flow_id."""
        return await self._storage.get_by_flow_id(flow_id)
    
    async def get_recent(self, limit: int = 50) -> list[FlowEntry]:
        """Получение последних записей."""
        # Сначала из буфера (самые свежие)
        buffer_entries = list(self._buffer)[-limit:]
        
        if len(buffer_entries) >= limit:
            return buffer_entries[-limit:]
        
        # Дополняем из БД
        remaining = limit - len(buffer_entries)
        db_entries = await self._storage.query(limit=remaining)
        
        # Объединяем (БД + буфер)
        return db_entries + buffer_entries
    
    async def get_stats(self) -> dict[str, Any]:
        """Статистика логгера."""
        now = datetime.now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        total = await self._storage.count()
        today = await self._storage.count(since=today_start)
        blocked = await self._storage.count(status=FlowStatus.BLOCKED)
        blocked_today = await self._storage.count(
            status=FlowStatus.BLOCKED,
            since=today_start,
        )
        
        storage_stats = await self._storage.get_storage_stats()
        
        return {
            "enabled": self.enabled,
            "total_logged": self._total_logged,
            "total_flushed": self._total_flushed,
            "total_dropped": self._total_dropped,
            "total_errors": self._total_errors,
            "buffer_size": len(self._buffer),
            "pending_flush": len(self._pending),
            "backpressure_active": self._backpressure_active,
            "logging_disabled": self._logging_disabled,
            "consecutive_failures": self._consecutive_failures,
            "storage_total": total,
            "storage_today": today,
            "blocked_total": blocked,
            "blocked_today": blocked_today,
            "retention_days": self._retention_days,
            "storage": storage_stats,
        }
    
    # ─────────────────────────────────────────────────────────────────────────
    # Streaming
    # ─────────────────────────────────────────────────────────────────────────
    
    async def stream_recent(
        self,
        interval: float = 1.0,
    ) -> AsyncIterator[list[FlowEntry]]:
        """
        Стриминг новых записей.
        
        Yields:
            Новые записи с момента последнего yield
        """
        last_id: str | None = None
        
        while self._running:
            entries = []
            
            # Собираем новые записи из буфера
            for entry in self._buffer:
                if last_id is None or entry.flow_id != last_id:
                    entries.append(entry)
                    last_id = entry.flow_id
            
            if entries:
                yield entries
            
            await asyncio.sleep(interval)


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

async def create_flow_logger(
    db_path: Path,
    *,
    salt: str | None = None,
    salt_file: str | None = None,
    salt_rotation_days: int = 30,
    retention_days: int = DEFAULT_RETENTION_DAYS,
    enabled: bool = True,
    # Privacy
    store_evidence: bool = True,
    evidence_max_length: int = 500,
    store_response_ips: bool = True,
    response_ips_max_count: int = 10,
    # DoS protection
    buffer_max_size: int = MAX_IN_MEMORY_ENTRIES,
    drop_on_overflow: bool = True,
    # Maintenance
    db_max_size_mb: int = DEFAULT_DB_MAX_SIZE_MB,
    fail_open: bool = True,
) -> FlowLogger:
    """
    Создание и запуск FlowLogger.
    
    Args:
        db_path: Путь к файлу БД
        salt: Соль для анонимизации (deprecated, use env or salt_file)
        salt_file: Path to salt file for persistence
        salt_rotation_days: Days between salt rotations
        retention_days: Дни хранения записей (max 90)
        enabled: Enable/disable logging
        store_evidence: Store evidence_summary (PII risk)
        evidence_max_length: Max length for evidence
        store_response_ips: Store response IPs (infra disclosure)
        response_ips_max_count: Max response IPs to store
        buffer_max_size: Max in-memory buffer
        drop_on_overflow: Drop oldest on overflow
        db_max_size_mb: Max database size
        fail_open: Continue DNS on failures
    
    Returns:
        Готовый к использованию FlowLogger
    """
    # Create salt manager
    salt_manager = SaltManager(
        salt_file=salt_file or str(db_path.parent / ".salt"),
        rotation_days=salt_rotation_days,
        double_window=True,
    )
    
    # Override with explicit salt if provided
    if salt:
        logger.warning("Using explicit salt parameter (deprecated, use env or salt_file)")
        anonymizer = IPAnonymizer(salt=salt)
    else:
        anonymizer = IPAnonymizer(salt_manager=salt_manager)
    
    storage = FlowLogStorage(
        db_path,
        max_size_mb=db_max_size_mb,
        fail_open=fail_open,
    )
    
    flow_logger = FlowLogger(
        storage,
        anonymizer,
        enabled=enabled,
        retention_days=min(retention_days, MAX_RETENTION_DAYS),
        # Privacy
        store_evidence=store_evidence,
        evidence_max_length=evidence_max_length,
        store_response_ips=store_response_ips,
        response_ips_max_count=response_ips_max_count,
        # DoS protection
        buffer_max_size=buffer_max_size,
        drop_on_overflow=drop_on_overflow,
        # Maintenance
        db_max_size_mb=db_max_size_mb,
        fail_open=fail_open,
    )
    
    await flow_logger.start()
    return flow_logger
