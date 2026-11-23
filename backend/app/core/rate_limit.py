"""Rate limiting middleware and utilities for EasyPi."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

from app.core.paths import get_data_dir

logger = logging.getLogger("easypi")
MAX_RATE_LIMIT_KEYS = 100_000


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""

    requests: int  # Number of allowed requests
    window: int  # Time window in seconds
    block_duration: int = 300  # Block duration after limit exceeded (5 min default)


@dataclass
class RateLimitEntry:
    """Track requests for a single key."""

    timestamps: list[float] = field(default_factory=list)
    blocked_until: float = 0.0


class RateLimiter:
    """
    Sliding-window limiter with a small durable SQLite store.

    The in-memory cache keeps the request path inexpensive. SQLite preserves
    authentication blocks across backend restarts and is safe for the shipped
    single-worker service. Database errors retain the in-memory protection.
    """

    def __init__(self, database_path: Path | None = None):
        # Key -> RateLimitEntry
        self._store: dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)
        self._cleanup_interval = 300  # Cleanup every 5 minutes
        self._last_cleanup = time.time()
        self._lock = threading.RLock()
        self._database_path = database_path
        if self._database_path is not None:
            self._initialize_database()
            self._load_persisted_entries()

    def _connect(self) -> sqlite3.Connection:
        if self._database_path is None:
            raise RuntimeError("Persistent rate-limit database is disabled")
        connection = sqlite3.connect(self._database_path, timeout=2.0)
        connection.execute("PRAGMA busy_timeout=2000")
        return connection

    def _initialize_database(self) -> None:
        assert self._database_path is not None
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limit_entries (
                    key TEXT PRIMARY KEY,
                    timestamps TEXT NOT NULL,
                    blocked_until REAL NOT NULL,
                    updated_at REAL NOT NULL
                )
                """
            )
        try:
            self._database_path.chmod(0o600)
        except OSError:
            pass

    def _load_persisted_entries(self) -> None:
        now = time.time()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    "SELECT key, timestamps, blocked_until FROM rate_limit_entries "
                    "WHERE updated_at > ? OR blocked_until > ? LIMIT 100000",
                    (now - 3600, now),
                ).fetchall()
            for key, raw_timestamps, blocked_until in rows:
                try:
                    timestamps = [float(value) for value in json.loads(raw_timestamps)]
                except (TypeError, ValueError, json.JSONDecodeError):
                    timestamps = []
                self._store[str(key)] = RateLimitEntry(
                    timestamps=[value for value in timestamps if value > now - 3600],
                    blocked_until=float(blocked_until),
                )
        except (OSError, sqlite3.Error) as exc:
            logger.error("Could not load persistent rate limits: %s", exc)

    def _persist_entry(self, key: str, entry: RateLimitEntry, now: float) -> None:
        if self._database_path is None:
            return
        try:
            with self._connect() as connection:
                connection.execute(
                    """
                    INSERT INTO rate_limit_entries(key, timestamps, blocked_until, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(key) DO UPDATE SET
                        timestamps=excluded.timestamps,
                        blocked_until=excluded.blocked_until,
                        updated_at=excluded.updated_at
                    """,
                    (key, json.dumps(entry.timestamps), entry.blocked_until, now),
                )
        except (OSError, sqlite3.Error) as exc:
            logger.error("Could not persist rate limit for %s: %s", key, exc)

    def _delete_persisted(self, keys: list[str]) -> None:
        if self._database_path is None or not keys:
            return
        try:
            with self._connect() as connection:
                connection.executemany(
                    "DELETE FROM rate_limit_entries WHERE key = ?",
                    ((key,) for key in keys),
                )
        except (OSError, sqlite3.Error) as exc:
            logger.error("Could not remove expired rate limits: %s", exc)

    def _cleanup_persisted_database(self, now: float) -> None:
        if self._database_path is None:
            return
        try:
            with self._connect() as connection:
                connection.execute(
                    "DELETE FROM rate_limit_entries "
                    "WHERE updated_at < ? AND blocked_until < ?",
                    (now - 3600, now),
                )
                count = connection.execute(
                    "SELECT COUNT(*) FROM rate_limit_entries"
                ).fetchone()[0]
                excess = max(0, int(count) - MAX_RATE_LIMIT_KEYS)
                if excess:
                    connection.execute(
                        "DELETE FROM rate_limit_entries WHERE key IN ("
                        "SELECT key FROM rate_limit_entries "
                        "ORDER BY updated_at ASC LIMIT ?)",
                        (excess,),
                    )
        except (OSError, sqlite3.Error) as exc:
            logger.error("Could not compact persistent rate limits: %s", exc)

    def _cleanup_old_entries(self) -> None:
        """Remove old entries to prevent memory leaks."""
        now = time.time()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now
        keys_to_remove = []

        for key, entry in self._store.items():
            # Remove if no recent activity and not blocked
            if not entry.timestamps and entry.blocked_until < now:
                keys_to_remove.append(key)
            # Clean old timestamps
            elif entry.timestamps:
                cutoff = now - 3600  # Keep last hour
                entry.timestamps = [ts for ts in entry.timestamps if ts > cutoff]
                if not entry.timestamps and entry.blocked_until < now:
                    keys_to_remove.append(key)

        for key in keys_to_remove:
            del self._store[key]
        self._delete_persisted(keys_to_remove)
        self._cleanup_persisted_database(now)

        if keys_to_remove:
            logger.debug(f"Rate limiter cleanup: removed {len(keys_to_remove)} entries")

    def is_rate_limited(
        self,
        key: str,
        config: RateLimitConfig,
    ) -> tuple[bool, Optional[int]]:
        """
        Check if the key is rate limited.

        Returns:
            (is_limited, retry_after_seconds)
        """
        with self._lock:
            self._cleanup_old_entries()

            now = time.time()
            if key not in self._store and len(self._store) >= MAX_RATE_LIMIT_KEYS:
                logger.error("Rate-limit key capacity reached; rejecting unseen key")
                return True, config.block_duration
            entry = self._store[key]

            if entry.blocked_until > now:
                retry_after = max(1, int(entry.blocked_until - now))
                return True, retry_after

            window_start = now - config.window
            entry.timestamps = [ts for ts in entry.timestamps if ts > window_start]

            if len(entry.timestamps) >= config.requests:
                entry.blocked_until = now + config.block_duration
                self._persist_entry(key, entry, now)
                logger.warning(
                    "Rate limit exceeded for %s, blocked for %ss",
                    key,
                    config.block_duration,
                )
                return True, config.block_duration

            entry.timestamps.append(now)
            self._persist_entry(key, entry, now)
            return False, None

    def reset(self, key: str) -> None:
        """Reset rate limit for a key (e.g., after successful login)."""
        with self._lock:
            if key in self._store:
                del self._store[key]
            self._delete_persisted([key])

    def get_remaining(self, key: str, config: RateLimitConfig) -> int:
        """Get remaining requests for a key."""
        now = time.time()
        with self._lock:
            entry = self._store.get(key)

        if not entry:
            return config.requests

        if entry.blocked_until > now:
            return 0

        window_start = now - config.window
        recent = len([ts for ts in entry.timestamps if ts > window_start])
        return max(0, config.requests - recent)


# Global rate limiter instance
rate_limiter = RateLimiter(get_data_dir() / "security" / "rate_limits.sqlite3")


# Pre-configured rate limits
RATE_LIMITS = {
    # Auth endpoints - strict limits
    "login": RateLimitConfig(
        requests=5, window=60, block_duration=300
    ),  # 5 per minute, block 5 min
    "register": RateLimitConfig(
        requests=3, window=300, block_duration=600
    ),  # 3 per 5 min, block 10 min
    "recovery": RateLimitConfig(
        requests=3, window=300, block_duration=900
    ),  # 3 per 5 min, block 15 min
    "password_change": RateLimitConfig(
        requests=3, window=60, block_duration=300
    ),  # 3 per minute
    "backup_recovery_key": RateLimitConfig(
        requests=3, window=60, block_duration=300
    ),  # 3 failed reauthentication attempts per minute
    "two_factor_verification": RateLimitConfig(
        requests=5, window=60, block_duration=300
    ),  # Shared per-user limit for sensitive TOTP verification
    # WebSocket token - moderate limit (used for each WS connection)
    "ws_token": RateLimitConfig(
        requests=30, window=60, block_duration=120
    ),  # 30 per minute, block 2 min
    # Terminal WebSocket token - stricter limit for sensitive access
    "terminal_ws_token": RateLimitConfig(
        requests=6, window=60, block_duration=300
    ),  # 6 per minute, block 5 min
    # API token generation
    "api_token": RateLimitConfig(
        requests=5, window=300, block_duration=300
    ),  # 5 per 5 min
    # Snapshot endpoints - prevent DoS on compromised token
    "snapshot": RateLimitConfig(
        requests=10, window=60, block_duration=120
    ),  # 10 per minute per IP, block 2 min
    # PTZ control - keyed by user+camera+command (see check_ptz_rate_limit)
    "ptz": RateLimitConfig(
        requests=30, window=10, block_duration=30
    ),  # ~3/s burst, block 30s
    "ptz_detect": RateLimitConfig(
        requests=5, window=60, block_duration=120
    ),  # 5 detects/min
    "ptz_discover": RateLimitConfig(
        requests=6, window=60, block_duration=120
    ),  # 6 network scans/min
    # Remote VPS identity checks and deployments are expensive and security-sensitive.
    "ssh_host_key": RateLimitConfig(requests=6, window=60, block_duration=300),
    "ssh_auth_check": RateLimitConfig(requests=5, window=300, block_duration=600),
    "dns_deploy": RateLimitConfig(requests=3, window=300, block_duration=600),
    "relay_operation": RateLimitConfig(requests=5, window=300, block_duration=600),
    # Public password-protected share access
    "share_access": RateLimitConfig(requests=10, window=60, block_duration=300),
    # General API - more lenient
    "api_default": RateLimitConfig(
        requests=100, window=60, block_duration=60
    ),  # 100 per minute
}


# Direct-peer addresses we trust to have set the forwarding headers (the local nginx).
# Anything else is treated as a direct client whose forwarding headers are IGNORED — so a
# client cannot forge its identity (and thus its rate-limit bucket / audit IP) by sending
# X-Forwarded-For / X-Real-IP. Extendable via env for non-standard deployments.
_TRUSTED_PROXIES = {"127.0.0.1", "::1", "localhost"} | {
    p.strip() for p in os.getenv("EASYPI_TRUSTED_PROXIES", "").split(",") if p.strip()
}


def get_client_ip(request: Request) -> str:
    """Extract the real client IP for rate-limiting / audit.

    Forwarding headers are honoured ONLY when the direct connection comes from a trusted
    reverse proxy. The shipped nginx sets `X-Real-IP $remote_addr` (overwriting any
    client-supplied value) and appends to X-Forwarded-For, so behind the proxy we take
    X-Real-IP, or the LAST (proxy-appended) X-Forwarded-For hop — never the first, which
    is client-controlled and was the previous brute-force bypass.
    """
    peer = request.client.host if request.client else None

    if peer in _TRUSTED_PROXIES:
        real_ip = (request.headers.get("X-Real-IP") or "").strip()
        if real_ip:
            return real_ip
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            if hops:
                return hops[-1]
        return peer

    # Direct connection (no trusted proxy in front): the TCP peer is authoritative and
    # cannot be spoofed. Ignore any client-supplied forwarding headers entirely.
    return peer or "unknown"


def rate_limit(limit_name: str = "api_default"):
    """
    Decorator to apply rate limiting to an endpoint.

    Usage:
        @router.post("/login")
        @rate_limit("login")
        async def login(request: Request, ...):
            ...
    """

    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find request in args/kwargs
            request: Optional[Request] = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break
            if not request:
                request = kwargs.get("request")

            if request:
                config = RATE_LIMITS.get(limit_name, RATE_LIMITS["api_default"])
                client_ip = get_client_ip(request)
                key = f"{limit_name}:{client_ip}"

                is_limited, retry_after = rate_limiter.is_rate_limited(key, config)

                if is_limited:
                    logger.warning(f"Rate limited: {limit_name} from {client_ip}")
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many requests. Please try again in {retry_after} seconds.",
                        headers={"Retry-After": str(retry_after)},
                    )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def check_rate_limit(request: Request, limit_name: str = "api_default") -> None:
    """
    Check rate limit and raise HTTPException if exceeded.

    Usage in endpoint:
        @router.post("/login")
        async def login(request: Request, ...):
            check_rate_limit(request, "login")
            ...
    """
    config = RATE_LIMITS.get(limit_name, RATE_LIMITS["api_default"])
    client_ip = get_client_ip(request)
    key = f"{limit_name}:{client_ip}"

    is_limited, retry_after = rate_limiter.is_rate_limited(key, config)

    if is_limited:
        logger.warning(f"Rate limited: {limit_name} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


def _subject_key(limit_name: str, subject: object, source: object | None = None) -> str:
    """Build a bounded, non-sensitive key for account-scoped limits."""
    normalized = str(subject).strip().casefold()
    if source is not None:
        normalized = f"{normalized}\0{str(source).strip().casefold()}"
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    return f"{limit_name}:subject:{digest}"


def check_subject_rate_limit(
    subject: object, limit_name: str, source: object | None = None
) -> None:
    """Apply a subject limit, optionally scoped to a source such as client IP."""
    config = RATE_LIMITS.get(limit_name, RATE_LIMITS["api_default"])
    key = _subject_key(limit_name, subject, source)
    is_limited, retry_after = rate_limiter.is_rate_limited(key, config)
    if is_limited:
        logger.warning("Rate limited: %s for account-scoped subject", limit_name)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


def reset_subject_rate_limit(
    subject: object, limit_name: str, source: object | None = None
) -> None:
    """Reset only the named subject's limit."""
    rate_limiter.reset(_subject_key(limit_name, subject, source))


def check_ptz_rate_limit(
    user_id, camera_id, command: str, limit_name: str = "ptz"
) -> None:
    """Rate-limit a PTZ command, keyed by user id + camera id + command type.

    Unlike :func:`check_rate_limit` (keyed by client IP), PTZ limits are per
    (user, camera, command) so one user hammering one camera cannot create an
    endless command stream, independent of their IP.
    """
    config = RATE_LIMITS.get(limit_name, RATE_LIMITS["api_default"])
    key = f"{limit_name}:{user_id}:{camera_id}:{command}"
    is_limited, retry_after = rate_limiter.is_rate_limited(key, config)
    if is_limited:
        logger.warning(
            f"PTZ rate limited: {limit_name} user={user_id} camera={camera_id} cmd={command}"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many PTZ requests. Please try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )


def reset_rate_limit(request: Request, limit_name: str) -> None:
    """Reset rate limit for a client (e.g., after successful login)."""
    client_ip = get_client_ip(request)
    key = f"{limit_name}:{client_ip}"
    rate_limiter.reset(key)
