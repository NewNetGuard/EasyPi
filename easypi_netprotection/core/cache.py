from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Generic, TypeVar

from ..config import get_settings


T = TypeVar("T")


@dataclass
class CacheEntry(Generic[T]):
    """Single cache entry with TTL tracking."""
    
    value: T
    expires_at: float
    created_at: float = field(default_factory=time.monotonic)
    hit_count: int = 0
    
    @property
    def is_expired(self) -> bool:
        return time.monotonic() > self.expires_at
    
    @property
    def remaining_ttl(self) -> float:
        return max(0, self.expires_at - time.monotonic())
    
    def touch(self) -> None:
        """Record a cache hit."""
        self.hit_count += 1


@dataclass
class CacheStats:
    """Cache statistics."""
    
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    expirations: int = 0
    current_size: int = 0
    max_size: int = 0
    
    @property
    def hit_ratio(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0
    
    def to_dict(self) -> dict:
        return {
            "hits": self.hits,
            "misses": self.misses,
            "evictions": self.evictions,
            "expirations": self.expirations,
            "current_size": self.current_size,
            "max_size": self.max_size,
            "hit_ratio": round(self.hit_ratio, 4),
        }


class LRUCache(Generic[T]):
    """Thread-safe LRU cache with TTL support."""
    
    def __init__(
        self,
        max_size: int | None = None,
        default_ttl: float | None = None,
        min_ttl: float | None = None,
        max_ttl: float | None = None,
    ):
        settings = get_settings()
        self.max_size = max_size or settings.cache.max_entries
        self.default_ttl = default_ttl or settings.cache.default_ttl_sec
        self.min_ttl = min_ttl or settings.cache.min_ttl_sec
        self.max_ttl = max_ttl or settings.cache.max_ttl_sec
        
        self._cache: OrderedDict[str, CacheEntry[T]] = OrderedDict()
        self._lock = asyncio.Lock()
        self._stats = CacheStats(max_size=self.max_size)
        self._cleanup_task: asyncio.Task | None = None
    
    async def start(self) -> None:
        """Start background cleanup task."""
        if self._cleanup_task is None:
            self._cleanup_task = asyncio.create_task(self._cleanup_loop())
    
    async def stop(self) -> None:
        """Stop background cleanup task."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None
    
    async def get(self, key: str) -> T | None:
        """Get value from cache."""
        async with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats.misses += 1
                return None
            
            if entry.is_expired:
                del self._cache[key]
                self._stats.expirations += 1
                self._stats.misses += 1
                self._stats.current_size = len(self._cache)
                return None
            
            # Move to end (most recently used)
            self._cache.move_to_end(key)
            entry.touch()
            self._stats.hits += 1
            return entry.value
    
    async def set(
        self,
        key: str,
        value: T,
        ttl: float | None = None,
    ) -> None:
        """Set value in cache with optional TTL."""
        if ttl is None:
            ttl = self.default_ttl
        
        # Clamp TTL to configured bounds
        ttl = max(self.min_ttl, min(ttl, self.max_ttl))
        
        async with self._lock:
            # Evict if at capacity
            while len(self._cache) >= self.max_size:
                self._evict_oldest()
            
            expires_at = time.monotonic() + ttl
            self._cache[key] = CacheEntry(value=value, expires_at=expires_at)
            self._cache.move_to_end(key)
            self._stats.current_size = len(self._cache)
    
    async def delete(self, key: str) -> bool:
        """Delete entry from cache."""
        async with self._lock:
            if key in self._cache:
                del self._cache[key]
                self._stats.current_size = len(self._cache)
                return True
            return False
    
    async def clear(self) -> None:
        """Clear all cache entries."""
        async with self._lock:
            self._cache.clear()
            self._stats.current_size = 0
    
    async def contains(self, key: str) -> bool:
        """Check if key exists and is not expired."""
        async with self._lock:
            entry = self._cache.get(key)
            if entry is None:
                return False
            if entry.is_expired:
                del self._cache[key]
                self._stats.expirations += 1
                self._stats.current_size = len(self._cache)
                return False
            return True
    
    def _evict_oldest(self) -> None:
        """Evict the oldest (least recently used) entry."""
        if self._cache:
            # First item is oldest due to move_to_end on access
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
            self._stats.evictions += 1
    
    async def _cleanup_loop(self) -> None:
        """Background task to remove expired entries."""
        while True:
            await asyncio.sleep(60)  # Check every minute
            await self._cleanup_expired()
    
    async def _cleanup_expired(self) -> None:
        """Remove all expired entries."""
        async with self._lock:
            now = time.monotonic()
            expired_keys = [
                key for key, entry in self._cache.items()
                if now > entry.expires_at
            ]
            for key in expired_keys:
                del self._cache[key]
                self._stats.expirations += 1
            
            self._stats.current_size = len(self._cache)
    
    @property
    def stats(self) -> CacheStats:
        """Get cache statistics."""
        self._stats.current_size = len(self._cache)
        return self._stats
    
    def __len__(self) -> int:
        return len(self._cache)


class DNSCache:
    """Specialized DNS response cache."""
    
    def __init__(
        self,
        max_entries: int | None = None,
        default_ttl: float | None = None,
        min_ttl: float | None = None,
        max_ttl: float | None = None,
    ):
        settings = get_settings()
        self._cache = LRUCache[dict](
            max_size=max_entries or settings.cache.max_entries,
            default_ttl=default_ttl or settings.cache.default_ttl_sec,
            min_ttl=min_ttl or settings.cache.min_ttl_sec,
            max_ttl=max_ttl or settings.cache.max_ttl_sec,
        )
        self._negative_ttl = settings.cache.negative_ttl_sec

    def stats(self) -> dict:
        """Return cache statistics."""
        return self._cache.stats.to_dict()
    
    async def start(self) -> None:
        """Start the cache."""
        # Use OrderedDict for LRU behavior
        from collections import OrderedDict
        self._cache._cache = OrderedDict()
        await self._cache.start()
    
    async def stop(self) -> None:
        """Stop the cache."""
        await self._cache.stop()
    
    def _make_key(self, domain: str, query_type: str) -> str:
        """Create cache key from domain and query type."""
        return f"{domain.lower().rstrip('.')}:{query_type.upper()}"
    
    async def get_response(
        self,
        domain: str,
        query_type: str,
    ) -> dict | None:
        """Get cached DNS response."""
        key = self._make_key(domain, query_type)
        return await self._cache.get(key)
    
    async def set_response(
        self,
        domain: str,
        query_type: str,
        response: dict,
        ttl: float | None = None,
    ) -> None:
        """Cache a DNS response."""
        key = self._make_key(domain, query_type)
        
        # Use response TTL if available, otherwise default
        if ttl is None:
            ttl = response.get("ttl", self._cache.default_ttl)
        
        await self._cache.set(key, response, ttl)
    
    async def set_negative(
        self,
        domain: str,
        query_type: str,
        response_code: str = "NXDOMAIN",
    ) -> None:
        """Cache a negative response (NXDOMAIN, etc)."""
        key = self._make_key(domain, query_type)
        response = {
            "domain": domain,
            "query_type": query_type,
            "response_code": response_code,
            "answers": [],
            "is_negative": True,
        }
        await self._cache.set(key, response, self._negative_ttl)
    
    async def invalidate(self, domain: str, query_type: str | None = None) -> None:
        """Invalidate cache entries for a domain."""
        if query_type:
            key = self._make_key(domain, query_type)
            await self._cache.delete(key)
        else:
            # Invalidate all query types for this domain
            prefix = f"{domain.lower().rstrip('.')}:"
            keys_to_delete = [
                k for k in list(self._cache._cache.keys())
                if k.startswith(prefix)
            ]
            for key in keys_to_delete:
                await self._cache.delete(key)
    
    async def clear(self) -> None:
        """Clear entire cache."""
        await self._cache.clear()
    
# Singleton instance
_dns_cache: DNSCache | None = None


def get_dns_cache() -> DNSCache:
    """Get cached DNS cache instance."""
    global _dns_cache
    if _dns_cache is None:
        _dns_cache = DNSCache()
    return _dns_cache
