"""
CT Scanner — Certificate Transparency logs scanner.

Scans CT logs for newly issued certificates to detect:
- Phishing domains mimicking brands
- Suspicious domain patterns
- Newly registered domains used for attacks

Features:
- Rate limiting to prevent Pi overload
- Deduplication
- Background scanning
- Integration with heuristics engine
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from ..time_utils import utc_now
from typing import Any, AsyncGenerator

import httpx

from .heuristics import HeuristicsEngine
from .models import ThreatSignals


@dataclass
class CTEntry:
    """A certificate transparency log entry."""
    domain: str
    issuer: str
    not_before: datetime
    not_after: datetime
    serial_number: str
    subject_cn: str | None = None
    san_names: list[str] = field(default_factory=list)
    
    @property
    def age_hours(self) -> float:
        """Hours since certificate was issued."""
        delta = utc_now() - self.not_before
        return delta.total_seconds() / 3600


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""
    requests_per_minute: int = 10
    requests_per_hour: int = 100
    batch_size: int = 50
    delay_between_batches: float = 5.0  # seconds
    max_concurrent: int = 2


class RateLimiter:
    """
    Token bucket rate limiter.
    
    Prevents overwhelming the Pi with too many requests.
    """
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self._minute_tokens = deque(maxlen=config.requests_per_minute)
        self._hour_tokens = deque(maxlen=config.requests_per_hour)
        self._lock = asyncio.Lock()
    
    async def acquire(self) -> bool:
        """
        Acquire a rate limit token.
        
        Returns True if allowed, False if rate limited.
        """
        async with self._lock:
            now = time.time()
            
            # Clean old tokens
            minute_ago = now - 60
            hour_ago = now - 3600
            
            while self._minute_tokens and self._minute_tokens[0] < minute_ago:
                self._minute_tokens.popleft()
            
            while self._hour_tokens and self._hour_tokens[0] < hour_ago:
                self._hour_tokens.popleft()
            
            # Check limits
            if len(self._minute_tokens) >= self.config.requests_per_minute:
                return False
            
            if len(self._hour_tokens) >= self.config.requests_per_hour:
                return False
            
            # Add token
            self._minute_tokens.append(now)
            self._hour_tokens.append(now)
            
            return True
    
    async def wait_for_token(self, timeout: float = 60) -> bool:
        """Wait until a token is available."""
        start = time.time()
        
        while time.time() - start < timeout:
            if await self.acquire():
                return True
            await asyncio.sleep(1)
        
        return False
    
    def get_stats(self) -> dict[str, int]:
        """Get rate limiter statistics."""
        return {
            "minute_tokens_used": len(self._minute_tokens),
            "minute_limit": self.config.requests_per_minute,
            "hour_tokens_used": len(self._hour_tokens),
            "hour_limit": self.config.requests_per_hour,
        }


class DomainDeduplicator:
    """
    Deduplication for scanned domains.
    
    Prevents processing the same domain multiple times.
    Uses time-based expiration for seen domains.
    """
    
    def __init__(
        self,
        ttl_hours: int = 24,
        max_entries: int = 100000,
    ):
        self.ttl_hours = ttl_hours
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}  # domain_hash -> timestamp
        self._lock = asyncio.Lock()
    
    async def is_new(self, domain: str) -> bool:
        """Check if domain is new (not seen recently)."""
        domain_hash = self._hash_domain(domain)
        now = time.time()
        
        async with self._lock:
            # Cleanup if needed
            if len(self._seen) > self.max_entries:
                await self._cleanup()
            
            # Check if seen
            if domain_hash in self._seen:
                seen_at = self._seen[domain_hash]
                if now - seen_at < self.ttl_hours * 3600:
                    return False
            
            # Mark as seen
            self._seen[domain_hash] = now
            return True
    
    async def _cleanup(self) -> None:
        """Remove expired entries."""
        now = time.time()
        cutoff = now - self.ttl_hours * 3600
        
        self._seen = {
            h: ts for h, ts in self._seen.items()
            if ts > cutoff
        }
    
    def _hash_domain(self, domain: str) -> str:
        """Hash domain for storage efficiency."""
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
    
    def get_stats(self) -> dict[str, int]:
        """Get deduplicator statistics."""
        return {
            "domains_tracked": len(self._seen),
            "max_entries": self.max_entries,
        }


class CTScanner:
    """
    Certificate Transparency logs scanner.
    
    Uses crt.sh API (public, no API key needed) to find:
    - Newly issued certificates
    - Suspicious domain patterns
    - Brand impersonation attempts
    
    IMPORTANT: Results are for OBSERVATION only, never auto-block.
    """
    
    # crt.sh API endpoint
    CRT_SH_URL = "https://crt.sh/"
    
    def __init__(
        self,
        heuristics: HeuristicsEngine | None = None,
        rate_limit_config: RateLimitConfig | None = None,
        dedup_ttl_hours: int = 24,
    ):
        """
        Initialize CT scanner.
        
        Args:
            heuristics: Heuristics engine for domain analysis
            rate_limit_config: Rate limiting configuration
            dedup_ttl_hours: Hours to remember seen domains
        """
        self.heuristics = heuristics or HeuristicsEngine()
        self.rate_limiter = RateLimiter(rate_limit_config or RateLimitConfig())
        self.deduplicator = DomainDeduplicator(ttl_hours=dedup_ttl_hours)
        
        self._client: httpx.AsyncClient | None = None
        self._running = False
        self._scan_task: asyncio.Task | None = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=30.0,
                limits=httpx.Limits(max_connections=5),
                headers={
                    "User-Agent": "EasyPi-NetProtection/1.0 (CT Scanner)",
                },
            )
        return self._client
    
    async def search_brand(
        self,
        brand_keyword: str,
        max_results: int = 100,
    ) -> AsyncGenerator[CTEntry, None]:
        """
        Search CT logs for certificates matching a brand keyword.
        
        This is useful for monitoring brand impersonation.
        
        Args:
            brand_keyword: Keyword to search (e.g., "paypal")
            max_results: Maximum results to return
        
        Yields:
            CTEntry objects for matching certificates
        """
        if not await self.rate_limiter.wait_for_token(timeout=30):
            return
        
        client = await self._get_client()
        
        try:
            # crt.sh JSON API
            params = {
                "q": f"%{brand_keyword}%",
                "output": "json",
            }
            
            response = await client.get(self.CRT_SH_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            count = 0
            seen_domains = set()
            
            for entry in data:
                if count >= max_results:
                    break
                
                # Extract domain from common name
                cn = entry.get("common_name", "")
                name_value = entry.get("name_value", "")
                
                # Parse domains from name_value (may contain multiple)
                domains = set()
                if cn:
                    domains.add(cn.lower())
                if name_value:
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name and not name.startswith("*"):
                            domains.add(name)
                
                for domain in domains:
                    if domain in seen_domains:
                        continue
                    
                    seen_domains.add(domain)
                    
                    # Check deduplication
                    if not await self.deduplicator.is_new(domain):
                        continue
                    
                    # Parse dates
                    not_before = self._parse_date(entry.get("not_before", ""))
                    not_after = self._parse_date(entry.get("not_after", ""))
                    
                    ct_entry = CTEntry(
                        domain=domain,
                        issuer=entry.get("issuer_name", ""),
                        not_before=not_before,
                        not_after=not_after,
                        serial_number=entry.get("serial_number", ""),
                        subject_cn=cn,
                    )
                    
                    count += 1
                    yield ct_entry
                    
        except httpx.HTTPError:
            pass  # Silently fail, CT scanning is best-effort
    
    async def scan_recent(
        self,
        hours: int = 24,
        keywords: list[str] | None = None,
    ) -> AsyncGenerator[tuple[CTEntry, ThreatSignals], None]:
        """
        Scan CT logs for recently issued suspicious certificates.
        
        Args:
            hours: How far back to look
            keywords: Brand keywords to search for
        
        Yields:
            Tuples of (CTEntry, ThreatSignals)
        """
        keywords = keywords or [
            "paypal", "google", "microsoft", "apple", "amazon",
            "bank", "login", "secure", "verify", "account",
        ]
        
        for keyword in keywords:
            # Rate limiting between keywords
            await asyncio.sleep(self.rate_limiter.config.delay_between_batches)
            
            async for entry in self.search_brand(keyword, max_results=50):
                # Skip if too old
                if entry.age_hours > hours:
                    continue
                
                # Analyze with heuristics
                signals = self.heuristics.analyze_domain(entry.domain)
                
                # Only yield if suspicious
                if signals.total_score >= 30 or signals.signal_count >= 1:
                    yield entry, signals
    
    async def analyze_domain(self, domain: str) -> tuple[CTEntry | None, ThreatSignals]:
        """
        Analyze a specific domain from CT logs.
        
        Args:
            domain: Domain to analyze
        
        Returns:
            Tuple of (CTEntry or None, ThreatSignals)
        """
        # First, run heuristics
        signals = self.heuristics.analyze_domain(domain)
        
        # Then try to find CT info
        if not await self.rate_limiter.wait_for_token(timeout=10):
            return None, signals
        
        client = await self._get_client()
        
        try:
            params = {
                "q": domain,
                "output": "json",
            }
            
            response = await client.get(self.CRT_SH_URL, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data:
                entry_data = data[0]  # Most recent
                
                ct_entry = CTEntry(
                    domain=domain,
                    issuer=entry_data.get("issuer_name", ""),
                    not_before=self._parse_date(entry_data.get("not_before", "")),
                    not_after=self._parse_date(entry_data.get("not_after", "")),
                    serial_number=entry_data.get("serial_number", ""),
                )
                
                # Update signals with domain age
                if ct_entry.age_hours < 24 * 7:  # Less than 7 days
                    age_days = int(ct_entry.age_hours / 24)
                    age_score, _ = self.heuristics.check_domain_age(domain, age_days)
                    signals.newreg_score = age_score
                    signals.domain_age_days = age_days
                
                return ct_entry, signals
                
        except httpx.HTTPError:
            pass
        
        return None, signals
    
    async def start_background_scan(
        self,
        callback: Any = None,
        interval_hours: int = 6,
        keywords: list[str] | None = None,
    ) -> None:
        """
        Start background CT scanning.
        
        Args:
            callback: Async callback function(CTEntry, ThreatSignals) for findings
            interval_hours: Hours between full scans
            keywords: Brand keywords to monitor
        """
        if self._running:
            return
        
        self._running = True
        self._scan_task = asyncio.create_task(
            self._background_scan_loop(callback, interval_hours, keywords)
        )
    
    async def stop_background_scan(self) -> None:
        """Stop background scanning."""
        self._running = False
        if self._scan_task:
            self._scan_task.cancel()
            try:
                await self._scan_task
            except asyncio.CancelledError:
                pass
            self._scan_task = None
    
    async def _background_scan_loop(
        self,
        callback: Any,
        interval_hours: int,
        keywords: list[str] | None,
    ) -> None:
        """Background scan loop."""
        while self._running:
            try:
                async for entry, signals in self.scan_recent(
                    hours=interval_hours * 2,  # Overlap for safety
                    keywords=keywords,
                ):
                    if callback:
                        await callback(entry, signals)
                
                # Wait for next scan
                await asyncio.sleep(interval_hours * 3600)
                
            except asyncio.CancelledError:
                break
            except Exception:
                # Log error but continue
                await asyncio.sleep(60)  # Wait before retry
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date from crt.sh format."""
        try:
            # crt.sh format: "2025-01-15T10:30:00"
            return datetime.fromisoformat(date_str.replace("Z", "+00:00").split("+")[0])
        except Exception:
            return utc_now()
    
    def get_stats(self) -> dict[str, Any]:
        """Get scanner statistics."""
        return {
            "running": self._running,
            "rate_limiter": self.rate_limiter.get_stats(),
            "deduplicator": self.deduplicator.get_stats(),
        }
    
    async def close(self) -> None:
        """Close scanner and cleanup resources."""
        await self.stop_background_scan()
        if self._client:
            await self._client.aclose()
            self._client = None


class CTScanResult:
    """
    Aggregated result from CT scanning session.
    
    Provides summary for UI display.
    """
    
    def __init__(self):
        self.entries: list[tuple[CTEntry, ThreatSignals]] = []
        self.scan_start: datetime = utc_now()
        self.scan_end: datetime | None = None
        self.keywords_scanned: list[str] = []
        self.errors: list[str] = []
    
    def add(self, entry: CTEntry, signals: ThreatSignals) -> None:
        """Add a scan result."""
        self.entries.append((entry, signals))
    
    def finish(self) -> None:
        """Mark scan as finished."""
        self.scan_end = utc_now()
    
    @property
    def duration_seconds(self) -> float:
        """Scan duration in seconds."""
        end = self.scan_end or utc_now()
        return (end - self.scan_start).total_seconds()
    
    @property
    def suspicious_count(self) -> int:
        """Count of suspicious domains found."""
        return sum(
            1 for _, signals in self.entries
            if signals.should_quarantine()
        )
    
    def to_ui_summary(self) -> dict[str, Any]:
        """Generate summary for UI."""
        return {
            "total_scanned": len(self.entries),
            "suspicious_found": self.suspicious_count,
            "duration_seconds": round(self.duration_seconds, 1),
            "keywords_scanned": self.keywords_scanned,
            "top_threats": [
                {
                    "domain": entry.domain,
                    "score": signals.total_score,
                    "signals": signals.signal_count,
                    "brand": signals.matched_brand,
                    "age_hours": entry.age_hours,
                }
                for entry, signals in sorted(
                    self.entries,
                    key=lambda x: x[1].total_score,
                    reverse=True,
                )[:10]
            ],
        }
