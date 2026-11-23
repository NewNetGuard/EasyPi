"""
Feed Manager — External threat feed subscriptions.

Only supports feeds with permissive licenses (CC0, MIT, Apache).
NO GPL feeds to avoid license contamination for commercial use.

Features:
- Feed subscription management
- Automatic updates with rate limiting
- License verification
- Domain extraction from various formats
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from ..time_utils import utc_now
from enum import Enum
from pathlib import Path
from typing import Any

import httpx

from ..safe_http import fetch_text, validate_remote_url_syntax
from .models import FeedConfig, SourceType, ThreatCategory


class FeedLicense(str, Enum):
    """Supported feed licenses."""
    CC0 = "cc0"  # Public domain
    MIT = "mit"  # MIT License
    APACHE = "apache"  # Apache 2.0
    BSD = "bsd"  # BSD License
    UNLICENSE = "unlicense"  # Unlicense
    # NOT SUPPORTED (would require GPL):
    # GPL = "gpl"
    # AGPL = "agpl"
    # COPYLEFT = "copyleft"


class FeedFormat(str, Enum):
    """Feed file formats."""
    HOSTS = "hosts"  # /etc/hosts format
    DOMAINS = "domains"  # One domain per line
    ADBLOCK = "adblock"  # AdBlock Plus format
    JSON = "json"  # JSON format
    CSV = "csv"  # CSV format


# Pre-approved feeds with permissive licenses
APPROVED_FEEDS = [
    FeedConfig(
        id="urlhaus_malware",
        name="URLhaus Malware Domains",
        url="https://urlhaus.abuse.ch/downloads/hostfile/",
        license="cc0",
        source_type=SourceType.FEED_CC0,
        categories=[ThreatCategory.MALWARE],
        update_interval_hours=6,
    ),
    FeedConfig(
        id="phishtank_online",
        name="PhishTank Online",
        url="https://data.phishtank.com/data/online-valid.json",
        license="free",
        source_type=SourceType.FEED_PERMISSIVE,
        categories=[ThreatCategory.PHISHING],
        update_interval_hours=12,
    ),
    # Steven Black's hosts - MIT License
    FeedConfig(
        id="stevenblack_hosts",
        name="Steven Black Hosts (Unified)",
        url="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        license="mit",
        source_type=SourceType.FEED_MIT,
        categories=[ThreatCategory.ADVERTISING, ThreatCategory.MALWARE],
        update_interval_hours=24,
    ),
    # Phishing Army - CC0
    FeedConfig(
        id="phishing_army",
        name="Phishing Army",
        url="https://phishing.army/download/phishing_army_blocklist.txt",
        license="cc0",
        source_type=SourceType.FEED_CC0,
        categories=[ThreatCategory.PHISHING],
        update_interval_hours=12,
    ),
]


class FeedParser:
    """Parses various feed formats into domain lists."""
    
    # Regex patterns for different formats
    HOSTS_PATTERN = re.compile(r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+(\S+)", re.MULTILINE)
    DOMAIN_PATTERN = re.compile(r"^([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$")
    ADBLOCK_DOMAIN_PATTERN = re.compile(r"^\|\|([^/^]+)\^")
    
    @classmethod
    def parse(
        cls,
        content: str,
        format_type: FeedFormat,
    ) -> list[str]:
        """
        Parse feed content into domain list.
        
        Args:
            content: Raw feed content
            format_type: Format of the feed
        
        Returns:
            List of domains
        """
        domains = set()
        
        if format_type == FeedFormat.HOSTS:
            domains = cls._parse_hosts(content)
        elif format_type == FeedFormat.DOMAINS:
            domains = cls._parse_domains(content)
        elif format_type == FeedFormat.ADBLOCK:
            domains = cls._parse_adblock(content)
        elif format_type == FeedFormat.JSON:
            domains = cls._parse_json(content)
        elif format_type == FeedFormat.CSV:
            domains = cls._parse_csv(content)
        
        # Clean and validate domains
        cleaned = set()
        for domain in domains:
            domain = cls._clean_domain(domain)
            if domain and cls._is_valid_domain(domain):
                cleaned.add(domain)
        
        return list(cleaned)
    
    @classmethod
    def _parse_hosts(cls, content: str) -> set[str]:
        """Parse /etc/hosts format."""
        domains = set()
        
        for match in cls.HOSTS_PATTERN.finditer(content):
            domain = match.group(1).lower()
            if domain not in ("localhost", "localhost.localdomain", "local"):
                domains.add(domain)
        
        return domains
    
    @classmethod
    def _parse_domains(cls, content: str) -> set[str]:
        """Parse one-domain-per-line format."""
        domains = set()
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            
            # Handle comments at end of line
            if "#" in line:
                line = line.split("#")[0].strip()
            
            domains.add(line.lower())
        
        return domains
    
    @classmethod
    def _parse_adblock(cls, content: str) -> set[str]:
        """Parse AdBlock Plus format."""
        domains = set()
        
        for line in content.splitlines():
            line = line.strip()
            
            # Skip comments and metadata
            if not line or line.startswith("!") or line.startswith("["):
                continue
            
            # Match ||domain.com^ pattern
            match = cls.ADBLOCK_DOMAIN_PATTERN.match(line)
            if match:
                domains.add(match.group(1).lower())
        
        return domains
    
    @classmethod
    def _parse_json(cls, content: str) -> set[str]:
        """Parse JSON format (various structures)."""
        import json
        
        domains = set()
        
        try:
            data = json.loads(content)
            
            # Handle different JSON structures
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str):
                        domains.add(item)
                    elif isinstance(item, dict):
                        # Try common field names
                        for field in ("domain", "url", "host", "name", "phish_url"):
                            if field in item:
                                value = item[field]
                                if isinstance(value, str):
                                    # Extract domain from URL if needed
                                    domain = cls._extract_domain(value)
                                    if domain:
                                        domains.add(domain)
            elif isinstance(data, dict):
                # Handle dict structures
                if "domains" in data:
                    domains.update(data["domains"])
                elif "data" in data:
                    return cls._parse_json(json.dumps(data["data"]))
        except json.JSONDecodeError:
            pass
        
        return domains
    
    @classmethod
    def _parse_csv(cls, content: str) -> set[str]:
        """Parse CSV format."""
        import csv
        from io import StringIO
        
        domains = set()
        
        try:
            reader = csv.reader(StringIO(content))
            header = None
            domain_col = 0
            
            for i, row in enumerate(reader):
                if i == 0:
                    # Try to find domain column in header
                    header = [c.lower() for c in row]
                    for col_name in ("domain", "host", "url", "name"):
                        if col_name in header:
                            domain_col = header.index(col_name)
                            break
                    continue
                
                if len(row) > domain_col:
                    value = row[domain_col]
                    domain = cls._extract_domain(value)
                    if domain:
                        domains.add(domain)
        except Exception:
            pass
        
        return domains
    
    @classmethod
    def _clean_domain(cls, domain: str) -> str:
        """Clean and normalize domain."""
        domain = domain.lower().strip()
        
        # Remove protocol
        domain = re.sub(r"^https?://", "", domain)
        
        # Remove path
        domain = domain.split("/")[0]
        
        # Remove port
        domain = domain.split(":")[0]
        
        # Remove leading/trailing dots
        domain = domain.strip(".")
        
        # Remove www prefix
        if domain.startswith("www."):
            domain = domain[4:]
        
        return domain
    
    @classmethod
    def _extract_domain(cls, url: str) -> str | None:
        """Extract domain from URL."""
        domain = cls._clean_domain(url)
        if cls._is_valid_domain(domain):
            return domain
        return None
    
    @classmethod
    def _is_valid_domain(cls, domain: str) -> bool:
        """Check if domain is valid."""
        if not domain or len(domain) < 3:
            return False
        
        # Must have at least one dot
        if "." not in domain:
            return False
        
        # No spaces or special chars
        if re.search(r"[\s<>\"'\\]", domain):
            return False
        
        # Basic domain pattern
        if not re.match(r"^[a-z0-9][-a-z0-9]*(\.[a-z0-9][-a-z0-9]*)+$", domain):
            return False
        
        return True
    
    @classmethod
    def detect_format(cls, content: str, url: str = "") -> FeedFormat:
        """Auto-detect feed format."""
        # Check by URL extension
        url_lower = url.lower()
        if url_lower.endswith(".json"):
            return FeedFormat.JSON
        if url_lower.endswith(".csv"):
            return FeedFormat.CSV
        
        # Check content
        content_start = content[:500].lower()
        
        if content.lstrip().startswith("{") or content.lstrip().startswith("["):
            return FeedFormat.JSON
        
        if "0.0.0.0" in content_start or "127.0.0.1" in content_start:
            return FeedFormat.HOSTS
        
        if "[adblock" in content_start or "||" in content_start:
            return FeedFormat.ADBLOCK
        
        return FeedFormat.DOMAINS


class FeedManager:
    """
    Manages external threat feed subscriptions.
    
    IMPORTANT: Only supports feeds with permissive licenses.
    GPL/AGPL feeds are NOT supported to ensure commercial viability.
    """
    
    # Supported licenses for commercial use
    COMMERCIAL_SAFE_LICENSES = {
        FeedLicense.CC0,
        FeedLicense.MIT,
        FeedLicense.APACHE,
        FeedLicense.BSD,
        FeedLicense.UNLICENSE,
    }
    
    def __init__(
        self,
        cache_dir: str | Path | None = None,
        max_domains_per_feed: int = 100000,
    ):
        """
        Initialize feed manager.
        
        Args:
            cache_dir: Directory for caching downloaded feeds
            max_domains_per_feed: Maximum domains to keep from each feed
        """
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.max_domains_per_feed = max_domains_per_feed
        
        self._feeds: dict[str, FeedConfig] = {}
        self._domains: dict[str, set[str]] = {}  # feed_id -> domains
        self._client: httpx.AsyncClient | None = None
        self._update_task: asyncio.Task | None = None
        
        # Load approved feeds
        for feed in APPROVED_FEEDS:
            self._feeds[feed.id] = feed
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=60.0,
                limits=httpx.Limits(max_connections=5),
                follow_redirects=True,
                headers={
                    "User-Agent": "EasyPi-NetProtection/1.0 (Feed Fetcher)",
                },
            )
        return self._client
    
    def add_feed(
        self,
        url: str,
        name: str,
        license_type: str,
        categories: list[ThreatCategory] | None = None,
        update_interval_hours: int = 24,
        user_confirmed_license: bool = False,
    ) -> tuple[FeedConfig | None, str | None]:
        """
        Add a custom feed subscription.
        
        Args:
            url: Feed URL
            name: Human-readable name
            license_type: License (must be permissive)
            categories: Threat categories
            update_interval_hours: Update interval
            user_confirmed_license: User confirms license responsibility
        
        Returns:
            Tuple of (FeedConfig or None, warning message or None)
            - Returns (None, error) if license not allowed
            - Returns (config, warning) if added with user responsibility
        """
        # Verify license is permissive
        try:
            license_enum = FeedLicense(license_type.lower())
        except ValueError:
            license_enum = None
        
        validate_remote_url_syntax(url)

        # GPL/AGPL feeds are NEVER allowed
        if license_type.lower() in ("gpl", "agpl", "gpl-2.0", "gpl-3.0", "agpl-3.0"):
            return None, (
                "❌ GPL/AGPL лицензии НЕ поддерживаются. "
                "Они несовместимы с коммерческим использованием. "
                "Используйте списки с CC0, MIT, Apache или BSD лицензией."
            )
        
        # Unknown license - require user confirmation
        warning: str | None = None
        if license_enum not in self.COMMERCIAL_SAFE_LICENSES:
            if not user_confirmed_license:
                return None, (
                    f"⚠️ Лицензия '{license_type}' не проверена. "
                    "Ответственность за соблюдение лицензии лежит на вас. "
                    "Подтвердите добавление списка, установив user_confirmed_license=True."
                )
            else:
                warning = (
                    f"⚠️ ВНИМАНИЕ: Вы добавили список с лицензией '{license_type}'. "
                    "Ответственность за соблюдение условий лицензии лежит на ВАС. "
                    "EasyPi не гарантирует совместимость этой лицензии с коммерческим использованием."
                )
                license_enum = FeedLicense.UNLICENSE  # Fallback for source type
        
        # Determine source type from license
        source_type = SourceType.FEED_PERMISSIVE
        if license_enum == FeedLicense.CC0:
            source_type = SourceType.FEED_CC0
        elif license_enum == FeedLicense.MIT:
            source_type = SourceType.FEED_MIT
        
        feed = FeedConfig(
            id=f"custom_{hashlib.sha256(url.encode()).hexdigest()[:8]}",
            name=name,
            url=url,
            license=license_type,
            source_type=source_type,
            categories=categories or [ThreatCategory.SUSPICIOUS],
            update_interval_hours=update_interval_hours,
            user_license_confirmed=user_confirmed_license,
        )
        
        self._feeds[feed.id] = feed
        return feed, warning
    
    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed subscription."""
        if feed_id in self._feeds:
            del self._feeds[feed_id]
            self._domains.pop(feed_id, None)
            return True
        return False
    
    def get_feed(self, feed_id: str) -> FeedConfig | None:
        """Get feed by ID."""
        return self._feeds.get(feed_id)
    
    def get_all_feeds(self) -> list[FeedConfig]:
        """Get all configured feeds."""
        return list(self._feeds.values())
    
    def enable_feed(self, feed_id: str) -> bool:
        """Enable a feed."""
        feed = self._feeds.get(feed_id)
        if feed:
            feed.enabled = True
            return True
        return False
    
    def disable_feed(self, feed_id: str) -> bool:
        """Disable a feed."""
        feed = self._feeds.get(feed_id)
        if feed:
            feed.enabled = False
            return True
        return False
    
    async def update_feed(self, feed_id: str) -> int:
        """
        Update a single feed.
        
        Returns count of domains loaded.
        """
        feed = self._feeds.get(feed_id)
        if not feed or not feed.enabled:
            return 0
        
        try:
            content = await fetch_text(
                feed.url,
                max_bytes=20 * 1024 * 1024,
                timeout_seconds=60,
            )
            
            # Detect format
            format_type = FeedParser.detect_format(content, feed.url)
            
            # Parse domains
            domains = FeedParser.parse(content, format_type)
            
            # Limit domains
            if len(domains) > self.max_domains_per_feed:
                domains = domains[:self.max_domains_per_feed]
            
            # Store
            self._domains[feed_id] = set(domains)
            feed.last_updated = utc_now()
            feed.domain_count = len(domains)
            
            # Cache to disk
            if self.cache_dir:
                await self._cache_feed(feed_id, domains)
            
            return len(domains)
            
        except httpx.HTTPError:
            return 0
    
    async def update_all_feeds(self) -> dict[str, int]:
        """
        Update all enabled feeds.
        
        Returns dict of feed_id -> domain count.
        """
        results = {}
        
        for feed_id, feed in self._feeds.items():
            if feed.enabled:
                count = await self.update_feed(feed_id)
                results[feed_id] = count
                
                # Small delay between feeds to be nice
                await asyncio.sleep(1)
        
        return results
    
    async def _cache_feed(self, feed_id: str, domains: list[str]) -> None:
        """Cache feed to disk."""
        if not self.cache_dir:
            return
        
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = self.cache_dir / f"{feed_id}.txt"
            
            content = "\n".join(sorted(domains))
            cache_file.write_text(content, encoding="utf-8")
        except Exception:
            pass
    
    async def _load_cached_feed(self, feed_id: str) -> list[str]:
        """Load feed from disk cache."""
        if not self.cache_dir:
            return []
        
        try:
            cache_file = self.cache_dir / f"{feed_id}.txt"
            if cache_file.exists():
                content = cache_file.read_text(encoding="utf-8")
                return [d.strip() for d in content.splitlines() if d.strip()]
        except Exception:
            pass
        
        return []
    
    def is_in_feed(self, domain: str) -> tuple[bool, FeedConfig | None]:
        """
        Check if domain is in any feed.
        
        Args:
            domain: Domain to check
        
        Returns:
            Tuple of (is_found, FeedConfig or None)
        """
        domain = domain.lower()
        
        for feed_id, domains in self._domains.items():
            if domain in domains:
                return True, self._feeds.get(feed_id)
        
        return False, None
    
    def get_matching_feeds(self, domain: str) -> list[FeedConfig]:
        """Get all feeds that contain this domain."""
        domain = domain.lower()
        matches = []
        
        for feed_id, domains in self._domains.items():
            if domain in domains:
                feed = self._feeds.get(feed_id)
                if feed:
                    matches.append(feed)
        
        return matches
    
    def get_all_domains(self) -> set[str]:
        """Get all domains from all feeds."""
        all_domains = set()
        for domains in self._domains.values():
            all_domains.update(domains)
        return all_domains
    
    def get_domains_by_category(
        self,
        category: ThreatCategory,
    ) -> set[str]:
        """Get domains for a specific category."""
        domains = set()
        
        for feed_id, feed in self._feeds.items():
            if category in feed.categories:
                feed_domains = self._domains.get(feed_id, set())
                domains.update(feed_domains)
        
        return domains
    
    async def start_auto_update(self, check_interval_hours: int = 1) -> None:
        """Start automatic feed updates."""
        if self._update_task and not self._update_task.done():
            return
        
        self._update_task = asyncio.create_task(
            self._auto_update_loop(check_interval_hours)
        )
    
    async def stop_auto_update(self) -> None:
        """Stop automatic feed updates."""
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
            self._update_task = None
    
    async def _auto_update_loop(self, check_interval_hours: int) -> None:
        """Background loop for automatic updates."""
        while True:
            try:
                now = utc_now()
                
                for feed_id, feed in self._feeds.items():
                    if not feed.enabled:
                        continue
                    
                    # Check if update needed
                    if feed.last_updated:
                        age = (now - feed.last_updated).total_seconds() / 3600
                        if age < feed.update_interval_hours:
                            continue
                    
                    await self.update_feed(feed_id)
                    await asyncio.sleep(5)  # Small delay between feeds
                
                # Sleep until next check
                await asyncio.sleep(check_interval_hours * 3600)
                
            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(60)  # Retry after error
    
    def get_stats(self) -> dict[str, Any]:
        """Get feed manager statistics."""
        total_domains = sum(len(d) for d in self._domains.values())
        
        return {
            "total_feeds": len(self._feeds),
            "enabled_feeds": sum(1 for f in self._feeds.values() if f.enabled),
            "total_domains": total_domains,
            "feeds": [
                {
                    "id": f.id,
                    "name": f.name,
                    "enabled": f.enabled,
                    "license": f.license,
                    "domain_count": f.domain_count,
                    "last_updated": f.last_updated.isoformat() if f.last_updated else None,
                    "categories": [c.value for c in f.categories],
                }
                for f in self._feeds.values()
            ],
        }
    
    async def close(self) -> None:
        """Close manager and cleanup resources."""
        await self.stop_auto_update()
        if self._client:
            await self._client.aclose()
            self._client = None
