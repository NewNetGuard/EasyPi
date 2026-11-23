"""
Safe Search Enforcer

DNS-level enforcement of Safe Search for major search engines.

Supported Services:
- Google: Forces SafeSearch via forcesafesearch.google.com
- Bing: Forces Strict mode via strict.bing.com
- YouTube: Forces Restricted Mode via restrict.youtube.com
- DuckDuckGo: Forces Safe mode via safe.duckduckgo.com

How it works:
- Returns CNAME records pointing to safe/restricted endpoints
- Search engines recognize these special hostnames and enforce filtering
- Works at DNS level - cannot be bypassed by browser settings

LIMITATIONS (document in UI):
- Only works when clients use this DNS server
- DoH/DoT configured on devices will bypass this protection
- Direct IP access to search engines bypasses DNS
- VPNs may use their own DNS servers
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, FrozenSet

logger = logging.getLogger(__name__)

# Short TTL for CNAME redirects (5 minutes)
# Ensures changes propagate quickly if SafeSearch is toggled
SAFESEARCH_TTL_SECONDS: int = 300


# ═══════════════════════════════════════════════════════════════════════════════
# SAFE SEARCH DEFINITIONS
# ═══════════════════════════════════════════════════════════════════════════════

class SafeSearchTarget(Enum):
    """Safe search enforcement targets."""
    
    GOOGLE = "google"
    BING = "bing"
    YOUTUBE = "youtube"
    DUCKDUCKGO = "duckduckgo"
    ALL = "all"


@dataclass(frozen=True, slots=True)
class SafeSearchRewrite:
    """
    A safe search DNS rewrite rule.
    
    Immutable and memory-efficient (frozen + slots).
    """
    
    domain: str                     # Original domain to intercept
    target: str                     # Safe/restricted target
    service: SafeSearchTarget       # Service type
    rewrite_type: str = "CNAME"     # Usually CNAME
    ttl: int = SAFESEARCH_TTL_SECONDS


# Safe endpoint domains (to detect CNAME cycles)
SAFE_ENDPOINTS: FrozenSet[str] = frozenset({
    "forcesafesearch.google.com",
    "strict.bing.com",
    "restrict.youtube.com",
    "restrictmoderate.youtube.com",
    "safe.duckduckgo.com",
})


def _build_google_rewrites() -> tuple[SafeSearchRewrite, ...]:
    """Build Google Safe Search rewrites (comprehensive regional coverage)."""
    target = "forcesafesearch.google.com"
    domains = ["google.com", "www.google.com"]
    
    # Regional TLDs
    for tld in [
        "co.uk", "de", "fr", "es", "it", "nl", "pl", "ru", "be", "at", "ch",
        "se", "no", "dk", "fi", "pt", "gr", "ie", "cz", "hu", "ro", "ua",
        "ca", "com.br", "com.mx", "com.ar", "cl", "co", "com.pe", "com.ve",
        "co.jp", "co.kr", "co.in", "com.au", "co.nz", "com.sg", "com.hk",
        "com.tw", "co.th", "com.my", "co.id", "com.ph", "com.vn",
        "co.za", "com.eg", "ae", "co.il", "com.tr", "com.sa",
    ]:
        domains.extend([f"google.{tld}", f"www.google.{tld}"])
    
    return tuple(SafeSearchRewrite(d, target, SafeSearchTarget.GOOGLE) for d in domains)


GOOGLE_REWRITES: tuple[SafeSearchRewrite, ...] = _build_google_rewrites()


def _build_bing_rewrites() -> tuple[SafeSearchRewrite, ...]:
    """Build Bing Safe Search rewrites."""
    target = "strict.bing.com"
    return tuple(SafeSearchRewrite(d, target, SafeSearchTarget.BING) for d in [
        "bing.com", "www.bing.com", "cn.bing.com", "global.bing.com",
    ])


BING_REWRITES: tuple[SafeSearchRewrite, ...] = _build_bing_rewrites()


def _build_youtube_rewrites() -> tuple[SafeSearchRewrite, ...]:
    """Build YouTube Restricted Mode rewrites."""
    target = "restrict.youtube.com"
    return tuple(SafeSearchRewrite(d, target, SafeSearchTarget.YOUTUBE) for d in [
        "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
        "youtubei.googleapis.com", "youtube.googleapis.com",
        "youtube-nocookie.com", "www.youtube-nocookie.com",
        "youtubekids.com", "www.youtubekids.com",
    ])


YOUTUBE_REWRITES: tuple[SafeSearchRewrite, ...] = _build_youtube_rewrites()


def _build_duckduckgo_rewrites() -> tuple[SafeSearchRewrite, ...]:
    """Build DuckDuckGo Safe Search rewrites."""
    target = "safe.duckduckgo.com"
    return tuple(SafeSearchRewrite(d, target, SafeSearchTarget.DUCKDUCKGO) for d in [
        "duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com",
        "duck.com", "www.duck.com",
    ])


DUCKDUCKGO_REWRITES: tuple[SafeSearchRewrite, ...] = _build_duckduckgo_rewrites()

# All rewrites combined (immutable tuple)
SAFESEARCH_REWRITES: tuple[SafeSearchRewrite, ...] = (
    GOOGLE_REWRITES + 
    BING_REWRITES + 
    YOUTUBE_REWRITES + 
    DUCKDUCKGO_REWRITES
)

# Pre-built domain lookup map (O(1) lookup, no allocations at query time)
_DOMAIN_MAP: dict[str, SafeSearchRewrite] = {
    r.domain.lower(): r for r in SAFESEARCH_REWRITES
}


# ═══════════════════════════════════════════════════════════════════════════════
# SAFE SEARCH ENFORCER
# ═══════════════════════════════════════════════════════════════════════════════

# Singleton
_enforcer_instance: "SafeSearchEnforcer | None" = None
_enforcer_lock = threading.Lock()


def get_safesearch_enforcer() -> "SafeSearchEnforcer":
    """Get the singleton SafeSearchEnforcer."""
    global _enforcer_instance
    
    if _enforcer_instance is None:
        with _enforcer_lock:
            if _enforcer_instance is None:
                _enforcer_instance = SafeSearchEnforcer()
    
    return _enforcer_instance


class SafeSearchEnforcer:
    """
    Enforces Safe Search at DNS level.
    
    IMPORTANT LIMITATIONS (document in UI):
    - Only works when clients use this DNS server
    - DoH (DNS over HTTPS) in browsers will BYPASS this
    - DoT (DNS over TLS) on devices will BYPASS this
    - VPNs typically use their own DNS servers
    - Direct IP access to search engines bypasses DNS
    
    Usage:
        enforcer = get_safesearch_enforcer()
        result = enforcer.check(domain, safe_search_enabled=True)
        if result:
            # Return CNAME to result.target with TTL=result.ttl
            pass
    """
    
    __slots__ = ('_lock', '_checks', '_redirects', '_redirects_by_service')
    
    def __init__(self):
        """Initialize the enforcer."""
        self._lock = threading.Lock()
        
        # Stats only (no PII stored)
        self._checks: int = 0
        self._redirects: int = 0
        self._redirects_by_service: dict[str, int] = {
            t.value: 0 for t in SafeSearchTarget if t != SafeSearchTarget.ALL
        }
        
        # Log only rule count, not domains
        logger.info(f"SafeSearch enforcer initialized with {len(SAFESEARCH_REWRITES)} rules")
    
    @staticmethod
    def is_safe_endpoint(domain: str) -> bool:
        """Check if domain is a safe endpoint (prevents CNAME cycles)."""
        return domain.lower().rstrip('.') in SAFE_ENDPOINTS
    
    def check(
        self,
        domain: str,
        safe_search_enabled: bool = True,
        targets: set[SafeSearchTarget] | None = None,
    ) -> SafeSearchRewrite | None:
        """
        Check if a domain should be redirected for Safe Search.
        
        Thread-safe. O(1) lookup, minimal allocations.
        
        Args:
            domain: The domain being queried
            safe_search_enabled: Whether safe search is enabled for this client
            targets: Optional set of specific targets to enforce (default: all)
        
        Returns:
            SafeSearchRewrite if redirect needed, None otherwise
        """
        self._checks += 1
        
        if not safe_search_enabled:
            return None
        
        domain_lower = domain.lower().rstrip('.')
        
        # Prevent CNAME cycles - don't redirect safe endpoints
        if domain_lower in SAFE_ENDPOINTS:
            return None
        
        # O(1) lookup in pre-built map
        rewrite = _DOMAIN_MAP.get(domain_lower)
        
        if rewrite is None:
            return None
        
        # Check if this target is enabled (optional filtering)
        if targets is not None:
            if SafeSearchTarget.ALL not in targets and rewrite.service not in targets:
                return None
        
        # Increment stats (no PII logging)
        self._redirects += 1
        with self._lock:
            self._redirects_by_service[rewrite.service.value] = (
                self._redirects_by_service.get(rewrite.service.value, 0) + 1
            )
        
        return rewrite
    
    def get_redirect_target(
        self,
        domain: str,
        safe_search_enabled: bool = True,
    ) -> str | None:
        """Get the redirect target for a domain, if any."""
        rewrite = self.check(domain, safe_search_enabled)
        return rewrite.target if rewrite else None
    
    def is_safesearch_domain(self, domain: str) -> bool:
        """Check if a domain is a known safe search endpoint."""
        return self.is_safe_endpoint(domain)
    
    def list_rules(
        self,
        service: SafeSearchTarget | None = None,
    ) -> list[SafeSearchRewrite]:
        """List safe search rules, optionally filtered by service."""
        if service is None or service == SafeSearchTarget.ALL:
            return list(SAFESEARCH_REWRITES)
        return [r for r in SAFESEARCH_REWRITES if r.service == service]
    
    @property
    def ttl(self) -> int:
        """Get the TTL for SafeSearch CNAME responses."""
        return SAFESEARCH_TTL_SECONDS
    
    @property
    def rule_count(self) -> int:
        """Get total number of rules."""
        return len(SAFESEARCH_REWRITES)
    
    def stats(self) -> dict[str, Any]:
        """Get enforcer statistics (no PII)."""
        return {
            "total_rules": len(SAFESEARCH_REWRITES),
            "rules_by_service": {
                "google": len(GOOGLE_REWRITES),
                "bing": len(BING_REWRITES),
                "youtube": len(YOUTUBE_REWRITES),
                "duckduckgo": len(DUCKDUCKGO_REWRITES),
            },
            "ttl_seconds": SAFESEARCH_TTL_SECONDS,
            "checks": self._checks,
            "redirects": self._redirects,
            "redirects_by_service": dict(self._redirects_by_service),
            "redirect_rate": round(self._redirects / self._checks, 4) if self._checks > 0 else 0,
        }
    
    @staticmethod
    def get_bypass_warning() -> str:
        """Get UI warning about SafeSearch limitations."""
        return (
            "⚠️ SafeSearch Limitations:\n"
            "• Only works when devices use this DNS server\n"
            "• DoH (DNS over HTTPS) in browsers bypasses this\n"
            "• DoT (DNS over TLS) on devices bypasses this\n"
            "• VPNs typically use their own DNS servers\n"
            "• Direct IP access bypasses DNS\n\n"
            "For full protection, also block DoH/DoT providers."
        )
