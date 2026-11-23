"""
EasyPi NetProtection - CNAME Chain Analyzer

Detects hidden trackers and ad networks disguised behind CNAME records.
This technique is used by first-party tracking systems to bypass blockers.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import Any

from ..verdict.evidence import Evidence, EvidenceSource


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# SAFETY LIMITS
# ════════════════════════════════════════════════════════════════════════════════

MAX_CNAME_CHAIN_LENGTH = 10  # RFC recommends max 8, we allow 10 for edge cases
ANALYSIS_CACHE_TTL = 300     # Cache analysis results for 5 minutes
ANALYSIS_CACHE_SIZE = 10000  # Max cached analysis results


# ════════════════════════════════════════════════════════════════════════════════
# CDN/SERVICE ALLOWLIST - Legitimate CNAMEs that shouldn't be blocked
# ════════════════════════════════════════════════════════════════════════════════

# These are legitimate CDN/infrastructure domains that use CNAME
# but are NOT primarily tracking services
CDN_ALLOWLIST: frozenset[str] = frozenset({
    # Major CDNs (content delivery, not tracking)
    "cloudflare.com",
    "cloudflare-dns.com",
    "akamaiedge.net",
    "akamai.net",
    "edgesuite.net",
    "llnwd.net",           # Limelight
    "stackpathdns.com",
    "cdn77.org",
    "jsdelivr.net",
    "unpkg.com",
    
    # Cloud providers (infrastructure)
    "amazonaws.com",
    "azure.com",
    "azure-api.net",
    "windows.net",         # Azure Storage
    "googleusercontent.com",
    "googleapis.com",
    "gstatic.com",
    
    # Common legitimate services
    "github.io",
    "github.com",
    "gitlab.io",
    "netlify.app",
    "netlify.com",
    "vercel.app",
    "vercel.com",
    "pages.dev",           # Cloudflare Pages
    "workers.dev",         # Cloudflare Workers
    "heroku.com",
    "herokuapp.com",
    
    # Email/communication infrastructure
    "outlook.com",
    "office365.com",
    "mailgun.org",
    "sendgrid.net",
    "mcsv.net",            # Mailchimp
    
    # E-commerce platforms (legitimate first-party domains)
    "ebay.com",
    "ebay-us.com",
    "ebaystatic.com",
    "ebayimg.com",
    "ebayrtm.com",
    "amazon.com",
    "amazon-adsystem.com",
    "media-amazon.com",
    "ssl-images-amazon.com",
    "cloudfront.net",       # Amazon CloudFront
    
    # DNS providers
    "ns.cloudflare.com",
    "dnsimple.com",
    "dnsmadeeasy.com",
    "route53.amazonaws.com",
})


# Known tracker domains that are often hidden behind CNAMEs
KNOWN_TRACKER_DOMAINS: frozenset[str] = frozenset({
    # Analytics
    "omtrdc.net",           # Adobe Analytics
    "2o7.net",              # Adobe/Omniture
    "demdex.net",           # Adobe Audience Manager
    "sc.omtrdc.net",
    
    # Ad networks
    "adsrvr.org",           # The Trade Desk
    "adnxs.com",            # AppNexus
    "doubleclick.net",      # Google Ads
    "googlesyndication.com",
    "googleadservices.com",
    
    # Tracking services
    "criteo.com",
    "criteo.net",
    "taboola.com",
    "outbrain.com",
    "mookie1.com",          # Media Math
    "rlcdn.com",            # Rapleaf
    "bluekai.com",
    "krxd.net",             # Krux/Salesforce DMP
    "exelator.com",
    "eyeota.net",
    "tapad.com",
    "quantserve.com",
    "scorecardresearch.com",
    "imrworldwide.com",
    
    # NOTE: Removed CDN domains that can be legitimate:
    # cloudfront.net, fastly.net, edgekey.net, trafficmanager.net, azureedge.net
    # These are now in CDN_ALLOWLIST and checked contextually
    
    # Social tracking (first-party tracking endpoints)
    "facebook.com",         # Only when CNAME points here from non-FB domain
    "fbcdn.net",
    "snap.com",
    
    # Known first-party tracking CNAMEs
    "eulerian.net",
    "at-o.net",             # AT Internet
    "wt-safetag.com",       # Webtrekk
})

# Patterns that indicate tracking even if not in known list
TRACKER_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r"^track(er|ing)?\."),
    re.compile(r"\.track(er|ing)?\."),
    re.compile(r"^analytic[s]?\."),
    re.compile(r"\.analytic[s]?\."),
    re.compile(r"^metric[s]?\."),
    re.compile(r"^telemetry\."),
    re.compile(r"^beacon\."),
    re.compile(r"^pixel\."),
    re.compile(r"^tag\."),
    re.compile(r"^collect\."),
    re.compile(r"^log\."),
    re.compile(r"^stats?\."),
)


@dataclass
class CNAMEChainResult:
    """Result of CNAME chain analysis."""
    
    original_domain: str
    chain: list[str]
    final_target: str
    is_cloaked: bool = False
    tracker_detected: bool = False
    detected_tracker: str | None = None
    confidence: int = 0
    reason: str = ""


class CNAMEChainAnalyzer:
    """
    Analyzes CNAME chains to detect hidden trackers.
    
    CNAME cloaking is a technique where first-party domains
    point to third-party trackers via CNAME records:
    
    analytics.example.com → CNAME → tracker.adnetwork.com
    
    This bypasses traditional ad blockers that only check
    the original domain.
    
    Features:
    - Chain length limits (fail-safe against loops/infinite chains)
    - Cycle detection
    - CDN/infrastructure allowlist  
    - Analysis result caching
    - Metrics without exposing full chains in logs
    """
    
    def __init__(self):
        self._known_trackers = set(KNOWN_TRACKER_DOMAINS)
        self._cdn_allowlist = set(CDN_ALLOWLIST)
        self._patterns = TRACKER_PATTERNS
        
        # Statistics (metrics only, no PII)
        self._chains_analyzed = 0
        self._cloaking_detected = 0
        self._chains_truncated = 0
        self._cycles_detected = 0
        self._allowlist_hits = 0
        self._cache_hits = 0
        self._cache_misses = 0
        
        # Analysis cache: (domain, chain_tuple) -> (result, timestamp)
        self._analysis_cache: dict[tuple[str, tuple[str, ...]], tuple[CNAMEChainResult, float]] = {}
    
    def add_tracker_domain(self, domain: str) -> None:
        """Add a domain to the known tracker list."""
        self._known_trackers.add(domain.lower().strip("."))
        self._clear_cache()
    
    def remove_tracker_domain(self, domain: str) -> None:
        """Remove a domain from the known tracker list."""
        self._known_trackers.discard(domain.lower().strip("."))
        self._clear_cache()
    
    def add_to_allowlist(self, domain: str) -> None:
        """Add a domain to the CDN/service allowlist."""
        self._cdn_allowlist.add(domain.lower().strip("."))
        self._clear_cache()
    
    def remove_from_allowlist(self, domain: str) -> None:
        """Remove a domain from the CDN/service allowlist."""
        self._cdn_allowlist.discard(domain.lower().strip("."))
        self._clear_cache()
    
    def _clear_cache(self) -> None:
        """Clear analysis cache when rules change."""
        self._analysis_cache.clear()
    
    def _get_cached_result(self, domain: str, chain: list[str]) -> CNAMEChainResult | None:
        """Get cached analysis result if still valid."""
        cache_key = (domain.lower(), tuple(c.lower() for c in chain))
        cached = self._analysis_cache.get(cache_key)
        
        if cached:
            result, timestamp = cached
            if time.time() - timestamp < ANALYSIS_CACHE_TTL:
                self._cache_hits += 1
                return result
            # Expired, remove
            del self._analysis_cache[cache_key]
        
        self._cache_misses += 1
        return None
    
    def _cache_result(self, domain: str, chain: list[str], result: CNAMEChainResult) -> None:
        """Cache analysis result."""
        # Evict old entries if cache is full
        if len(self._analysis_cache) >= ANALYSIS_CACHE_SIZE:
            # Remove oldest 10%
            now = time.time()
            to_remove = []
            for key, (_, ts) in self._analysis_cache.items():
                if now - ts > ANALYSIS_CACHE_TTL or len(to_remove) < ANALYSIS_CACHE_SIZE // 10:
                    to_remove.append(key)
            for key in to_remove:
                self._analysis_cache.pop(key, None)
        
        cache_key = (domain.lower(), tuple(c.lower() for c in chain))
        self._analysis_cache[cache_key] = (result, time.time())
    
    async def analyze(
        self,
        domain: str,
        context: dict[str, Any],
    ) -> list[Evidence]:
        """
        Analyze domain for CNAME cloaking.
        
        Note: This is typically called post-resolution when
        the CNAME chain is already known from the DNS response.
        """
        # Get CNAME chain from context if available
        cname_chain = context.get("cname_chain", [])
        
        if not cname_chain:
            return []
        
        result = self.analyze_chain(domain, cname_chain)
        
        evidence_items: list[Evidence] = []
        
        if result.tracker_detected:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_CNAME,
                signal=f"CNAME cloaking detected: {domain} → {result.detected_tracker}",
                confidence=result.confidence,
                weight=0.85,
                suggested_action="deny",
                metadata={
                    "original_domain": domain,
                    "cname_chain": result.chain,
                    "tracker": result.detected_tracker,
                    "reason": result.reason,
                },
            ))
        elif result.is_cloaked:
            # Suspicious but not definitively a tracker
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_CNAME,
                signal=f"suspicious CNAME chain: {domain} → {result.final_target}",
                confidence=result.confidence,
                weight=0.5,
                suggested_action="observe",
                metadata={
                    "original_domain": domain,
                    "cname_chain": result.chain,
                    "final_target": result.final_target,
                },
            ))
        
        return evidence_items
    
    def analyze_chain(
        self,
        original_domain: str,
        cname_chain: list[str],
    ) -> CNAMEChainResult:
        """
        Analyze a CNAME chain for cloaking.
        
        Args:
            original_domain: The domain originally queried
            cname_chain: List of domains in the CNAME chain
        
        Returns:
            Analysis result with detection details
            
        Safety features:
        - Chain length limit (MAX_CNAME_CHAIN_LENGTH)
        - Cycle detection
        - CDN/infrastructure allowlist
        - Result caching
        """
        self._chains_analyzed += 1
        
        if not cname_chain:
            return CNAMEChainResult(
                original_domain=original_domain,
                chain=[],
                final_target=original_domain,
            )
        
        # Check cache first
        cached = self._get_cached_result(original_domain, cname_chain)
        if cached:
            return cached
        
        # === SAFETY: Limit chain length ===
        if len(cname_chain) > MAX_CNAME_CHAIN_LENGTH:
            self._chains_truncated += 1
            logger.debug(f"CNAME chain truncated: {len(cname_chain)} > {MAX_CNAME_CHAIN_LENGTH}")
            cname_chain = cname_chain[:MAX_CNAME_CHAIN_LENGTH]
        
        original_lower = original_domain.lower().strip(".")
        chain_lower = [d.lower().strip(".") for d in cname_chain]
        
        # === SAFETY: Detect cycles ===
        seen = {original_lower}
        for cname in chain_lower:
            if cname in seen:
                self._cycles_detected += 1
                logger.debug(f"CNAME cycle detected at: {cname}")
                # Return safe result - don't block on cycles
                result = CNAMEChainResult(
                    original_domain=original_domain,
                    chain=cname_chain,
                    final_target=cname,
                    is_cloaked=False,
                    tracker_detected=False,
                    confidence=0,
                    reason="cycle_detected",
                )
                self._cache_result(original_domain, cname_chain, result)
                return result
            seen.add(cname)
        
        final_target = chain_lower[-1] if chain_lower else original_lower
        
        # Get base domains for comparison
        original_base = self._get_base_domain(original_lower)
        final_base = self._get_base_domain(final_target)
        
        # === CDN/ALLOWLIST CHECK ===
        # If final target is in allowlist, allow it regardless of cross-domain
        if final_base in self._cdn_allowlist:
            self._allowlist_hits += 1
            result = CNAMEChainResult(
                original_domain=original_domain,
                chain=cname_chain,
                final_target=final_target,
                is_cloaked=False,
                tracker_detected=False,
                confidence=0,
                reason="cdn_allowlist",
            )
            self._cache_result(original_domain, cname_chain, result)
            return result
        
        # Check if this is cross-domain CNAME (potential cloaking)
        is_cross_domain = original_base != final_base
        
        # Check each domain in chain against known trackers
        for cname in chain_lower:
            cname_base = self._get_base_domain(cname)
            
            # Skip if this CNAME is in allowlist (intermediate CDN hops)
            if cname_base in self._cdn_allowlist:
                continue
            
            if cname_base in self._known_trackers:
                self._cloaking_detected += 1
                result = CNAMEChainResult(
                    original_domain=original_domain,
                    chain=cname_chain,
                    final_target=final_target,
                    is_cloaked=True,
                    tracker_detected=True,
                    detected_tracker=cname,
                    confidence=95,
                    reason=f"known tracker domain: {cname_base}",
                )
                self._cache_result(original_domain, cname_chain, result)
                return result
            
            # Check patterns (but not for allowlisted domains)
            for pattern in self._patterns:
                if pattern.search(cname):
                    self._cloaking_detected += 1
                    result = CNAMEChainResult(
                        original_domain=original_domain,
                        chain=cname_chain,
                        final_target=final_target,
                        is_cloaked=True,
                        tracker_detected=True,
                        detected_tracker=cname,
                        confidence=75,
                        reason=f"tracking pattern in CNAME: {pattern.pattern}",
                    )
                    self._cache_result(original_domain, cname_chain, result)
                    return result
        
        # Cross-domain CNAME is suspicious even if not a known tracker
        # But with lower confidence and only if not to allowlisted domain
        if is_cross_domain and final_base not in self._cdn_allowlist:
            # Calculate suspicion level
            confidence = 40
            
            # Long chains are more suspicious
            if len(cname_chain) > 2:
                confidence += 10
            
            # Very short TTL cross-domain is suspicious (tracking pixel behavior)
            # But we don't have TTL here, so skip
            
            result = CNAMEChainResult(
                original_domain=original_domain,
                chain=cname_chain,
                final_target=final_target,
                is_cloaked=True,
                tracker_detected=False,
                confidence=max(0, confidence),
                reason=f"cross-domain CNAME: {original_base} → {final_base}",
            )
            self._cache_result(original_domain, cname_chain, result)
            return result
        
        # Clean chain
        result = CNAMEChainResult(
            original_domain=original_domain,
            chain=cname_chain,
            final_target=final_target,
            is_cloaked=False,
            tracker_detected=False,
            confidence=0,
        )
        self._cache_result(original_domain, cname_chain, result)
        return result
    
    def _get_base_domain(self, domain: str) -> str:
        """Extract the base domain (e.g., example.com from sub.example.com)."""
        parts = domain.split(".")
        if len(parts) >= 2:
            # Handle common SLDs like co.uk, com.au
            common_slds = {"co.uk", "com.au", "co.jp", "com.br", "co.nz"}
            if len(parts) >= 3:
                potential_sld = ".".join(parts[-2:])
                if potential_sld in common_slds:
                    return ".".join(parts[-3:])
            return ".".join(parts[-2:])
        return domain
    
    def is_known_tracker(self, domain: str) -> bool:
        """Check if domain is a known tracker."""
        base = self._get_base_domain(domain.lower().strip("."))
        return base in self._known_trackers
    
    def is_allowlisted(self, domain: str) -> bool:
        """Check if domain is in CDN/service allowlist."""
        base = self._get_base_domain(domain.lower().strip("."))
        return base in self._cdn_allowlist
    
    def check_single_cname(self, cname_target: str) -> tuple[bool, str]:
        """
        Quick check if a single CNAME target is suspicious.
        
        Returns:
            Tuple of (is_suspicious, reason)
        """
        target_lower = cname_target.lower().strip(".")
        base = self._get_base_domain(target_lower)
        
        # Allowlist takes precedence
        if base in self._cdn_allowlist:
            return False, "allowlisted"
        
        if base in self._known_trackers:
            return True, f"known tracker: {base}"
        
        for pattern in self._patterns:
            if pattern.search(target_lower):
                return True, f"tracking pattern: {pattern.pattern}"
        
        return False, ""
    
    def get_stats(self) -> dict[str, Any]:
        """
        Get analyzer statistics (metrics only, no PII/domains).
        
        Safe to log - contains only aggregate counts.
        """
        cache_total = self._cache_hits + self._cache_misses
        return {
            "chains_analyzed": self._chains_analyzed,
            "cloaking_detected": self._cloaking_detected,
            "chains_truncated": self._chains_truncated,
            "cycles_detected": self._cycles_detected,
            "allowlist_hits": self._allowlist_hits,
            "detection_rate": (
                self._cloaking_detected / self._chains_analyzed
                if self._chains_analyzed > 0 else 0.0
            ),
            "cache_hit_rate": (
                self._cache_hits / cache_total
                if cache_total > 0 else 0.0
            ),
            "cache_size": len(self._analysis_cache),
            "known_trackers_count": len(self._known_trackers),
            "allowlist_count": len(self._cdn_allowlist),
        }


# Singleton instance
_analyzer: CNAMEChainAnalyzer | None = None


def get_cname_analyzer() -> CNAMEChainAnalyzer:
    """Get the CNAME chain analyzer instance."""
    global _analyzer
    if _analyzer is None:
        _analyzer = CNAMEChainAnalyzer()
    return _analyzer
