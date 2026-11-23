"""
EasyPi NetProtection - Domain Intelligence

Provides domain categorization, reputation scoring, and threat detection
based on domain characteristics and external intelligence sources.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..core.cache import LRUCache
from ..verdict.evidence import Evidence, EvidenceSource


logger = logging.getLogger(__name__)


class DomainCategory(str, Enum):
    """Domain content categories."""
    
    # Unwanted
    ADVERTISING = "advertising"
    TRACKING = "tracking"
    TELEMETRY = "telemetry"
    CRYPTOMINING = "cryptomining"
    
    # Dangerous
    MALWARE = "malware"
    PHISHING = "phishing"
    SPAM = "spam"
    BOTNET = "botnet"
    
    # Content
    ADULT = "adult"
    GAMBLING = "gambling"
    SOCIAL_MEDIA = "social_media"
    STREAMING = "streaming"
    GAMING = "gaming"
    
    # Infrastructure
    CDN = "cdn"
    CLOUD = "cloud"
    VPN = "vpn"
    PROXY = "proxy"
    
    # Safe
    SEARCH_ENGINE = "search_engine"
    EMAIL = "email"
    BANKING = "banking"
    GOVERNMENT = "government"
    EDUCATION = "education"
    
    # Unknown
    UNKNOWN = "unknown"


@dataclass
class DomainReputation:
    """Reputation information for a domain."""
    
    domain: str
    score: int  # 0-100, higher = safer
    categories: list[DomainCategory] = field(default_factory=list)
    is_known_safe: bool = False
    first_seen_days: int | None = None
    registrar: str | None = None
    flags: list[str] = field(default_factory=list)
    # Penalty from the shape of the name alone (zone, digits, hyphens, length).
    # Words in the name never contribute to it.
    structure_penalty: int = 0

    @property
    def is_suspicious(self) -> bool:
        """Check if domain has suspicious characteristics."""
        return self.score < 50 or len(self.flags) >= 2

    @property
    def looks_generated(self) -> bool:
        """The name is shaped like a machine-generated one (DGA, throwaway host)."""
        return self.structure_penalty > GENERATED_NAME_PENALTY


# A block needs at least three of the four structural signs (suspicious zone,
# very long name, many hyphens, many digits); the largest two-sign penalty is
# exactly 30. One or two signs alone (a ".xyz" shop, a video CDN host) only
# make a domain suspicious. Same threshold as the old reputation score < 20.
GENERATED_NAME_PENALTY = 30


def _word(word: str) -> str:
    """Match a whole word inside a domain name: label and hyphen boundaries only.

    A plain substring makes "virustotal.com" a virus and "essex.ac.uk" adult.
    """
    return rf"(?<![a-z0-9]){word}(?![a-z0-9])"


# Known domain patterns for quick categorization. A name is only a hint: these
# categories never block on their own (see DomainIntelProvider.analyze). Ad and
# tracker networks are blocked by the blocklists, which run before intel. What
# can block is the shape of a name (see GENERATED_NAME_PENALTY), never a word.
KNOWN_PATTERNS: dict[DomainCategory, list[str]] = {
    DomainCategory.ADVERTISING: [
        r"^ad[sx]?\.",
        r"\.ad[sx]?\.",
        r"doubleclick",
        r"googlesyndication",
        r"googleadservices",
        _word("advertising"),
        _word("adserver"),
        _word("adtech"),
        r"adnxs",
        r"adsrvr",
        r"taboola",
        r"outbrain",
    ],
    DomainCategory.TRACKING: [
        _word("tracking"),
        _word("tracker"),
        _word("analytics"),
        _word("telemetry"),
        _word("metrics"),
        _word("pixel"),
        _word("beacon"),
        r"hotjar",
        r"mixpanel",
        _word("amplitude"),
        r"segment\.io",
        r"facebook.*pixel",
    ],
    DomainCategory.MALWARE: [
        _word("malware"),
        _word("virus"),
        _word("trojan"),
    ],
    DomainCategory.ADULT: [
        _word("porn"),
        _word("xxx"),
        _word("adult"),
        _word("sex"),
    ],
    DomainCategory.SOCIAL_MEDIA: [
        r"facebook\.com",
        r"instagram\.com",
        r"twitter\.com",
        r"tiktok\.com",
        r"snapchat\.com",
        r"linkedin\.com",
    ],
    DomainCategory.SEARCH_ENGINE: [
        r"google\.com",
        r"bing\.com",
        r"duckduckgo\.com",
        r"yahoo\.com",
        r"yandex\.",
    ],
    DomainCategory.CDN: [
        r"cloudflare",
        r"akamai",
        r"fastly",
        r"cloudfront",
        r"cdn\.",
        r"\.cdn\.",
    ],
}

# Known safe domains (whitelist)
KNOWN_SAFE_DOMAINS: set[str] = {
    "google.com",
    "youtube.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "github.com",
    "stackoverflow.com",
    "wikipedia.org",
    "cloudflare.com",
}

# Suspicious TLDs
SUSPICIOUS_TLDS: set[str] = {
    "xyz", "top", "club", "work", "date", "loan",
    "download", "stream", "gq", "ml", "cf", "ga", "tk",
    "buzz", "wang", "win", "bid", "click", "link",
}


class DomainIntelProvider:
    """
    Domain intelligence provider.
    
    Analyzes domains for:
    - Category classification
    - Reputation scoring
    - Threat indicators
    - Age and registration info
    """
    
    def __init__(self):
        self._pattern_cache: dict[DomainCategory, list[re.Pattern]] = {}
        self._compile_patterns()
        
        # Cache for reputation lookups
        self._reputation_cache: LRUCache[DomainReputation] = LRUCache(
            max_size=10000,
            default_ttl=3600,  # 1 hour
        )
        
        # Statistics
        self._lookups = 0
        self._cache_hits = 0
    
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for efficiency."""
        for category, patterns in KNOWN_PATTERNS.items():
            self._pattern_cache[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
    
    async def analyze(
        self,
        domain: str,
        context: dict[str, Any],
    ) -> list[Evidence]:
        """
        Analyze domain and return evidence items.
        
        Implements the IntelProvider protocol.
        """
        self._lookups += 1
        evidence_items: list[Evidence] = []
        
        # Get or compute reputation
        reputation = await self.get_reputation(domain)
        
        # Generate evidence based on reputation
        if reputation.is_known_safe:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_DOMAIN,
                signal=f"domain is known safe (score: {reputation.score})",
                confidence=90,
                weight=0.7,
                suggested_action="allow",
                metadata={
                    "categories": [c.value for c in reputation.categories],
                },
            ))

        elif reputation.looks_generated:
            structure = [flag for flag in reputation.flags if flag in self._STRUCTURE_FLAGS]
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_DOMAIN,
                signal=f"domain name looks machine-generated ({', '.join(structure)})",
                confidence=95,
                weight=0.9,
                suggested_action="deny",
                metadata={"flags": structure, "basis": "domain_structure"},
            ))

        elif reputation.is_suspicious:
            evidence_items.append(Evidence(
                source=EvidenceSource.INTEL_DOMAIN,
                signal=f"domain has suspicious indicators (score: {reputation.score})",
                confidence=60,
                weight=0.6,
                suggested_action="observe",
                metadata={
                    "flags": reputation.flags,
                },
            ))
        
        # Category evidence comes from words in the domain name only. A word is
        # a hint, never proof: "virustotal.com" is an antivirus service and
        # "tracking.dpd.de" a parcel tracker. Name categories are therefore
        # recorded for review and never block on their own; real blocking
        # comes from blocklists, threat feeds and multi-signal heuristics.
        for category in reputation.categories:
            if category in self._NAME_HINT_CATEGORIES:
                evidence_items.append(Evidence(
                    source=EvidenceSource.INTEL_DOMAIN,
                    signal=f"domain name suggests {category.value}",
                    confidence=60,
                    weight=0.5,
                    suggested_action="observe",
                    metadata={"category": category.value, "basis": "domain_name"},
                ))

        return evidence_items

    _NAME_HINT_CATEGORIES = frozenset({
        DomainCategory.ADVERTISING,
        DomainCategory.TRACKING,
        DomainCategory.MALWARE,
        DomainCategory.PHISHING,
        DomainCategory.ADULT,
    })

    _STRUCTURE_FLAGS = frozenset({
        "suspicious_tld",
        "very_long_domain",
        "excessive_hyphens",
        "high_numeric_ratio",
    })

    async def get_reputation(self, domain: str) -> DomainReputation:
        """Get reputation for a domain."""
        # Check cache
        cached = await self._reputation_cache.get(domain)
        if cached is not None:
            self._cache_hits += 1
            return cached
        
        # Compute reputation
        reputation = self._compute_reputation(domain)
        
        # Cache result
        await self._reputation_cache.set(domain, reputation)
        
        return reputation
    
    def _compute_reputation(self, domain: str) -> DomainReputation:
        """Compute reputation score and categories for domain."""
        domain_lower = domain.lower().strip(".")
        
        categories: list[DomainCategory] = []
        flags: list[str] = []
        score = 50  # Start neutral
        
        # Check known safe domains
        base_domain = self._get_base_domain(domain_lower)
        if base_domain in KNOWN_SAFE_DOMAINS:
            return DomainReputation(
                domain=domain,
                score=95,
                categories=[DomainCategory.UNKNOWN],
                is_known_safe=True,
            )
        
        # Check pattern matches
        for category, patterns in self._pattern_cache.items():
            for pattern in patterns:
                if pattern.search(domain_lower):
                    categories.append(category)
                    break
        
        # Adjust score based on categories
        if DomainCategory.MALWARE in categories:
            score = 5
            flags.append("malware_pattern")
        elif DomainCategory.PHISHING in categories:
            score = 5
            flags.append("phishing_pattern")
        elif DomainCategory.ADVERTISING in categories:
            score = 30
            flags.append("advertising_domain")
        elif DomainCategory.TRACKING in categories:
            score = 25
            flags.append("tracking_domain")
        elif DomainCategory.ADULT in categories:
            score = 40
            flags.append("adult_content")
        
        structure_penalty = 0

        # Check TLD
        tld = self._get_tld(domain_lower)
        if tld in SUSPICIOUS_TLDS:
            structure_penalty += 15
            flags.append("suspicious_tld")

        # Check domain length (very long = suspicious)
        if len(domain_lower) > 50:
            structure_penalty += 10
            flags.append("very_long_domain")

        # Check for excessive hyphens (DGA indicator)
        if domain_lower.count("-") > 3:
            structure_penalty += 10
            flags.append("excessive_hyphens")

        # Check for numeric patterns (DGA indicator)
        numeric_ratio = sum(c.isdigit() for c in domain_lower) / max(len(domain_lower), 1)
        if numeric_ratio > 0.3:
            structure_penalty += 15
            flags.append("high_numeric_ratio")

        # Clamp score
        score = max(0, min(100, score - structure_penalty))

        if not categories:
            categories.append(DomainCategory.UNKNOWN)
        
        return DomainReputation(
            domain=domain,
            score=score,
            categories=categories,
            is_known_safe=False,
            flags=flags,
            structure_penalty=structure_penalty,
        )
    
    def _get_base_domain(self, domain: str) -> str:
        """Extract base domain (e.g., google.com from www.google.com)."""
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return domain
    
    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        parts = domain.split(".")
        if parts:
            return parts[-1]
        return ""
    
    def categorize(self, domain: str) -> list[DomainCategory]:
        """Quick categorization without full reputation lookup."""
        domain_lower = domain.lower()
        categories = []
        
        for category, patterns in self._pattern_cache.items():
            for pattern in patterns:
                if pattern.search(domain_lower):
                    categories.append(category)
                    break
        
        return categories or [DomainCategory.UNKNOWN]
    
    def is_safe_search_domain(self, domain: str) -> bool:
        """Check if domain should have SafeSearch enforced."""
        safe_search_domains = {
            "google.com", "google.co.uk", "google.de", "google.fr",
            "youtube.com",
            "bing.com",
            "duckduckgo.com",
        }
        base = self._get_base_domain(domain.lower())
        return base in safe_search_domains
    
    def get_stats(self) -> dict[str, Any]:
        """Get provider statistics."""
        return {
            "total_lookups": self._lookups,
            "cache_hits": self._cache_hits,
            "cache_hit_ratio": (
                self._cache_hits / self._lookups
                if self._lookups > 0 else 0.0
            ),
            "cache_size": self._reputation_cache._cache_size if hasattr(self._reputation_cache, '_cache_size') else 0,
        }


# Singleton instance
_provider: DomainIntelProvider | None = None


def get_domain_intel() -> DomainIntelProvider:
    """Get the domain intel provider instance."""
    global _provider
    if _provider is None:
        _provider = DomainIntelProvider()
    return _provider
