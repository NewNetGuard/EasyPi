"""
Ad & Tracker Detector - Behavioral analysis without blocklists.

Detects advertising and tracking domains based on behavioral patterns:
- Third-party request patterns
- High entropy domains
- Tracking pixel signatures
- Cookie syncing behavior
- CNAME cloaking

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Set

from ..text_utils import shannon_entropy

logger = logging.getLogger(__name__)


# Known advertising/tracking TLDs
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs abused for spam
    '.buzz', '.link', '.click', '.top', '.win',  # Marketing-heavy TLDs
    '.bid', '.trade', '.date', '.download',
}

# Advertising/tracking keywords matched as WHOLE domain tokens (precise:
# 'ad' matches the label "ad"/"ads", NOT "adidas"/"download"/"gradient").
AD_KEYWORDS = {
    'ad', 'ads', 'adv', 'advert', 'adverts', 'advertising', 'banner',
    'track', 'tracks', 'tracking', 'tracker', 'trackers', 'pixel', 'pixels',
    'analytics', 'telemetry', 'metric', 'metrics', 'tag', 'tags', 'beacon',
    'click', 'clicks', 'impression', 'impressions', 'conversion', 'affiliate',
    'doubleclick', 'adsense', 'adserver', 'adservers', 'adtech', 'adservice',
    'adsystem', 'adexchange', 'adcdn', 'adsync', 'adtag', 'adimg',
    'rtb', 'dsp', 'ssp', 'prebid', 'popads', 'popunder', 'interstitial',
    'retargeting', 'remarketing', 'cookiesync', 'admob', 'adroll',
}

# Unambiguous ad prefixes for glued tokens (e.g. "pagead2", "adservice-eu").
# A token STARTING with any of these is treated as advertising.
STRONG_AD_PREFIXES = (
    'adserver', 'adservice', 'adsystem', 'adsense', 'adtech', 'adexchange',
    'doubleclick', 'googlesyndication', 'googleadservices', 'pagead',
    'adnxs', 'adroll', 'smartadserver', 'adform', 'adcolony',
)

# Unambiguous third-party ad / RTB / measurement NETWORKS — safe to block on the
# registrable name alone (no first-party site is named like these), used for
# real-time blocking of UNLISTED ad-network domains the static list misses.
# Deliberately excludes ambiguous tokens (ad/ads/tag/pixel) and first-party-ish
# names (facebook, snap) so direct-name blocking stays ~zero false-positive.
AD_NETWORK_REGISTRABLE = frozenset({
    'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com', 'pubmatic.com',
    'rubiconproject.com', 'openx.net', 'adsrvr.org', 'moatads.com',
    'scorecardresearch.com', 'quantserve.com', 'casalemedia.com', '3lift.com',
    'bidswitch.net', 'sharethrough.com', 'yieldmo.com', 'gumgum.com',
    'indexww.com', 'districtm.io', 'teads.tv',
})

# Pure telemetry / measurement domains (no end-user dashboard) — safe to block on
# the registrable name. These only collect data; nothing on a page depends on them.
DEFINITE_TRACKER_NETWORKS = frozenset({
    'sentry-cdn.com', 'nr-data.net', 'scorecardresearch.com', 'quantserve.com',
    'mixpanel.com', 'amplitude.com', 'fullstory.com', 'mouseflow.com',
    'smartlook.com', 'logrocket.com', 'mxpnl.com', 'hotjar.io', 'hotjar.com',
    # Google Tag Manager: serves only the gtm.js container from googletagmanager.com;
    # its admin dashboard lives on tagmanager.google.com, so blocking this registrable
    # is safe. (Small chance a site injects functional widgets via GTM — watched.)
    'googletagmanager.com',
})

# Known tracker SDKs that ship from a SHARED CDN (so the registrable is a CDN we
# normally allow). These EXACT hostnames are dedicated tracker distributions, safe
# to block without touching the rest of the CDN. e.g. Bugsnag's browser SDK.
KNOWN_TRACKER_CDN_HOSTS = frozenset({
    'd2wy8f7a9ursnm.cloudfront.net',
    'd2wy8f7a9ursvm.cloudfront.net',
})

# Error / telemetry / product-analytics services that ALSO host an end-user
# dashboard on the same registrable (app.sentry.io, app.datadoghq.com). We must
# block only their telemetry/ingest endpoints, never the dashboard — so a match
# requires both the registrable AND a telemetry-shaped label below.
TELEMETRY_DASHBOARD_SERVICES = frozenset({
    'sentry.io', 'bugsnag.com', 'datadoghq.com', 'rollbar.com', 'raygun.io',
    'honeybadger.io', 'trackjs.com', 'newrelic.com', 'segment.io', 'segment.com',
})
TELEMETRY_LABELS = frozenset({
    'ingest', 'intake', 'sessions', 'session', 'rum', 'telemetry', 'beacon',
    'beacons', 'collect', 'collector', 'metrics', 'events', 'logs', 'errors',
    'browser', 'track', 'tracking',
})

# Known legitimate CDNs (whitelist patterns)
LEGITIMATE_CDN_PATTERNS = [
    r'.*cloudfront\.net$',
    r'.*cloudflare\.com$',
    r'.*akamai\.net$',
    r'.*fastly\.net$',
    r'.*cdn\.ampproject\.org$',
]


@dataclass
class AdTrackerResult:
    """Result from ad/tracker detection."""
    domain: str
    is_suspicious: bool
    confidence: float  # 0.0 - 1.0
    risk_weight: int  # Signal weight for aggregator
    reasons: List[str]
    indicators: Dict[str, float]  # Individual indicator scores
    is_definite_ad: bool = False  # unambiguous ad network -> safe to block on name
    is_definite_tracker: bool = False  # telemetry/error tracker -> safe to block
    
    def __repr__(self) -> str:
        status = "SUSPICIOUS" if self.is_suspicious else "CLEAN"
        return (
            f"AdTrackerResult({self.domain}, {status}, "
            f"confidence={self.confidence:.2f}, weight={self.risk_weight})"
        )


class AdTrackerDetector:
    """
    Behavioral ad/tracker detector.
    
    Uses multiple heuristics to identify advertising and tracking domains
    without relying on blocklists.
    """
    
    def __init__(
        self,
        entropy_threshold: float = 3.4,
        ad_keyword_weight: int = 17,
        high_entropy_weight: int = 13,
        suspicious_tld_weight: int = 9,
    ):
        """
        Initialize detector.
        
        Args:
            entropy_threshold: Shannon entropy threshold for random-looking domains
            ad_keyword_weight: Weight for ad-related keywords
            high_entropy_weight: Weight for high-entropy domains
            suspicious_tld_weight: Weight for suspicious TLDs
        """
        self.entropy_threshold = entropy_threshold
        self.ad_keyword_weight = ad_keyword_weight
        self.high_entropy_weight = high_entropy_weight
        self.suspicious_tld_weight = suspicious_tld_weight
        
        # Compile CDN whitelist patterns
        self.cdn_patterns = [re.compile(p) for p in LEGITIMATE_CDN_PATTERNS]
        
        logger.info("AdTrackerDetector initialized")
    
    def analyze(self, domain: str, context: Optional[Dict] = None) -> AdTrackerResult:
        """
        Analyze domain for ad/tracker characteristics.
        
        Args:
            domain: Domain to analyze
            context: Optional context (parent_domain, request_count, etc.)
        
        Returns:
            AdTrackerResult with analysis
        """
        domain = domain.lower().strip().rstrip('.')
        
        reasons = []
        indicators = {}
        total_score = 0.0
        
        # Skip if whitelisted CDN
        if self._is_whitelisted_cdn(domain):
            return AdTrackerResult(
                domain=domain,
                is_suspicious=False,
                confidence=0.0,
                risk_weight=0,
                reasons=["Legitimate CDN"],
                indicators={},
                is_definite_ad=False,
                is_definite_tracker=False,
            )
        
        # 1. Check for ad keywords in domain
        ad_keyword_score = self._check_ad_keywords(domain)
        if ad_keyword_score > 0:
            indicators['ad_keywords'] = ad_keyword_score
            total_score += ad_keyword_score
            reasons.append("Contains ad-related keywords")
        
        # 2. Check domain entropy (random-looking)
        entropy = self._calculate_entropy(domain)
        if entropy > self.entropy_threshold:
            entropy_score = min((entropy - self.entropy_threshold) * 10, self.high_entropy_weight)
            indicators['high_entropy'] = entropy_score
            total_score += entropy_score
            reasons.append(f"High entropy: {entropy:.2f} (random-looking)")
        
        # 3. Check for suspicious TLD
        tld_score = self._check_suspicious_tld(domain)
        if tld_score > 0:
            indicators['suspicious_tld'] = tld_score
            total_score += tld_score
            tld = self._get_tld(domain)
            reasons.append(f"Suspicious TLD: {tld}")
        
        # 4. Check subdomain depth (too many levels)
        depth_score = self._check_subdomain_depth(domain)
        if depth_score > 0:
            indicators['subdomain_depth'] = depth_score
            total_score += depth_score
            depth = domain.count('.')
            reasons.append(f"Deep subdomain structure: {depth} levels")

        # 4b. Lightweight signal for tracking-like subdomains
        tracking_subdomain_score = self._check_tracking_subdomains(domain)
        if tracking_subdomain_score > 0:
            indicators['tracking_subdomain'] = tracking_subdomain_score
            total_score += tracking_subdomain_score
            reasons.append("Tracking-like subdomain pattern")
        
        # 5. Third-party context analysis (if provided)
        if context:
            third_party_score = self._analyze_third_party_context(domain, context)
            if third_party_score > 0:
                indicators['third_party_flood'] = third_party_score
                total_score += third_party_score
                reasons.append("Third-party tracking pattern detected")
        
        # 6. Tracking pixel pattern (if context available)
        if context and self._is_tracking_pixel_pattern(context):
            pixel_score = 15
            indicators['tracking_pixel'] = pixel_score
            total_score += pixel_score
            reasons.append("Tracking pixel signature (tiny request)")
        
        # 7. Cookie syncing pattern
        if context and self._is_cookie_syncing(context):
            sync_score = 12
            indicators['cookie_sync'] = sync_score
            total_score += sync_score
            reasons.append("Cookie syncing detected (redirect chain)")
        
        # Calculate confidence based on number of indicators
        num_indicators = len(indicators)
        if num_indicators >= 3:
            confidence = 0.9
        elif num_indicators == 2:
            confidence = 0.7
        elif num_indicators == 1:
            confidence = 0.5
        else:
            confidence = 0.0
        
        # Determine if suspicious
        # Lower threshold for domains with strong ad keyword matches
        has_strong_keyword_match = indicators.get('ad_keywords', 0) >= 8  # Catch partial matches too
        
        if has_strong_keyword_match and total_score >= 7:
            # Strong ad keyword alone is enough for high-confidence detection
            is_suspicious = True
        elif total_score >= 13 and num_indicators >= 2:
            # Multiple weaker indicators
            is_suspicious = True
        else:
            is_suspicious = False
        
        # Calculate risk weight for signal aggregator
        if is_suspicious:
            risk_weight = min(int(total_score), 30)
        else:
            risk_weight = 0

        # Unambiguous third-party ad network: blockable on the name alone. Force
        # suspicious so the engine can promote it to an active block (reason=
        # advertising) even when it carries no ad keyword (e.g. "criteo.com").
        is_definite_ad = self._is_definite_ad_network(domain)
        is_definite_tracker = (not is_definite_ad) and self._is_definite_tracker(domain)
        if is_definite_ad or is_definite_tracker:
            is_suspicious = True
            risk_weight = max(risk_weight, self.ad_keyword_weight)
            confidence = max(confidence, 0.9)
            if is_definite_ad and 'definite_ad_network' not in indicators:
                indicators['definite_ad_network'] = float(self.ad_keyword_weight)
                reasons.append("Known third-party ad network")
            elif is_definite_tracker and 'definite_tracker' not in indicators:
                indicators['definite_tracker'] = float(self.ad_keyword_weight)
                reasons.append("Known tracking/telemetry endpoint")

        return AdTrackerResult(
            domain=domain,
            is_suspicious=is_suspicious,
            confidence=confidence,
            risk_weight=risk_weight,
            reasons=reasons,
            indicators=indicators,
            is_definite_ad=is_definite_ad,
            is_definite_tracker=is_definite_tracker,
        )
    
    def _is_whitelisted_cdn(self, domain: str) -> bool:
        """Check if domain is a legitimate CDN."""
        if domain in KNOWN_TRACKER_CDN_HOSTS:
            return False  # dedicated tracker SDK host on a shared CDN -> not exempt
        for pattern in self.cdn_patterns:
            if pattern.match(domain):
                return True
        return False
    
    def _check_ad_keywords(self, domain: str) -> float:
        """
        Check for advertising keywords matched at TOKEN boundaries.

        Splits the domain into labels and hyphen-separated tokens (ignoring the
        TLD) and matches whole tokens — so "ads.x.com" / "ad-server.x.com" hit,
        while "adidas.de", "download.cdn.com", "gradient.io" do NOT. The old
        substring match flagged those legit domains as ads (a false-positive
        source that could get real sites blocked).
        """
        domain_lower = domain.lower().strip('.')
        parts = domain_lower.split('.')
        labels = parts[:-1] if len(parts) > 1 else parts  # ignore TLD
        tokens: Set[str] = set()
        for label in labels:
            for tok in label.split('-'):
                if tok:
                    tokens.add(tok)

        # 1) exact whole-token match (precise; no 'ad' inside 'adidas')
        if tokens & AD_KEYWORDS:
            return float(self.ad_keyword_weight)

        # 2) unambiguous ad prefixes for glued tokens (pagead2, adservice-eu…)
        for tok in tokens:
            if any(tok.startswith(p) for p in STRONG_AD_PREFIXES):
                return float(self.ad_keyword_weight)

        return 0.0

    def _is_definite_ad_network(self, domain: str) -> bool:
        """Unambiguous third-party ad network -> safe to block on the name alone.

        True when the registrable domain is a known ad/RTB/measurement network, or
        any hyphen/label token starts with a STRONG ad prefix (doubleclick,
        googlesyndication, adservice, adnxs, …). Token-boundary based, so legitimate
        names like 'adidas.de' or 'gradient.io' never match.
        """
        d = domain.lower().strip('.')
        parts = d.split('.')
        reg = '.'.join(parts[-2:]) if len(parts) >= 2 else d
        if reg in AD_NETWORK_REGISTRABLE:
            return True
        labels = parts[:-1] if len(parts) > 1 else parts  # ignore TLD
        for label in labels:
            for tok in label.split('-'):
                if tok and any(tok.startswith(p) for p in STRONG_AD_PREFIXES):
                    return True
        return False

    def _is_definite_tracker(self, domain: str) -> bool:
        """Telemetry / error-tracking endpoint that is safe to block on the name.

        Pure-telemetry registrables (sentry-cdn.com, nr-data.net, …) match outright.
        Services that also run a dashboard on the same registrable (sentry.io,
        datadoghq.com, …) match ONLY when a telemetry-shaped label is present
        (o123.ingest.sentry.io, http-intake.logs.datadoghq.com) — so app.sentry.io
        and other dashboards stay reachable.
        """
        d = domain.lower().strip('.')
        if d in KNOWN_TRACKER_CDN_HOSTS:
            return True
        parts = d.split('.')
        reg = '.'.join(parts[-2:]) if len(parts) >= 2 else d
        if reg in DEFINITE_TRACKER_NETWORKS:
            return True
        if reg in TELEMETRY_DASHBOARD_SERVICES:
            labels = parts[:-2]  # sub-labels under the registrable
            for label in labels:
                for tok in label.split('-'):
                    if tok in TELEMETRY_LABELS:
                        return True
        return False

    def _calculate_entropy(self, domain: str) -> float:
        """Shannon entropy of the domain's SLD (the registrable label).

        Extracts the SLD, then defers the entropy maths to the shared helper.
        """
        parts = domain.split('.')
        sld = parts[-2] if len(parts) >= 2 else domain
        return shannon_entropy(sld)
    
    def _check_suspicious_tld(self, domain: str) -> float:
        """Check for suspicious TLD."""
        tld = self._get_tld(domain)
        if tld in SUSPICIOUS_TLDS:
            return self.suspicious_tld_weight
        return 0.0
    
    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        parts = domain.split('.')
        if len(parts) >= 2:
            return f'.{parts[-1]}'
        return ''
    
    def _check_subdomain_depth(self, domain: str) -> float:
        """Check for excessive subdomain depth."""
        depth = domain.count('.')
        
        if depth >= 4:
            return 10  # Very deep (e.g., a.b.c.d.example.com)
        elif depth >= 3:
            return 5   # Deep (e.g., a.b.c.example.com)
        
        return 0.0

    def _check_tracking_subdomains(self, domain: str) -> float:
        """Detect common tracking/ads subdomain patterns (moderate weight)."""
        patterns = (
            ".track.",
            ".tracking.",
            ".stats.",
            ".metrics.",
            ".analytics.",
            ".pixel.",
            ".ads.",
            ".ad.",
            ".beacon.",
        )
        lowered = f".{domain.lower().strip('.') }."
        for pattern in patterns:
            if pattern in lowered:
                return 6.0
        return 0.0
    
    def _analyze_third_party_context(self, domain: str, context: Dict) -> float:
        """
        Analyze third-party request context.
        
        Context may include:
        - parent_domain: The main page domain
        - request_count: Number of requests to this domain
        - other_third_parties: List of other third-party domains on same page
        """
        score = 0.0

        other_parties = context.get('other_third_parties')
        third_party_count = context.get('third_party_count')
        if isinstance(other_parties, list) and other_parties:
            third_party_count = len(other_parties)
        if third_party_count is None:
            third_party_count = 0

        # Strong page-level crowding signal even without an explicit parent domain.
        # This keeps the detector useful when the caller can only provide
        # aggregate context instead of a full request tree.
        if third_party_count > 10:
            score += 12
        elif third_party_count > 5:
            score += 8

        # Check if this is third-party relative to the current parent/page.
        parent = context.get('parent_domain')
        if parent and not self._is_same_organization(domain, parent):
            # It's third-party. Boost score further because the crowding signal
            # is now grounded in a confirmed cross-site relationship.
            if third_party_count > 10:
                score += 4
            elif third_party_count > 5:
                score += 2

            # High request count to third-party = suspicious
            request_count = context.get('request_count', 0)
            if request_count > 20:
                score += 6
        
        return score
    
    def _is_same_organization(self, domain1: str, domain2: str) -> bool:
        """Check if two domains belong to same organization."""
        # Simple check: compare eTLD+1 (e.g., example.com)
        def get_etld_plus_one(domain: str) -> str:
            parts = domain.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return domain
        
        return get_etld_plus_one(domain1) == get_etld_plus_one(domain2)
    
    def _is_tracking_pixel_pattern(self, context: Dict) -> bool:
        """
        Detect tracking pixel pattern.
        
        Characteristics:
        - Very small payload (<1KB)
        - Fast request (<1 second)
        - Many similar requests
        """
        bytes_transferred = context.get('bytes_transferred', 0)
        duration = context.get('duration_seconds', 0)
        request_count = context.get('request_count', 0)
        
        # Tracking pixel: tiny, fast, frequent
        if bytes_transferred < 1000 and duration < 1.0 and request_count > 5:
            return True
        
        return False
    
    def _is_cookie_syncing(self, context: Dict) -> bool:
        """
        Detect cookie syncing pattern.
        
        Characteristics:
        - Multiple redirects (3+)
        - Fast redirect chain (<2 seconds)
        """
        num_redirects = context.get('num_redirects', 0)
        redirect_duration = context.get('redirect_duration', 0)
        
        if num_redirects >= 3 and redirect_duration < 2.0:
            return True
        
        return False


# Singleton instance
_ad_tracker_detector: Optional[AdTrackerDetector] = None
_detector_lock = threading.Lock()


def get_ad_tracker_detector() -> AdTrackerDetector:
    """Get singleton AdTrackerDetector instance."""
    global _ad_tracker_detector
    
    if _ad_tracker_detector is None:
        with _detector_lock:
            if _ad_tracker_detector is None:
                _ad_tracker_detector = AdTrackerDetector()
    
    return _ad_tracker_detector
