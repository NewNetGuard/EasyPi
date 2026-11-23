"""
Homoglyph Detector - Brand impersonation detection.

Detects domains that use visually similar characters (homoglyphs)
to impersonate legitimate brands.
Examples: аpple.com (Cyrillic а), g00gle.com, paypa1.com

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


@dataclass
class HomoglyphResult:
    """Result of homoglyph detection."""
    domain: str
    is_suspicious: bool
    score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    matched_brand: Optional[str]
    reasons: List[str]
    
    @property
    def risk_weight(self) -> int:
        """Risk weight for signal aggregator."""
        if not self.is_suspicious:
            return 0
        
        # Scale from 0 to 40 based on score
        return int(40 * self.score * self.confidence)


class HomoglyphDetector:
    """
    Detects brand impersonation using homoglyphs.
    
    Techniques:
    - Unicode homoglyphs (Cyrillic, Greek, etc.)
    - Digit substitution (0 for o, 1 for l)
    - Character doubling/dropping
    - Common typosquatting patterns
    """
    
    # Homoglyph mappings: suspicious char -> normal char
    HOMOGLYPHS: Dict[str, str] = {
        # Cyrillic lookalikes
        'а': 'a',  # Cyrillic а
        'е': 'e',  # Cyrillic е
        'о': 'o',  # Cyrillic о
        'р': 'p',  # Cyrillic р
        'с': 'c',  # Cyrillic с
        'у': 'y',  # Cyrillic у
        'х': 'x',  # Cyrillic х
        'ѕ': 's',  # Cyrillic ѕ
        'і': 'i',  # Cyrillic і
        'ј': 'j',  # Cyrillic ј
        'ԁ': 'd',  # Cyrillic ԁ
        'ԛ': 'q',  # Cyrillic ԛ
        'ѡ': 'w',  # Cyrillic ѡ
        'һ': 'h',  # Cyrillic һ
        'ʙ': 'b',  # Cyrillic ʙ
        
        # Greek lookalikes
        'α': 'a',  # Greek alpha
        'β': 'b',  # Greek beta
        'ε': 'e',  # Greek epsilon
        'η': 'n',  # Greek eta
        'ι': 'i',  # Greek iota
        'κ': 'k',  # Greek kappa
        'ν': 'v',  # Greek nu
        'ο': 'o',  # Greek omicron
        'ρ': 'p',  # Greek rho
        'τ': 't',  # Greek tau
        'υ': 'u',  # Greek upsilon
        'χ': 'x',  # Greek chi
        'ω': 'w',  # Greek omega
        
        # Latin lookalikes
        'ɑ': 'a',  # Latin alpha
        'ɡ': 'g',  # Latin script g
        'ı': 'i',  # Latin dotless i
        'ȷ': 'j',  # Latin dotless j
        'ɩ': 'i',  # Latin iota
        'ɴ': 'n',  # Latin small capital N
        'ɵ': 'o',  # Latin barred o
        'ʀ': 'r',  # Latin small capital R
        'ʏ': 'y',  # Latin small capital Y
        
        # Common digit substitutions
        '0': 'o',
        '1': 'l',
        '3': 'e',
        '4': 'a',
        '5': 's',
        '6': 'g',
        '7': 't',
        '8': 'b',
        '9': 'g',
        
        # Special characters
        'ℓ': 'l',  # Script small l
        'ⅰ': 'i',  # Roman numeral one
        'ⅱ': 'ii',
        'ⅲ': 'iii',
        'ⅳ': 'iv',
        'ⅴ': 'v',
        'ⅵ': 'vi',
        'ⅶ': 'vii',
        'ⅷ': 'viii',
        'ⅸ': 'ix',
        'ⅹ': 'x',
        
        # Other confusables
        'ǫ': 'q',
        'ɒ': 'a',
        'ḃ': 'b',
        'ċ': 'c',
        'ḋ': 'd',
        'ė': 'e',
        'ḟ': 'f',
        'ġ': 'g',
        'ḣ': 'h',
        'ṁ': 'm',
        'ṅ': 'n',
        'ȯ': 'o',
        'ṗ': 'p',
        'ṙ': 'r',
        'ṡ': 's',
        'ṫ': 't',
        'ẇ': 'w',
        'ẋ': 'x',
        'ẏ': 'y',
        'ż': 'z',
    }
    
    # High-value brands to protect
    PROTECTED_BRANDS: Dict[str, List[str]] = {
        # Major tech companies
        'google': ['google', 'gmail', 'youtube', 'android', 'chrome'],
        'apple': ['apple', 'icloud', 'itunes', 'iphone', 'macbook'],
        'microsoft': ['microsoft', 'outlook', 'windows', 'office', 'xbox', 'azure', 'bing'],
        'amazon': ['amazon', 'aws', 'prime', 'alexa', 'kindle'],
        'facebook': ['facebook', 'instagram', 'whatsapp', 'messenger', 'meta'],
        
        # Financial
        'paypal': ['paypal'],
        'stripe': ['stripe'],
        'visa': ['visa'],
        'mastercard': ['mastercard'],
        'amex': ['americanexpress', 'amex'],
        'chase': ['chase', 'jpmorgan'],
        'bankofamerica': ['bankofamerica', 'bofa'],
        'wellsfargo': ['wellsfargo'],
        'citibank': ['citibank', 'citi'],
        'hsbc': ['hsbc'],
        'barclays': ['barclays'],
        
        # E-commerce
        'ebay': ['ebay'],
        'alibaba': ['alibaba', 'aliexpress', 'taobao'],
        'shopify': ['shopify'],
        'walmart': ['walmart'],
        'target': ['target'],
        
        # Social/Communication
        'twitter': ['twitter', 'tweetdeck'],
        'linkedin': ['linkedin'],
        'tiktok': ['tiktok'],
        'snapchat': ['snapchat'],
        'telegram': ['telegram'],
        'discord': ['discord'],
        'slack': ['slack'],
        'zoom': ['zoom'],
        
        # Entertainment
        'netflix': ['netflix'],
        'spotify': ['spotify'],
        'disney': ['disney', 'disneyplus', 'hulu'],
        'hbo': ['hbo', 'hbomax'],
        'twitch': ['twitch'],
        
        # Cloud/Tech
        'dropbox': ['dropbox'],
        'github': ['github'],
        'gitlab': ['gitlab'],
        'cloudflare': ['cloudflare'],
        'digitalocean': ['digitalocean'],
        
        # Gaming
        'steam': ['steam', 'steampowered', 'valve'],
        'epicgames': ['epicgames', 'fortnite'],
        'roblox': ['roblox'],
        'playstation': ['playstation', 'sony'],
        'nintendo': ['nintendo'],
        
        # Crypto
        'coinbase': ['coinbase'],
        'binance': ['binance'],
        'crypto': ['crypto'],
        
        # German brands (for EasyPi users)
        'deutsche': ['deutschebank', 'deutschepost', 'deutschebahn'],
        'sparkasse': ['sparkasse'],
        'postbank': ['postbank'],
        'commerzbank': ['commerzbank'],
        'telekom': ['telekom', 'tmobile'],
        'vodafone': ['vodafone'],
        'o2': ['o2'],
        'saturn': ['saturn'],
        'mediamarkt': ['mediamarkt'],
        'otto': ['otto'],
        'zalando': ['zalando'],
        'lidl': ['lidl'],
        'aldi': ['aldi'],
        'rewe': ['rewe'],
        'edeka': ['edeka'],
    }
    
    # Flatten all brand names for quick lookup
    ALL_BRANDS: Set[str] = set()
    for brand_list in PROTECTED_BRANDS.values():
        ALL_BRANDS.update(brand_list)
    
    def __init__(self, score_threshold: float = 0.5):
        self.score_threshold = score_threshold
        
        # Build reverse lookup
        self._brand_lookup: Dict[str, str] = {}
        for brand, aliases in self.PROTECTED_BRANDS.items():
            for alias in aliases:
                self._brand_lookup[alias] = brand
    
    @lru_cache(maxsize=10000)
    def _normalize(self, text: str) -> str:
        """Normalize text by replacing homoglyphs."""
        result = []
        for char in text.lower():
            result.append(self.HOMOGLYPHS.get(char, char))
        return ''.join(result)
    
    def _has_non_ascii(self, text: str) -> bool:
        """Check if text contains non-ASCII characters."""
        return any(ord(c) > 127 for c in text)
    
    def _has_mixed_scripts(self, text: str) -> bool:
        """Check if text mixes different scripts (Latin + Cyrillic, etc.)."""
        scripts = set()
        for char in text:
            if char.isalpha():
                if ord(char) < 128:
                    scripts.add('latin')
                elif 0x0400 <= ord(char) <= 0x04FF:
                    scripts.add('cyrillic')
                elif 0x0370 <= ord(char) <= 0x03FF:
                    scripts.add('greek')
                else:
                    scripts.add('other')
        
        return len(scripts) > 1
    
    def _get_sld(self, domain: str) -> str:
        """Extract second-level domain."""
        domain = domain.lower().strip().rstrip('.')
        parts = domain.split('.')
        
        if len(parts) < 2:
            return domain
        
        # Handle common SLDs
        if len(parts) >= 3 and parts[-2] in {'co', 'com', 'net', 'org', 'gov', 'ac'}:
            return parts[-3]
        
        return parts[-2]
    
    def _find_brand_match(
        self,
        normalized: str,
        original: str,
    ) -> Tuple[Optional[str], float, List[str]]:
        """
        Find if normalized domain matches a protected brand.
        
        Returns: (brand_name, similarity_score, reasons)
        """
        reasons = []
        
        # Direct match
        if normalized in self.ALL_BRANDS:
            brand = self._brand_lookup.get(normalized, normalized)
            
            # Check if original had homoglyphs
            if original != normalized:
                reasons.append(f"Homoglyph attack on '{brand}'")
                return brand, 1.0, reasons
            else:
                # Exact match, not suspicious
                return None, 0.0, []
        
        # Check for partial matches
        for brand_name in self.ALL_BRANDS:
            # Brand embedded in domain
            if brand_name in normalized and normalized != brand_name:
                brand = self._brand_lookup.get(brand_name, brand_name)
                
                # Check patterns like "google-security.com"
                if re.match(rf'^{brand_name}[-_]', normalized):
                    reasons.append(f"Brand prefix: '{brand}' with suffix")
                    return brand, 0.8, reasons
                
                # Check patterns like "secure-google.com"
                if re.search(rf'[-_]{brand_name}$', normalized):
                    reasons.append(f"Brand suffix: prefix with '{brand}'")
                    return brand, 0.8, reasons
                
                # Brand somewhere in domain
                if len(normalized) < len(brand_name) + 5:
                    reasons.append(f"Brand embedded: '{brand}' in domain")
                    return brand, 0.6, reasons
        
        # Check for typosquatting (1-2 character difference)
        for brand_name in self.ALL_BRANDS:
            if len(brand_name) < 4:
                continue
            
            distance = self._levenshtein_distance(normalized, brand_name)
            
            if distance == 1:
                brand = self._brand_lookup.get(brand_name, brand_name)
                reasons.append(f"Typosquatting: 1 char from '{brand}'")
                return brand, 0.9, reasons
            elif distance == 2 and len(brand_name) >= 6:
                brand = self._brand_lookup.get(brand_name, brand_name)
                reasons.append(f"Typosquatting: 2 chars from '{brand}'")
                return brand, 0.7, reasons
        
        return None, 0.0, []
    
    @staticmethod
    @lru_cache(maxsize=10000)
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return HomoglyphDetector._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _check_digit_substitution(
        self,
        original: str,
        normalized: str,
    ) -> Tuple[float, List[str]]:
        """Check for digit substitution patterns."""
        reasons = []
        score = 0.0
        
        # Count digit substitutions
        digit_subs = 0
        for i, (orig, norm) in enumerate(zip(original, normalized)):
            if orig.isdigit() and not norm.isdigit():
                digit_subs += 1
        
        if digit_subs > 0:
            score = min(0.3 * digit_subs, 0.6)
            reasons.append(f"{digit_subs} digit substitution(s)")
        
        return score, reasons
    
    def analyze(self, domain: str) -> HomoglyphResult:
        """
        Analyze domain for brand impersonation.
        
        Returns HomoglyphResult with detection details.
        """
        domain = domain.lower().strip().rstrip('.')
        sld = self._get_sld(domain)
        normalized = self._normalize(sld)
        
        all_reasons = []
        total_score = 0.0
        matched_brand = None
        
        # Check for non-ASCII (immediate red flag if any)
        if self._has_non_ascii(sld):
            total_score += 0.3
            all_reasons.append("Contains non-ASCII characters")
            
            if self._has_mixed_scripts(sld):
                total_score += 0.4
                all_reasons.append("Mixed character scripts (homoglyph attack)")
        
        # Check for brand match
        brand, brand_score, brand_reasons = self._find_brand_match(normalized, sld)
        if brand:
            matched_brand = brand
            total_score += brand_score * 0.6
            all_reasons.extend(brand_reasons)
        
        # Check digit substitution (only if resembles a brand)
        if matched_brand or total_score > 0.2:
            digit_score, digit_reasons = self._check_digit_substitution(sld, normalized)
            total_score += digit_score
            all_reasons.extend(digit_reasons)
        
        # Normalize total score
        total_score = min(total_score, 1.0)
        
        # Calculate confidence
        if matched_brand:
            confidence = 0.9
        elif self._has_non_ascii(sld):
            confidence = 0.8
        else:
            confidence = 0.6
        
        # Determine if suspicious
        is_suspicious = total_score >= self.score_threshold
        
        return HomoglyphResult(
            domain=domain,
            is_suspicious=is_suspicious,
            score=total_score,
            confidence=confidence,
            matched_brand=matched_brand,
            reasons=all_reasons if all_reasons else ["No brand impersonation detected"],
        )
    
    def is_suspicious(self, domain: str) -> bool:
        """Quick check if domain appears to impersonate a brand."""
        return self.analyze(domain).is_suspicious
    
    def batch_analyze(self, domains: List[str]) -> List[HomoglyphResult]:
        """Analyze multiple domains."""
        return [self.analyze(d) for d in domains]
    
    def add_brand(self, brand_name: str, aliases: List[str] | None = None) -> None:
        """Add a new brand to protect."""
        brand_name = brand_name.lower()
        if aliases is None:
            aliases = [brand_name]
        else:
            aliases = [a.lower() for a in aliases]
        
        self.PROTECTED_BRANDS[brand_name] = aliases
        self.ALL_BRANDS.update(aliases)
        
        for alias in aliases:
            self._brand_lookup[alias] = brand_name


# Singleton instance
_instance: HomoglyphDetector | None = None


def get_homoglyph_detector() -> HomoglyphDetector:
    """Get singleton HomoglyphDetector instance."""
    global _instance
    
    if _instance is None:
        _instance = HomoglyphDetector()
    
    return _instance


# Quick helper functions
def is_homoglyph_attack(domain: str) -> bool:
    """Quick check if domain uses homoglyphs."""
    return get_homoglyph_detector().is_suspicious(domain)


def analyze_domain_homoglyph(domain: str) -> HomoglyphResult:
    """Get full homoglyph analysis for domain."""
    return get_homoglyph_detector().analyze(domain)
