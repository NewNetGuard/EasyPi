"""
Heuristics Engine — Domain analysis with multiple signal detection.

All heuristics produce SIGNALS only, never auto-block.
Signals are combined to determine quarantine threshold.

Detectors:
- DGA (Domain Generation Algorithm)
- Homoglyph/punycode attacks
- Entropy analysis
- Domain age (newreg)
- Suspicious patterns
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..text_utils import shannon_entropy

from .models import (
    HeuristicSignal,
    ThreatSignals,
)


@dataclass
class DGAResult:
    """Result of DGA analysis."""
    is_dga: bool
    score: float  # 0-100
    features: dict[str, float]
    details: str


@dataclass
class HomoglyphResult:
    """Result of homoglyph/brand impersonation check."""
    is_homoglyph: bool
    score: float  # 0-100
    matched_brand: str | None
    original_domain: str | None
    confusables: list[str]
    details: str


@dataclass  
class EntropyResult:
    """Result of entropy analysis."""
    entropy: float
    score: float  # 0-100 (higher = more suspicious)
    is_suspicious: bool
    details: str


class HeuristicsEngine:
    """
    Multi-signal heuristics engine for domain analysis.
    
    IMPORTANT: This engine produces SIGNALS ONLY.
    It never makes blocking decisions on its own.
    """
    
    # DGA detection thresholds
    DGA_ENTROPY_THRESHOLD = 3.5
    DGA_CONSONANT_RATIO_THRESHOLD = 0.65
    DGA_DIGIT_RATIO_THRESHOLD = 0.3
    DGA_LENGTH_THRESHOLD = 15
    
    # Common DGA TLDs
    DGA_SUSPICIOUS_TLDS = {
        "xyz", "top", "club", "online", "site", "info", "tk", "ml", "ga", "cf", "gq",
        "buzz", "work", "life", "live", "click", "link", "space", "pw", "cc",
    }
    
    # Vowels and consonants
    VOWELS = set("aeiou")
    CONSONANTS = set("bcdfghjklmnpqrstvwxyz")
    
    # Homoglyph mappings (confusable characters)
    HOMOGLYPHS = {
        "0": ["o", "O"],
        "1": ["l", "I", "i"],
        "3": ["e", "E"],
        "4": ["a", "A"],
        "5": ["s", "S"],
        "6": ["g", "G"],
        "7": ["t", "T"],
        "8": ["b", "B"],
        "@": ["a", "A"],
        "$": ["s", "S"],
        "!": ["i", "l", "1"],
        # Cyrillic/Latin confusables
        "а": ["a"],  # Cyrillic а
        "е": ["e"],  # Cyrillic е
        "о": ["o"],  # Cyrillic о
        "р": ["p"],  # Cyrillic р
        "с": ["c"],  # Cyrillic с
        "у": ["y"],  # Cyrillic у
        "х": ["x"],  # Cyrillic х
    }
    
    # Reverse mapping for detection
    CONFUSABLE_TO_ASCII = {}
    for ascii_char, confusables in HOMOGLYPHS.items():
        for conf in confusables:
            CONFUSABLE_TO_ASCII[conf] = ascii_char
    
    def __init__(self, protected_brands: list[dict[str, Any]] | None = None):
        """
        Initialize heuristics engine.
        
        Args:
            protected_brands: List of brand dicts with 'name', 'domains', 'keywords'
        """
        self.protected_brands = protected_brands or self._default_brands()
        self._brand_patterns = self._compile_brand_patterns()
    
    def _default_brands(self) -> list[dict[str, Any]]:
        """Default protected brands for homoglyph detection."""
        return [
            {"name": "paypal", "domains": ["paypal.com"], "keywords": ["paypal", "paypa1", "paypai"]},
            {"name": "google", "domains": ["google.com", "gmail.com"], "keywords": ["google", "goog1e", "googie"]},
            {"name": "microsoft", "domains": ["microsoft.com", "outlook.com"], "keywords": ["microsoft", "micr0soft"]},
            {"name": "apple", "domains": ["apple.com", "icloud.com"], "keywords": ["apple", "app1e", "appie"]},
            {"name": "amazon", "domains": ["amazon.com"], "keywords": ["amazon", "amaz0n", "amazn"]},
            {"name": "facebook", "domains": ["facebook.com", "fb.com"], "keywords": ["facebook", "faceb00k"]},
            {"name": "netflix", "domains": ["netflix.com"], "keywords": ["netflix", "netf1ix", "netfiix"]},
            {"name": "instagram", "domains": ["instagram.com"], "keywords": ["instagram", "1nstagram"]},
            {"name": "twitter", "domains": ["twitter.com", "x.com"], "keywords": ["twitter", "tw1tter"]},
            {"name": "linkedin", "domains": ["linkedin.com"], "keywords": ["linkedin", "l1nkedin"]},
            {"name": "bank", "domains": [], "keywords": ["bank", "banking", "secure-bank", "mybank"]},
            {"name": "login", "domains": [], "keywords": ["login", "log1n", "signin", "sign-in"]},
            {"name": "account", "domains": [], "keywords": ["account", "acc0unt", "my-account"]},
            {"name": "verify", "domains": [], "keywords": ["verify", "verification", "ver1fy"]},
            {"name": "support", "domains": [], "keywords": ["support", "supp0rt", "helpdesk"]},
        ]
    
    def _compile_brand_patterns(self) -> dict[str, re.Pattern]:
        """Compile regex patterns for brand detection."""
        patterns = {}
        for brand in self.protected_brands:
            name = brand["name"]
            keywords = brand.get("keywords", [name])
            
            # Create pattern that matches any keyword
            pattern_str = "|".join(re.escape(kw) for kw in keywords)
            patterns[name] = re.compile(pattern_str, re.IGNORECASE)
        
        return patterns
    
    def analyze_domain(self, domain: str) -> ThreatSignals:
        """
        Analyze domain with all heuristics.
        
        Returns ThreatSignals with all detected signals.
        This is for OBSERVATION only, not blocking.
        """
        # Normalize domain
        domain = domain.lower().strip(".")
        
        # Extract parts
        parts = domain.split(".")
        if len(parts) < 2:
            return ThreatSignals(domain=domain)
        
        tld = parts[-1]
        sld = parts[-2]  # Second-level domain
        subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""
        
        # Run all detectors
        dga_result = self.detect_dga(sld, tld, subdomain)
        homoglyph_result = self.detect_homoglyph(domain)
        entropy_result = self.analyze_entropy(sld)
        
        # Build signals list
        signals = []
        
        if dga_result.score > 20:
            signals.append(HeuristicSignal(
                name="dga",
                score=dga_result.score,
                details=dga_result.details,
            ))
        
        if homoglyph_result.score > 20:
            signals.append(HeuristicSignal(
                name="homoglyph",
                score=homoglyph_result.score,
                details=homoglyph_result.details,
            ))
        
        if entropy_result.score > 40:
            signals.append(HeuristicSignal(
                name="entropy",
                score=entropy_result.score,
                details=entropy_result.details,
            ))
        
        return ThreatSignals(
            domain=domain,
            signals=signals,
            dga_score=dga_result.score,
            homoglyph_score=homoglyph_result.score,
            entropy_score=entropy_result.score,
            matched_brand=homoglyph_result.matched_brand,
        )
    
    def detect_dga(
        self,
        sld: str,
        tld: str,
        subdomain: str = "",
    ) -> DGAResult:
        """
        Detect Domain Generation Algorithm patterns.
        
        Features analyzed:
        - Character entropy
        - Consonant/vowel ratio
        - Digit ratio
        - Length
        - N-gram frequency
        - Suspicious TLD
        """
        features: dict[str, float] = {}
        score = 0.0
        details_parts = []
        
        # 1. Entropy
        entropy = self._calculate_entropy(sld)
        features["entropy"] = entropy
        if entropy > self.DGA_ENTROPY_THRESHOLD:
            score += 25
            details_parts.append(f"high entropy ({entropy:.2f})")
        
        # 2. Consonant ratio
        consonant_ratio = self._consonant_ratio(sld)
        features["consonant_ratio"] = consonant_ratio
        if consonant_ratio > self.DGA_CONSONANT_RATIO_THRESHOLD:
            score += 20
            details_parts.append(f"high consonant ratio ({consonant_ratio:.2f})")
        
        # 3. Digit ratio
        digit_ratio = sum(1 for c in sld if c.isdigit()) / max(len(sld), 1)
        features["digit_ratio"] = digit_ratio
        if digit_ratio > self.DGA_DIGIT_RATIO_THRESHOLD:
            score += 15
            details_parts.append(f"many digits ({digit_ratio:.2f})")
        
        # 4. Length
        features["length"] = len(sld)
        if len(sld) > self.DGA_LENGTH_THRESHOLD:
            score += 15
            details_parts.append(f"long domain ({len(sld)} chars)")
        
        # 5. Suspicious TLD
        if tld in self.DGA_SUSPICIOUS_TLDS:
            score += 15
            features["suspicious_tld"] = 1.0
            details_parts.append(f"suspicious TLD (.{tld})")
        else:
            features["suspicious_tld"] = 0.0
        
        # 6. No vowels check
        vowel_count = sum(1 for c in sld if c in self.VOWELS)
        if vowel_count == 0 and len(sld) > 5:
            score += 10
            details_parts.append("no vowels")
        
        # 7. Subdomain analysis (DGA often uses random subdomains)
        if subdomain:
            sub_entropy = self._calculate_entropy(subdomain.replace(".", ""))
            if sub_entropy > 3.8:
                score += 10
                details_parts.append(f"suspicious subdomain entropy ({sub_entropy:.2f})")
        
        score = min(100, score)
        is_dga = score >= 50
        
        return DGAResult(
            is_dga=is_dga,
            score=score,
            features=features,
            details="; ".join(details_parts) if details_parts else "no DGA indicators",
        )
    
    def detect_homoglyph(self, domain: str) -> HomoglyphResult:
        """
        Detect homoglyph/punycode brand impersonation attacks.
        
        Examples:
        - paypa1.com (1 instead of l)
        - g00gle.com (0 instead of o)
        - аpple.com (Cyrillic а)
        """
        confusables_found = []
        matched_brand = None
        original_domain = None
        score = 0.0
        details_parts = []
        
        # 1. Check for punycode (internationalized domain)
        if domain.startswith("xn--"):
            score += 30
            details_parts.append("punycode domain (IDN)")
            try:
                decoded = domain.encode("ascii").decode("idna")
                domain = decoded
            except Exception:
                pass
        
        # 2. Normalize domain (replace homoglyphs with ASCII)
        normalized = self._normalize_homoglyphs(domain)
        
        if normalized != domain:
            confusables_found = [c for c in domain if c in self.CONFUSABLE_TO_ASCII]
            score += 20
            details_parts.append(f"homoglyph characters: {confusables_found}")
        
        # 3. Check against protected brands
        for brand in self.protected_brands:
            brand_name = brand["name"]
            pattern = self._brand_patterns.get(brand_name)
            
            if pattern:
                # Check both original and normalized
                if pattern.search(domain) or pattern.search(normalized):
                    # Check if it's NOT an official domain
                    official_domains = brand.get("domains", [])
                    base_domain = ".".join(domain.split(".")[-2:])
                    
                    if base_domain not in official_domains:
                        matched_brand = brand_name
                        
                        # Calculate similarity
                        similarity = self._brand_similarity(domain, brand_name)
                        score += 30 + (similarity * 20)
                        details_parts.append(f"resembles '{brand_name}' ({similarity:.0%} similar)")
                        break
        
        # 4. Check for suspicious patterns
        suspicious_patterns = [
            (r"secure[d]?[-_.]", 15, "contains 'secure'"),
            (r"login[-_.]", 15, "contains 'login'"),
            (r"verif[y|ication][-_.]", 15, "contains 'verify'"),
            (r"account[-_.]", 10, "contains 'account'"),
            (r"update[-_.]", 10, "contains 'update'"),
            (r"confirm[-_.]", 10, "contains 'confirm'"),
            (r"[0-9]{4,}", 10, "contains long number"),
        ]
        
        for pattern, points, description in suspicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                score += points
                details_parts.append(description)
        
        score = min(100, score)
        is_homoglyph = score >= 40 and matched_brand is not None
        
        return HomoglyphResult(
            is_homoglyph=is_homoglyph,
            score=score,
            matched_brand=matched_brand,
            original_domain=original_domain,
            confusables=confusables_found,
            details="; ".join(details_parts) if details_parts else "no homoglyph indicators",
        )
    
    def analyze_entropy(self, text: str) -> EntropyResult:
        """Analyze Shannon entropy of text."""
        entropy = self._calculate_entropy(text)
        
        # Score based on entropy (higher entropy = more random = more suspicious)
        if entropy < 2.5:
            score = 0
            details = f"low entropy ({entropy:.2f}) - normal"
        elif entropy < 3.5:
            score = 30
            details = f"moderate entropy ({entropy:.2f})"
        elif entropy < 4.0:
            score = 60
            details = f"high entropy ({entropy:.2f}) - suspicious"
        else:
            score = 85
            details = f"very high entropy ({entropy:.2f}) - likely random"
        
        return EntropyResult(
            entropy=entropy,
            score=score,
            is_suspicious=score >= 50,
            details=details,
        )
    
    def check_domain_age(
        self,
        domain: str,
        age_days: int | None,
    ) -> tuple[float, str]:
        """
        Check domain age signal.
        
        Returns:
            Tuple of (score, details)
        """
        if age_days is None:
            return 0, "domain age unknown"
        
        if age_days < 7:
            return 80, f"very new domain ({age_days} days)"
        elif age_days < 30:
            return 50, f"new domain ({age_days} days)"
        elif age_days < 90:
            return 25, f"relatively new domain ({age_days} days)"
        else:
            return 0, f"established domain ({age_days} days)"
    
    # --------------------------
    # Helper Methods
    # --------------------------
    
    def _calculate_entropy(self, text: str) -> float:
        """Shannon entropy — delegates to the shared helper (single source of truth)."""
        return shannon_entropy(text)
    
    def _consonant_ratio(self, text: str) -> float:
        """Calculate ratio of consonants to total letters."""
        letters = [c for c in text.lower() if c.isalpha()]
        if not letters:
            return 0.0
        
        consonants = sum(1 for c in letters if c in self.CONSONANTS)
        return consonants / len(letters)
    
    def _normalize_homoglyphs(self, text: str) -> str:
        """Replace homoglyph characters with ASCII equivalents."""
        result = []
        for char in text:
            if char in self.CONFUSABLE_TO_ASCII:
                result.append(self.CONFUSABLE_TO_ASCII[char])
            elif char in self.HOMOGLYPHS:
                # Digit to letter
                replacements = self.HOMOGLYPHS[char]
                result.append(replacements[0] if replacements else char)
            else:
                result.append(char)
        return "".join(result)
    
    def _brand_similarity(self, domain: str, brand: str) -> float:
        """Calculate similarity between domain and brand name."""
        # Simple Levenshtein-based similarity
        domain_clean = re.sub(r"[^a-z0-9]", "", domain.lower())
        brand_clean = brand.lower()
        
        # Check if brand is substring
        if brand_clean in domain_clean:
            return 0.9
        
        # Calculate edit distance ratio
        distance = self._levenshtein_distance(domain_clean, brand_clean)
        max_len = max(len(domain_clean), len(brand_clean))
        
        if max_len == 0:
            return 0.0
        
        similarity = 1 - (distance / max_len)
        return max(0.0, similarity)
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
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
    
    def add_brand(
        self,
        name: str,
        domains: list[str],
        keywords: list[str] | None = None,
    ) -> None:
        """Add a protected brand at runtime."""
        brand = {
            "name": name,
            "domains": domains,
            "keywords": keywords or [name],
        }
        self.protected_brands.append(brand)
        self._brand_patterns = self._compile_brand_patterns()
