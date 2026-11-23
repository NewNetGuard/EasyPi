"""
DGA Detector - Domain Generation Algorithm detection.

Detects randomly-generated domains used by botnets.
Examples: qwxk3j2h.ru, a7b3c9d2e5f8.com

© 2025 EasyPi Project
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Tuple

from ..text_utils import shannon_entropy

logger = logging.getLogger(__name__)


@dataclass
class DGAResult:
    """Result of DGA detection."""
    domain: str
    is_dga: bool
    score: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    reasons: List[str]
    
    @property
    def risk_weight(self) -> int:
        """Risk weight for signal aggregator."""
        if not self.is_dga:
            return 0
        
        # Scale from 0 to 35 based on score
        return int(35 * self.score * self.confidence)


class DGADetector:
    """
    Detects Domain Generation Algorithm domains.
    
    Uses multiple heuristics:
    - Entropy analysis
    - Consonant/vowel ratio
    - Character distribution
    - N-gram analysis
    - Digit ratio
    """
    
    # English letter frequencies for entropy calculation
    ENGLISH_FREQ = {
        'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425,
        'e': 0.1270, 'f': 0.0223, 'g': 0.0202, 'h': 0.0609,
        'i': 0.0697, 'j': 0.0015, 'k': 0.0077, 'l': 0.0403,
        'm': 0.0241, 'n': 0.0675, 'o': 0.0751, 'p': 0.0193,
        'q': 0.0010, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
        'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015,
        'y': 0.0197, 'z': 0.0007,
    }
    
    VOWELS = set('aeiou')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyz')
    
    # Common English bigrams.
    # Expanded coverage (~150 entries) reduces false positives on legitimate
    # but unusual domains: the more real English bigrams are recognized, the
    # higher the "common ratio" for natural names, while random DGA strings
    # still score low. True DGA domains rarely match many of these regardless.
    COMMON_BIGRAMS = {
        # High-frequency core
        'th', 'he', 'in', 'en', 'nt', 're', 'er', 'an', 'ti', 'es',
        'on', 'at', 'se', 'nd', 'or', 'ar', 'al', 'te', 'co', 'de',
        'to', 'ra', 'et', 'ed', 'it', 'sa', 'em', 'ro', 'ou', 'ea',
        'ne', 'ri', 'ni', 'ec', 'di', 'li', 've', 'io', 'le', 'is',
        'ch', 'as', 'ur', 'ca', 'el', 'ma', 'la', 'pe', 'si', 'st',
        'ng', 'no', 'lo', 'me', 'fo', 'ha', 'ow', 'be', 'ce', 'mo',
        'pr', 'un', 'ac', 'wa',
        # Doubled letters (very common in English words)
        'll', 'ee', 'oo', 'ss', 'tt', 'ff', 'pp', 'rr', 'mm', 'nn', 'dd',
        # Common vowel/consonant combinations
        'om', 'ad', 'ai', 'ay', 'ey', 'oy', 'ol', 'ot', 'us', 'ut',
        'ul', 'um', 'up', 'ab', 'ob', 'ub', 'ap', 'op', 'ip', 'am',
        'im', 'ic', 'id', 'if', 'ig', 'ev', 'iv', 'ov', 'ew', 'aw',
        'ho', 'hi', 'hu', 'fa', 'fe', 'fi', 'ge', 'gi', 'go', 'gu',
        'ke', 'ki', 'nu', 'pa', 'po', 'pu', 'qu', 'so', 'su', 'ta',
        'tu', 'ty', 'va', 'vi', 'wo', 'ye', 'yo', 'da', 'do', 'du',
        # Common consonant clusters / endings
        'wh', 'sh', 'gh', 'ph', 'ck', 'ct', 'ci', 'cy',
        'rs', 'ts', 'ns', 'ms', 'ds', 'ks', 'ls', 'ps',
        'rt', 'rd', 'rn', 'rm', 'rk', 'rl', 'rg',
        'lt', 'ld', 'lk', 'lf', 'lp',
        'nc', 'nk', 'mp', 'mb', 'sp', 'sk', 'sm', 'sn', 'sl', 'sc',
        'tr', 'dr', 'br', 'cr', 'fr', 'gr', 'wr', 'bl', 'cl', 'fl', 'gl', 'pl',
    }
    
    # Common TLDs used by DGA
    DGA_TLDS = {
        'ru', 'cn', 'tk', 'cc', 'pw', 'ga', 'gq', 'ml',
        'cf', 'top', 'xyz', 'click', 'link', 'work',
        'party', 'gdn', 'bid', 'trade', 'webcam', 'date',
        'review', 'stream', 'download', 'racing', 'win',
    }
    
    # Known safe TLDs (less suspicious)
    SAFE_TLDS = {
        'gov', 'edu', 'mil', 'int', 'museum', 'aero',
        'coop', 'pro', 'jobs', 'travel',
    }
    
    # Minimum domain length to analyze
    MIN_LENGTH = 4
    
    # Thresholds
    ENTROPY_THRESHOLD = 3.8  # High entropy = suspicious
    CONSONANT_RATIO_MAX = 0.85  # Too many consonants
    DIGIT_RATIO_MAX = 0.4  # Too many digits
    BIGRAM_THRESHOLD = 0.2  # Too few common bigrams
    
    def __init__(
        self,
        entropy_threshold: float = 3.8,
        score_threshold: float = 0.6,
    ):
        self.entropy_threshold = entropy_threshold
        self.score_threshold = score_threshold
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Shannon entropy — delegates to the shared helper (single source of truth)."""
        return shannon_entropy(text)
    
    def _get_sld(self, domain: str) -> str:
        """Extract second-level domain for analysis."""
        domain = domain.lower().strip().rstrip('.')
        parts = domain.split('.')
        
        if len(parts) < 2:
            return domain
        
        # Handle common SLDs (co.uk, com.br, etc.)
        if len(parts) >= 3 and parts[-2] in {'co', 'com', 'net', 'org', 'gov', 'ac'}:
            return parts[-3]
        
        return parts[-2]
    
    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain."""
        domain = domain.lower().strip().rstrip('.')
        parts = domain.split('.')
        return parts[-1] if parts else ""
    
    def _analyze_character_distribution(self, sld: str) -> Tuple[float, List[str]]:
        """Analyze character distribution."""
        if not sld:
            return 0.0, []
        
        sld = sld.lower()
        reasons = []
        score = 0.0
        
        # Count character types
        vowels = sum(1 for c in sld if c in self.VOWELS)
        consonants = sum(1 for c in sld if c in self.CONSONANTS)
        digits = sum(1 for c in sld if c.isdigit())
        letters = vowels + consonants
        
        if letters == 0:
            return 0.5, ["No letters in domain"]
        
        # Consonant ratio
        consonant_ratio = consonants / letters if letters > 0 else 0
        if consonant_ratio > self.CONSONANT_RATIO_MAX:
            score += 0.3
            reasons.append(f"High consonant ratio: {consonant_ratio:.2f}")
        
        # Digit ratio
        digit_ratio = digits / len(sld)
        if digit_ratio > self.DIGIT_RATIO_MAX:
            score += 0.3
            reasons.append(f"High digit ratio: {digit_ratio:.2f}")
        
        # Check for vowel absence
        if vowels == 0 and len(sld) > 5:
            score += 0.2
            reasons.append("No vowels in domain")
        
        # Check for digit-only or mostly digits
        if digits > letters and len(sld) > 4:
            score += 0.2
            reasons.append("More digits than letters")
        
        return min(score, 1.0), reasons
    
    def _analyze_bigrams(self, sld: str) -> Tuple[float, List[str]]:
        """Analyze bigram patterns."""
        if len(sld) < 3:
            return 0.0, []
        
        sld = sld.lower()
        # Extract only letter bigrams
        letters_only = ''.join(c for c in sld if c.isalpha())
        
        if len(letters_only) < 2:
            return 0.0, []
        
        bigrams = [letters_only[i:i+2] for i in range(len(letters_only)-1)]
        if not bigrams:
            return 0.0, []
        
        common_count = sum(1 for bg in bigrams if bg in self.COMMON_BIGRAMS)
        common_ratio = common_count / len(bigrams)
        
        reasons = []
        score = 0.0
        
        if common_ratio < self.BIGRAM_THRESHOLD:
            score = 0.4 * (1 - common_ratio / self.BIGRAM_THRESHOLD)
            reasons.append(f"Few common bigrams: {common_ratio:.2f}")
        
        # Check for repeating patterns (sign of simple DGA)
        if len(set(bigrams)) < len(bigrams) / 2:
            score += 0.1
            reasons.append("Repeating bigram patterns")
        
        return min(score, 1.0), reasons

    def _analyze_language_model(self, sld: str) -> Tuple[float, List[str]]:
        """Learned naturalness: a trained character n-gram LANGUAGE MODEL scores how
        machine-generated the name looks. This is the proper, learned replacement for
        the hand-coded common-bigram check. Falls back to that bigram heuristic only
        when no trained model is present yet (e.g. a fresh install before first train)."""
        try:
            from .ml_classifier import get_domain_ml_model
            from ..config import get_settings
            model = get_domain_ml_model(get_settings().NETPROTECTION_DATA_DIR)
            if model.available:
                g = model.gibberish_score(sld)
                if g >= 0.8:  # only clear gibberish contributes (avoid FPs on unusual real names)
                    return min(g, 1.0), ["Language model: name looks machine-generated (%.2f)" % g]
                return 0.0, []
        except Exception:
            pass
        return self._analyze_bigrams(sld)  # fallback: hand-coded bigram heuristic

    def _analyze_entropy(self, sld: str) -> Tuple[float, List[str]]:
        """Analyze domain entropy."""
        entropy = self._calculate_entropy(sld)
        
        reasons = []
        score = 0.0
        
        if entropy > self.entropy_threshold:
            # Scale: 3.8 -> 0, 5.0 -> 1.0
            score = min((entropy - self.entropy_threshold) / 1.2, 1.0)
            reasons.append(f"High entropy: {entropy:.2f}")
        
        # Very low entropy is also suspicious (repeated patterns)
        if len(sld) > 6 and entropy < 2.0:
            score += 0.2
            reasons.append(f"Low entropy (repetitive): {entropy:.2f}")
        
        return score, reasons
    
    def _check_tld(self, tld: str) -> Tuple[float, List[str]]:
        """Check TLD suspiciousness."""
        if tld in self.SAFE_TLDS:
            return -0.2, ["Safe TLD"]
        
        if tld in self.DGA_TLDS:
            return 0.2, [f"Suspicious TLD: .{tld}"]
        
        return 0.0, []
    
    def _check_patterns(self, sld: str) -> Tuple[float, List[str]]:
        """Check for suspicious patterns."""
        reasons = []
        score = 0.0
        
        # All hex characters
        if re.match(r'^[0-9a-f]+$', sld.lower()) and len(sld) >= 8:
            score += 0.4
            reasons.append("Hex-like pattern")
        
        # Alternating consonants and digits
        if re.match(r'^([bcdfghjklmnpqrstvwxyz][0-9])+', sld.lower()):
            score += 0.3
            reasons.append("Alternating consonant-digit pattern")
        
        # Long strings without vowels
        consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', sld.lower())
        if consonant_runs:
            score += 0.2 * len(consonant_runs)
            reasons.append(f"Long consonant runs: {consonant_runs}")
        
        # Random looking (mixed case in original could indicate)
        if len(sld) > 10 and len(set(sld.lower())) > len(sld) * 0.7:
            score += 0.1
            reasons.append("High character diversity")
        
        return min(score, 1.0), reasons
    
    def analyze(self, domain: str) -> DGAResult:
        """
        Analyze domain for DGA characteristics.
        
        Returns DGAResult with detection details.
        """
        domain = domain.lower().strip().rstrip('.')
        sld = self._get_sld(domain)
        tld = self._get_tld(domain)
        
        # Skip short domains
        if len(sld) < self.MIN_LENGTH:
            return DGAResult(
                domain=domain,
                is_dga=False,
                score=0.0,
                confidence=0.0,
                reasons=["Domain too short for analysis"],
            )
        
        all_reasons = []
        total_score = 0.0
        
        # Run all analyses
        analyses = [
            self._analyze_entropy(sld),
            self._analyze_character_distribution(sld),
            self._analyze_language_model(sld),  # learned LM (replaces hand bigram list)
            self._check_patterns(sld),
            self._check_tld(tld),
        ]
        
        for score, reasons in analyses:
            total_score += score
            all_reasons.extend(reasons)
        
        # Normalize score (5 analyses, max contribution ~1.0 each)
        normalized_score = min(total_score / 2.5, 1.0)
        
        # Calculate confidence based on domain length
        # Longer domains give more confident results
        if len(sld) < 6:
            confidence = 0.5
        elif len(sld) < 10:
            confidence = 0.7
        else:
            confidence = 0.9
        
        # Determine if DGA
        is_dga = normalized_score >= self.score_threshold
        
        return DGAResult(
            domain=domain,
            is_dga=is_dga,
            score=normalized_score,
            confidence=confidence,
            reasons=all_reasons if all_reasons else ["No suspicious patterns"],
        )
    
    def is_dga(self, domain: str) -> bool:
        """Quick check if domain appears to be DGA."""
        return self.analyze(domain).is_dga
    
    def batch_analyze(self, domains: List[str]) -> List[DGAResult]:
        """Analyze multiple domains."""
        return [self.analyze(d) for d in domains]


# Singleton instance
_instance: DGADetector | None = None


def get_dga_detector() -> DGADetector:
    """Get singleton DGADetector instance."""
    global _instance
    
    if _instance is None:
        _instance = DGADetector()
    
    return _instance


# Quick helper functions
def is_dga_domain(domain: str) -> bool:
    """Quick check if domain is DGA-generated."""
    return get_dga_detector().is_dga(domain)


def analyze_domain_dga(domain: str) -> DGAResult:
    """Get full DGA analysis for domain."""
    return get_dga_detector().analyze(domain)
