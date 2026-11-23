"""
Domain Analyzer - Structural analysis of domain names.

Analyzes domain structure for suspicious patterns:
- Length analysis
- Subdomain depth
- Number/special character ratio
- Entropy and randomness

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
class DomainAnalysisResult:
    """Result of domain structural analysis."""
    domain: str
    total_score: float  # 0.0 - 1.0
    length_score: float
    depth_score: float
    numbers_score: float
    structure_score: float
    reasons: List[str]
    
    @property
    def risk_weight(self) -> int:
        """
        Risk weight for signal aggregator.
        
        Length: up to 10
        Depth: up to 10
        Numbers: up to 15
        Structure: up to 10
        Total max: ~35-40 but capped at 25
        """
        return min(int(self.total_score * 25), 25)


class DomainAnalyzer:
    """
    Structural analysis of domain names.
    
    Identifies suspicious patterns in domain structure.
    """
    
    # Length thresholds
    SUSPICIOUS_LENGTH = 25
    VERY_SUSPICIOUS_LENGTH = 40
    
    # Subdomain depth
    MAX_NORMAL_DEPTH = 3
    SUSPICIOUS_DEPTH = 5
    
    # Character ratios
    MAX_DIGIT_RATIO = 0.3
    MAX_HYPHEN_RATIO = 0.15
    
    # Suspicious patterns
    SUSPICIOUS_PATTERNS = [
        r'\d{5,}',           # 5+ consecutive digits
        r'[a-z]\d+[a-z]\d+', # Alternating letters and numbers
        r'(.)\1{3,}',        # 4+ repeated characters
        r'-{2,}',            # Multiple consecutive hyphens
        r'^-|-$',            # Leading/trailing hyphen
        r'\d+-\d+',          # Numbers with hyphens (like IPs)
    ]
    
    # Common safe subdomain patterns
    SAFE_SUBDOMAINS = {
        'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'sftp',
        'api', 'cdn', 'static', 'assets', 'images', 'img',
        'dev', 'test', 'staging', 'prod', 'beta', 'alpha',
        'app', 'mobile', 'm', 'admin', 'dashboard',
        'auth', 'login', 'sso', 'oauth', 'accounts',
        'docs', 'help', 'support', 'status', 'blog',
        'shop', 'store', 'cart', 'checkout', 'pay',
        'ns', 'ns1', 'ns2', 'ns3', 'mx', 'mx1', 'mx2',
        'vpn', 'remote', 'proxy', 'gateway', 'gw',
        'eu', 'us', 'uk', 'de', 'fr', 'asia', 'global',
        'web', 'www2', 'www3', 'portal', 'intranet',
    }
    
    def __init__(
        self,
        length_threshold: int = 25,
        depth_threshold: int = 4,
    ):
        self.length_threshold = length_threshold
        self.depth_threshold = depth_threshold
        
        # Compile patterns
        self._patterns = [
            (re.compile(p, re.IGNORECASE), p)
            for p in self.SUSPICIOUS_PATTERNS
        ]
    
    def _analyze_length(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze domain length."""
        domain = domain.rstrip('.')
        length = len(domain)
        
        # Also check SLD length
        parts = domain.split('.')
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        sld_length = len(sld)
        
        reasons = []
        score = 0.0
        
        # Full domain length
        if length > self.VERY_SUSPICIOUS_LENGTH:
            score += 0.5
            reasons.append(f"Very long domain: {length} chars")
        elif length > self.SUSPICIOUS_LENGTH:
            # Scale from 25-40
            score += 0.25 * (length - self.SUSPICIOUS_LENGTH) / 15
            reasons.append(f"Long domain: {length} chars")
        
        # SLD length
        if sld_length > 20:
            score += 0.3
            reasons.append(f"Very long SLD: {sld_length} chars")
        elif sld_length > 15:
            score += 0.15
            reasons.append(f"Long SLD: {sld_length} chars")
        
        return min(score, 1.0), reasons
    
    def _analyze_depth(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze subdomain depth."""
        domain = domain.rstrip('.')
        parts = domain.split('.')
        depth = len(parts)
        
        reasons = []
        score = 0.0
        
        if depth > self.SUSPICIOUS_DEPTH:
            score = 0.6 + 0.1 * (depth - self.SUSPICIOUS_DEPTH)
            reasons.append(f"Very deep subdomain: {depth} levels")
        elif depth > self.MAX_NORMAL_DEPTH:
            score = 0.2 * (depth - self.MAX_NORMAL_DEPTH)
            reasons.append(f"Deep subdomain: {depth} levels")
        
        # Check for suspicious subdomain names
        suspicious_sub_count = 0
        for part in parts[:-2]:  # Exclude SLD and TLD
            if part.lower() not in self.SAFE_SUBDOMAINS:
                # Check if it looks random
                if len(part) > 10 and self._calculate_entropy(part) > 3.5:
                    suspicious_sub_count += 1
        
        if suspicious_sub_count > 0:
            score += 0.2 * suspicious_sub_count
            reasons.append(f"{suspicious_sub_count} suspicious subdomain(s)")
        
        return min(score, 1.0), reasons
    
    def _analyze_numbers(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze digit usage in domain."""
        domain = domain.rstrip('.')
        parts = domain.split('.')
        
        # Focus on SLD and subdomains (not TLD)
        analysis_parts = parts[:-1] if len(parts) > 1 else parts
        text = '.'.join(analysis_parts)
        
        if not text:
            return 0.0, []
        
        digits = sum(1 for c in text if c.isdigit())
        letters = sum(1 for c in text if c.isalpha())
        total = digits + letters
        
        if total == 0:
            return 0.0, []
        
        digit_ratio = digits / total
        
        reasons = []
        score = 0.0
        
        if digit_ratio > 0.5:
            score = 0.6
            reasons.append(f"High digit ratio: {digit_ratio:.0%}")
        elif digit_ratio > self.MAX_DIGIT_RATIO:
            score = 0.3 * (digit_ratio - self.MAX_DIGIT_RATIO) / 0.2
            reasons.append(f"Many digits: {digit_ratio:.0%}")
        
        # Check for IP-like patterns
        if re.search(r'\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}', text):
            score += 0.3
            reasons.append("IP-like pattern in domain")
        
        # Check for long number sequences
        long_numbers = re.findall(r'\d{5,}', text)
        if long_numbers:
            score += 0.2 * len(long_numbers)
            reasons.append(f"Long number sequence(s): {long_numbers}")
        
        return min(score, 1.0), reasons
    
    def _analyze_structure(self, domain: str) -> Tuple[float, List[str]]:
        """Analyze domain structure patterns."""
        domain = domain.rstrip('.')
        parts = domain.split('.')
        
        # Analyze SLD primarily
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        
        reasons = []
        score = 0.0
        
        # Check suspicious patterns
        for pattern, pattern_str in self._patterns:
            if pattern.search(sld):
                score += 0.2
                reasons.append(f"Suspicious pattern: {pattern_str}")
        
        # Check hyphen usage
        hyphens = sld.count('-')
        if hyphens > 0:
            hyphen_ratio = hyphens / len(sld) if sld else 0
            
            if hyphen_ratio > self.MAX_HYPHEN_RATIO:
                score += 0.3
                reasons.append(f"Many hyphens: {hyphens}")
            
            if hyphens > 3:
                score += 0.2
                reasons.append(f"Excessive hyphens: {hyphens}")
        
        # Check for unusual character combinations
        if re.search(r'[a-z]{2,}\d+[a-z]{2,}\d+', sld.lower()):
            score += 0.2
            reasons.append("Alternating text-number pattern")
        
        # Check for very short SLD (potential squatting)
        if len(sld) <= 2 and len(parts) > 2:
            score += 0.1
            reasons.append("Very short SLD with subdomains")
        
        return min(score, 1.0), reasons
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """Shannon entropy — delegates to the shared helper (single source of truth)."""
        return shannon_entropy(text)
    
    def analyze(self, domain: str) -> DomainAnalysisResult:
        """
        Analyze domain structure.
        
        Returns DomainAnalysisResult with detailed scores.
        """
        domain = domain.lower().strip().rstrip('.')
        
        # Run all analyses
        length_score, length_reasons = self._analyze_length(domain)
        depth_score, depth_reasons = self._analyze_depth(domain)
        numbers_score, numbers_reasons = self._analyze_numbers(domain)
        structure_score, structure_reasons = self._analyze_structure(domain)
        
        # Combine reasons
        all_reasons = length_reasons + depth_reasons + numbers_reasons + structure_reasons
        
        # Weight the scores
        # Length: 25%, Depth: 25%, Numbers: 30%, Structure: 20%
        total_score = (
            length_score * 0.25 +
            depth_score * 0.25 +
            numbers_score * 0.30 +
            structure_score * 0.20
        )
        
        return DomainAnalysisResult(
            domain=domain,
            total_score=total_score,
            length_score=length_score,
            depth_score=depth_score,
            numbers_score=numbers_score,
            structure_score=structure_score,
            reasons=all_reasons if all_reasons else ["Normal domain structure"],
        )
    
    def get_risk_signals(self, domain: str) -> List[Tuple[str, int, str]]:
        """
        Get individual risk signals for signal aggregator.
        
        Returns: List of (signal_type, weight, reason)
        """
        result = self.analyze(domain)
        signals = []
        
        if result.length_score > 0.2:
            weight = int(result.length_score * 10)
            signals.append(('domain_length', weight, f"Length: {len(domain)} chars"))
        
        if result.depth_score > 0.2:
            weight = int(result.depth_score * 10)
            depth = len(domain.split('.'))
            signals.append(('domain_depth', weight, f"Depth: {depth} levels"))
        
        if result.numbers_score > 0.2:
            weight = int(result.numbers_score * 15)
            signals.append(('domain_numbers', weight, "Numbers in domain"))
        
        return signals
    
    def batch_analyze(self, domains: List[str]) -> List[DomainAnalysisResult]:
        """Analyze multiple domains."""
        return [self.analyze(d) for d in domains]


# Singleton instance
_instance: DomainAnalyzer | None = None


def get_domain_analyzer() -> DomainAnalyzer:
    """Get singleton DomainAnalyzer instance."""
    global _instance
    
    if _instance is None:
        _instance = DomainAnalyzer()
    
    return _instance


# Quick helper function
def analyze_domain_structure(domain: str) -> DomainAnalysisResult:
    """Get full domain structure analysis."""
    return get_domain_analyzer().analyze(domain)
