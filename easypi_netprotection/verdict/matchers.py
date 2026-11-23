"""
EasyPi NetProtection - Domain Matchers

Rule-based domain matching with support for exact, wildcard,
regex, IP-based, and ASN-based patterns.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..vault.models import Matcher, MatcherKind
from .evidence import Evidence, EvidenceSource


logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of a matcher evaluation."""
    
    matched: bool
    matcher_id: str
    pattern: str
    action: str
    confidence: int
    reason: str
    priority: int = 0
    redirect_target: str | None = None
    tags: list[str] = field(default_factory=list)
    
    def to_evidence(self, source: EvidenceSource) -> Evidence:
        """Convert match result to evidence."""
        return Evidence(
            source=source,
            signal=self.reason,
            confidence=self.confidence,
            weight=source.base_weight,
            suggested_action=self.action,
            metadata={
                "matcher_id": self.matcher_id,
                "pattern": self.pattern,
                "tags": self.tags,
            },
        )


class BaseMatcher(ABC):
    """Abstract base class for domain matchers."""
    
    def __init__(self, matcher: Matcher):
        self.matcher = matcher
        self._compiled: Any = None
        self._compile()
    
    @abstractmethod
    def _compile(self) -> None:
        """Compile the pattern for efficient matching."""
        pass
    
    @abstractmethod
    def matches(self, domain: str) -> bool:
        """Check if domain matches the pattern."""
        pass
    
    def evaluate(self, domain: str) -> MatchResult | None:
        """Evaluate domain against this matcher."""
        if not self.matcher.enabled:
            return None
        
        if self.matches(domain):
            return MatchResult(
                matched=True,
                matcher_id=self.matcher.id,
                pattern=self.matcher.pattern,
                action=self.matcher.action,
                confidence=100,  # Exact rule match
                reason=f"matched {self.matcher.kind.value} pattern: {self.matcher.pattern}",
                priority=self.matcher.priority,
                redirect_target=self.matcher.redirect_target,
                tags=self.matcher.tags,
            )
        
        return None
    
    @property
    def evidence_source(self) -> EvidenceSource:
        """Get the evidence source for this matcher type."""
        source_map = {
            MatcherKind.EXACT: EvidenceSource.MATCHER_EXACT,
            MatcherKind.WILDCARD: EvidenceSource.MATCHER_WILDCARD,
            MatcherKind.REGEX: EvidenceSource.MATCHER_REGEX,
            MatcherKind.IP: EvidenceSource.MATCHER_IP,
            MatcherKind.ASN: EvidenceSource.MATCHER_ASN,
        }
        return source_map.get(self.matcher.kind, EvidenceSource.MATCHER_EXACT)


class ExactMatcher(BaseMatcher):
    """Exact domain matching (case-insensitive)."""
    
    def _compile(self) -> None:
        self._compiled = self.matcher.pattern.lower().strip(".")
    
    def matches(self, domain: str) -> bool:
        normalized = domain.lower().strip(".")
        return normalized == self._compiled


class WildcardMatcher(BaseMatcher):
    """
    Wildcard domain matching.
    
    Supports:
    - *.example.com - matches any subdomain
    - ads.*.com - matches any domain in middle
    - *.* - matches all domains
    """
    
    def _compile(self) -> None:
        pattern = self.matcher.pattern.lower().strip(".")
        # Convert to regex for efficient matching
        # Escape dots, convert * to regex wildcard
        escaped = re.escape(pattern).replace(r"\*", r"[^.]*")
        self._compiled = re.compile(f"^{escaped}$", re.IGNORECASE)
    
    def matches(self, domain: str) -> bool:
        normalized = domain.lower().strip(".")
        
        # Fast path for common *.domain.com pattern
        pattern = self.matcher.pattern.lower().strip(".")
        if pattern.startswith("*."):
            suffix = pattern[2:]  # Remove "*."
            if normalized == suffix or normalized.endswith("." + suffix):
                return True
            return False
        
        # General regex match
        return bool(self._compiled.match(normalized))


class RegexMatcher(BaseMatcher):
    """Regular expression domain matching with ReDoS protection."""
    
    # Maximum pattern length to prevent excessive complexity
    MAX_PATTERN_LENGTH = 500
    
    # Patterns that often cause catastrophic backtracking
    DANGEROUS_PATTERNS = [
        r'(\w+)+',     # Nested quantifiers
        r'(a+)+',
        r'(.*)*',
        r'(.+)+',
        r'(a|a)+',     # Alternation with overlap
    ]
    
    def _compile(self) -> None:
        pattern = self.matcher.pattern
        
        # Check pattern length
        if len(pattern) > self.MAX_PATTERN_LENGTH:
            logger.warning(f"Regex pattern too long ({len(pattern)} chars), rejecting")
            self._compiled = None
            return
        
        # Check for dangerous patterns (basic ReDoS detection)
        pattern_lower = pattern.lower()
        for dangerous in self.DANGEROUS_PATTERNS:
            if dangerous in pattern_lower:
                logger.warning("Potentially dangerous regex pattern detected")
                self._compiled = None
                return
        
        try:
            self._compiled = re.compile(
                pattern,
                re.IGNORECASE,
            )
        except re.error as e:
            logger.error(f"Invalid regex pattern '{pattern}': {e}")
            self._compiled = None
    
    def matches(self, domain: str) -> bool:
        if self._compiled is None:
            return False
        
        # Limit domain length to prevent long-running matches
        if len(domain) > 253:  # Max DNS domain length
            return False
        
        return bool(self._compiled.search(domain))


class IPMatcher(BaseMatcher):
    """
    IP address matching for DNS responses.
    
    Matches if the resolved IP falls within the specified
    IP address or network range.
    """
    
    def _compile(self) -> None:
        try:
            # Support both single IPs and CIDR notation
            if "/" in self.matcher.pattern:
                self._compiled = ipaddress.ip_network(
                    self.matcher.pattern,
                    strict=False,
                )
            else:
                self._compiled = ipaddress.ip_address(self.matcher.pattern)
        except ValueError as e:
            logger.error(f"Invalid IP pattern '{self.matcher.pattern}': {e}")
            self._compiled = None
    
    def matches(self, domain: str) -> bool:
        # IP matcher doesn't match domains directly
        # It's used in post-resolution phase
        return False
    
    def matches_ip(self, ip_str: str) -> bool:
        """Check if an IP address matches this pattern."""
        if self._compiled is None:
            return False
        
        try:
            ip = ipaddress.ip_address(ip_str)
            
            if isinstance(self._compiled, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
                return ip in self._compiled
            else:
                return ip == self._compiled
                
        except ValueError:
            return False
    
    def evaluate_ip(self, ip_str: str) -> MatchResult | None:
        """Evaluate IP address against this matcher."""
        if not self.matcher.enabled:
            return None
        
        if self.matches_ip(ip_str):
            return MatchResult(
                matched=True,
                matcher_id=self.matcher.id,
                pattern=self.matcher.pattern,
                action=self.matcher.action,
                confidence=100,
                reason=f"response IP {ip_str} matches pattern {self.matcher.pattern}",
                priority=self.matcher.priority,
                redirect_target=self.matcher.redirect_target,
                tags=self.matcher.tags,
            )
        
        return None


class ASNMatcher(BaseMatcher):
    """
    ASN (Autonomous System Number) matching.
    
    Matches if the resolved IP belongs to the specified ASN.
    Requires external ASN lookup.
    """
    
    def _compile(self) -> None:
        # ASN can be specified as "AS12345" or just "12345"
        pattern = self.matcher.pattern.upper()
        if pattern.startswith("AS"):
            self._compiled = int(pattern[2:])
        else:
            try:
                self._compiled = int(pattern)
            except ValueError:
                logger.error(f"Invalid ASN pattern '{self.matcher.pattern}'")
                self._compiled = None
    
    def matches(self, domain: str) -> bool:
        # ASN matcher doesn't match domains directly
        return False
    
    def matches_asn(self, asn: int) -> bool:
        """Check if an ASN matches this pattern."""
        if self._compiled is None:
            return False
        return asn == self._compiled
    
    def evaluate_asn(self, asn: int, asn_name: str = "") -> MatchResult | None:
        """Evaluate ASN against this matcher."""
        if not self.matcher.enabled:
            return None
        
        if self.matches_asn(asn):
            return MatchResult(
                matched=True,
                matcher_id=self.matcher.id,
                pattern=self.matcher.pattern,
                action=self.matcher.action,
                confidence=95,  # Slightly lower - ASN can have mixed content
                reason=f"IP belongs to AS{asn} ({asn_name})",
                priority=self.matcher.priority,
                redirect_target=self.matcher.redirect_target,
                tags=self.matcher.tags,
            )
        
        return None


def create_matcher(matcher: Matcher) -> BaseMatcher:
    """Factory function to create appropriate matcher instance."""
    matcher_classes = {
        MatcherKind.EXACT: ExactMatcher,
        MatcherKind.WILDCARD: WildcardMatcher,
        MatcherKind.REGEX: RegexMatcher,
        MatcherKind.IP: IPMatcher,
        MatcherKind.ASN: ASNMatcher,
    }
    
    cls = matcher_classes.get(matcher.kind, ExactMatcher)
    return cls(matcher)


class MatcherRegistry:
    """
    Registry of all active matchers with efficient lookup.
    
    Organizes matchers by type and provides batch evaluation.
    """
    
    def __init__(self):
        self._matchers: dict[str, BaseMatcher] = {}
        self._by_kind: dict[MatcherKind, list[BaseMatcher]] = {
            kind: [] for kind in MatcherKind
        }
        self._sorted_by_priority: list[BaseMatcher] = []
    
    def add(self, matcher: Matcher) -> None:
        """Add a matcher to the registry."""
        instance = create_matcher(matcher)
        self._matchers[matcher.id] = instance
        self._by_kind[matcher.kind].append(instance)
        self._resort()
    
    def remove(self, matcher_id: str) -> None:
        """Remove a matcher from the registry."""
        if matcher_id not in self._matchers:
            return
        
        instance = self._matchers.pop(matcher_id)
        self._by_kind[instance.matcher.kind].remove(instance)
        self._resort()
    
    def get(self, matcher_id: str) -> BaseMatcher | None:
        """Get a specific matcher by ID."""
        return self._matchers.get(matcher_id)
    
    def _resort(self) -> None:
        """Re-sort matchers by priority (highest first)."""
        self._sorted_by_priority = sorted(
            self._matchers.values(),
            key=lambda m: m.matcher.priority,
            reverse=True,
        )
    
    def evaluate_domain(self, domain: str) -> list[MatchResult]:
        """
        Evaluate domain against all domain-based matchers.
        
        Returns all matches sorted by priority.
        """
        results = []
        
        for matcher in self._sorted_by_priority:
            if matcher.matcher.kind in (MatcherKind.IP, MatcherKind.ASN):
                continue  # Skip IP/ASN matchers for domain evaluation
            
            result = matcher.evaluate(domain)
            if result:
                results.append(result)
        
        return results
    
    def evaluate_ip(self, ip_str: str) -> list[MatchResult]:
        """Evaluate IP address against IP matchers."""
        results = []
        
        for matcher in self._by_kind[MatcherKind.IP]:
            if isinstance(matcher, IPMatcher):
                result = matcher.evaluate_ip(ip_str)
                if result:
                    results.append(result)
        
        return results
    
    def evaluate_asn(self, asn: int, asn_name: str = "") -> list[MatchResult]:
        """Evaluate ASN against ASN matchers."""
        results = []
        
        for matcher in self._by_kind[MatcherKind.ASN]:
            if isinstance(matcher, ASNMatcher):
                result = matcher.evaluate_asn(asn, asn_name)
                if result:
                    results.append(result)
        
        return results
    
    def find_best_match(self, domain: str) -> MatchResult | None:
        """
        Find the best matching rule for a domain.
        
        Priority order:
        1. ALLOW rules (highest priority first)
        2. Other rules (highest priority first)
        """
        results = self.evaluate_domain(domain)
        
        if not results:
            return None
        
        # Allow rules take precedence
        allow_results = [r for r in results if r.action == "allow"]
        if allow_results:
            return max(allow_results, key=lambda r: r.priority)
        
        # Otherwise, highest priority wins
        return results[0]  # Already sorted by priority
    
    def load_from_list(self, matchers: list[Matcher]) -> None:
        """Load multiple matchers at once."""
        self._matchers.clear()
        for kind in MatcherKind:
            self._by_kind[kind].clear()
        
        for matcher in matchers:
            instance = create_matcher(matcher)
            self._matchers[matcher.id] = instance
            self._by_kind[matcher.kind].append(instance)
        
        self._resort()
    
    @property
    def count(self) -> int:
        """Total number of matchers."""
        return len(self._matchers)
    
    def create_from_dict(self, data: dict[str, Any]) -> Matcher:
        """
        Create a matcher from dictionary with validation.
        
        Raises:
            ValueError: If validation fails
        """
        from ..vault.models import MatcherCreate
        
        try:
            # Validate through Pydantic model
            create_model = MatcherCreate(**data)
            
            # Generate ID if not provided
            import secrets
            matcher_id = data.get("id") or f"m_{secrets.token_hex(8)}"
            
            matcher = Matcher(
                id=matcher_id,
                pattern=create_model.pattern,
                kind=create_model.kind,
                action=create_model.action,
                priority=create_model.priority,
                enabled=create_model.enabled,
                tags=create_model.tags,
                redirect_ip=create_model.redirect_ip,
                comment=create_model.comment,
            )
            return matcher
        except Exception as e:
            raise ValueError(f"Invalid matcher data: {e}")
    
    def update(self, matcher_id: str, data: dict[str, Any]) -> Matcher:
        """
        Update an existing matcher.
        
        Raises:
            ValueError: If matcher not found or validation fails
        """
        from ..vault.models import MatcherUpdate
        
        instance = self._matchers.get(matcher_id)
        if not instance:
            raise ValueError(f"Matcher {matcher_id} not found")
        
        try:
            # Validate through Pydantic
            update_model = MatcherUpdate(**data)
            updates = update_model.model_dump(exclude_unset=True)
            
            # Apply updates to existing matcher
            for key, value in updates.items():
                if hasattr(instance.matcher, key):
                    setattr(instance.matcher, key, value)
            
            # Recreate the matcher instance if kind changed
            if "kind" in updates:
                self.remove(matcher_id)
                self.add(instance.matcher)
            
            return instance.matcher
        except Exception as e:
            raise ValueError(f"Invalid update data: {e}")
    
    def stats(self) -> dict[str, Any]:
        """Get registry statistics."""
        return {
            "total": self.count,
            "by_kind": {
                kind.value: len(matchers)
                for kind, matchers in self._by_kind.items()
            },
            "enabled": sum(
                1 for m in self._matchers.values()
                if m.matcher.enabled
            ),
        }


# Global registry instance
_registry: MatcherRegistry | None = None


def get_matcher_registry() -> MatcherRegistry:
    """Get the global matcher registry."""
    global _registry
    if _registry is None:
        _registry = MatcherRegistry()
    return _registry
