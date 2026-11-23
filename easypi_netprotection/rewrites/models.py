"""
DNS Rewrite Models

Data structures for DNS rewrite rules.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
import fnmatch


class RewriteType(str, Enum):
    """Type of rewrite target."""
    
    # IP address rewrites
    A = "A"           # IPv4 address
    AAAA = "AAAA"     # IPv6 address
    
    # Domain rewrites
    CNAME = "CNAME"   # Redirect to another domain
    
    # Special rewrites
    NXDOMAIN = "NXDOMAIN"   # Return NXDOMAIN (domain doesn't exist)
    NODATA = "NODATA"       # Return empty response
    REFUSED = "REFUSED"     # Return REFUSED
    
    # Passthrough (disable rewrite for specific pattern)
    PASSTHROUGH = "PASSTHROUGH"


@dataclass
class RewriteRule:
    """
    A DNS rewrite rule.
    
    Attributes:
        id: Unique identifier
        domain: Domain pattern to match (supports wildcards)
        answer: Target answer (IP, domain, or special value)
        rewrite_type: Type of rewrite (A, AAAA, CNAME, etc.)
        enabled: Whether the rule is active
        comment: Optional description
        priority: Higher priority rules are evaluated first
        created_at: When the rule was created
        updated_at: When the rule was last modified
    """
    
    id: str
    domain: str
    answer: str
    rewrite_type: RewriteType = RewriteType.A
    enabled: bool = True
    comment: str = ""
    priority: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    # Internal: compiled regex for wildcard matching
    _pattern: re.Pattern | None = field(default=None, repr=False, compare=False)
    
    def __post_init__(self):
        """Compile pattern for matching."""
        self._compile_pattern()
    
    def _compile_pattern(self) -> None:
        """Compile domain pattern to regex."""
        pattern = self.domain.lower()
        
        # Handle wildcards
        if "*" in pattern:
            # Convert wildcard pattern to regex
            # *.example.com -> (.*\.)?example\.com$
            regex = fnmatch.translate(pattern)
            # Fix: fnmatch adds \Z, we want $
            regex = regex.replace(r"\Z", "$")
            self._pattern = re.compile(regex, re.IGNORECASE)
        else:
            self._pattern = None
    
    def matches(self, query_domain: str) -> bool:
        """
        Check if this rule matches the given domain.
        
        Args:
            query_domain: Domain to check (e.g., "www.example.com")
            
        Returns:
            True if the rule matches
        """
        query = query_domain.lower().rstrip(".")
        pattern = self.domain.lower().rstrip(".")
        
        # Exact match
        if query == pattern:
            return True
        
        # Wildcard match
        if self._pattern:
            return bool(self._pattern.match(query))
        
        return False
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for storage/API."""
        return {
            "id": self.id,
            "domain": self.domain,
            "answer": self.answer,
            "rewrite_type": self.rewrite_type.value,
            "enabled": self.enabled,
            "comment": self.comment,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RewriteRule":
        """Create from dictionary."""
        return cls(
            id=data["id"],
            domain=data["domain"],
            answer=data["answer"],
            rewrite_type=RewriteType(data.get("rewrite_type", "A")),
            enabled=data.get("enabled", True),
            comment=data.get("comment", ""),
            priority=data.get("priority", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if "created_at" in data else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if "updated_at" in data else datetime.now(),
        )


@dataclass
class RewriteMatch:
    """Result of a rewrite rule match."""
    
    rule: RewriteRule
    original_domain: str
    rewritten_answer: str
    rewrite_type: RewriteType
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule.id,
            "original_domain": self.original_domain,
            "rewritten_answer": self.rewritten_answer,
            "rewrite_type": self.rewrite_type.value,
            "comment": self.rule.comment,
        }
