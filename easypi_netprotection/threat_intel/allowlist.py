"""
Allowlist Manager — Manual allowlist for trusted domains.

Features:
- Exact, wildcard, and regex patterns
- Expiration support
- Import/export
- Priority over all threat detection
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta
from ..time_utils import utc_now
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class AllowlistEntry(BaseModel):
    """An entry in the allowlist."""
    id: str = Field(default_factory=lambda: f"allow_{uuid.uuid4().hex[:8]}")
    pattern: str = Field(..., description="Domain or pattern to allow")
    pattern_type: str = Field(default="exact", description="exact, wildcard, regex, suffix")
    reason: str = Field(default="", description="Why this was added")
    added_by: str = Field(default="system")
    added_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime | None = Field(default=None)
    enabled: bool = Field(default=True)
    hit_count: int = Field(default=0, description="How many times this rule matched")
    last_hit: datetime | None = Field(default=None)
    tags: list[str] = Field(default_factory=list)
    
    _compiled_regex: re.Pattern | None = None
    
    def matches(self, domain: str) -> bool:
        """Check if domain matches this allowlist entry."""
        if not self.enabled:
            return False
        
        if self.expires_at and utc_now() > self.expires_at:
            return False
        
        domain = domain.lower().strip(".")
        pattern = self.pattern.lower()
        
        if self.pattern_type == "exact":
            return domain == pattern
        
        elif self.pattern_type == "wildcard":
            return fnmatch(domain, pattern)
        
        elif self.pattern_type == "suffix":
            # Matches domain and all subdomains
            return domain == pattern or domain.endswith("." + pattern)
        
        elif self.pattern_type == "regex":
            try:
                if self._compiled_regex is None:
                    self._compiled_regex = re.compile(pattern, re.IGNORECASE)
                return bool(self._compiled_regex.match(domain))
            except re.error:
                return False
        
        return False
    
    def record_hit(self) -> None:
        """Record a hit on this rule."""
        self.hit_count += 1
        self.last_hit = utc_now()


class AllowlistManager:
    """
    Manages the domain allowlist.
    
    Allowlist has priority over ALL threat detection.
    If a domain is allowlisted, it will never be blocked or quarantined.
    """
    
    def __init__(self, db_path: str | Path | None = None):
        """
        Initialize allowlist manager.
        
        Args:
            db_path: Optional path to JSON file for persistence
        """
        self.db_path = Path(db_path) if db_path else None
        self._entries: dict[str, AllowlistEntry] = {}
        
        # Index for faster lookups
        self._exact_index: dict[str, str] = {}  # domain -> entry_id
        self._suffix_index: dict[str, str] = {}  # suffix -> entry_id
        
        if self.db_path and self.db_path.exists():
            self._load()
    
    def _load(self) -> None:
        """Load from file."""
        if not self.db_path:
            return
        
        try:
            with open(self.db_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for entry_data in data.get("entries", []):
                # Handle datetime fields
                if "added_at" in entry_data:
                    entry_data["added_at"] = datetime.fromisoformat(entry_data["added_at"])
                if "expires_at" in entry_data and entry_data["expires_at"]:
                    entry_data["expires_at"] = datetime.fromisoformat(entry_data["expires_at"])
                if "last_hit" in entry_data and entry_data["last_hit"]:
                    entry_data["last_hit"] = datetime.fromisoformat(entry_data["last_hit"])
                
                entry = AllowlistEntry(**entry_data)
                self._add_to_indexes(entry)
                self._entries[entry.id] = entry
        except Exception:
            pass
    
    def _save(self) -> None:
        """Save to file."""
        if not self.db_path:
            return
        
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            
            data = {
                "entries": [
                    {
                        **entry.model_dump(exclude={"_compiled_regex"}),
                        "added_at": entry.added_at.isoformat(),
                        "expires_at": entry.expires_at.isoformat() if entry.expires_at else None,
                        "last_hit": entry.last_hit.isoformat() if entry.last_hit else None,
                    }
                    for entry in self._entries.values()
                ]
            }
            
            with open(self.db_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def _add_to_indexes(self, entry: AllowlistEntry) -> None:
        """Add entry to lookup indexes."""
        pattern = entry.pattern.lower()
        
        if entry.pattern_type == "exact":
            self._exact_index[pattern] = entry.id
        elif entry.pattern_type == "suffix":
            self._suffix_index[pattern] = entry.id
    
    def _remove_from_indexes(self, entry: AllowlistEntry) -> None:
        """Remove entry from lookup indexes."""
        pattern = entry.pattern.lower()
        
        self._exact_index.pop(pattern, None)
        self._suffix_index.pop(pattern, None)
    
    def add(
        self,
        pattern: str,
        pattern_type: str = "exact",
        reason: str = "",
        added_by: str = "admin",
        expires_days: int | None = None,
        tags: list[str] | None = None,
    ) -> AllowlistEntry:
        """
        Add domain or pattern to allowlist.
        
        Args:
            pattern: Domain or pattern to allow
            pattern_type: Type of pattern (exact, wildcard, suffix, regex)
            reason: Why this is being added
            added_by: Who added it
            expires_days: Days until expiration (None for permanent)
            tags: Optional tags for organization
        
        Returns:
            Created AllowlistEntry
        """
        pattern = pattern.lower().strip(".")
        
        # Check for duplicate
        existing = self.get_by_pattern(pattern)
        if existing:
            # Update existing
            existing.reason = reason or existing.reason
            existing.enabled = True
            if expires_days:
                existing.expires_at = utc_now() + timedelta(days=expires_days)
            self._save()
            return existing
        
        entry = AllowlistEntry(
            pattern=pattern,
            pattern_type=pattern_type,
            reason=reason,
            added_by=added_by,
            expires_at=utc_now() + timedelta(days=expires_days) if expires_days else None,
            tags=tags or [],
        )
        
        self._entries[entry.id] = entry
        self._add_to_indexes(entry)
        self._save()
        
        return entry
    
    def remove(self, entry_id: str) -> bool:
        """Remove entry from allowlist."""
        entry = self._entries.pop(entry_id, None)
        if entry:
            self._remove_from_indexes(entry)
            self._save()
            return True
        return False
    
    def remove_by_pattern(self, pattern: str) -> bool:
        """Remove entry by pattern."""
        entry = self.get_by_pattern(pattern)
        if entry:
            return self.remove(entry.id)
        return False
    
    def disable(self, entry_id: str) -> bool:
        """Disable an entry without removing it."""
        entry = self._entries.get(entry_id)
        if entry:
            entry.enabled = False
            self._save()
            return True
        return False
    
    def enable(self, entry_id: str) -> bool:
        """Enable a disabled entry."""
        entry = self._entries.get(entry_id)
        if entry:
            entry.enabled = True
            self._save()
            return True
        return False
    
    def is_allowed(self, domain: str) -> tuple[bool, AllowlistEntry | None]:
        """
        Check if domain is allowlisted.
        
        Args:
            domain: Domain to check
        
        Returns:
            Tuple of (is_allowed, matching_entry)
        """
        domain = domain.lower().strip(".")
        
        # Fast path: exact match
        if domain in self._exact_index:
            entry_id = self._exact_index[domain]
            entry = self._entries.get(entry_id)
            if entry and entry.matches(domain):
                entry.record_hit()
                return True, entry
        
        # Check suffix index
        parts = domain.split(".")
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix in self._suffix_index:
                entry_id = self._suffix_index[suffix]
                entry = self._entries.get(entry_id)
                if entry and entry.matches(domain):
                    entry.record_hit()
                    return True, entry
        
        # Slow path: check all wildcard and regex patterns
        for entry in self._entries.values():
            if entry.pattern_type in ("wildcard", "regex"):
                if entry.matches(domain):
                    entry.record_hit()
                    return True, entry
        
        return False, None
    
    def get(self, entry_id: str) -> AllowlistEntry | None:
        """Get entry by ID."""
        return self._entries.get(entry_id)
    
    def get_by_pattern(self, pattern: str) -> AllowlistEntry | None:
        """Get entry by pattern."""
        pattern = pattern.lower()
        for entry in self._entries.values():
            if entry.pattern.lower() == pattern:
                return entry
        return None
    
    def get_all(self, include_disabled: bool = False) -> list[AllowlistEntry]:
        """Get all allowlist entries."""
        entries = list(self._entries.values())
        if not include_disabled:
            entries = [e for e in entries if e.enabled]
        return sorted(entries, key=lambda e: e.added_at, reverse=True)
    
    def get_by_tag(self, tag: str) -> list[AllowlistEntry]:
        """Get entries by tag."""
        return [e for e in self._entries.values() if tag in e.tags]
    
    def search(self, query: str) -> list[AllowlistEntry]:
        """Search entries by pattern or reason."""
        query = query.lower()
        results = []
        
        for entry in self._entries.values():
            if query in entry.pattern.lower() or query in entry.reason.lower():
                results.append(entry)
        
        return results
    
    def cleanup_expired(self) -> int:
        """Remove expired entries. Returns count removed."""
        now = utc_now()
        expired = [
            eid for eid, e in self._entries.items()
            if e.expires_at and e.expires_at < now
        ]
        
        for eid in expired:
            entry = self._entries.pop(eid)
            self._remove_from_indexes(entry)
        
        if expired:
            self._save()
        
        return len(expired)
    
    def get_stats(self) -> dict[str, Any]:
        """Get allowlist statistics."""
        entries = list(self._entries.values())
        enabled = [e for e in entries if e.enabled]
        
        return {
            "total_entries": len(entries),
            "enabled_entries": len(enabled),
            "by_type": {
                "exact": sum(1 for e in enabled if e.pattern_type == "exact"),
                "wildcard": sum(1 for e in enabled if e.pattern_type == "wildcard"),
                "suffix": sum(1 for e in enabled if e.pattern_type == "suffix"),
                "regex": sum(1 for e in enabled if e.pattern_type == "regex"),
            },
            "total_hits": sum(e.hit_count for e in entries),
            "most_used": sorted(
                [{"pattern": e.pattern, "hits": e.hit_count} for e in entries if e.hit_count > 0],
                key=lambda x: x["hits"],
                reverse=True,
            )[:10],
        }
    
    def export_to_list(self) -> list[str]:
        """Export all patterns as plain list."""
        return [e.pattern for e in self._entries.values() if e.enabled]
    
    def import_from_list(
        self,
        patterns: list[str],
        pattern_type: str = "exact",
        reason: str = "bulk import",
        added_by: str = "import",
        tags: list[str] | None = None,
    ) -> int:
        """
        Import patterns from a list.
        
        Returns count of entries added.
        """
        count = 0
        tags = tags or ["import"]
        
        for pattern in patterns:
            pattern = pattern.strip()
            if not pattern or pattern.startswith("#"):
                continue
            
            # Detect pattern type if auto
            detected_type = pattern_type
            if pattern.startswith("*."):
                detected_type = "suffix"
                pattern = pattern[2:]  # Remove *.
            elif "*" in pattern:
                detected_type = "wildcard"
            
            existing = self.get_by_pattern(pattern)
            if not existing:
                self.add(
                    pattern=pattern,
                    pattern_type=detected_type,
                    reason=reason,
                    added_by=added_by,
                    tags=tags,
                )
                count += 1
        
        return count
    
    def to_ui_list(self) -> list[dict[str, Any]]:
        """Generate UI-friendly list."""
        entries = self.get_all(include_disabled=True)
        
        return [
            {
                "id": e.id,
                "pattern": e.pattern,
                "type": e.pattern_type,
                "reason": e.reason,
                "added_by": e.added_by,
                "added_at": e.added_at.isoformat(),
                "expires_at": e.expires_at.isoformat() if e.expires_at else None,
                "enabled": e.enabled,
                "hits": e.hit_count,
                "last_hit": e.last_hit.isoformat() if e.last_hit else None,
                "tags": e.tags,
            }
            for e in entries
        ]
