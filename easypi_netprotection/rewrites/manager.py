"""
DNS Rewrite Manager — Security Hardened

Manages DNS rewrite rules with comprehensive security:
- Atomic persistence with rollback
- Thread-safe with write serialization
- Input validation (punycode, loops, cycles)
- Protected system zones
- Rate limiting metrics
- Sanitized logging
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import RewriteRule, RewriteType, RewriteMatch
from ..config import get_settings


logger = logging.getLogger(__name__)


# Module-level singleton
_manager_instance: "RewriteManager | None" = None
_manager_lock = threading.Lock()


def get_rewrite_manager(data_dir: str | None = None) -> "RewriteManager":
    """Get or create the singleton RewriteManager."""
    global _manager_instance
    
    if _manager_instance is None:
        if data_dir is None:
            data_dir = get_settings().NETPROTECTION_DATA_DIR
            
        with _manager_lock:
            if _manager_instance is None:
                _manager_instance = RewriteManager(data_dir)
    
    return _manager_instance


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS & SECURITY CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Security limits
MAX_RULES = 5000                    # Prevent DoS via rule flooding
MAX_DOMAIN_LENGTH = 253             # RFC 1035 limit
MAX_WILDCARD_DEPTH = 3              # Max * segments (e.g., *.*.example.com)
MIN_WILDCARD_SPECIFICITY = 2        # Minimum labels after wildcard
DEFAULT_REWRITE_TTL = 300           # TTL for rewritten responses
MAX_CNAME_CHAIN = 10                # Max CNAME chain depth to prevent loops

# Protected system zones — NXDOMAIN rules CANNOT target these
PROTECTED_ZONES = frozenset([
    "localhost",
    "localdomain", 
    "local",           # mDNS
    "home.arpa",       # Home networks (RFC 8375)
    "internal",
    "lan",
    "corp",
    "intranet",
    "in-addr.arpa",    # Reverse DNS
    "ip6.arpa",        # IPv6 reverse DNS
])

# Forbidden patterns — too broad, dangerous
FORBIDDEN_PATTERNS = frozenset([
    "*",               # Match everything
    "*.*",             # Match all TLDs
    "**",              # Invalid
    "*.*.*",           # Too broad
])

# Punycode pattern for IDN domains
PUNYCODE_PREFIX = "xn--"


class RewriteManager:
    """
    Manages DNS rewrite rules with security hardening.
    
    Security features:
    - Atomic file writes with rollback
    - Thread-safe with write serialization
    - Input validation (punycode, loops, cycles)
    - Protected system zones
    - Rate limiting metrics
    - Sanitized logging
    """
    
    DEFAULT_FILE = "rewrites.json"
    BACKUP_FILE = "rewrites.json.bak"
    TEMP_SUFFIX = ".tmp"
    FILE_PERMISSIONS = 0o600  # Owner read/write only
    
    def __init__(self, data_dir: str | Path | None = None):
        """Initialize the manager."""
        configured_data_dir = Path(data_dir or get_settings().NETPROTECTION_DATA_DIR)
        if configured_data_dir.is_absolute():
            self._data_dir = configured_data_dir
        else:
            # Backend and DNS services use different WorkingDirectory values.
            # Resolve the shared relative setting from the EasyPi install root.
            self._data_dir = Path(__file__).resolve().parents[2] / configured_data_dir
        
        self._file_path = self._data_dir / self.DEFAULT_FILE
        self._backup_path = self._data_dir / self.BACKUP_FILE
        self._rules: dict[str, RewriteRule] = {}
        
        # Thread safety
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()  # Serialize all writes
        
        # Statistics
        self._hits = 0
        self._misses = 0
        self._parse_errors = 0
        self._validation_errors = 0
        self._load_errors = 0
        self._save_errors = 0
        self._last_load_time: float = 0
        self._last_save_time: float = 0
        self._loaded_file_signature = (0, 0, 0)
        self._last_external_change_check = 0.0
        self._external_change_check_interval = 0.25
        
        # Load existing rules
        self._load()
    
    # ─────────────────────────────────────────────────────────────────────────
    # PERSISTENCE — Atomic with Rollback
    # ─────────────────────────────────────────────────────────────────────────
    
    def _load(self) -> bool:
        """Load rules from file with validation and rollback support."""
        start_time = time.monotonic()
        
        if not self._file_path.exists():
            with self._lock:
                self._rules = {}
                self._clear_cache()
            self._loaded_file_signature = (0, 0, 0)
            logger.info(f"No rewrites file at {self._file_path}, starting fresh")
            return True
        
        try:
            with open(self._file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Validate structure
            if not isinstance(data, dict) or "rules" not in data:
                raise ValueError("Invalid file structure: missing 'rules' key")
            
            rules = data.get("rules", [])
            if not isinstance(rules, list):
                raise ValueError("Invalid file structure: 'rules' must be a list")
            
            loaded_rules: dict[str, RewriteRule] = {}
            errors = 0
            
            for i, rule_data in enumerate(rules):
                try:
                    rule = RewriteRule.from_dict(rule_data)
                    # Re-validate on load
                    self._validate_rule(rule.domain, rule.answer, rule.rewrite_type)
                    loaded_rules[rule.id] = rule
                except Exception as e:
                    errors += 1
                    self._parse_errors += 1
                    # Sanitize log — don't expose full rule data
                    logger.warning(f"Skipped invalid rule #{i}: {type(e).__name__}")
            
            with self._lock:
                self._rules = loaded_rules
                self._clear_cache()
            
            self._last_load_time = time.monotonic() - start_time
            self._loaded_file_signature = self._file_signature()
            logger.info(f"Loaded {len(loaded_rules)} rewrite rules ({errors} skipped) in {self._last_load_time*1000:.1f}ms")
            return True
            
        except json.JSONDecodeError as e:
            self._load_errors += 1
            logger.error(f"Corrupted rewrites.json: {e}")
            return self._try_rollback()
            
        except Exception as e:
            self._load_errors += 1
            logger.error(f"Failed to load rewrites: {type(e).__name__}")
            return self._try_rollback()
    
    def _try_rollback(self) -> bool:
        """Try to restore from backup file."""
        if not self._backup_path.exists():
            logger.warning("No backup file available for rollback")
            return False
        
        try:
            logger.warning("Attempting rollback from backup...")
            shutil.copy2(self._backup_path, self._file_path)
            
            # Reload from restored file
            with open(self._file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            rules = data.get("rules", [])
            with self._lock:
                self._rules.clear()
                for rule_data in rules:
                    try:
                        rule = RewriteRule.from_dict(rule_data)
                        self._rules[rule.id] = rule
                    except Exception:
                        pass
                self._clear_cache()
            
            logger.info(f"Rollback successful: restored {len(self._rules)} rules")
            self._loaded_file_signature = self._file_signature()
            return True
            
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            return False
    
    def _save(self) -> bool:
        """Save rules atomically with backup."""
        # Serialize all writes
        with self._write_lock:
            start_time = time.monotonic()
            
            try:
                # Ensure directory exists with proper permissions
                self._data_dir.mkdir(parents=True, exist_ok=True)
                
                # Backup existing file
                if self._file_path.exists():
                    try:
                        shutil.copy2(self._file_path, self._backup_path)
                    except Exception as e:
                        logger.warning(f"Backup failed: {e}")
                
                # Prepare data
                with self._lock:
                    data = {
                        "version": 1,
                        "updated_at": datetime.now().isoformat(),
                        "rule_count": len(self._rules),
                        "rules": [rule.to_dict() for rule in self._rules.values()],
                    }
                
                # Atomic write: temp file + rename
                temp_path = self._file_path.with_suffix(self.TEMP_SUFFIX)
                
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())  # Force write to disk
                
                # Set permissions before rename (chmod 600)
                try:
                    os.chmod(temp_path, self.FILE_PERMISSIONS)
                except OSError:
                    pass  # Windows may not support chmod
                
                # Atomic rename
                temp_path.replace(self._file_path)
                self._loaded_file_signature = self._file_signature()
                
                self._last_save_time = time.monotonic() - start_time
                logger.debug(f"Saved {len(self._rules)} rules in {self._last_save_time*1000:.1f}ms")
                return True
                
            except Exception as e:
                self._save_errors += 1
                logger.error(f"Failed to save rewrites: {type(e).__name__}")
                return False
    
    def _clear_cache(self) -> None:
        """Clear the lookup cache."""
        self._lookup_cached.cache_clear()
    
    # ─────────────────────────────────────────────────────────────────────────
    # VALIDATION — Security Checks
    # ─────────────────────────────────────────────────────────────────────────
    
    def _validate_rule(
        self,
        domain: str,
        answer: str,
        rewrite_type: RewriteType,
    ) -> None:
        """
        Comprehensive rule validation.
        
        Checks:
        - Domain format (punycode, length, labels)
        - Wildcard restrictions
        - Self-loop detection
        - Protected zones
        - IP address format
        - CNAME cycle potential
        """
        # Normalize domain
        domain = self._normalize_domain(domain)
        
        # Check forbidden patterns
        if domain in FORBIDDEN_PATTERNS:
            raise ValueError(f"Pattern too broad: {domain}")
        
        # Validate wildcard rules
        self._validate_wildcard(domain)
        
        # Check protected zones for NXDOMAIN
        if rewrite_type == RewriteType.NXDOMAIN:
            self._check_protected_zones(domain)
        
        # Validate answer based on type
        self._validate_answer(answer, rewrite_type, domain)
        
        # Check for self-loops
        if rewrite_type == RewriteType.CNAME:
            self._check_cname_loop(domain, answer)
    
    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain: lowercase, strip trailing dot, validate format."""
        domain = domain.lower().strip().rstrip(".")
        
        if not domain:
            raise ValueError("Domain cannot be empty")
        
        if len(domain) > MAX_DOMAIN_LENGTH:
            raise ValueError(f"Domain too long: {len(domain)} > {MAX_DOMAIN_LENGTH}")
        
        # Split into labels
        labels = domain.split(".")
        
        for label in labels:
            if label == "*":
                continue  # Wildcard
            
            if not label:
                raise ValueError("Empty label in domain")
            
            if len(label) > 63:
                raise ValueError(f"Label too long: {len(label)} > 63")
            
            # Check for valid characters (including punycode)
            if label.startswith(PUNYCODE_PREFIX):
                # Punycode label — validate format
                if not re.match(r'^xn--[a-z0-9-]+$', label):
                    raise ValueError(f"Invalid punycode label: {label}")
            else:
                # Regular label — allow alphanumeric and hyphen
                if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label) and label != "*":
                    # Single char labels are OK
                    if len(label) == 1 and label.isalnum():
                        pass
                    else:
                        raise ValueError(f"Invalid label format: {label}")
        
        return domain
    
    def _validate_wildcard(self, domain: str) -> None:
        """Validate wildcard pattern restrictions."""
        if "*" not in domain:
            return
        
        labels = domain.split(".")
        wildcard_count = sum(1 for label in labels if label == "*")
        
        # Limit wildcard depth
        if wildcard_count > MAX_WILDCARD_DEPTH:
            raise ValueError(f"Too many wildcards: {wildcard_count} > {MAX_WILDCARD_DEPTH}")
        
        # Ensure minimum specificity
        non_wildcard_labels = [label for label in labels if label != "*"]
        if len(non_wildcard_labels) < MIN_WILDCARD_SPECIFICITY:
            raise ValueError(f"Wildcard too broad: need at least {MIN_WILDCARD_SPECIFICITY} specific labels")
        
        # Warn about complex patterns
        if wildcard_count > 1:
            logger.warning("Complex wildcard pattern detected")
    
    def _check_protected_zones(self, domain: str) -> None:
        """Check if domain targets a protected zone."""
        domain_lower = domain.lower().rstrip(".")
        
        # Direct match
        if domain_lower in PROTECTED_ZONES:
            raise ValueError(f"Cannot create NXDOMAIN rule for protected zone: {domain}")
        
        # Check if domain ends with protected zone
        for zone in PROTECTED_ZONES:
            if domain_lower == zone or domain_lower.endswith("." + zone):
                raise ValueError(f"Cannot create NXDOMAIN rule targeting {zone} zone")
        
        # Check wildcard covering protected zones
        if domain_lower.startswith("*."):
            base = domain_lower[2:]
            if base in PROTECTED_ZONES:
                raise ValueError(f"Wildcard would block protected zone: {base}")
    
    def _validate_answer(
        self,
        answer: str,
        rewrite_type: RewriteType,
        source_domain: str,
    ) -> None:
        """Validate answer format based on type."""
        import ipaddress
        
        if rewrite_type == RewriteType.A:
            if not answer:
                raise ValueError("A record requires IPv4 address")
            try:
                ip = ipaddress.ip_address(answer)
                if ip.version != 4:
                    raise ValueError(f"A record requires IPv4, got IPv6: {answer}")
            except ValueError as e:
                raise ValueError(f"Invalid IPv4 address: {answer}") from e
        
        elif rewrite_type == RewriteType.AAAA:
            if not answer:
                raise ValueError("AAAA record requires IPv6 address")
            try:
                ip = ipaddress.ip_address(answer)
                if ip.version != 6:
                    raise ValueError(f"AAAA record requires IPv6, got IPv4: {answer}")
            except ValueError as e:
                raise ValueError(f"Invalid IPv6 address: {answer}") from e
        
        elif rewrite_type == RewriteType.CNAME:
            if not answer:
                raise ValueError("CNAME requires target domain")
            
            # Validate target
            if len(answer) > MAX_DOMAIN_LENGTH:
                raise ValueError("CNAME target too long")
            
            # Basic format check
            if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', answer.lower().rstrip(".")):
                if len(answer.rstrip(".")) > 1:  # Allow single char
                    raise ValueError(f"Invalid CNAME target format: {answer}")
        
        # NXDOMAIN, NODATA, REFUSED, PASSTHROUGH don't need answer validation
    
    def _check_cname_loop(self, source: str, target: str) -> None:
        """Check for direct self-loop in CNAME."""
        source_normalized = source.lower().rstrip(".").replace("*.", "")
        target_normalized = target.lower().rstrip(".")
        
        # Direct self-reference
        if source_normalized == target_normalized:
            raise ValueError(f"CNAME self-loop: {source} -> {target}")
        
        # Check if target matches source pattern
        if source.startswith("*."):
            base = source[2:]
            if target_normalized == base or target_normalized.endswith("." + base):
                raise ValueError(f"CNAME would create loop: {source} -> {target}")
        
        # Check existing rules for potential cycle (max depth check)
        visited = {source_normalized}
        current = target_normalized
        
        for _ in range(MAX_CNAME_CHAIN):
            match = self._lookup_cached(current)
            if not match:
                break
            
            if match.rule.rewrite_type != RewriteType.CNAME:
                break
            
            next_target = match.rule.answer.lower().rstrip(".")
            if next_target in visited:
                raise ValueError(f"CNAME chain would create cycle at: {next_target}")
            
            visited.add(next_target)
            current = next_target
    
    # ─────────────────────────────────────────────────────────────────────────
    # CRUD Operations
    # ─────────────────────────────────────────────────────────────────────────
    
    def add(
        self,
        domain: str,
        answer: str,
        rewrite_type: RewriteType | str = RewriteType.A,
        comment: str = "",
        priority: int = 0,
        enabled: bool = True,
    ) -> RewriteRule:
        """
        Add a new rewrite rule with full validation.
        
        Args:
            domain: Domain pattern (supports * wildcard)
            answer: Target (IP, domain, or special value)
            rewrite_type: Type of rewrite
            comment: Optional description
            priority: Higher = evaluated first (0-1000)
            enabled: Whether rule is active
            
        Returns:
            The created rule
            
        Raises:
            ValueError: If rule limit reached or validation fails
        """
        # Normalize inputs
        domain = self._normalize_domain(domain)
        
        if isinstance(rewrite_type, str):
            rewrite_type = RewriteType(rewrite_type)
        
        # Full validation
        self._validate_rule(domain, answer, rewrite_type)
        
        # Sanitize comment (prevent log injection)
        comment = comment[:500].replace("\n", " ").replace("\r", " ")
        
        with self._lock:
            if len(self._rules) >= MAX_RULES:
                self._validation_errors += 1
                raise ValueError(f"Maximum rule limit ({MAX_RULES}) reached")
            
            # Check for duplicate domain (warn only)
            for existing in self._rules.values():
                if existing.domain == domain and existing.enabled:
                    logger.warning("New rule may conflict with existing rule (same pattern)")
                    break
            
            rule = RewriteRule(
                id=str(uuid.uuid4()),
                domain=domain,
                answer=answer,
                rewrite_type=rewrite_type,
                comment=comment,
                priority=max(0, min(1000, priority)),  # Clamp 0-1000
                enabled=enabled,
            )
            
            self._rules[rule.id] = rule
            self._clear_cache()
            self._save()
        
        # Sanitized log — hash domain for privacy
        domain_hash = hashlib.sha256(domain.encode()).hexdigest()[:8]
        logger.info(f"Added rewrite rule: {domain_hash}... ({rewrite_type.value})")
        return rule
    
    def update(
        self,
        rule_id: str,
        **kwargs,
    ) -> RewriteRule | None:
        """
        Update an existing rule with validation.
        
        Args:
            rule_id: ID of the rule to update
            **kwargs: Fields to update
            
        Returns:
            Updated rule or None if not found
        """
        with self._lock:
            if rule_id not in self._rules:
                return None
            
            rule = self._rules[rule_id]
            
            # Prepare new values for validation
            new_domain = kwargs.get("domain", rule.domain)
            new_answer = kwargs.get("answer", rule.answer)
            new_type = kwargs.get("rewrite_type", rule.rewrite_type)
            
            if isinstance(new_type, str):
                new_type = RewriteType(new_type)
            
            # Normalize domain if changed
            if "domain" in kwargs:
                new_domain = self._normalize_domain(new_domain)
            
            # Full validation
            self._validate_rule(new_domain, new_answer, new_type)
            
            # Apply updates
            if "domain" in kwargs:
                rule.domain = new_domain
                rule._compile_pattern()
            if "answer" in kwargs:
                rule.answer = new_answer
            if "rewrite_type" in kwargs:
                rule.rewrite_type = new_type
            if "comment" in kwargs:
                rule.comment = kwargs["comment"][:500].replace("\n", " ").replace("\r", " ")
            if "priority" in kwargs:
                rule.priority = max(0, min(1000, kwargs["priority"]))
            if "enabled" in kwargs:
                rule.enabled = kwargs["enabled"]
            
            rule.updated_at = datetime.now()
            
            self._clear_cache()
            self._save()
        
        logger.info(f"Updated rewrite rule {rule_id[:8]}...")
        return rule
    
    def delete(self, rule_id: str) -> bool:
        """Delete a rule."""
        with self._lock:
            if rule_id not in self._rules:
                return False
            
            del self._rules[rule_id]
            self._clear_cache()
            self._save()
        
        logger.info(f"Deleted rewrite rule {rule_id[:8]}...")
        return True
    
    def get(self, rule_id: str) -> RewriteRule | None:
        """Get a rule by ID."""
        return self._rules.get(rule_id)
    
    def list_all(self) -> list[RewriteRule]:
        """Get all rules sorted by priority (descending), then specificity."""
        with self._lock:
            return sorted(
                self._rules.values(),
                key=lambda r: (
                    -r.priority,                           # Higher priority first
                    -r.domain.count("."),                  # More specific first
                    r.domain.startswith("*."),             # Exact before wildcard
                    r.domain,                              # Alphabetical tiebreak
                ),
            )
    
    def clear_all(self) -> int:
        """Delete all rules. Returns count of deleted rules."""
        with self._lock:
            count = len(self._rules)
            self._rules.clear()
            self._clear_cache()
            self._save()
        
        logger.warning(f"Cleared all {count} rewrite rules")
        return count
    
    # ─────────────────────────────────────────────────────────────────────────
    # Lookup
    # ─────────────────────────────────────────────────────────────────────────
    
    def lookup(self, domain: str) -> RewriteMatch | None:
        """Look up a rewrite rule for a domain."""
        self._reload_if_changed()
        normalized = domain.lower().rstrip(".")
        result = self._lookup_cached(normalized)
        
        if result:
            self._hits += 1
        else:
            self._misses += 1
        
        return result

    def _reload_if_changed(self) -> None:
        """Notice atomic writes made by another EasyPi service process."""
        now = time.monotonic()
        if now - self._last_external_change_check < self._external_change_check_interval:
            return
        self._last_external_change_check = now
        current_signature = self._file_signature()
        if current_signature != self._loaded_file_signature:
            self.reload()

    def _file_signature(self) -> tuple[int, int, int]:
        """Return identity fields changed by an atomic file replacement."""
        try:
            details = self._file_path.stat()
        except FileNotFoundError:
            return (0, 0, 0)
        except OSError:
            return self._loaded_file_signature
        return (details.st_mtime_ns, details.st_size, details.st_ino)
    
    @lru_cache(maxsize=4096)
    def _lookup_cached(self, domain: str) -> RewriteMatch | None:
        """Cached lookup with deterministic ordering."""
        with self._lock:
            # Sort by: priority DESC, specificity DESC, exact before wildcard
            enabled_rules = sorted(
                (r for r in self._rules.values() if r.enabled),
                key=lambda r: (
                    -r.priority,
                    -r.domain.count("."),
                    r.domain.startswith("*."),
                ),
            )
        
        for rule in enabled_rules:
            if rule.matches(domain):
                return RewriteMatch(
                    rule=rule,
                    original_domain=domain,
                    rewritten_answer=rule.answer,
                    rewrite_type=rule.rewrite_type,
                )
        
        return None
    
    # ─────────────────────────────────────────────────────────────────────────
    # Statistics & Monitoring
    # ─────────────────────────────────────────────────────────────────────────
    
    def stats(self) -> dict[str, Any]:
        """Get comprehensive statistics for monitoring."""
        cache_info = self._lookup_cached.cache_info()
        
        with self._lock:
            enabled = sum(1 for r in self._rules.values() if r.enabled)
            disabled = len(self._rules) - enabled
            wildcard_count = sum(1 for r in self._rules.values() if "*" in r.domain)
            
            # Count by type
            type_counts = {}
            for r in self._rules.values():
                t = r.rewrite_type.value
                type_counts[t] = type_counts.get(t, 0) + 1
        
        total_lookups = self._hits + self._misses
        
        return {
            # Rule counts
            "total_rules": len(self._rules),
            "enabled_rules": enabled,
            "disabled_rules": disabled,
            "wildcard_rules": wildcard_count,
            "rules_by_type": type_counts,
            "max_rules": MAX_RULES,
            
            # Cache stats
            "cache_hits": self._hits,
            "cache_misses": self._misses,
            "hit_rate": round(self._hits / total_lookups, 4) if total_lookups > 0 else 0,
            "cache_size": cache_info.currsize,
            "cache_maxsize": cache_info.maxsize,
            
            # Error stats
            "parse_errors": self._parse_errors,
            "validation_errors": self._validation_errors,
            "load_errors": self._load_errors,
            "save_errors": self._save_errors,
            
            # Performance
            "last_load_time_ms": round(self._last_load_time * 1000, 2),
            "last_save_time_ms": round(self._last_save_time * 1000, 2),
            
            # Health
            "healthy": self._load_errors == 0 and self._save_errors == 0,
        }
    
    def reload(self) -> bool:
        """Reload rules from file (serialized)."""
        with self._write_lock:
            return self._load()
