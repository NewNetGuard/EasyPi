"""
Parental Controller

Main entry point for parental controls, combining age filtering
and scheduling into a unified interface.

RULE PRIORITY (highest to lowest):
1. Whitelist - ALWAYS allows, overrides everything (for educational resources)
2. Blacklist - ALWAYS blocks (parent's explicit block)
3. Schedule - Time-based restrictions (bedtime, pause, daily limit)
4. Age Filter - Category-based filtering by age group
5. Custom Categories - Additional blocked/allowed categories

AUTHORIZATION:
All modification endpoints require admin role. Read-only access for
viewing own profile status is allowed for bound devices.

FAIL-SAFE BEHAVIOR:
- If category database unavailable: OBSERVE mode with admin alert
- Unknown domains: ALLOW with logging (not blocking by default)
- Expired category TTL: Continue with cached data + warning

PRIVACY (PII):
- Blocked domain logs are anonymized (hashed) for child profiles
- Metrics are aggregated, no individual domain tracking
- Detailed logs only available to admin with explicit flag
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from ..config import get_settings

from .age_filter import (
    AgeCategory,
    get_age_filter,
)
from .scheduler import (
    get_schedule_manager,
    ALWAYS_ALLOWED_DOMAINS,
)

# Optional app blocker for IP-based blocking
try:
    from .app_blocker import AppBlocker, get_app_blocker, BLOCKABLE_APPS
    APP_BLOCKER_AVAILABLE = True
except ImportError:
    APP_BLOCKER_AVAILABLE = False
    AppBlocker = None
    BLOCKABLE_APPS = {}


logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

# Category database TTL (how long cached categories are valid)
CATEGORY_DB_TTL_HOURS = 24

# Unknown domain handling
UNKNOWN_DOMAIN_ACTION = "allow"  # "allow", "observe", or "block"

# Privacy settings
ANONYMIZE_CHILD_LOGS = True
LOG_BLOCKED_DOMAINS = False  # Set True only for debugging


def _hash_domain(domain: str) -> str:
    """Hash domain for privacy-preserving logs."""
    return hashlib.sha256(domain.encode()).hexdigest()[:12]


@dataclass
class ParentalProfile:
    """
    Parental control profile for a device/user.
    
    Combines age-based filtering with schedule restrictions.
    """
    
    id: str
    name: str
    description: str = ""
    
    # Age-based filtering
    age_category: AgeCategory = AgeCategory.TEEN
    age_filter_enabled: bool = True
    
    # Custom category overrides
    blocked_categories: list[str] = field(default_factory=list)  # Additional blocks
    allowed_categories: list[str] = field(default_factory=list)  # Override unblock
    
    # Domain overrides
    whitelist: list[str] = field(default_factory=list)
    blacklist: list[str] = field(default_factory=list)
    
    # Schedule
    schedule_id: str | None = None
    
    # SafeSearch enforcement
    safe_search: bool = True
    youtube_restricted: bool = True
    
    # IP-based app blocking (for apps that bypass DNS)
    # Supported: telegram, whatsapp, signal, tor, messenger, snapchat, wechat, viber, imessage, discord, line
    blocked_apps: list[str] = field(default_factory=list)
    
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "age_category": self.age_category.value,
            "age_filter_enabled": self.age_filter_enabled,
            "blocked_categories": self.blocked_categories,
            "allowed_categories": self.allowed_categories,
            "whitelist": self.whitelist,
            "blacklist": self.blacklist,
            "schedule_id": self.schedule_id,
            "safe_search": self.safe_search,
            "youtube_restricted": self.youtube_restricted,
            "blocked_apps": self.blocked_apps,
            "enabled": self.enabled,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ParentalProfile":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            age_category=AgeCategory(data.get("age_category", "teen")),
            age_filter_enabled=data.get("age_filter_enabled", True),
            blocked_categories=data.get("blocked_categories", []),
            allowed_categories=data.get("allowed_categories", []),
            whitelist=data.get("whitelist", []),
            blacklist=data.get("blacklist", []),
            schedule_id=data.get("schedule_id"),
            safe_search=data.get("safe_search", True),
            youtube_restricted=data.get("youtube_restricted", True),
            blocked_apps=data.get("blocked_apps", []),
            enabled=data.get("enabled", True),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(),
        )


@dataclass
class ParentalCheckResult:
    """Result of parental control check."""
    
    allowed: bool
    reason: str = ""
    blocked_by: str = ""  # "age_filter", "schedule", "blacklist", "category"
    category: str = ""
    schedule_action: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "category": self.category,
            "schedule_action": self.schedule_action,
        }


# Preset profiles for quick setup
PRESET_PROFILES: dict[str, dict[str, Any]] = {
    "child_safe": {
        "name": "Child Safe (0-7)",
        "description": "Maximum protection for young children",
        "age_category": AgeCategory.CHILD,
        "safe_search": True,
        "youtube_restricted": True,
    },
    "kid_friendly": {
        "name": "Kid Friendly (8-12)",
        "description": "Age-appropriate filtering for kids",
        "age_category": AgeCategory.KID,
        "safe_search": True,
        "youtube_restricted": True,
    },
    "teen": {
        "name": "Teen (13-17)",
        "description": "Moderate filtering for teenagers",
        "age_category": AgeCategory.TEEN,
        "safe_search": True,
        "youtube_restricted": False,
    },
    "adult": {
        "name": "Adult (18+)",
        "description": "Minimal filtering - security only",
        "age_category": AgeCategory.ADULT,
        "safe_search": False,
        "youtube_restricted": False,
    },
}


class ParentalController:
    """
    Main parental control controller.
    
    Coordinates age filtering, scheduling, and profile management.
    """
    
    def __init__(self, data_dir: str | Path | None = None):
        if data_dir:
            self._data_dir = Path(data_dir)
        else:
            self._data_dir = get_settings().NETPROTECTION_DATA_DIR
            
        self._profiles_file = self._data_dir / "parental_profiles.json"
        
        self._profiles: dict[str, ParentalProfile] = {}
        self._profile_bindings: dict[str, str] = {}  # device_profile_id -> parental_profile_id
        
        self._age_filter = get_age_filter()
        self._schedule_manager = get_schedule_manager()
        
        # App blocker for IP-based blocking (Telegram, WhatsApp, etc.)
        if APP_BLOCKER_AVAILABLE:
            self._app_blocker = get_app_blocker(data_dir)
        else:
            self._app_blocker = None
        
        self._lock = threading.Lock()
        self._stats = {
            "checks": 0,
            "blocked": 0,
            "blocked_by_age": 0,
            "blocked_by_schedule": 0,
            "blocked_by_blacklist": 0,
            "blocked_by_app_blocker": 0,
            "failsafe_allows": 0,  # Count of allows due to unavailable filter DB
        }
        
        self._load_profiles()
    
    def _load_profiles(self) -> None:
        """Load profiles from disk."""
        if not self._profiles_file.exists():
            return
        
        try:
            with open(self._profiles_file, 'r') as f:
                data = json.load(f)
            
            for profile_data in data.get("profiles", []):
                try:
                    profile = ParentalProfile.from_dict(profile_data)
                    self._profiles[profile.id] = profile
                except Exception as e:
                    logger.warning(f"Failed to load parental profile: {e}")
            
            self._profile_bindings = data.get("bindings", {})
            
            # Load schedules
            schedules_data = data.get("schedules", [])
            self._schedule_manager.load_schedules(schedules_data)
            
            logger.info(f"Loaded {len(self._profiles)} parental profiles")
            
        except Exception as e:
            logger.error(f"Failed to load parental profiles: {e}")
    
    def _save_profiles(self) -> None:
        """Save profiles to disk."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            
            data = {
                "profiles": [p.to_dict() for p in self._profiles.values()],
                "bindings": self._profile_bindings,
                "schedules": self._schedule_manager.save_schedules(),
            }
            
            # Atomic write
            temp_file = self._profiles_file.with_suffix('.tmp')
            with open(temp_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            temp_file.replace(self._profiles_file)
            os.chmod(self._profiles_file, 0o600)
            
        except Exception as e:
            logger.error(f"Failed to save parental profiles: {e}")
    
    def check(
        self,
        device_profile_id: str,
        domain: str,
        now: datetime | None = None,
    ) -> ParentalCheckResult:
        """
        Check if domain access is allowed by parental controls.
        
        RULE PRIORITY (evaluated in order):
        1. Whitelist - ALWAYS allows (educational resources override)
        2. Blacklist - ALWAYS blocks (explicit parent block)
        3. Schedule - Time restrictions (bedtime, pause, limit)
        4. Age Filter - Category filtering by age group
        5. Custom Categories - Additional blocks/allows
        
        Args:
            device_profile_id: The device profile ID
            domain: Domain being accessed
            now: Current time (for testing), uses UTC internally
            
        Returns:
            ParentalCheckResult with decision and reason
        """
        self._stats["checks"] += 1
        domain_lower = domain.lower().rstrip('.')
        
        # Use UTC for consistent time handling
        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            # Assume local time, convert to UTC-aware
            now = now.replace(tzinfo=timezone.utc)
        
        # Get parental profile for this device
        parental_profile_id = self._profile_bindings.get(device_profile_id)
        if not parental_profile_id:
            return ParentalCheckResult(allowed=True, reason="No parental profile")
        
        profile = self._profiles.get(parental_profile_id)
        if not profile or not profile.enabled:
            return ParentalCheckResult(allowed=True, reason="Parental profile disabled")
        
        # ─────────────────────────────────────────────────────────────────────
        # PRIORITY 1: Whitelist (ALWAYS ALLOW - highest priority)
        # Use case: Educational resources that should bypass all restrictions
        # ─────────────────────────────────────────────────────────────────────
        if self._matches_pattern_list(domain_lower, profile.whitelist):
            return ParentalCheckResult(allowed=True, reason="Whitelisted (priority override)")
        
        # Also check essential domains (safety)
        for safe_domain in ALWAYS_ALLOWED_DOMAINS:
            if domain_lower == safe_domain or domain_lower.endswith('.' + safe_domain):
                return ParentalCheckResult(allowed=True, reason="Essential domain")
        
        # ─────────────────────────────────────────────────────────────────────
        # PRIORITY 2: Blacklist (ALWAYS BLOCK - explicit parent decision)
        # ─────────────────────────────────────────────────────────────────────
        if self._matches_pattern_list(domain_lower, profile.blacklist):
            self._record_block(profile, "blacklist", domain_lower)
            return ParentalCheckResult(
                allowed=False,
                reason="Domain blacklisted by parent",
                blocked_by="blacklist",
            )
        
        # ─────────────────────────────────────────────────────────────────────
        # PRIORITY 3: Schedule (time-based restrictions)
        # ─────────────────────────────────────────────────────────────────────
        if profile.schedule_id:
            schedule_result = self._check_schedule(profile, domain_lower, now)
            if schedule_result and not schedule_result.allowed:
                return schedule_result
        
        # ─────────────────────────────────────────────────────────────────────
        # PRIORITY 4: Age Filter (category-based by age group)
        # ─────────────────────────────────────────────────────────────────────
        if profile.age_filter_enabled:
            age_result = self._check_age_filter(profile, domain_lower)
            if age_result and not age_result.allowed:
                return age_result
        
        # ─────────────────────────────────────────────────────────────────────
        # PRIORITY 5: Custom blocked categories
        # ─────────────────────────────────────────────────────────────────────
        if profile.blocked_categories:
            cat_result = self._check_custom_categories(profile, domain_lower)
            if cat_result and not cat_result.allowed:
                return cat_result
        
        return ParentalCheckResult(allowed=True, reason="Allowed by parental controls")
    
    def _matches_pattern_list(self, domain: str, patterns: list[str]) -> bool:
        """Check if domain matches any pattern in list (exact or wildcard)."""
        for pattern in patterns:
            pattern_lower = pattern.lower()
            # General wildcard support (e.g., *xvideos*, *.porn)
            if "*" in pattern_lower or "?" in pattern_lower:
                if fnmatch.fnmatch(domain, pattern_lower):
                    return True
                continue
            if pattern_lower.startswith('*.'):
                base = pattern_lower[2:]
                if domain == base or domain.endswith('.' + base):
                    return True
                continue
            if domain == pattern_lower:
                return True
        return False
    
    def _record_block(
        self,
        profile: ParentalProfile,
        blocked_by: str,
        domain: str,
    ) -> None:
        """Record a block with privacy-preserving logging."""
        self._stats["blocked"] += 1
        self._stats[f"blocked_by_{blocked_by}"] += 1
        
        # Privacy: anonymize domain for child profiles in logs
        if ANONYMIZE_CHILD_LOGS and profile.age_category in (AgeCategory.CHILD, AgeCategory.KID):
            log_domain = _hash_domain(domain)
        elif LOG_BLOCKED_DOMAINS:
            log_domain = domain
        else:
            log_domain = _hash_domain(domain)
        
        logger.debug(
            f"Parental block: profile={profile.name}, by={blocked_by}, "
            f"domain_hash={log_domain}"
        )
    
    def _check_schedule(
        self,
        profile: ParentalProfile,
        domain: str,
        now: datetime,
    ) -> ParentalCheckResult | None:
        """Check schedule restrictions."""
        allowed, reason = self._schedule_manager.check_access(
            profile.schedule_id, domain, now
        )
        if not allowed:
            self._record_block(profile, "schedule", domain)
            
            schedule = self._schedule_manager.get_schedule(profile.schedule_id)
            action = ""
            if schedule and schedule.rule:
                action = schedule.rule.get_current_action(now).value
            
            return ParentalCheckResult(
                allowed=False,
                reason=reason,
                blocked_by="schedule",
                schedule_action=action,
            )
        return None
    
    def _check_age_filter(
        self,
        profile: ParentalProfile,
        domain: str,
    ) -> ParentalCheckResult | None:
        """Check age-based content filter."""
        # Check if category DB is available and fresh
        if not self._age_filter_available():
            # Fail-safe: observe mode with warning
            logger.warning("Age filter database unavailable, allowing with observation")
            self._stats["failsafe_allows"] += 1
            return None  # Allow to continue
        
        result = self._age_filter.check(domain, profile.age_category)
        
        if result.blocked:
            # Check if category is in allowed_categories override
            if result.category and result.category.value in profile.allowed_categories:
                return None  # Allow despite age filter (parent override)
            
            self._record_block(profile, "age", domain)
            return ParentalCheckResult(
                allowed=False,
                reason=result.reason,
                blocked_by="age_filter",
                category=result.category.value if result.category else "",
            )
        
        return None
    
    def _check_custom_categories(
        self,
        profile: ParentalProfile,
        domain: str,
    ) -> ParentalCheckResult | None:
        """Check custom blocked categories."""
        # This would integrate with external categorization service
        # For now, rely on age_filter's detection
        return None
    
    def _age_filter_available(self) -> bool:
        """Check if age filter database is available and fresh."""
        if self._age_filter is None:
            return False
        try:
            if self._age_filter.refresh_if_stale(CATEGORY_DB_TTL_HOURS):
                logger.info("Refreshed parental category cache after TTL expiry")
        except Exception as exc:
            # Keep the last complete cache, matching the documented stale-cache
            # behavior. Never replace it with a partial rebuild.
            logger.warning("Could not refresh parental category cache: %s", exc)
        return self._age_filter.category_data_available
    
    def create_profile(
        self,
        name: str,
        preset: str | None = None,
        age_category: AgeCategory | None = None,
        **kwargs,
    ) -> ParentalProfile:
        """Create a new parental profile."""
        import uuid
        
        profile_id = str(uuid.uuid4())
        
        # Start with preset if specified
        if preset and preset in PRESET_PROFILES:
            preset_data = PRESET_PROFILES[preset].copy()
            preset_data.update(kwargs)
            kwargs = preset_data
        
        profile = ParentalProfile(
            id=profile_id,
            name=name,
            age_category=age_category or kwargs.pop('age_category', AgeCategory.TEEN),
            **kwargs,
        )
        
        with self._lock:
            self._profiles[profile_id] = profile
            self._save_profiles()
        
        logger.info(f"Created parental profile: {name}")
        return profile
    
    def update_profile(
        self,
        profile_id: str,
        **updates,
    ) -> ParentalProfile | None:
        """Update a parental profile."""
        with self._lock:
            profile = self._profiles.get(profile_id)
            if not profile:
                return None
            
            for key, value in updates.items():
                if hasattr(profile, key):
                    if key == 'age_category' and isinstance(value, str):
                        value = AgeCategory(value)
                    setattr(profile, key, value)
            
            profile.updated_at = datetime.now()
            self._save_profiles()
        
        return profile
    
    def delete_profile(self, profile_id: str) -> bool:
        """Delete a parental profile."""
        with self._lock:
            if profile_id not in self._profiles:
                return False
            
            del self._profiles[profile_id]
            
            # Remove bindings
            self._profile_bindings = {
                k: v for k, v in self._profile_bindings.items()
                if v != profile_id
            }
            
            self._save_profiles()
        
        return True
    
    def bind_to_device(
        self,
        device_profile_id: str,
        parental_profile_id: str,
    ) -> bool:
        """Bind a parental profile to a device profile."""
        if parental_profile_id not in self._profiles:
            return False
        
        with self._lock:
            self._profile_bindings[device_profile_id] = parental_profile_id
            self._save_profiles()
        
        return True
    
    def unbind_device(self, device_profile_id: str) -> bool:
        """Remove parental profile binding from device."""
        with self._lock:
            if device_profile_id in self._profile_bindings:
                del self._profile_bindings[device_profile_id]
                self._save_profiles()
                return True
        return False
    
    def get_profile(self, profile_id: str) -> ParentalProfile | None:
        """Get a parental profile by ID."""
        return self._profiles.get(profile_id)
    
    def get_profile_for_device(self, device_profile_id: str) -> ParentalProfile | None:
        """Get parental profile bound to a device profile."""
        parental_id = self._profile_bindings.get(device_profile_id)
        if parental_id:
            return self._profiles.get(parental_id)
        return None
    
    def list_profiles(self) -> list[ParentalProfile]:
        """List all parental profiles."""
        return list(self._profiles.values())
    
    def create_schedule_for_profile(
        self,
        profile_id: str,
        rule_name: str = "Schedule",
        bedtime_enabled: bool = False,
        daily_limit_minutes: int | None = None,
    ) -> bool:
        """Create and attach a schedule to a profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return False
        
        self._schedule_manager.create_schedule(
            profile_id=profile_id,
            rule_name=rule_name,
            bedtime_enabled=bedtime_enabled,
            daily_limit_minutes=daily_limit_minutes,
        )
        
        with self._lock:
            profile.schedule_id = profile_id  # Use profile_id as schedule key
            self._save_profiles()
        
        return True
    
    def pause_device(
        self,
        device_profile_id: str,
        duration_minutes: int = 30,
    ) -> bool:
        """Pause internet for a device."""
        parental_id = self._profile_bindings.get(device_profile_id)
        if not parental_id:
            return False
        
        profile = self._profiles.get(parental_id)
        if not profile or not profile.schedule_id:
            return False
        
        return self._schedule_manager.pause_profile(
            profile.schedule_id, duration_minutes
        )
    
    def resume_device(self, device_profile_id: str) -> bool:
        """Resume internet for a device."""
        parental_id = self._profile_bindings.get(device_profile_id)
        if not parental_id:
            return False
        
        profile = self._profiles.get(parental_id)
        if not profile or not profile.schedule_id:
            return False
        
        return self._schedule_manager.resume_profile(profile.schedule_id)
    
    def get_stats(self) -> dict[str, Any]:
        """Get parental control statistics."""
        stats = {
            "total_checks": self._stats["checks"],
            "total_blocked": self._stats["blocked"],
            "blocked_by_age_filter": self._stats["blocked_by_age"],
            "blocked_by_schedule": self._stats["blocked_by_schedule"],
            "blocked_by_blacklist": self._stats["blocked_by_blacklist"],
            "blocked_by_app_blocker": self._stats.get("blocked_by_app_blocker", 0),
            "profiles_count": len(self._profiles),
            "bindings_count": len(self._profile_bindings),
            "age_filter_stats": self._age_filter.get_stats(),
            "schedule_stats": self._schedule_manager.get_stats(),
        }
        
        # Add app blocker info if available
        if self._app_blocker:
            stats["app_blocker_available"] = True
            stats["blockable_apps"] = list(BLOCKABLE_APPS.keys())
        else:
            stats["app_blocker_available"] = False
        
        return stats
    
    def get_presets(self) -> dict[str, dict[str, Any]]:
        """Get available preset profiles."""
        return {
            key: {
                "name": val["name"],
                "description": val["description"],
                "age_category": val["age_category"].value,
            }
            for key, val in PRESET_PROFILES.items()
        }
    
    # ═══════════════════════════════════════════════════════════════════════════
    # APP BLOCKING (IP-based for apps that bypass DNS)
    # ═══════════════════════════════════════════════════════════════════════════
    
    def get_blockable_apps(self) -> list[dict[str, Any]]:
        """
        Get list of apps that can be blocked via IP.
        
        These apps bypass DNS (Telegram, WhatsApp, Signal, etc.)
        and require IP-level blocking.
        
        Returns:
            List of app info dicts with name, display_name, description
        """
        if not self._app_blocker:
            return []
        return self._app_blocker.list_blockable_apps()
    
    def set_blocked_apps(
        self,
        profile_id: str,
        apps: list[str],
    ) -> bool:
        """
        Set the list of blocked apps for a profile.
        
        Args:
            profile_id: Parental profile ID
            apps: List of app names to block (telegram, whatsapp, signal)
        
        Returns:
            True if successful
        """
        profile = self._profiles.get(profile_id)
        if not profile:
            return False
        
        # Validate apps
        valid_apps = [a.lower() for a in apps if a.lower() in BLOCKABLE_APPS]
        
        with self._lock:
            profile.blocked_apps = valid_apps
            profile.updated_at = datetime.now()
            self._save_profiles()
        
        # Sync with app blocker if available
        self.sync_app_blocking()
        
        logger.info(f"Set blocked apps for profile {profile.name}: {valid_apps}")
        return True
    
    def add_blocked_app(self, profile_id: str, app: str) -> bool:
        """Add an app to the blocked list for a profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return False
        
        app_lower = app.lower()
        if app_lower not in BLOCKABLE_APPS:
            return False
        
        if app_lower in profile.blocked_apps:
            return True  # Already blocked
        
        with self._lock:
            profile.blocked_apps.append(app_lower)
            profile.updated_at = datetime.now()
            self._save_profiles()
        
        self.sync_app_blocking()
        return True
    
    def remove_blocked_app(self, profile_id: str, app: str) -> bool:
        """Remove an app from the blocked list for a profile."""
        profile = self._profiles.get(profile_id)
        if not profile:
            return False
        
        app_lower = app.lower()
        if app_lower not in profile.blocked_apps:
            return True  # Already not blocked
        
        with self._lock:
            profile.blocked_apps.remove(app_lower)
            profile.updated_at = datetime.now()
            self._save_profiles()
        
        self.sync_app_blocking()
        return True
    
    def sync_app_blocking(self) -> bool:
        """
        Sync app blocking rules with iptables.
        
        This should be called after profile changes to update
        the actual firewall rules.
        
        Returns:
            True if successful
        """
        if not self._app_blocker:
            logger.warning("App blocker not available")
            return False
        
        return self._app_blocker.sync_from_devices()
    
    def enable_app_blocking_for_device(
        self,
        device_ip: str,
        apps: list[str],
    ) -> bool:
        """
        Directly enable app blocking for a device IP.
        
        This is a low-level method for immediate blocking.
        For profile-based blocking, use set_blocked_apps().
        
        Args:
            device_ip: Device IP address
            apps: Apps to block
        
        Returns:
            True if successful
        """
        if not self._app_blocker:
            return False
        
        return self._app_blocker.enable_blocking(device_ip, apps)
    
    def disable_app_blocking_for_device(
        self,
        device_ip: str,
        apps: list[str] | None = None,
    ) -> bool:
        """
        Disable app blocking for a device IP.
        
        Args:
            device_ip: Device IP address
            apps: Apps to unblock (None = all)
        
        Returns:
            True if successful
        """
        if not self._app_blocker:
            return False
        
        return self._app_blocker.disable_blocking(device_ip, apps)
    
    def get_app_blocking_status(self, device_ip: str) -> dict[str, Any]:
        """Get current app blocking status for a device."""
        if not self._app_blocker:
            return {"active": False, "apps": [], "available": False}
        
        status = self._app_blocker.get_blocking_status(device_ip)
        status["available"] = True
        return status


# Singleton
_controller: ParentalController | None = None
_controller_lock = threading.Lock()


def get_parental_controller(data_dir: str | None = None) -> ParentalController:
    """Get singleton ParentalController."""
    global _controller
    
    if _controller is None:
        if data_dir is None:
            data_dir = get_settings().NETPROTECTION_DATA_DIR
            
        with _controller_lock:
            if _controller is None:
                _controller = ParentalController(data_dir)
    
    return _controller
