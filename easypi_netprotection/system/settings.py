"""
EasyPi NetProtection — Settings Manager.

Управление настройками IPv6, Fail-Safe и другими системными параметрами.
Настройки персистятся в JSON-файл.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# SETTINGS MODELS
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class IPv6Settings:
    """IPv6 DNS settings."""
    
    enabled: bool = True
    """Enable IPv6 (AAAA) record resolution."""
    
    block_ipv6_dns: bool = False
    """Block IPv6 DNS queries to prevent DNS leaks via IPv6."""
    
    audit_mode: bool = True
    """Log IPv6 queries without blocking (for analysis)."""
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IPv6Settings":
        return cls(
            enabled=data.get("enabled", True),
            block_ipv6_dns=data.get("block_ipv6_dns", False),
            audit_mode=data.get("audit_mode", True),
        )


@dataclass
class FailSafeSettings:
    """Fail-Safe mode settings."""
    
    enabled: bool = True
    """Enable automatic fallback to backup DNS on failure."""
    
    fallback_dns: str = "1.1.1.1"
    """Fallback DNS server to use when NetProtection fails."""
    
    fallback_dns_secondary: str = "8.8.8.8"
    """Secondary fallback DNS server."""
    
    timeout_seconds: int = 5
    """Timeout in seconds before triggering fail-safe."""
    
    auto_recover: bool = True
    """Automatically switch back when NetProtection recovers."""
    
    recovery_check_interval: int = 30
    """Interval in seconds for checking if NetProtection recovered."""
    
    max_failures: int = 3
    """Number of consecutive failures before triggering fail-safe."""
    
    # Runtime state (not persisted)
    is_active: bool = field(default=False, repr=False)
    failure_count: int = field(default=0, repr=False)
    activated_at: datetime | None = field(default=None, repr=False)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "fallback_dns": self.fallback_dns,
            "fallback_dns_secondary": self.fallback_dns_secondary,
            "timeout_seconds": self.timeout_seconds,
            "auto_recover": self.auto_recover,
            "recovery_check_interval": self.recovery_check_interval,
            "max_failures": self.max_failures,
            # Include runtime state for status reporting
            "is_active": self.is_active,
            "failure_count": self.failure_count,
            "activated_at": self.activated_at.isoformat() if self.activated_at else None,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FailSafeSettings":
        return cls(
            enabled=data.get("enabled", True),
            fallback_dns=data.get("fallback_dns", "1.1.1.1"),
            fallback_dns_secondary=data.get("fallback_dns_secondary", "8.8.8.8"),
            timeout_seconds=data.get("timeout_seconds", 5),
            auto_recover=data.get("auto_recover", True),
            recovery_check_interval=data.get("recovery_check_interval", 30),
            max_failures=data.get("max_failures", 3),
        )


@dataclass
class ShadowModeSettings:
    """Shadow Mode settings."""
    
    enabled: bool = False
    """Enable Shadow Mode (log-only, no blocking)."""
    
    duration_hours: int | None = None
    """Auto-disable after N hours (None = indefinite)."""
    
    started_at: datetime | None = None
    """When shadow mode was enabled."""
    
    capture_all: bool = True
    """Capture all queries (including allowed)."""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "duration_hours": self.duration_hours,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "capture_all": self.capture_all,
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ShadowModeSettings":
        started_at = None
        if data.get("started_at"):
            try:
                started_at = datetime.fromisoformat(data["started_at"])
            except (ValueError, TypeError):
                pass
        
        return cls(
            enabled=data.get("enabled", False),
            duration_hours=data.get("duration_hours"),
            started_at=started_at,
            capture_all=data.get("capture_all", True),
        )


@dataclass 
class AllSettings:
    """All NetProtection settings."""
    
    ipv6: IPv6Settings = field(default_factory=IPv6Settings)
    fail_safe: FailSafeSettings = field(default_factory=FailSafeSettings)
    shadow_mode: ShadowModeSettings = field(default_factory=ShadowModeSettings)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "ipv6": self.ipv6.to_dict(),
            "fail_safe": self.fail_safe.to_dict(),
            "shadow_mode": self.shadow_mode.to_dict(),
        }
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AllSettings":
        return cls(
            ipv6=IPv6Settings.from_dict(data.get("ipv6", {})),
            fail_safe=FailSafeSettings.from_dict(data.get("fail_safe", {})),
            shadow_mode=ShadowModeSettings.from_dict(data.get("shadow_mode", {})),
        )


# ════════════════════════════════════════════════════════════════════════════════
# SETTINGS MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class SettingsManager:
    """
    Manages NetProtection settings with persistence.
    
    Thread-safe singleton pattern.
    """
    
    _instance: "SettingsManager | None" = None
    _lock = threading.Lock()
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, data_dir: str | Path | None = None):
        if hasattr(self, "_initialized") and self._initialized:
            return
        
        self._data_dir = Path(data_dir) if data_dir else Path("/var/lib/easypi-netprotection")
        self._settings_file = self._data_dir / "settings.json"
        self._settings = AllSettings()
        self._file_lock = threading.Lock()
        self._initialized = True
        
        # Load settings on init
        self._load()
    
    def _load(self) -> None:
        """Load settings from file."""
        if not self._settings_file.exists():
            logger.info("No settings file found, using defaults")
            return
        
        try:
            with self._file_lock:
                data = json.loads(self._settings_file.read_text())
                self._settings = AllSettings.from_dict(data)
            logger.info("Loaded settings from %s", self._settings_file)
        except Exception as e:
            logger.error("Failed to load settings: %s", e)
    
    def _save(self) -> None:
        """Save settings to file."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            
            with self._file_lock:
                # Atomic write with temp file
                temp_file = self._settings_file.with_suffix(".tmp")
                temp_file.write_text(json.dumps(self._settings.to_dict(), indent=2))
                temp_file.replace(self._settings_file)
            
            logger.debug("Saved settings to %s", self._settings_file)
        except Exception as e:
            logger.error("Failed to save settings: %s", e)
    
    # ─────────────────────────────────────────────────────────────────────────
    # IPv6 Settings
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_ipv6_settings(self) -> IPv6Settings:
        """Get IPv6 settings."""
        return self._settings.ipv6
    
    def update_ipv6_settings(self, **kwargs) -> IPv6Settings:
        """Update IPv6 settings."""
        for key, value in kwargs.items():
            if hasattr(self._settings.ipv6, key):
                setattr(self._settings.ipv6, key, value)
        self._save()
        logger.info("Updated IPv6 settings: %s", kwargs)
        return self._settings.ipv6
    
    # ─────────────────────────────────────────────────────────────────────────
    # Fail-Safe Settings
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_fail_safe_settings(self) -> FailSafeSettings:
        """Get fail-safe settings."""
        return self._settings.fail_safe
    
    def update_fail_safe_settings(self, **kwargs) -> FailSafeSettings:
        """Update fail-safe settings (excluding runtime state)."""
        for key, value in kwargs.items():
            if hasattr(self._settings.fail_safe, key) and key not in ("is_active", "failure_count", "activated_at"):
                setattr(self._settings.fail_safe, key, value)
        self._save()
        logger.info("Updated fail-safe settings: %s", kwargs)
        return self._settings.fail_safe
    
    def activate_fail_safe(self) -> None:
        """Activate fail-safe mode."""
        self._settings.fail_safe.is_active = True
        self._settings.fail_safe.activated_at = datetime.now()
        logger.warning("Fail-safe mode ACTIVATED")
    
    def deactivate_fail_safe(self) -> None:
        """Deactivate fail-safe mode."""
        self._settings.fail_safe.is_active = False
        self._settings.fail_safe.activated_at = None
        self._settings.fail_safe.failure_count = 0
        logger.info("Fail-safe mode deactivated")
    
    def record_failure(self) -> bool:
        """Record a failure. Returns True if fail-safe should be activated."""
        self._settings.fail_safe.failure_count += 1
        if self._settings.fail_safe.failure_count >= self._settings.fail_safe.max_failures:
            self.activate_fail_safe()
            return True
        return False
    
    def record_success(self) -> None:
        """Record a successful operation (resets failure count)."""
        if self._settings.fail_safe.failure_count > 0:
            self._settings.fail_safe.failure_count = 0
            logger.debug("Failure count reset on success")
        
        if self._settings.fail_safe.is_active and self._settings.fail_safe.auto_recover:
            self.deactivate_fail_safe()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Shadow Mode Settings
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_shadow_mode_settings(self) -> ShadowModeSettings:
        """Get shadow mode settings."""
        # Check for auto-expire
        if self._settings.shadow_mode.enabled and self._settings.shadow_mode.duration_hours:
            if self._settings.shadow_mode.started_at:
                from datetime import timedelta
                expires_at = self._settings.shadow_mode.started_at + timedelta(hours=self._settings.shadow_mode.duration_hours)
                if datetime.now() >= expires_at:
                    self._settings.shadow_mode.enabled = False
                    self._settings.shadow_mode.started_at = None
                    self._save()
                    logger.info("Shadow mode auto-expired")
        
        return self._settings.shadow_mode
    
    def update_shadow_mode_settings(self, **kwargs) -> ShadowModeSettings:
        """Update shadow mode settings."""
        was_enabled = self._settings.shadow_mode.enabled
        
        for key, value in kwargs.items():
            if hasattr(self._settings.shadow_mode, key):
                setattr(self._settings.shadow_mode, key, value)
        
        # Set started_at when enabling
        if not was_enabled and self._settings.shadow_mode.enabled:
            self._settings.shadow_mode.started_at = datetime.now()
            logger.info("Shadow mode enabled")
        elif was_enabled and not self._settings.shadow_mode.enabled:
            self._settings.shadow_mode.started_at = None
            logger.info("Shadow mode disabled")
        
        self._save()
        return self._settings.shadow_mode
    
    # ─────────────────────────────────────────────────────────────────────────
    # All Settings
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_all_settings(self) -> AllSettings:
        """Get all settings."""
        return self._settings
    
    def export_settings(self) -> dict[str, Any]:
        """Export all settings as dict."""
        return self._settings.to_dict()
    
    def import_settings(self, data: dict[str, Any]) -> None:
        """Import settings from dict."""
        self._settings = AllSettings.from_dict(data)
        self._save()
        logger.info("Imported settings")


# ════════════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

_manager: SettingsManager | None = None


def get_settings_manager(data_dir: str | Path | None = None) -> SettingsManager:
    """Get or create the settings manager singleton."""
    global _manager
    if _manager is None:
        _manager = SettingsManager(data_dir)
    return _manager


def reset_settings_manager() -> None:
    """Reset the settings manager (for testing)."""
    global _manager
    _manager = None
    SettingsManager._instance = None
