"""
Profile Manager

Manages device profiles and bindings with persistence.

SECURITY FEATURES:
- Atomic JSON writes with backup/rollback
- File permissions 0o600 (owner read/write only)
- LRU cache with TTL for lookup invalidation
- Binding priority: MAC > IP > CIDR with conflict logging
- PII masking in logs (MAC/IP hashed or partially masked)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import (
    DeviceProfile,
    DeviceBinding,
    BindingType,
    FilterLevel,
    FILTER_LEVEL_BLOCKLISTS,
    normalize_mac,
    mask_mac,
    mask_ip,
    hash_identifier,
)
from ..config import get_settings


logger = logging.getLogger(__name__)


# Module-level singleton
_manager_instance: "ProfileManager | None" = None
_manager_lock = threading.Lock()


def get_profile_manager(data_dir: str | None = None) -> "ProfileManager":
    """Get or create the singleton ProfileManager."""
    global _manager_instance

    if _manager_instance is None:
        if data_dir is None:
            data_dir = get_settings().NETPROTECTION_DATA_DIR

        with _manager_lock:
            if _manager_instance is None:
                _manager_instance = ProfileManager(data_dir)

    return _manager_instance


def trigger_profiles_reload(data_dir: str | None = None) -> bool:
    """
    Trigger immediate profiles reload by creating signal file.
    Called from backend after profile/binding changes.

    Returns:
        True if signal file was created successfully
    """
    data_path = Path(data_dir) if data_dir else get_settings().NETPROTECTION_DATA_DIR
    signal_file = data_path / ".profiles_reload"

    try:
        signal_file.touch()
        logger.info(f"Profiles reload signal created: {signal_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to create profiles reload signal: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═══════════════════════════════════════════════════════════════════════════════

MAX_PROFILES = 100
MAX_BINDINGS = 1000
MAX_WHITELIST_ENTRIES = 500
MAX_BLACKLIST_ENTRIES = 500
CACHE_TTL_SECONDS = 300  # 5 minutes cache TTL
# Persist binding stats (last_seen/query_count/blocked_count) periodically so UI can
# show whether a device is actually using EasyPi DNS (and avoid terminal debugging).
BINDINGS_STATS_FLUSH_INTERVAL_SEC = 15.0


# ═══════════════════════════════════════════════════════════════════════════════
# TTL LRU CACHE
# ═══════════════════════════════════════════════════════════════════════════════


class TTLCache:
    """LRU cache with TTL expiration."""

    def __init__(self, maxsize: int = 4096, ttl: int = CACHE_TTL_SECONDS):
        self._cache: dict[str, tuple[Any, float]] = {}
        self._maxsize = maxsize
        self._ttl = ttl
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> tuple[bool, Any]:
        """Get value from cache. Returns (found, value)."""
        with self._lock:
            if key in self._cache:
                value, timestamp = self._cache[key]
                if time.time() - timestamp < self._ttl:
                    self._hits += 1
                    return True, value
                else:
                    # Expired
                    del self._cache[key]
            self._misses += 1
            return False, None

    def set(self, key: str, value: Any) -> None:
        """Set value in cache."""
        with self._lock:
            # Evict oldest if full
            if len(self._cache) >= self._maxsize and key not in self._cache:
                oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
                del self._cache[oldest_key]

            self._cache[key] = (value, time.time())

    def clear(self) -> None:
        """Clear the cache."""
        with self._lock:
            self._cache.clear()

    def stats(self) -> dict:
        """Get cache statistics."""
        with self._lock:
            total = self._hits + self._misses
            return {
                "size": len(self._cache),
                "maxsize": self._maxsize,
                "ttl": self._ttl,
                "hits": self._hits,
                "misses": self._misses,
                "hit_rate": round(self._hits / total, 4) if total > 0 else 0,
            }


class ProfileManager:
    """
    Manages device profiles and MAC/IP bindings.

    Features:
    - Profile CRUD operations
    - Device binding by MAC/IP/CIDR with priority-based resolution
    - Fast lookup with TTL cache
    - JSON persistence with atomic writes
    - Conflict logging
    - Statistics tracking

    BINDING PRIORITY (highest first):
    1. MAC address (priority 100) - most specific
    2. IP address (priority 50) - for static IPs
    3. CIDR range (priority 10) - for subnets

    When multiple bindings match, highest priority wins.
    Conflicts are logged for admin review.
    """

    PROFILES_FILE = "profiles.json"
    BINDINGS_FILE = "bindings.json"
    RELOAD_SIGNAL_FILE = ".profiles_reload"
    BACKUP_SUFFIX = ".bak"
    FILE_PERMISSIONS = 0o600

    def __init__(self, data_dir: str | Path | None = None):
        """Initialize the manager."""
        if data_dir:
            self._data_dir = Path(data_dir)
        else:
            self._data_dir = get_settings().NETPROTECTION_DATA_DIR

        self._profiles_path = self._data_dir / self.PROFILES_FILE
        self._bindings_path = self._data_dir / self.BINDINGS_FILE
        self._reload_signal_path = self._data_dir / self.RELOAD_SIGNAL_FILE
        self._settings_path = self._data_dir / "settings.json"
        # A remote Personal DNS resolver cannot observe the LAN MAC address
        # behind a public client IP.  Its root-owned container unit may opt out
        # of LAN admission quarantine explicitly; every other deployment keeps
        # the fail-closed local default.
        unknown_policy_override = os.environ.get(
            "NETPROTECTION_UNKNOWN_DEVICE_MODE", ""
        ).strip().lower()
        self._unknown_policy_override = (
            unknown_policy_override
            if unknown_policy_override in {"block", "default"}
            else None
        )
        self._unknown_policy_mtime_ns: int | None = None
        self._unknown_policy_mode = "block"
        self._last_check_time = 0.0
        self._check_interval = 2.0  # Check signal file every 2 seconds

        self._profiles: dict[str, DeviceProfile] = {}
        self._bindings: dict[str, DeviceBinding] = {}

        # Lookup indexes
        self._mac_index: dict[str, str] = {}  # MAC -> binding_id
        self._ip_index: dict[str, str] = {}  # IP -> binding_id
        self._profile_bindings: dict[str, set[str]] = {}  # profile_id -> {binding_ids}

        # Thread safety
        self._lock = threading.RLock()
        self._write_lock = threading.Lock()

        # TTL Cache for lookups (invalidated on any binding/profile change)
        self._lookup_cache = TTLCache(maxsize=4096, ttl=CACHE_TTL_SECONDS)

        # Stats
        self._lookups = 0
        self._hits = 0
        self._misses = 0
        self._conflicts = 0  # Number of multi-match conflicts

        # Binding stats persistence (for "Protected / Not protected" UI).
        self._bindings_stats_dirty = False
        try:
            self._bindings_stats_flush_interval_sec = float(
                os.environ.get(
                    "NETPROTECTION_BINDINGS_STATS_FLUSH_INTERVAL_SEC",
                    str(BINDINGS_STATS_FLUSH_INTERVAL_SEC),
                )
            )
        except Exception:
            self._bindings_stats_flush_interval_sec = float(
                BINDINGS_STATS_FLUSH_INTERVAL_SEC
            )
        self._last_bindings_stats_flush = time.monotonic()

        # Load data
        self._load()
        self._ensure_default_profile()
        self._refresh_unknown_device_policy(force=True)

    def _refresh_unknown_device_policy(self, *, force: bool = False) -> None:
        if self._unknown_policy_override is not None:
            self._unknown_policy_mode = self._unknown_policy_override
            return
        try:
            mtime_ns = self._settings_path.stat().st_mtime_ns
        except OSError:
            # No settings file means a fresh installation: fail closed.
            self._unknown_policy_mode = "block"
            self._unknown_policy_mtime_ns = None
            return
        if not force and mtime_ns == self._unknown_policy_mtime_ns:
            return
        try:
            payload = json.loads(self._settings_path.read_text(encoding="utf-8"))
            section = payload.get("unknown_devices")
            # Missing security policy is an unreviewed legacy configuration.
            # Never silently restore the former permissive Default behavior.
            mode = (
                section.get("mode", "block")
                if isinstance(section, dict)
                else "block"
            )
            self._unknown_policy_mode = (
                mode if mode in {"block", "default"} else "block"
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            # Corrupt security policy must not silently relax protection.
            self._unknown_policy_mode = "block"
        self._unknown_policy_mtime_ns = mtime_ns

    @property
    def block_unknown_devices(self) -> bool:
        self._refresh_unknown_device_policy()
        return self._unknown_policy_mode == "block"

    def is_known_device(self, client_ip: str, client_mac: str | None = None) -> bool:
        """Return whether one enabled MAC+network identity identifies this client.

        A MAC-only or IP-only match is not an identity proof: both values are
        independently spoofable on a LAN. Named bindings form a pair only when
        their profile and normalized device name match. For backward-compatible
        unnamed bindings, pairing is accepted only when the profile contains one
        active MAC and one active IP/range binding, avoiding cross-device matches.
        """
        import ipaddress

        # Admission runs before ``lookup_profile`` in the verdict pipeline.  If
        # this check does not consume the reload signal itself, a newly approved
        # device (or a known device after a DHCP address change) is denied before
        # execution can ever reach ``lookup_profile``, which used to be the only
        # place that reloaded bindings.  Keep the fail-closed MAC+IP check, but
        # make sure it evaluates the current root-approved binding snapshot.
        self._check_reload_signal()

        def active(binding: DeviceBinding | None) -> bool:
            if binding is None or not binding.enabled:
                return False
            profile = self._profiles.get(binding.profile_id)
            return profile is not None and profile.enabled

        if not client_mac:
            return False
        try:
            normalized_mac = normalize_mac(client_mac)
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False

        with self._lock:
            mac_binding = self._bindings.get(
                self._mac_index.get(normalized_mac, "")
            )
            if not active(mac_binding):
                return False

            network_matches: list[DeviceBinding] = []
            exact = self._bindings.get(self._ip_index.get(client_ip, ""))
            if active(exact):
                network_matches.append(exact)
            try:
                for candidate in self._bindings.values():
                    if (
                        candidate.binding_type != BindingType.RANGE
                        or not active(candidate)
                    ):
                        continue
                    if address in ipaddress.ip_network(candidate.value, strict=False):
                        network_matches.append(candidate)
            except ValueError:
                return False

            for network_binding in network_matches:
                if network_binding.profile_id != mac_binding.profile_id:
                    continue

                mac_name = mac_binding.name.strip().casefold()
                network_name = network_binding.name.strip().casefold()
                if mac_name or network_name:
                    if not mac_name or mac_name != network_name:
                        continue
                    same_identity = [
                        self._bindings[binding_id]
                        for binding_id in self._profile_bindings.get(
                            mac_binding.profile_id, set()
                        )
                        if binding_id in self._bindings
                        and active(self._bindings[binding_id])
                        and self._bindings[binding_id].name.strip().casefold()
                        == mac_name
                    ]
                    mac_count = sum(
                        item.binding_type == BindingType.MAC
                        for item in same_identity
                    )
                    network_count = sum(
                        item.binding_type in {BindingType.IP, BindingType.RANGE}
                        for item in same_identity
                    )
                    if mac_count == 1 and network_count == 1:
                        return True
                    continue

                active_ids = self._profile_bindings.get(mac_binding.profile_id, set())
                active_bindings = [
                    self._bindings[binding_id]
                    for binding_id in active_ids
                    if binding_id in self._bindings
                    and active(self._bindings[binding_id])
                ]
                mac_count = sum(
                    item.binding_type == BindingType.MAC for item in active_bindings
                )
                network_count = sum(
                    item.binding_type in {BindingType.IP, BindingType.RANGE}
                    for item in active_bindings
                )
                if mac_count == 1 and network_count == 1:
                    return True
        return False

    # ─────────────────────────────────────────────────────────────────────────
    # PERSISTENCE
    # ─────────────────────────────────────────────────────────────────────────

    def _load(self) -> bool:
        """Load profiles and bindings from disk."""
        success = True

        # Load profiles
        if self._profiles_path.exists():
            try:
                with open(self._profiles_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for profile_data in data.get("profiles", []):
                    try:
                        profile = DeviceProfile.from_dict(profile_data)
                        self._profiles[profile.id] = profile
                    except Exception as e:
                        logger.warning(f"Invalid profile data: {e}")

                logger.info(f"Loaded {len(self._profiles)} device profiles")
            except Exception as e:
                logger.error(f"Failed to load profiles: {e}")
                success = False

        # Load bindings
        if self._bindings_path.exists():
            try:
                with open(self._bindings_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

                for binding_data in data.get("bindings", []):
                    try:
                        binding = DeviceBinding.from_dict(binding_data)
                        self._bindings[binding.id] = binding
                        self._index_binding(binding)
                    except Exception as e:
                        logger.warning(f"Invalid binding data: {e}")

                logger.info(f"Loaded {len(self._bindings)} device bindings")
            except Exception as e:
                logger.error(f"Failed to load bindings: {e}")
                success = False

        # Update profile device counts
        self._update_device_counts()

        return success

    def _save_profiles(self) -> bool:
        """Save profiles atomically."""
        with self._write_lock:
            try:
                self._data_dir.mkdir(parents=True, exist_ok=True)

                # Backup
                if self._profiles_path.exists():
                    shutil.copy2(
                        self._profiles_path,
                        self._profiles_path.with_suffix(self.BACKUP_SUFFIX),
                    )

                data = {
                    "version": 1,
                    "updated_at": datetime.now().isoformat(),
                    "profiles": [p.to_dict() for p in self._profiles.values()],
                }

                temp_path = self._profiles_path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())

                try:
                    os.chmod(temp_path, self.FILE_PERMISSIONS)
                except OSError:
                    pass

                temp_path.replace(self._profiles_path)
                return True

            except Exception as e:
                logger.error(f"Failed to save profiles: {e}")
                return False

    def _save_bindings(self) -> bool:
        """Save bindings atomically."""
        with self._write_lock:
            try:
                self._data_dir.mkdir(parents=True, exist_ok=True)

                # Backup
                if self._bindings_path.exists():
                    shutil.copy2(
                        self._bindings_path,
                        self._bindings_path.with_suffix(self.BACKUP_SUFFIX),
                    )

                data = {
                    "version": 1,
                    "updated_at": datetime.now().isoformat(),
                    "bindings": [b.to_dict() for b in self._bindings.values()],
                }

                temp_path = self._bindings_path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())

                try:
                    os.chmod(temp_path, self.FILE_PERMISSIONS)
                except OSError:
                    pass

                temp_path.replace(self._bindings_path)
                return True

            except Exception as e:
                logger.error(f"Failed to save bindings: {e}")
                return False

    def _maybe_prepare_bindings_stats_flush_locked(self) -> list[dict[str, Any]] | None:
        """Return a snapshot for flushing binding stats (must be called under self._lock)."""
        if not self._bindings_stats_dirty:
            return None
        now = time.monotonic()
        if (
            now - self._last_bindings_stats_flush
            < self._bindings_stats_flush_interval_sec
        ):
            return None
        self._bindings_stats_dirty = False
        self._last_bindings_stats_flush = now
        return [b.to_dict() for b in self._bindings.values()]

    def _save_bindings_snapshot(self, bindings_snapshot: list[dict[str, Any]]) -> bool:
        """Persist bindings from a prepared snapshot (no need to hold self._lock)."""
        with self._write_lock:
            try:
                self._data_dir.mkdir(parents=True, exist_ok=True)

                # Backup
                if self._bindings_path.exists():
                    shutil.copy2(
                        self._bindings_path,
                        self._bindings_path.with_suffix(self.BACKUP_SUFFIX),
                    )

                data = {
                    "version": 1,
                    "updated_at": datetime.now().isoformat(),
                    "bindings": bindings_snapshot,
                }

                temp_path = self._bindings_path.with_suffix(".tmp")
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())

                try:
                    os.chmod(temp_path, self.FILE_PERMISSIONS)
                except OSError:
                    pass

                temp_path.replace(self._bindings_path)
                return True
            except Exception as e:
                logger.error(f"Failed to save bindings snapshot: {e}")
                return False

    # ─────────────────────────────────────────────────────────────────────────
    # INDEXING
    # ─────────────────────────────────────────────────────────────────────────

    def _index_binding(self, binding: DeviceBinding) -> None:
        """Add binding to lookup indexes."""
        if binding.binding_type == BindingType.MAC:
            self._mac_index[binding.value] = binding.id
        elif binding.binding_type == BindingType.IP:
            self._ip_index[binding.value] = binding.id
        # CIDR ranges are checked at lookup time

        # Profile -> bindings index
        if binding.profile_id not in self._profile_bindings:
            self._profile_bindings[binding.profile_id] = set()
        self._profile_bindings[binding.profile_id].add(binding.id)

    def _unindex_binding(self, binding: DeviceBinding) -> None:
        """Remove binding from lookup indexes."""
        if binding.binding_type == BindingType.MAC:
            self._mac_index.pop(binding.value, None)
        elif binding.binding_type == BindingType.IP:
            self._ip_index.pop(binding.value, None)

        # Profile -> bindings index
        if binding.profile_id in self._profile_bindings:
            self._profile_bindings[binding.profile_id].discard(binding.id)

    def _rebuild_indexes(self) -> None:
        """Rebuild all lookup indexes."""
        self._mac_index.clear()
        self._ip_index.clear()
        self._profile_bindings.clear()

        for binding in self._bindings.values():
            self._index_binding(binding)

    def _update_device_counts(self) -> None:
        """Update device counts in profiles."""
        for profile in self._profiles.values():
            binding_ids = self._profile_bindings.get(profile.id, set())
            profile.device_count = len(binding_ids)

    def _ensure_default_profile(self) -> None:
        """Ensure a default profile exists."""
        has_default = any(p.is_default for p in self._profiles.values())

        if not has_default:
            default = DeviceProfile(
                id=str(uuid.uuid4()),
                name="Default",
                description="Default profile for unbound devices",
                filter_level=FilterLevel.STANDARD,
                is_default=True,
            )
            self._profiles[default.id] = default
            self._save_profiles()
            logger.info("Created default device profile")

    # ─────────────────────────────────────────────────────────────────────────
    # PROFILE CRUD
    # ─────────────────────────────────────────────────────────────────────────

    def create_profile(
        self,
        name: str,
        description: str = "",
        filter_level: FilterLevel | str = FilterLevel.STANDARD,
        enabled_blocklists: list[str] | None = None,
        whitelist: list[str] | None = None,
        blacklist: list[str] | None = None,
        safe_search: bool = False,
        is_default: bool = False,
    ) -> DeviceProfile:
        """Create a new profile."""
        if isinstance(filter_level, str):
            filter_level = FilterLevel(filter_level)

        with self._lock:
            if len(self._profiles) >= MAX_PROFILES:
                raise ValueError(f"Maximum profile limit ({MAX_PROFILES}) reached")

            # If setting as default, unset others
            if is_default:
                for p in self._profiles.values():
                    p.is_default = False

            # Validate lists
            whitelist = whitelist or []
            blacklist = blacklist or []

            if len(whitelist) > MAX_WHITELIST_ENTRIES:
                raise ValueError(f"Whitelist too large (max {MAX_WHITELIST_ENTRIES})")
            if len(blacklist) > MAX_BLACKLIST_ENTRIES:
                raise ValueError(f"Blacklist too large (max {MAX_BLACKLIST_ENTRIES})")

            profile = DeviceProfile(
                id=str(uuid.uuid4()),
                name=name[:100],
                description=description[:500],
                filter_level=filter_level,
                enabled_blocklists=enabled_blocklists or [],
                whitelist=whitelist,
                blacklist=blacklist,
                safe_search=safe_search,
                is_default=is_default,
            )

            self._profiles[profile.id] = profile
            self._save_profiles()

        logger.info(f"Created profile: {name}")
        return profile

    def update_profile(self, profile_id: str, **kwargs) -> DeviceProfile | None:
        """Update a profile."""
        with self._lock:
            if profile_id not in self._profiles:
                return None

            profile = self._profiles[profile_id]

            if "name" in kwargs:
                profile.name = kwargs["name"][:100]
            if "description" in kwargs:
                profile.description = kwargs["description"][:500]
            if "filter_level" in kwargs:
                fl = kwargs["filter_level"]
                profile.filter_level = FilterLevel(fl) if isinstance(fl, str) else fl
            if "enabled_blocklists" in kwargs:
                profile.enabled_blocklists = kwargs["enabled_blocklists"]
            if "whitelist" in kwargs:
                wl = kwargs["whitelist"]
                if len(wl) > MAX_WHITELIST_ENTRIES:
                    raise ValueError("Whitelist too large")
                profile.whitelist = [d.lower().strip().rstrip(".") for d in wl]
            if "blacklist" in kwargs:
                bl = kwargs["blacklist"]
                if len(bl) > MAX_BLACKLIST_ENTRIES:
                    raise ValueError("Blacklist too large")
                profile.blacklist = [d.lower().strip().rstrip(".") for d in bl]
            if "safe_search" in kwargs:
                profile.safe_search = kwargs["safe_search"]
            if "parental_enabled" in kwargs:
                profile.parental_enabled = bool(kwargs["parental_enabled"])
            if "schedule_enabled" in kwargs:
                profile.schedule_enabled = kwargs["schedule_enabled"]
            if "schedule" in kwargs:
                profile.schedule = kwargs["schedule"]
            if "log_queries" in kwargs:
                profile.log_queries = kwargs["log_queries"]
            if "enabled" in kwargs:
                profile.enabled = kwargs["enabled"]
            if "is_default" in kwargs and kwargs["is_default"]:
                # Unset other defaults
                for p in self._profiles.values():
                    p.is_default = False
                profile.is_default = True

            profile.updated_at = datetime.now()
            self._save_profiles()
            self._clear_cache()

        logger.info(f"Updated profile {profile_id[:8]}...")
        return profile

    def delete_profile(self, profile_id: str) -> bool:
        """Delete a profile (and its bindings)."""
        with self._lock:
            if profile_id not in self._profiles:
                return False

            profile = self._profiles[profile_id]

            # Cannot delete default profile
            if profile.is_default:
                raise ValueError("Cannot delete default profile")

            # Delete associated bindings
            binding_ids = list(self._profile_bindings.get(profile_id, []))
            for bid in binding_ids:
                if bid in self._bindings:
                    binding = self._bindings[bid]
                    self._unindex_binding(binding)
                    del self._bindings[bid]

            del self._profiles[profile_id]
            self._save_profiles()
            self._save_bindings()
            self._clear_cache()

        logger.info(f"Deleted profile {profile_id[:8]}...")
        return True

    def get_profile(self, profile_id: str) -> DeviceProfile | None:
        """Get a profile by ID."""
        return self._profiles.get(profile_id)

    def list_profiles(self) -> list[DeviceProfile]:
        """List all profiles."""
        with self._lock:
            return sorted(
                self._profiles.values(),
                key=lambda p: (not p.is_default, p.name.lower()),
            )

    def get_default_profile(self) -> DeviceProfile | None:
        """Get the default profile."""
        for profile in self._profiles.values():
            if profile.is_default:
                return profile
        return None

    # ─────────────────────────────────────────────────────────────────────────
    # BINDING CRUD
    # ─────────────────────────────────────────────────────────────────────────

    def create_binding(
        self,
        profile_id: str,
        binding_type: BindingType | str,
        value: str,
        name: str = "",
        trusted: bool = False,
    ) -> DeviceBinding:
        """
        Create a device binding.

        Args:
            profile_id: ID of profile to bind to
            binding_type: mac, ip, or range
            value: MAC address, IP, or CIDR
            name: Friendly device name
            trusted: Whether device is in trusted network zone
        """
        if isinstance(binding_type, str):
            binding_type = BindingType(binding_type)

        with self._lock:
            if profile_id not in self._profiles:
                raise ValueError(f"Profile not found: {profile_id}")

            if len(self._bindings) >= MAX_BINDINGS:
                raise ValueError(f"Maximum binding limit ({MAX_BINDINGS}) reached")

            # Check for duplicates
            if binding_type == BindingType.MAC:
                normalized = normalize_mac(value)
                if normalized in self._mac_index:
                    raise ValueError("MAC address already bound")
            elif binding_type == BindingType.IP:
                if value in self._ip_index:
                    raise ValueError("IP address already bound")

            binding = DeviceBinding(
                id=str(uuid.uuid4()),
                profile_id=profile_id,
                binding_type=binding_type,
                value=value,
                name=name[:100],
                trusted=trusted,
            )

            self._bindings[binding.id] = binding
            self._index_binding(binding)
            self._update_device_counts()
            self._save_bindings()
            self._clear_cache()

        # Log with masked PII
        if binding_type == BindingType.MAC:
            masked = mask_mac(value)
        elif binding_type == BindingType.IP:
            masked = mask_ip(value)
        else:
            masked = f"{value.split('/')[0]}..."  # CIDR: show network only

        logger.info(
            f"Created binding: {binding_type.value}={masked} "
            f"(hash:{hash_identifier(value)[:8]}) -> profile {profile_id[:8]}..."
        )
        return binding

    def update_binding(self, binding_id: str, **kwargs) -> DeviceBinding | None:
        """Update a binding."""
        with self._lock:
            if binding_id not in self._bindings:
                return None

            binding = self._bindings[binding_id]
            old_binding = DeviceBinding.from_dict(binding.to_dict())

            # Remove old indexes
            self._unindex_binding(old_binding)

            if "profile_id" in kwargs:
                new_profile = kwargs["profile_id"]
                if new_profile not in self._profiles:
                    raise ValueError(f"Profile not found: {new_profile}")
                binding.profile_id = new_profile
            if "name" in kwargs:
                binding.name = kwargs["name"][:100]
            if "enabled" in kwargs:
                binding.enabled = kwargs["enabled"]

            # Re-index
            self._index_binding(binding)

            binding.updated_at = datetime.now()
            self._update_device_counts()
            self._save_bindings()
            self._clear_cache()

        return binding

    def delete_binding(self, binding_id: str) -> bool:
        """Delete a binding."""
        with self._lock:
            if binding_id not in self._bindings:
                return False

            binding = self._bindings[binding_id]
            self._unindex_binding(binding)
            del self._bindings[binding_id]

            self._update_device_counts()
            self._save_bindings()
            self._clear_cache()

        logger.info(f"Deleted binding {binding_id[:8]}...")
        return True

    def get_binding(self, binding_id: str) -> DeviceBinding | None:
        """Get a binding by ID."""
        return self._bindings.get(binding_id)

    def list_bindings(self, profile_id: str | None = None) -> list[DeviceBinding]:
        """List bindings, optionally filtered by profile."""
        with self._lock:
            if profile_id:
                binding_ids = self._profile_bindings.get(profile_id, set())
                bindings = [
                    self._bindings[bid] for bid in binding_ids if bid in self._bindings
                ]
            else:
                bindings = list(self._bindings.values())

            return sorted(bindings, key=lambda b: (b.name.lower(), b.value))

    # ─────────────────────────────────────────────────────────────────────────
    # LOOKUP WITH PRIORITY-BASED CONFLICT RESOLUTION
    # ─────────────────────────────────────────────────────────────────────────

    def _check_reload_signal(self) -> None:
        """Check if reload signal file exists and trigger reload if so."""
        import time

        now = time.time()
        if now - self._last_check_time < self._check_interval:
            return
        self._last_check_time = now

        if self._reload_signal_path.exists():
            try:
                self._reload_signal_path.unlink()
                logger.info("Profile reload signal received - reloading profiles")
                self.reload()
            except Exception as e:
                logger.error(f"Failed to process reload signal: {e}")

    def lookup_profile(
        self,
        client_ip: str,
        client_mac: str | None = None,
    ) -> DeviceProfile | None:
        """
        Look up the profile for a client using priority-based resolution.

        Priority order (highest first):
        1. MAC address binding (priority 100)
        2. IP address binding (priority 50)
        3. CIDR range binding (priority 10)
        4. Default profile (priority 0)

        When multiple bindings match, highest priority wins.
        Conflicts (multiple matches at same priority) are logged.

        Returns:
            The resolved DeviceProfile, or default profile if no match.
        """
        # Check for reload signal (every 2 seconds)
        self._check_reload_signal()

        self._lookups += 1

        # Check TTL cache first
        cache_key = f"{client_ip}:{client_mac or ''}"
        found, cached_value = self._lookup_cache.get(cache_key)
        if found:
            self._hits += 1
            cached_profile = cached_value
            cached_binding_id: str | None = None
            # Cache value is (profile, binding_id) for fast "last seen" updates.
            if isinstance(cached_value, tuple) and len(cached_value) == 2:
                cached_profile, cached_binding_id = cached_value

            snapshot: list[dict[str, Any]] | None = None
            if cached_binding_id:
                with self._lock:
                    binding = self._bindings.get(cached_binding_id)
                    if binding and binding.enabled:
                        binding.last_seen = datetime.now()
                        binding.query_count += 1
                        self._bindings_stats_dirty = True
                        snapshot = self._maybe_prepare_bindings_stats_flush_locked()
            if snapshot:
                self._save_bindings_snapshot(snapshot)

            return cached_profile

        # Perform lookup
        profile, binding_id, snapshot = self._do_lookup(client_ip, client_mac)

        # Cache result
        self._lookup_cache.set(cache_key, (profile, binding_id))
        if snapshot:
            self._save_bindings_snapshot(snapshot)

        if profile and not profile.is_default:
            self._hits += 1
        else:
            self._misses += 1

        return profile

    def _do_lookup(
        self,
        client_ip: str,
        client_mac: str | None,
    ) -> tuple[DeviceProfile | None, str | None, list[dict[str, Any]] | None]:
        """
        Perform actual lookup with priority-based conflict resolution.

        Collects ALL matching bindings, sorts by priority, logs conflicts.
        """
        import ipaddress

        matches: list[
            tuple[int, DeviceBinding, str]
        ] = []  # (priority, binding, match_type)

        with self._lock:
            # 1. Check MAC binding (priority 100)
            if client_mac:
                try:
                    normalized_mac = normalize_mac(client_mac)
                    if normalized_mac in self._mac_index:
                        binding_id = self._mac_index[normalized_mac]
                        binding = self._bindings.get(binding_id)
                        if binding and binding.enabled:
                            matches.append((binding.priority, binding, "mac"))
                except ValueError:
                    pass

            # 2. Check IP binding (priority 50)
            if client_ip in self._ip_index:
                binding_id = self._ip_index[client_ip]
                binding = self._bindings.get(binding_id)
                if binding and binding.enabled:
                    matches.append((binding.priority, binding, "ip"))

            # 3. Check CIDR ranges (priority 10)
            try:
                ip = ipaddress.ip_address(client_ip)
                for binding in self._bindings.values():
                    if binding.binding_type == BindingType.RANGE and binding.enabled:
                        try:
                            network = ipaddress.ip_network(binding.value, strict=False)
                            if ip in network:
                                matches.append((binding.priority, binding, "cidr"))
                        except ValueError:
                            continue
            except ValueError:
                pass

            # No matches -> return default
            if not matches:
                return self.get_default_profile(), None, None

            # Sort by priority (highest first)
            matches.sort(key=lambda x: -x[0])

            # Check for conflicts (multiple matches at same priority level)
            if len(matches) > 1:
                top_priority = matches[0][0]
                conflicts = [m for m in matches if m[0] == top_priority]

                if len(conflicts) > 1:
                    self._conflicts += 1
                    # Log conflict with masked PII
                    conflict_info = ", ".join(
                        f"{m[2]}:{m[1].binding_type.value}" for m in conflicts
                    )
                    logger.warning(
                        f"Binding conflict for client {mask_ip(client_ip)} "
                        f"(hash:{hash_identifier(client_ip)[:8]}): "
                        f"matches=[{conflict_info}], using first by priority"
                    )

            # Use highest priority binding
            _, winning_binding, match_type = matches[0]
            profile = self._profiles.get(winning_binding.profile_id)

            if profile and profile.enabled:
                # Update binding stats
                winning_binding.last_seen = datetime.now()
                winning_binding.query_count += 1
                self._bindings_stats_dirty = True
                snapshot = self._maybe_prepare_bindings_stats_flush_locked()

                # Debug log with masked PII
                logger.debug(
                    f"Profile lookup: {mask_ip(client_ip)} -> "
                    f"profile={profile.name} via {match_type}"
                )
                return profile, winning_binding.id, snapshot

            # Binding exists but profile disabled/missing
            return self.get_default_profile(), None, None

    def _clear_cache(self) -> None:
        """Clear lookup cache (called on any profile/binding change)."""
        self._lookup_cache.clear()
        logger.debug("Profile lookup cache cleared")

    # ─────────────────────────────────────────────────────────────────────────
    # FILTERING DECISION
    # ─────────────────────────────────────────────────────────────────────────

    def should_filter(
        self,
        domain: str,
        client_ip: str,
        client_mac: str | None = None,
        category: str | None = None,
    ) -> tuple[bool, str | None]:
        """
        Determine if a domain should be filtered for a client.

        Returns:
            (should_block, reason)
        """
        profile = self.lookup_profile(client_ip, client_mac)

        if not profile or not profile.enabled:
            return False, None

        # Check schedule
        if not profile.is_active_now():
            return False, None

        domain = domain.lower().rstrip(".")

        # 1. Check profile whitelist (always allow)
        if profile.is_whitelisted(domain):
            return False, None

        # 2. Check profile blacklist (always block)
        if profile.is_blacklisted(domain):
            return True, f"profile_blacklist:{profile.name}"

        # 3. Check filter level
        if profile.filter_level == FilterLevel.NONE:
            return False, None

        # Get blocklists for this filter level
        if profile.filter_level == FilterLevel.CUSTOM:
            enabled_lists = set(profile.enabled_blocklists)
        else:
            enabled_lists = set(FILTER_LEVEL_BLOCKLISTS.get(profile.filter_level, []))

        # If category provided, check if it's in enabled lists
        if category and category.lower() in enabled_lists:
            return True, f"profile_filter:{profile.name}:{category}"

        return False, None

    def get_blocklists_for_client(
        self,
        client_ip: str,
        client_mac: str | None = None,
    ) -> set[str]:
        """Get the set of enabled blocklist categories for a client."""
        profile = self.lookup_profile(client_ip, client_mac)

        if not profile or not profile.enabled:
            return set()

        if profile.filter_level == FilterLevel.NONE:
            return set()

        if profile.filter_level == FilterLevel.CUSTOM:
            return set(profile.enabled_blocklists)

        return set(FILTER_LEVEL_BLOCKLISTS.get(profile.filter_level, []))

    # ─────────────────────────────────────────────────────────────────────────
    # STATISTICS
    # ─────────────────────────────────────────────────────────────────────────

    def record_query(
        self,
        client_ip: str,
        client_mac: str | None = None,
        blocked: bool = False,
    ) -> None:
        """Record a query for statistics."""
        snapshot: list[dict[str, Any]] | None = None
        with self._lock:
            # Find binding
            binding = None

            if client_mac:
                try:
                    normalized = normalize_mac(client_mac)
                    if normalized in self._mac_index:
                        binding = self._bindings.get(self._mac_index[normalized])
                except ValueError:
                    pass

            if not binding and client_ip in self._ip_index:
                binding = self._bindings.get(self._ip_index[client_ip])

            if binding:
                if blocked:
                    binding.blocked_count += 1
                    self._bindings_stats_dirty = True
                binding.last_seen = datetime.now()
                snapshot = self._maybe_prepare_bindings_stats_flush_locked()

        if snapshot:
            self._save_bindings_snapshot(snapshot)

    def stats(self) -> dict[str, Any]:
        """Get manager statistics."""
        cache_stats = self._lookup_cache.stats()

        with self._lock:
            # Count by filter level
            level_counts = {}
            for profile in self._profiles.values():
                level = profile.filter_level.value
                level_counts[level] = level_counts.get(level, 0) + 1

            # Count by binding type
            type_counts = {}
            for binding in self._bindings.values():
                bt = binding.binding_type.value
                type_counts[bt] = type_counts.get(bt, 0) + 1

        total = self._hits + self._misses

        return {
            "total_profiles": len(self._profiles),
            "total_bindings": len(self._bindings),
            "profiles_by_level": level_counts,
            "bindings_by_type": type_counts,
            "lookups": self._lookups,
            "hits": self._hits,
            "misses": self._misses,
            "conflicts": self._conflicts,  # Binding conflicts detected
            "hit_rate": round(self._hits / total, 4) if total > 0 else 0,
            # TTL cache stats
            "cache_size": cache_stats["size"],
            "cache_maxsize": cache_stats["maxsize"],
            "cache_ttl": cache_stats["ttl"],
            "cache_hits": cache_stats["hits"],
            "cache_misses": cache_stats["misses"],
        }

    def reload(self) -> bool:
        """Reload from disk."""
        with self._write_lock:
            self._profiles.clear()
            self._bindings.clear()
            self._rebuild_indexes()
            self._clear_cache()
            return self._load()
