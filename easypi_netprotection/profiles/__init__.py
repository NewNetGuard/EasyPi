"""
Device Profiles Module

Per-device DNS filtering based on MAC/IP addresses.
Allows different filtering policies for different devices.

SECURITY NOTES:
- Binding priority: MAC (100) > IP (50) > CIDR (10) > Default
- MAC can be spoofed; treat as convenience, not security boundary
- CIDR limited to /16 max to prevent overly broad rules
- All endpoints require admin authentication
- PII (MAC/IP) masked in logs - use hash for correlation
"""

from .models import (
    DeviceProfile,
    DeviceBinding,
    BindingType,
    FilterLevel,
    # PII masking utilities
    mask_mac,
    mask_ip,
    hash_identifier,
)
from .manager import (
    ProfileManager,
    get_profile_manager,
    trigger_profiles_reload,
)

__all__ = [
    "DeviceProfile",
    "DeviceBinding",
    "BindingType",
    "FilterLevel",
    "ProfileManager",
    "get_profile_manager",
    "trigger_profiles_reload",
    # PII masking
    "mask_mac",
    "mask_ip",
    "hash_identifier",
]
