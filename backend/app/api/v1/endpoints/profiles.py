"""
Device Profiles API Endpoints

Per-device DNS filtering profiles management.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Optional, List
from fastapi import APIRouter, HTTPException, status, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
import re

try:
    from app.api.deps import require_admin
    from app.core.rate_limit import get_client_ip
    from app.models.user import User
    from app.services.operation_event_service import OperationEventService
except ModuleNotFoundError:
    from backend.app.api.deps import require_admin
    from backend.app.core.rate_limit import get_client_ip
    from backend.app.models.user import User
    from backend.app.services.operation_event_service import OperationEventService

# Import profile manager
try:
    from easypi_netprotection.profiles import (
        get_profile_manager,
        trigger_profiles_reload,
        DeviceProfile,
        DeviceBinding,
        BindingType,
        FilterLevel,
    )
    PROFILES_AVAILABLE = True
except ImportError:
    PROFILES_AVAILABLE = False
    # Define placeholders for when NetProtection is not available
    get_profile_manager = None
    trigger_profiles_reload = None
    DeviceProfile = None
    DeviceBinding = None
    BindingType = None
    FilterLevel = None


logger = logging.getLogger(__name__)
router = APIRouter()
operation_event_service = OperationEventService()


def _record_profile_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/guard-security",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record profile event %s: %s", action_id, exc)


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, calls: int = 60, period: int = 60):
        self.calls = calls
        self.period = period
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
    
    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._requests[key] = [t for t in self._requests[key] if now - t < self.period]
            if len(self._requests[key]) >= self.calls:
                return False
            self._requests[key].append(now)
            return True


_rate_limiter = RateLimiter(calls=60, period=60)


def check_rate_limit(request: Request):
    """Rate limit check."""
    client_ip = get_client_ip(request)
    if not _rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded",
            headers={"Retry-After": "60"},
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class ProfileCreate(BaseModel):
    """Request model for creating a profile."""
    
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    filter_level: str = Field(default="standard")
    enabled_blocklists: List[str] = Field(default_factory=list)
    whitelist: List[str] = Field(default_factory=list)
    blacklist: List[str] = Field(default_factory=list)
    safe_search: bool = Field(default=False)
    is_default: bool = Field(default=False)
    
    @field_validator("filter_level")
    @classmethod
    def validate_filter_level(cls, v):
        valid = ["none", "minimal", "standard", "strict", "custom"]
        if v.lower() not in valid:
            raise ValueError(f"Invalid filter level. Must be one of: {', '.join(valid)}")
        return v.lower()


class ProfileUpdate(BaseModel):
    """Request model for updating a profile."""
    
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    filter_level: Optional[str] = None
    enabled_blocklists: Optional[List[str]] = None
    whitelist: Optional[List[str]] = None
    blacklist: Optional[List[str]] = None
    safe_search: Optional[bool] = None
    schedule_enabled: Optional[bool] = None
    schedule: Optional[dict] = None
    log_queries: Optional[bool] = None
    enabled: Optional[bool] = None
    is_default: Optional[bool] = None


class ProfileResponse(BaseModel):
    """Response model for a profile."""
    
    id: str
    name: str
    description: str
    filter_level: str
    enabled_blocklists: List[str]
    whitelist: List[str]
    blacklist: List[str]
    safe_search: bool
    schedule_enabled: bool
    schedule: dict
    log_queries: bool
    is_default: bool
    device_count: int
    enabled: bool
    created_at: str
    updated_at: str


class ProfileListResponse(BaseModel):
    """Response model for list of profiles."""
    
    profiles: List[ProfileResponse]
    total: int


class BindingCreate(BaseModel):
    """Request model for creating a binding."""
    
    profile_id: str
    binding_type: str = Field(..., description="mac, ip, or range")
    value: str = Field(..., description="MAC address, IP, or CIDR")
    name: str = Field(default="", max_length=100)
    trusted: bool = Field(
        default=False, 
        description="Mark as trusted device (higher priority in conflict resolution)"
    )
    
    @field_validator("binding_type")
    @classmethod
    def validate_binding_type(cls, v):
        valid = ["mac", "ip", "range"]
        if v.lower() not in valid:
            raise ValueError(f"Invalid binding type. Must be one of: {', '.join(valid)}")
        return v.lower()
    
    @field_validator("value")
    @classmethod
    def validate_value(cls, v, info):
        bt = info.data.get("binding_type", "").lower() if info.data else ""
        
        if bt == "mac":
            # Basic MAC validation
            clean = re.sub(r'[:\-.]', '', v)
            if len(clean) != 12 or not re.match(r'^[0-9A-Fa-f]{12}$', clean):
                raise ValueError("Invalid MAC address format")
        
        elif bt == "ip":
            import ipaddress
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError("Invalid IP address format")
        
        elif bt == "range":
            import ipaddress
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError:
                raise ValueError("Invalid CIDR range format")
        
        return v


class BindingUpdate(BaseModel):
    """Request model for updating a binding."""
    
    profile_id: Optional[str] = None
    name: Optional[str] = Field(None, max_length=100)
    enabled: Optional[bool] = None
    trusted: Optional[bool] = None


class BindingResponse(BaseModel):
    """Response model for a binding."""
    
    id: str
    profile_id: str
    binding_type: str
    value: str  # Note: Consider masking in response for privacy
    name: str
    enabled: bool
    trusted: bool
    priority: int
    last_seen: Optional[str]
    query_count: int
    blocked_count: int
    created_at: str
    updated_at: str


class BindingListResponse(BaseModel):
    """Response model for list of bindings."""
    
    bindings: List[BindingResponse]
    total: int


class ProfileStatsResponse(BaseModel):
    """Response model for profile statistics."""
    
    total_profiles: int
    total_bindings: int
    profiles_by_level: dict
    bindings_by_type: dict
    conflicts: int
    lookups: int
    hits: int
    misses: int
    conflicts: int
    hit_rate: float
    cache_size: int
    cache_ttl: int


class LookupRequest(BaseModel):
    """Request model for profile lookup."""
    
    client_ip: str
    client_mac: Optional[str] = None


class LookupResponse(BaseModel):
    """Response model for profile lookup."""
    
    profile_id: Optional[str]
    profile_name: Optional[str]
    filter_level: Optional[str]
    is_default: bool
    matched_by: Optional[str] = None  # mac, ip, cidr, or default


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _get_manager():
    """Get profile manager or raise error."""
    if not PROFILES_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Device Profiles module not available",
        )
    return get_profile_manager()


def _profile_to_response(profile: "DeviceProfile") -> ProfileResponse:
    """Convert profile to response model."""
    return ProfileResponse(
        id=profile.id,
        name=profile.name,
        description=profile.description,
        filter_level=profile.filter_level.value,
        enabled_blocklists=profile.enabled_blocklists,
        whitelist=profile.whitelist,
        blacklist=profile.blacklist,
        safe_search=profile.safe_search,
        schedule_enabled=profile.schedule_enabled,
        schedule=profile.schedule,
        log_queries=profile.log_queries,
        is_default=profile.is_default,
        device_count=profile.device_count,
        enabled=profile.enabled,
        created_at=profile.created_at.isoformat(),
        updated_at=profile.updated_at.isoformat(),
    )


def _binding_to_response(binding: DeviceBinding) -> BindingResponse:
    """Convert binding to response model."""
    return BindingResponse(
        id=binding.id,
        profile_id=binding.profile_id,
        binding_type=binding.binding_type.value,
        value=binding.value,
        name=binding.name,
        enabled=binding.enabled,
        trusted=binding.trusted,
        priority=binding.priority,
        last_seen=binding.last_seen.isoformat() if binding.last_seen else None,
        query_count=binding.query_count,
        blocked_count=binding.blocked_count,
        created_at=binding.created_at.isoformat(),
        updated_at=binding.updated_at.isoformat(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# PROFILE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/profiles", response_model=ProfileListResponse)
async def list_profiles(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """List all device profiles."""
    check_rate_limit(request)
    manager = _get_manager()
    profiles = manager.list_profiles()
    
    return ProfileListResponse(
        profiles=[_profile_to_response(p) for p in profiles],
        total=len(profiles),
    )


@router.post("/profiles", response_model=ProfileResponse, status_code=201)
async def create_profile(
    request: Request,
    profile: ProfileCreate,
    current_user: User = Depends(require_admin),
):
    """
    Create a new device profile.
    
    **Filter Levels:**
    - `none`: No filtering (passthrough)
    - `minimal`: Only malware/phishing
    - `standard`: Malware + ads + trackers
    - `strict`: Everything including adult content
    - `custom`: Custom blocklist selection
    """
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    try:
        new_profile = manager.create_profile(
            name=profile.name,
            description=profile.description,
            filter_level=profile.filter_level,
            enabled_blocklists=profile.enabled_blocklists,
            whitelist=profile.whitelist,
            blacklist=profile.blacklist,
            safe_search=profile.safe_search,
            is_default=profile.is_default,
        )
        
        # Trigger reload signal for netprotection
        if trigger_profiles_reload:
            trigger_profiles_reload()
        
        logger.info(f"Created profile: {profile.name}")
        _record_profile_event(
            action_id="profiles.create",
            title="Create device profile",
            subtitle=f"Profiles - {profile.name}",
            status="success",
            message=f"Created profile: {profile.name}",
            started_at=started_at,
        )
        return _profile_to_response(new_profile)
        
    except ValueError as e:
        _record_profile_event(
            action_id="profiles.create",
            title="Create device profile",
            subtitle=f"Profiles - {profile.name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/profiles/stats", response_model=ProfileStatsResponse)
async def get_profile_stats(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """Get profile statistics including cache and conflict info."""
    check_rate_limit(request)
    manager = _get_manager()
    stats = manager.stats()

    return ProfileStatsResponse(
        total_profiles=stats["total_profiles"],
        total_bindings=stats["total_bindings"],
        profiles_by_level=stats["profiles_by_level"],
        bindings_by_type=stats["bindings_by_type"],
        lookups=stats["lookups"],
        hits=stats["hits"],
        misses=stats["misses"],
        conflicts=stats["conflicts"],
        hit_rate=stats["hit_rate"],
        cache_size=stats["cache_size"],
        cache_ttl=stats["cache_ttl"],
    )


@router.get("/profiles/{profile_id}", response_model=ProfileResponse)
async def get_profile(
    request: Request,
    profile_id: str,
    current_user: User = Depends(require_admin),
):
    """Get a specific profile."""
    check_rate_limit(request)
    manager = _get_manager()
    profile = manager.get_profile(profile_id)
    
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found",
        )
    
    return _profile_to_response(profile)


@router.put("/profiles/{profile_id}", response_model=ProfileResponse)
async def update_profile(
    request: Request,
    profile_id: str,
    update: ProfileUpdate,
    current_user: User = Depends(require_admin),
):
    """Update a profile."""
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    update_data = update.model_dump(exclude_none=True)
    
    if not update_data:
        _record_profile_event(
            action_id="profiles.update",
            title="Update device profile",
            subtitle=f"Profiles - {profile_id}",
            status="failed",
            message="No fields to update",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )
    
    try:
        updated = manager.update_profile(profile_id, **update_data)
    except ValueError as e:
        _record_profile_event(
            action_id="profiles.update",
            title="Update device profile",
            subtitle=f"Profiles - {profile_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    
    if not updated:
        _record_profile_event(
            action_id="profiles.update",
            title="Update device profile",
            subtitle=f"Profiles - {profile_id}",
            status="failed",
            message="Profile not found",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Profile not found",
        )
    
    # Trigger reload signal for netprotection
    if trigger_profiles_reload:
        trigger_profiles_reload()

    _record_profile_event(
        action_id="profiles.update",
        title="Update device profile",
        subtitle=f"Profiles - {updated.name}",
        status="success",
        message=f"Updated profile: {updated.name}",
        started_at=started_at,
    )
    return _profile_to_response(updated)


@router.delete("/profiles/{profile_id}")
async def delete_profile(
    request: Request,
    profile_id: str,
    current_user: User = Depends(require_admin),
):
    """Delete a profile."""
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    try:
        if not manager.delete_profile(profile_id):
            _record_profile_event(
                action_id="profiles.delete",
                title="Delete device profile",
                subtitle=f"Profiles - {profile_id}",
                status="failed",
                message="Profile not found",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Profile not found",
            )
    except ValueError as e:
        _record_profile_event(
            action_id="profiles.delete",
            title="Delete device profile",
            subtitle=f"Profiles - {profile_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    
    # Trigger reload signal for netprotection
    if trigger_profiles_reload:
        trigger_profiles_reload()

    _record_profile_event(
        action_id="profiles.delete",
        title="Delete device profile",
        subtitle=f"Profiles - {profile_id}",
        status="success",
        message="Profile deleted",
        started_at=started_at,
    )
    return {"success": True, "message": "Profile deleted"}


# ═══════════════════════════════════════════════════════════════════════════════
# BINDING ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/bindings", response_model=BindingListResponse)
async def list_bindings(
    request: Request,
    profile_id: Optional[str] = Query(None, description="Filter by profile"),
    current_user: User = Depends(require_admin),
):
    """List device bindings."""
    check_rate_limit(request)
    manager = _get_manager()
    bindings = manager.list_bindings(profile_id)
    
    return BindingListResponse(
        bindings=[_binding_to_response(b) for b in bindings],
        total=len(bindings),
    )


@router.post("/bindings", response_model=BindingResponse, status_code=201)
async def create_binding(
    request: Request,
    binding: BindingCreate,
    current_user: User = Depends(require_admin),
):
    """
    Create a device binding.
    
    **Binding Types & Priority:**
    - `mac`: MAC address (priority 100, highest)
    - `ip`: Static IP address (priority 50)
    - `range`: IP range in CIDR notation (priority 10, max /16)
    
    **Security Notes:**
    - MAC addresses can be spoofed; use IP bindings for static devices
    - CIDR ranges limited to /16 (65536 addresses) max
    - Set `trusted=true` for devices in trusted network zones (+10 priority)
    - Conflicts are logged; highest priority binding wins
    
    **MAC Address Formats:**
    - `aa:bb:cc:dd:ee:ff`
    - `aa-bb-cc-dd-ee-ff`  
    - `aabbccddeeff`
    """
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    try:
        new_binding = manager.create_binding(
            profile_id=binding.profile_id,
            binding_type=binding.binding_type,
            value=binding.value,
            name=binding.name,
            trusted=binding.trusted,
        )
        
        # Trigger reload signal for netprotection
        if trigger_profiles_reload:
            trigger_profiles_reload()
        
        # Note: manager.create_binding logs with masked PII
        _record_profile_event(
            action_id="profiles.binding.create",
            title="Create device binding",
            subtitle=f"Profiles - {binding.name or binding.binding_type}",
            status="success",
            message="Device binding created",
            started_at=started_at,
        )
        return _binding_to_response(new_binding)
        
    except ValueError as e:
        _record_profile_event(
            action_id="profiles.binding.create",
            title="Create device binding",
            subtitle=f"Profiles - {binding.name or binding.binding_type}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/bindings/{binding_id}", response_model=BindingResponse)
async def get_binding(
    request: Request,
    binding_id: str,
    current_user: User = Depends(require_admin),
):
    """Get a specific binding."""
    check_rate_limit(request)
    manager = _get_manager()
    binding = manager.get_binding(binding_id)
    
    if not binding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Binding not found",
        )
    
    return _binding_to_response(binding)


@router.put("/bindings/{binding_id}", response_model=BindingResponse)
async def update_binding(
    request: Request,
    binding_id: str,
    update: BindingUpdate,
    current_user: User = Depends(require_admin),
):
    """Update a binding."""
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    update_data = update.model_dump(exclude_none=True)
    
    if not update_data:
        _record_profile_event(
            action_id="profiles.binding.update",
            title="Update device binding",
            subtitle=f"Profiles - {binding_id}",
            status="failed",
            message="No fields to update",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )
    
    try:
        updated = manager.update_binding(binding_id, **update_data)
    except ValueError as e:
        _record_profile_event(
            action_id="profiles.binding.update",
            title="Update device binding",
            subtitle=f"Profiles - {binding_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    
    if not updated:
        _record_profile_event(
            action_id="profiles.binding.update",
            title="Update device binding",
            subtitle=f"Profiles - {binding_id}",
            status="failed",
            message="Binding not found",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Binding not found",
        )
    
    # Trigger reload signal for netprotection
    if trigger_profiles_reload:
        trigger_profiles_reload()

    _record_profile_event(
        action_id="profiles.binding.update",
        title="Update device binding",
        subtitle=f"Profiles - {binding_id}",
        status="success",
        message="Device binding updated",
        started_at=started_at,
    )
    return _binding_to_response(updated)


@router.delete("/bindings/{binding_id}")
async def delete_binding(
    request: Request,
    binding_id: str,
    current_user: User = Depends(require_admin),
):
    """Delete a binding."""
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    if not manager.delete_binding(binding_id):
        _record_profile_event(
            action_id="profiles.binding.delete",
            title="Delete device binding",
            subtitle=f"Profiles - {binding_id}",
            status="failed",
            message="Binding not found",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Binding not found",
        )
    
    # Trigger reload signal for netprotection
    if trigger_profiles_reload:
        trigger_profiles_reload()

    _record_profile_event(
        action_id="profiles.binding.delete",
        title="Delete device binding",
        subtitle=f"Profiles - {binding_id}",
        status="success",
        message="Device binding deleted",
        started_at=started_at,
    )
    return {"success": True, "message": "Binding deleted"}


# ═══════════════════════════════════════════════════════════════════════════════
# LOOKUP & STATS
# ═══════════════════════════════════════════════════════════════════════════════

@router.post("/profiles/lookup", response_model=LookupResponse)
async def lookup_profile(
    request: Request,
    lookup: LookupRequest,
    current_user: User = Depends(require_admin),
):
    """
    Look up which profile applies to a client.
    
    Use this to test profile bindings.
    """
    check_rate_limit(request)
    manager = _get_manager()
    
    profile = manager.lookup_profile(
        client_ip=lookup.client_ip,
        client_mac=lookup.client_mac,
    )
    
    if profile:
        return LookupResponse(
            profile_id=profile.id,
            profile_name=profile.name,
            filter_level=profile.filter_level.value,
            is_default=profile.is_default,
            matched_by="default" if profile.is_default else "binding",
        )
    
    return LookupResponse(
        profile_id=None,
        profile_name=None,
        filter_level=None,
        is_default=False,
        matched_by=None,
    )


@router.post("/profiles/reload")
async def reload_profiles(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """Reload profiles from disk."""
    check_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()

    if manager.reload():
        _record_profile_event(
            action_id="profiles.reload",
            title="Reload device profiles",
            subtitle="Profiles - Runtime",
            status="success",
            message="Profiles reloaded",
            started_at=started_at,
        )
        return {"success": True, "message": "Profiles reloaded"}

    _record_profile_event(
        action_id="profiles.reload",
        title="Reload device profiles",
        subtitle="Profiles - Runtime",
        status="failed",
        message="Failed to reload profiles",
        started_at=started_at,
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to reload profiles",
    )
