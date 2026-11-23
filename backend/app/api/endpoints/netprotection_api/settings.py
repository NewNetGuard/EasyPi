"""NetProtection settings routes."""

from .context import (
    APIRouter,
    HTTPException,
    Depends,
    List,
    Optional,
    datetime,
    timezone,
    BaseModel,
    Field,
    field_validator,
    require_admin,
    User,
    netprotection_service,
    _record_netprotection_event,
)

router = APIRouter()

# ============ Settings (IPv6, Fail-Safe, Shadow Mode) ============


class IPv6SettingsUpdate(BaseModel):
    """IPv6 settings update."""

    enabled: Optional[bool] = None
    block_ipv6_dns: Optional[bool] = None
    audit_mode: Optional[bool] = None


class FailSafeSettingsUpdate(BaseModel):
    """Fail-Safe settings update."""

    enabled: Optional[bool] = None
    fallback_dns: Optional[str] = Field(None, max_length=253)
    timeout_seconds: Optional[int] = Field(None, ge=1, le=30)
    auto_recover: Optional[bool] = None

    @field_validator("fallback_dns")
    @classmethod
    def validate_fallback_dns(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        import re

        # IPv4 pattern
        ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        # IPv6 pattern (simplified)
        ipv6_pattern = r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
        # Hostname pattern (letters, digits, hyphens, dots)
        hostname_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"

        if not (
            re.match(ipv4_pattern, v)
            or re.match(ipv6_pattern, v)
            or re.match(hostname_pattern, v)
        ):
            raise ValueError("Invalid DNS server address")
        return v


class ShadowModeSettingsUpdate(BaseModel):
    """Shadow Mode settings update."""

    enabled: Optional[bool] = None
    duration_hours: Optional[int] = Field(None, ge=1, le=168)
    capture_all: Optional[bool] = None


class UnknownDeviceSettingsUpdate(BaseModel):
    mode: str = Field(..., pattern="^(block|default)$")


@router.get("/settings")
async def get_all_settings(_admin: User = Depends(require_admin)):
    """Get all NetProtection settings."""
    return await netprotection_service.get_all_settings()


@router.get("/settings/ipv6")
async def get_ipv6_settings(_admin: User = Depends(require_admin)):
    """Get IPv6 settings."""
    return await netprotection_service.get_ipv6_settings()


@router.get("/settings/unknown-devices")
async def get_unknown_device_settings(_admin: User = Depends(require_admin)):
    return await netprotection_service.get_unknown_device_settings()


@router.put("/settings/unknown-devices")
async def update_unknown_device_settings(
    request: UnknownDeviceSettingsUpdate,
    _admin: User = Depends(require_admin),
):
    previous = await netprotection_service.get_unknown_device_settings()
    previous_mode = previous.get("data", {}).get("mode", "block")
    result = await netprotection_service.update_unknown_device_settings(request.mode)
    if not await netprotection_service.sync_unknown_device_admission_policy():
        # Keep DNS and L3 admission on the same policy. A failed privileged
        # update must not leave either a bypass or an unexpected disconnect.
        await netprotection_service.update_unknown_device_settings(previous_mode)
        await netprotection_service.sync_unknown_device_admission_policy()
        raise HTTPException(
            status_code=500,
            detail="Policy was not changed because firewall admission sync failed",
        )
    return result


@router.get("/settings/ipv6/status")
async def get_ipv6_status(_admin: User = Depends(require_admin)):
    """Get the real IPv6 state of this device (for the Advanced Settings panel)."""
    return await netprotection_service.get_ipv6_status()


@router.put("/settings/ipv6")
async def update_ipv6_settings(
    settings: IPv6SettingsUpdate, _admin: User = Depends(require_admin)
):
    """Update IPv6 settings."""
    updates = settings.model_dump(exclude_none=True)
    return await netprotection_service.update_ipv6_settings(updates)


@router.get("/settings/failsafe")
async def get_failsafe_settings(_admin: User = Depends(require_admin)):
    """Get Fail-Safe settings."""
    return await netprotection_service.get_failsafe_settings()


@router.put("/settings/failsafe")
async def update_failsafe_settings(
    settings: FailSafeSettingsUpdate, _admin: User = Depends(require_admin)
):
    """Update Fail-Safe settings."""
    updates = settings.model_dump(exclude_none=True)
    return await netprotection_service.update_failsafe_settings(updates)


class FailSafeTrigger(BaseModel):
    """Fail-Safe trigger action."""

    action: str = Field(..., pattern="^(activate|deactivate)$")


@router.post("/settings/failsafe/trigger")
async def trigger_failsafe(
    trigger: FailSafeTrigger, _admin: User = Depends(require_admin)
):
    """Manually activate/deactivate Fail-Safe mode."""
    return await netprotection_service.trigger_failsafe(trigger.action)


@router.get("/settings/shadow-mode")
async def get_shadow_mode_settings(_admin: User = Depends(require_admin)):
    """Get Shadow Mode settings."""
    return await netprotection_service.get_shadow_mode_settings()


@router.put("/settings/shadow-mode")
async def update_shadow_mode_settings(
    settings: ShadowModeSettingsUpdate, _admin: User = Depends(require_admin)
):
    """Update Shadow Mode settings."""
    updates = settings.model_dump(exclude_none=True)
    return await netprotection_service.update_shadow_mode_settings(updates)


# ============ App Blocking (IP-based for DNS-bypass apps) ============


class AppBlockingUpdate(BaseModel):
    """Update blocked apps for a device."""

    apps: List[str] = Field(
        ...,
        description=(
            "List of apps to block: telegram, whatsapp, signal, tor, messenger, "
            "snapchat, wechat, viber, imessage, discord, line"
        ),
    )


@router.get("/app-blocking/apps")
async def get_blockable_apps(_admin: User = Depends(require_admin)):
    """
    Get list of apps that can be blocked via IP.

    These apps bypass DNS (Telegram, WhatsApp, Signal, Tor)
    and require IP-level blocking.
    """
    return await netprotection_service.get_blockable_apps()


@router.get("/app-blocking/devices/{device_id}/status")
async def get_device_app_blocking_status(
    device_id: str, _admin: User = Depends(require_admin)
):
    """Get app blocking status for a specific device."""
    return await netprotection_service.get_app_blocking_status(device_id)


@router.put("/app-blocking/devices/{device_id}")
async def set_device_blocked_apps(
    device_id: str, request: AppBlockingUpdate, _admin: User = Depends(require_admin)
):
    """
    Set blocked apps for a device.

    This enables IP-based blocking for apps that bypass DNS:
    - telegram: Telegram Messenger
    - whatsapp: WhatsApp Messenger
    - signal: Signal Messenger
    - tor: Tor Browser/Network
    - messenger: Facebook Messenger
    - snapchat: Snapchat
    - wechat: WeChat
    - viber: Viber
    - imessage: iMessage
    - discord: Discord
    - line: LINE
    """
    result = await netprotection_service.set_device_blocked_apps(
        device_id, request.apps
    )
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    return {"success": True, "blocked_apps": request.apps}


@router.post("/app-blocking/sync")
async def sync_app_blocking(_admin: User = Depends(require_admin)):
    """
    Sync app blocking rules with iptables.

    Call this after making changes to device blocked_apps to
    apply the firewall rules.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    success = await netprotection_service.sync_app_blocking()
    _record_netprotection_event(
        action_id="netprotection.app-blocking.sync",
        title="Sync app blocking rules",
        subtitle="Guard Security · App blocking",
        status="success" if success else "failed",
        message="App blocking rules synced" if success else "App blocking sync failed",
        started_at=started_at,
    )
    return {"success": success}


@router.post("/app-blocking/update-lists")
async def update_app_ip_lists(_admin: User = Depends(require_admin)):
    """
    Update IP lists for blockable apps from external sources.

    This fetches the latest IP ranges for Telegram, Tor, etc.
    from their official sources.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    success = await netprotection_service.update_app_ip_lists()
    _record_netprotection_event(
        action_id="netprotection.app-blocking.update-lists",
        title="Update app IP lists",
        subtitle="Guard Security · App blocking",
        status="success" if success else "failed",
        message="App IP lists updated" if success else "App IP list update failed",
        started_at=started_at,
    )
    return {"success": success}
