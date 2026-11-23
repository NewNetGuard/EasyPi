"""NetProtection devices routes."""

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
    Query,
    field_validator,
    logger,
    require_admin,
    User,
    netprotection_service,
    _record_netprotection_event,
    ShieldProfileSet,
    DeviceUpdate,
)

from app.services.unknown_device_admission_service import (
    UnknownDeviceAdmissionError,
    UnknownDeviceNotFound,
    unknown_device_admission_service,
)

import asyncio
import re
from pydantic import ConfigDict

router = APIRouter()

# ============ Shield Profiles ============


@router.get("/shields")
async def get_shield_profiles(_admin: User = Depends(require_admin)):
    """Get available shield profiles."""
    profiles = await netprotection_service.get_shield_profiles()
    current = await netprotection_service.get_current_shield_profile()

    return {
        "profiles": profiles,
        "current": current,
    }


@router.post("/shields/set")
async def set_shield_profile(
    request: ShieldProfileSet, _admin: User = Depends(require_admin)
):
    """Set shield profile."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.set_shield_profile(request.profile_id)
        _record_netprotection_event(
            action_id="netprotection.shield.set",
            title="Set shield profile",
            subtitle=f"Guard Security · {request.profile_id}",
            status="success" if result.get("success", True) else "failed",
            message=result.get(
                "message", f"Shield profile set to {request.profile_id}"
            ),
            started_at=started_at,
        )
        return result
    except ValueError as e:
        _record_netprotection_event(
            action_id="netprotection.shield.set",
            title="Set shield profile",
            subtitle=f"Guard Security · {request.profile_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))


# ============ Devices ============


@router.get("/devices")
async def get_devices(_admin: User = Depends(require_admin)):
    """Get discovered devices."""
    return await netprotection_service.get_devices()


class DeviceCreate(BaseModel):
    """Schema for creating a device."""

    name: str = Field(..., min_length=1, max_length=64)
    ip: Optional[str] = None
    mac: Optional[str] = None
    parental: bool = False
    safesearch: bool = False
    enabled: bool = True
    profile_id: Optional[str] = None
    blocked_services: Optional[List[str]] = None
    # IP-based app blocking (Telegram, WhatsApp, Signal, Tor)
    blocked_apps: Optional[List[str]] = None


class UnknownDeviceApproval(BaseModel):
    """Only administrator-controlled metadata is accepted from the browser.

    The observed MAC and IP are deliberately absent: they are loaded from the
    server-side quarantine record at decision time.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=64)
    access_profile: str = Field(
        default="balanced", pattern="^(strict|balanced|kids|minimal)$"
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = " ".join(value.strip().split())
        if not cleaned or any(not char.isprintable() for char in cleaned):
            raise ValueError("Device name contains invalid characters")
        return cleaned


class UnknownDeviceIdentityReplacement(BaseModel):
    """Select only a server-proposed managed identity for a quarantined MAC."""

    model_config = ConfigDict(extra="forbid")

    target_device_id: str = Field(..., min_length=1, max_length=64)

    @field_validator("target_device_id")
    @classmethod
    def validate_target_device_id(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9_-]{1,64}", cleaned):
            raise ValueError("Invalid managed device identity")
        return cleaned


def _validate_unknown_device_id(device_id: str) -> None:
    if not re.fullmatch(r"unknown_[0-9a-f]{20}", device_id):
        raise HTTPException(status_code=404, detail="Unknown device not found")


@router.get("/devices/quarantine")
async def get_unknown_device_quarantine(
    include_blocked: bool = Query(False),
    _admin: User = Depends(require_admin),
):
    """Return pending/blocked passive observations and available access profiles."""
    try:
        await asyncio.to_thread(unknown_device_admission_service.refresh)
        devices = await asyncio.to_thread(
            unknown_device_admission_service.list_devices,
            include_blocked=include_blocked,
        )
        profiles = [
            profile
            for profile in await netprotection_service.get_shield_profiles()
            if profile.get("id") in {"strict", "balanced", "kids", "minimal"}
        ]
        return {
            "enabled": unknown_device_admission_service.is_block_mode(),
            "pending": [item for item in devices if item.get("status") == "pending"],
            "blocked": [item for item in devices if item.get("status") == "blocked"],
            "access_profiles": profiles,
            "identity_assurance": "observed_mac_ip_pair",
            "spoof_resistant": False,
        }
    except UnknownDeviceAdmissionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/devices/quarantine/{device_id}/block")
async def block_unknown_device(
    device_id: str, _admin: User = Depends(require_admin)
):
    """Acknowledge the device and retain the firewall's deny decision."""
    _validate_unknown_device_id(device_id)
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        observed = await asyncio.to_thread(
            unknown_device_admission_service.get_device, device_id
        )
        blocked = await netprotection_service.block_unknown_device_admission(
            str(observed.get("ip") or ""), str(observed.get("mac") or "")
        )
        if not blocked:
            raise RuntimeError("Persistent firewall block could not be activated")
        device = await asyncio.to_thread(
            unknown_device_admission_service.block, device_id
        )
    except UnknownDeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except UnknownDeviceAdmissionError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except RuntimeError as exc:
        _record_netprotection_event(
            action_id="netprotection.devices.quarantine.block",
            title="Block unknown device",
            subtitle="Guard Security",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=503,
            detail="Device block could not be activated safely",
        ) from exc
    _record_netprotection_event(
        action_id="netprotection.devices.quarantine.block",
        title="Block unknown device",
        subtitle=f"Guard Security · {device.get('hostname') or device.get('ip')}",
        status="success",
        message="Unknown device remains blocked by LAN admission policy",
        started_at=started_at,
    )
    return {"success": True, "device": device}


@router.post("/devices/quarantine/{device_id}/allow")
async def allow_unknown_device(
    device_id: str,
    approval: UnknownDeviceApproval,
    _admin: User = Depends(require_admin),
):
    """Atomically publish the server-observed MAC+IP as a managed identity."""
    _validate_unknown_device_id(device_id)
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        observed = await asyncio.to_thread(
            unknown_device_admission_service.get_device, device_id
        )
        client = netprotection_service.managed_client_record(
            approval.name, observed["ip"], observed["mac"], approval.access_profile
        )
        result = await netprotection_service.approve_client_transactional(
            client,
            # Always clear a possible durable block. This is idempotent and
            # also recovers if a previous Block reached the root firewall but
            # backend state persistence failed before recording the status.
            release_persistent_block=True,
        )
        try:
            await asyncio.to_thread(
                unknown_device_admission_service.mark_allowed, device_id
            )
        except UnknownDeviceAdmissionError:
            # The active managed MAC+IP policy is authoritative. A subsequent
            # refresh removes the now-approved observation safely.
            logger.warning(
                "Managed device %s was allowed but quarantine cleanup failed", device_id
            )
    except UnknownDeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (UnknownDeviceAdmissionError, RuntimeError) as exc:
        _record_netprotection_event(
            action_id="netprotection.devices.quarantine.allow",
            title="Allow unknown device",
            subtitle=f"Guard Security · {approval.name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=503,
            detail="Device remains blocked because its policy could not be activated",
        ) from exc

    _record_netprotection_event(
        action_id="netprotection.devices.quarantine.allow",
        title="Allow unknown device",
        subtitle=f"Guard Security · {approval.name}",
        status="success",
        message=(
            f"Allowed observed MAC+IP with the {approval.access_profile} access profile"
        ),
        started_at=started_at,
    )
    return {"success": True, "client": result.get("client")}


@router.post("/devices/quarantine/{device_id}/replace-identity")
async def replace_unknown_device_identity(
    device_id: str,
    replacement: UnknownDeviceIdentityReplacement,
    _admin: User = Depends(require_admin),
):
    """Move an existing Device ID and its policy to an observed replacement MAC."""
    _validate_unknown_device_id(device_id)
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        await asyncio.to_thread(unknown_device_admission_service.refresh)
        observed = await asyncio.to_thread(
            unknown_device_admission_service.get_device, device_id
        )
        candidate = observed.get("identity_candidate")
        if (
            not isinstance(candidate, dict)
            or candidate.get("device_id") != replacement.target_device_id
            or candidate.get("identity_state") != "possible_mac_change"
            or candidate.get("conflicts")
        ):
            raise ValueError(
                "Current network evidence does not safely support this identity replacement"
            )
        result = await netprotection_service.approve_client_transactional(
            {
                "ip": observed["ip"],
                "ids": [observed["ip"]],
                "mac": observed["mac"],
            },
            existing_client_id=replacement.target_device_id,
            release_persistent_block=True,
        )
        try:
            await asyncio.to_thread(
                unknown_device_admission_service.mark_allowed, device_id
            )
        except UnknownDeviceNotFound:
            # The proactive monitor may remove the now-managed observation
            # between policy publication and this idempotent cleanup.
            pass
        except UnknownDeviceAdmissionError:
            logger.warning(
                "Identity %s migrated but quarantine cleanup failed", device_id
            )
    except UnknownDeviceNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (UnknownDeviceAdmissionError, RuntimeError) as exc:
        _record_netprotection_event(
            action_id="netprotection.devices.identity.replace",
            title="Reconnect known device",
            subtitle="Guard Security · PRISM Identity",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=503,
            detail="Device remains blocked because identity migration could not be completed safely",
        ) from exc

    client = result.get("client") or {}
    _record_netprotection_event(
        action_id="netprotection.devices.identity.replace",
        title="Known device reconnected",
        subtitle=f"Guard Security · {client.get('name') or replacement.target_device_id}",
        status="success",
        message="Device ID and its existing protection policy were moved to the new MAC address",
        started_at=started_at,
    )
    return {"success": True, "client": client}


@router.post("/devices")
async def create_device(device: DeviceCreate, _admin: User = Depends(require_admin)):
    """Create a new device entry."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.create_device(device.model_dump())
    _record_netprotection_event(
        action_id="netprotection.devices.create",
        title="Create device",
        subtitle=f"Guard Security · {device.name}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Created device: {device.name}"),
        started_at=started_at,
    )
    return result


@router.put("/devices/{device_id}")
async def update_device(
    device_id: str, updates: DeviceUpdate, _admin: User = Depends(require_admin)
):
    """Update device settings (name, profile, etc)."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.update_device(
        device_id, updates.model_dump(exclude_none=True)
    )
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    _record_netprotection_event(
        action_id="netprotection.devices.update",
        title="Update device",
        subtitle=f"Guard Security · {device_id}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Updated device: {device_id}"),
        started_at=started_at,
    )
    return result


@router.put("/devices/{device_id}/shield")
async def set_device_shield(
    device_id: str, request: ShieldProfileSet, _admin: User = Depends(require_admin)
):
    """Set shield profile for specific device."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.update_device(
        device_id, {"shield_profile": request.profile_id}
    )
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    _record_netprotection_event(
        action_id="netprotection.devices.shield",
        title="Set device shield",
        subtitle=f"Guard Security · {device_id}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Device shield set to {request.profile_id}"),
        started_at=started_at,
    )
    return result


@router.delete("/devices/{device_id}")
async def delete_device(device_id: str, _admin: User = Depends(require_admin)):
    """Delete a device from the system."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.delete_device(device_id)
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    _record_netprotection_event(
        action_id="netprotection.devices.delete",
        title="Delete device",
        subtitle=f"Guard Security · {device_id}",
        status="success",
        message=f"Deleted device: {device_id}",
        started_at=started_at,
    )
    return {"success": True, "message": "Device deleted"}


@router.post("/parental/sync")
async def sync_parental_blocklist(_admin: User = Depends(require_admin)):
    """Manually trigger sync of parental blocklists to NetProtection profiles."""
    started_at = datetime.now(timezone.utc).isoformat()
    await netprotection_service._sync_blocklist()
    _record_netprotection_event(
        action_id="netprotection.parental.sync",
        title="Sync parental blocklist",
        subtitle="Guard Security · Parental controls",
        status="success",
        message="Blocklist synced",
        started_at=started_at,
    )
    return {"success": True, "message": "Blocklist synced"}


# ============ Threat Intelligence ============


@router.get("/threat-intel/stats")
async def get_threat_stats(_admin: User = Depends(require_admin)):
    """Get threat intelligence statistics."""
    return await netprotection_service.get_threat_stats()


@router.get("/threat-intel/blocklist")
async def get_blocklist_info(_admin: User = Depends(require_admin)):
    """Get generated blocklist info."""
    return await netprotection_service.get_blocklist_info()


@router.post("/threat-intel/blocklist/generate")
async def generate_blocklist(_admin: User = Depends(require_admin)):
    """Generate blocklist from threat intelligence."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.generate_blocklist(confirmed_by="admin")
    _record_netprotection_event(
        action_id="netprotection.threat-intel.generate",
        title="Generate threat intelligence blocklist",
        subtitle="Guard Security · Threat intelligence",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", "Threat intelligence blocklist generated"),
        started_at=started_at,
    )
    return result


@router.post("/threat-intel/cleanup")
async def cleanup_threats(_admin: User = Depends(require_admin)):
    """Cleanup expired threat entries."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.cleanup_expired_threats()
    _record_netprotection_event(
        action_id="netprotection.threat-intel.cleanup",
        title="Cleanup expired threats",
        subtitle="Guard Security · Threat intelligence",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", "Expired threats cleaned up"),
        started_at=started_at,
    )
    return result
