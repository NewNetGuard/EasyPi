"""
Tailscale Remote Access API Router

Simple endpoints for ON/OFF control of remote VPN access.
No user input required - all configuration is handled internally.

Security: All endpoints require admin authentication.
"""

import asyncio
import logging

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime, timezone
import re

from ...services.remote_access.tailscale_service import get_tailscale_service
from ...api.deps import require_admin
from ...services.operation_event_service import OperationEventService


router = APIRouter(prefix="/remote/tailscale", tags=["Remote Access"])
operation_event_service = OperationEventService()
logger = logging.getLogger(__name__)
AUTH_KEY_PATTERN = re.compile(
    r"^tskey-(?!(?:api|client|scim|webhook)-)[A-Za-z0-9_-]{16,480}$"
)


def _record_tailscale_event(
    *,
    action_id: str,
    title: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            title=title,
            subtitle="Remote Access · Tailscale",
            route="/remote-access",
            status=status,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record Tailscale event %s: %s", action_id, exc)


# Response models

class ErrorDetail(BaseModel):
    message: str
    code: str
    details: Optional[str] = None


class StatusResponse(BaseModel):
    enabled: bool
    tailscale_running: bool
    lan_cidr: Optional[str]
    tailscale_ips: list[str] = []
    advertised_routes: list[str] = []
    exit_node_advertised: bool
    hostname: Optional[str]
    tailnet: Optional[str]
    backend_state: Optional[str]
    last_error: Optional[str]
    last_enabled_at: Optional[str]
    taildrop_importer_active: bool = False
    taildrop_device_eligible: bool = False
    taildrop_error: Optional[str] = None
    taildrop_free_bytes: Optional[int] = None
    taildrop_reserve_bytes: Optional[int] = None


class EnableResponse(BaseModel):
    success: bool
    pending: Optional[bool] = None
    lan_cidr: Optional[str] = None
    details: Optional[str] = None
    status: Optional[StatusResponse] = None
    error: Optional[ErrorDetail] = None


class DisableResponse(BaseModel):
    success: bool
    details: Optional[str] = None
    status: Optional[StatusResponse] = None
    error: Optional[ErrorDetail] = None


class ConfigResponse(BaseModel):
    has_authkey: bool
    interface: str


class SaveAuthkeyRequest(BaseModel):
    authkey: str = Field(..., min_length=22, max_length=486, description="Tailscale auth key")
    
    @field_validator('authkey')
    @classmethod
    def validate_authkey(cls, v: str) -> str:
        # Strip whitespace
        v = v.strip()
        if not AUTH_KEY_PATTERN.fullmatch(v):
            raise ValueError("Invalid Tailscale auth key format")
        return v


class SaveAuthkeyResponse(BaseModel):
    success: bool
    error: Optional[ErrorDetail] = None


class InstallStatusResponse(BaseModel):
    installed: bool
    version: Optional[str] = None
    installing: bool = False


class InstallResponse(BaseModel):
    success: bool
    message: str
    version: Optional[str] = None
    error: Optional[ErrorDetail] = None


class UninstallResponse(BaseModel):
    success: bool
    message: str
    error: Optional[ErrorDetail] = None


# Endpoints

@router.post("/enable", response_model=EnableResponse)
async def enable_remote_access(admin: dict = Depends(require_admin)):
    """
    Enable remote VPN access. **Requires admin authentication.**
    
    No request body required - all configuration is automatic:
    - LAN CIDR is auto-detected from network interface
    - Auth key comes from server configuration
    - Always enables Subnet Router + Exit Node mode
    
    Returns success status with detected LAN CIDR and current status.
    
    **Security**: Executes privileged operations with sudo.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    service = get_tailscale_service()
    result = await asyncio.to_thread(service.enable_remote_access)
    _record_tailscale_event(
        action_id="tailscale.enable",
        title="Enable remote access",
        status="success" if result.get("success") else "failed",
        message=(
            result.get("details")
            or result.get("error", {}).get("details")
            or result.get("error", {}).get("message")
            or "Remote access enable finished"
        ),
        started_at=started_at,
    )
    
    return EnableResponse(**result)


@router.post("/disable", response_model=DisableResponse)
async def disable_remote_access(admin: dict = Depends(require_admin)):
    """
    Disable remote VPN access. **Requires admin authentication.**
    
    No request body required.
    Stops Tailscale and updates internal state.
    
    Returns success status.
    
    **Security**: Executes privileged operations with sudo.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    service = get_tailscale_service()
    result = await asyncio.to_thread(service.disable_remote_access)
    _record_tailscale_event(
        action_id="tailscale.disable",
        title="Disable remote access",
        status="success" if result.get("success") else "failed",
        message=(
            result.get("details")
            or result.get("error", {}).get("details")
            or result.get("error", {}).get("message")
            or "Remote access disable finished"
        ),
        started_at=started_at,
    )
    
    return DisableResponse(**result)


@router.get("/status", response_model=StatusResponse)
async def get_status(admin: dict = Depends(require_admin)):
    """
    Get current status of remote VPN access. **Requires admin authentication.**
    
    Returns:
    - enabled: Whether remote access was enabled via this API
    - tailscale_running: Whether Tailscale daemon is actually connected
    - lan_cidr: Detected or last-used LAN CIDR
    - tailscale_ips: List of Tailscale IP addresses
    - advertised_routes: Routes being advertised
    - exit_node_advertised: Whether exit node is advertised
    - hostname: Tailscale hostname
    - tailnet: Tailnet name
    - last_error: Last error message if any
    """
    service = get_tailscale_service()
    status = await asyncio.to_thread(service.get_status)
    
    return StatusResponse(**status.to_dict())


@router.get("/config", response_model=ConfigResponse)
async def get_config(admin: dict = Depends(require_admin)):
    """
    Get current configuration. **Requires admin authentication.**
    Returns whether auth key is configured.
    """
    service = get_tailscale_service()
    # Check if authkey exists and is not empty
    authkey = await asyncio.to_thread(service._get_authkey)
    has_authkey = bool(authkey and authkey.strip())
    return ConfigResponse(
        has_authkey=has_authkey,
        interface=service.config.interface
    )


@router.post("/config", response_model=SaveAuthkeyResponse)
async def save_authkey(
    request: SaveAuthkeyRequest,
    admin: dict = Depends(require_admin)
):
    """
    Save Tailscale auth key to config. **Requires admin authentication.**
    
    **Security**: Auth key is validated and securely stored.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    service = get_tailscale_service()
    result = await asyncio.to_thread(service.save_authkey, request.authkey)
    _record_tailscale_event(
        action_id="tailscale.authkey.save",
        title="Save Tailscale auth key",
        status="success" if result.get("success") else "failed",
        message=result.get("error", {}).get("details") or result.get("error", {}).get("message") or "Saved Tailscale auth key",
        started_at=started_at,
    )
    return SaveAuthkeyResponse(**result)


@router.get("/install-status", response_model=InstallStatusResponse)
async def get_install_status(admin: dict = Depends(require_admin)):
    """
    Check if Tailscale is installed. **Requires admin authentication.**
    """
    service = get_tailscale_service()
    install_status = await asyncio.to_thread(service.get_install_status)
    return InstallStatusResponse(**install_status)


@router.post("/install", response_model=InstallResponse)
async def install_tailscale(admin: dict = Depends(require_admin)):
    """
    Install Tailscale on the system. **Requires admin authentication.**
    
    Uses the official Tailscale install script.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    service = get_tailscale_service()
    result = await service.install_tailscale()
    _record_tailscale_event(
        action_id="tailscale.install",
        title="Install Tailscale",
        status="success" if result.get("success") else "failed",
        message=result.get("message") or result.get("error", {}).get("details") or "Install Tailscale finished",
        started_at=started_at,
    )
    return InstallResponse(**result)


@router.post("/uninstall", response_model=UninstallResponse)
async def uninstall_tailscale(admin: dict = Depends(require_admin)):
    """
    Uninstall Tailscale from the system. **Requires admin authentication.**
    """
    started_at = datetime.now(timezone.utc).isoformat()
    service = get_tailscale_service()
    result = await service.uninstall_tailscale()
    _record_tailscale_event(
        action_id="tailscale.uninstall",
        title="Uninstall Tailscale",
        status="success" if result.get("success") else "failed",
        message=result.get("message") or result.get("error", {}).get("details") or "Uninstall Tailscale finished",
        started_at=started_at,
    )
    return UninstallResponse(**result)
