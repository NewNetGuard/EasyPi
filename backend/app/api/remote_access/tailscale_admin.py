"""
Tailscale Admin API Endpoints

Provides REST endpoints for managing Tailscale settings via Admin API:
- Configure API credentials
- Manage DNS settings (set NetProtection as nameserver)
- Manage devices (approve routes, enable exit node)
"""

import asyncio
import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator
import logging

from app.services.remote_access.tailscale_admin_api import (
    tailscale_admin_api,
)
from app.services.remote_access.tailscale_service import get_tailscale_service
from app.api.deps import require_admin
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger("easypi.tailscale_admin_api")

router = APIRouter(prefix="/remote/tailscale/admin", tags=["Remote Access - Tailscale Admin API"])
operation_event_service = OperationEventService()


# =============================================================================
# Security Validators
# =============================================================================

# Tailscale API key pattern: tskey-api-k... (alphanumeric with dashes)
API_KEY_PATTERN = re.compile(r'^tskey-api-[A-Za-z0-9_-]{16,480}$')

# Tailnet pattern: alphanumeric, dots, dashes (e.g., example.com, tail12345.ts.net)
TAILNET_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]{2,63}$')

# Device ID pattern (Tailscale uses numeric IDs)
DEVICE_ID_PATTERN = re.compile(r'^[A-Za-z0-9_-]{1,128}$')


def _record_tailscale_admin_event(
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
            subtitle="Remote Access · Tailscale Admin",
            route="/remote-access",
            status=status,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        return


def validate_ip_address(ip: str) -> bool:
    """Validate IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Validate CIDR notation (e.g., 192.168.1.0/24)."""
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


# =============================================================================
# Request/Response Schemas with Validation
# =============================================================================

class SetCredentialsRequest(BaseModel):
    """Request to set Tailscale Admin API credentials."""
    api_key: str = Field(..., min_length=26, max_length=490, description="Tailscale API key (tskey-api-...)")
    tailnet: str = Field(..., min_length=1, max_length=64, description="Tailnet name (e.g., tail12345.ts.net) or '-' for default")
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v: str) -> str:
        v = v.strip()
        if not API_KEY_PATTERN.match(v):
            raise ValueError('API key must start with "tskey-api-" and contain only alphanumeric characters and dashes')
        return v
    
    @field_validator('tailnet')
    @classmethod
    def validate_tailnet(cls, v: str) -> str:
        v = v.strip()
        # Allow "-" as special value (uses API key's default tailnet)
        if v == '-':
            return v
        v = v.lower()
        if not TAILNET_PATTERN.match(v):
            raise ValueError('Tailnet must be "-" or contain only alphanumeric characters, dots, and dashes (e.g., tail12345.ts.net)')
        # Prevent path traversal and injection
        if '..' in v or '/' in v or '\\' in v:
            raise ValueError('Invalid tailnet name')
        return v


class CredentialsStatusResponse(BaseModel):
    """Response showing API credentials status."""
    configured: bool
    tailnet: Optional[str] = None
    has_api_key: bool = False


class DNSConfigResponse(BaseModel):
    """DNS configuration response."""
    nameservers: List[str]
    magic_dns: bool
    override_local_dns: bool
    search_paths: List[str]


class SetDNSRequest(BaseModel):
    """Request to set DNS nameservers."""
    nameservers: List[str] = Field(..., min_length=1, max_length=10, description="List of DNS server IPs")
    override_local_dns: bool = Field(default=True, description="Force all clients to use these nameservers")
    magic_dns: bool = Field(default=True, description="Enable MagicDNS for Tailscale hostnames")
    
    @field_validator('nameservers')
    @classmethod
    def validate_nameservers(cls, v: List[str]) -> List[str]:
        validated = []
        for ns in v:
            ns = ns.strip()
            if not validate_ip_address(ns):
                raise ValueError(f'Invalid IP address: {ns}')
            validated.append(ns)
        return validated


class SetupNetProtectionDNSRequest(BaseModel):
    """Request to setup NetProtection as DNS for all Tailscale clients."""
    netprotection_tailscale_ip: Optional[str] = Field(
        default=None,
        description="Tailscale IP of EasyPi NetProtection (auto-detected if not provided)"
    )
    easypi_tailscale_ip: Optional[str] = Field(
        default=None,
        description="Deprecated alias for netprotection_tailscale_ip"
    )
    
    @field_validator('netprotection_tailscale_ip', 'easypi_tailscale_ip')
    @classmethod
    def validate_netprotection_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not validate_ip_address(v):
            raise ValueError(f'Invalid IP address: {v}')
        return v


class DeviceResponse(BaseModel):
    """Device information response."""
    id: str
    name: str
    hostname: str
    user: str
    tailscale_ips: List[str]
    advertised_routes: List[str]
    enabled_routes: List[str]
    is_exit_node: bool
    is_exit_node_enabled: bool
    last_seen: Optional[str] = None
    os: Optional[str] = None


class ApproveRoutesRequest(BaseModel):
    """Request to approve routes for a device."""
    routes: List[str] = Field(..., min_length=1, max_length=50, description="Routes to approve (e.g., ['192.168.1.0/24'])")
    
    @field_validator('routes')
    @classmethod
    def validate_routes(cls, v: List[str]) -> List[str]:
        validated = []
        for route in v:
            route = route.strip()
            try:
                route = str(ipaddress.ip_network(route, strict=True))
            except ValueError:
                raise ValueError(f'Invalid CIDR notation: {route}')
            if route in validated:
                raise ValueError(f'Duplicate route: {route}')
            validated.append(route)
        return validated


class EnableExitNodeRequest(BaseModel):
    """Request to enable/disable exit node."""
    enable: bool = Field(default=True, description="Enable or disable exit node")


# =============================================================================
# Endpoints
# =============================================================================

@router.get("/credentials", response_model=CredentialsStatusResponse)
async def get_credentials_status(admin: dict = Depends(require_admin)):
    """
    Get Tailscale Admin API credentials status.
    
    Returns whether API is configured (does NOT return the actual key).
    """
    tailscale_admin_api.load_config()
    
    return CredentialsStatusResponse(
        configured=tailscale_admin_api.is_configured(),
        tailnet=tailscale_admin_api.config.tailnet,
        has_api_key=bool(tailscale_admin_api.config.api_key),
    )


@router.post("/credentials")
async def set_credentials(
    request: SetCredentialsRequest,
    admin: dict = Depends(require_admin),
):
    """
    Set Tailscale Admin API credentials.
    
    Get your API key from: https://login.tailscale.com/admin/settings/keys
    Your tailnet name is shown in the admin console URL or settings.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        tailscale_admin_api.set_credentials(
            api_key=request.api_key,
            tailnet=request.tailnet,
        )
        
        # Verify credentials by making a test API call
        try:
            await tailscale_admin_api.get_dns_settings()
            _record_tailscale_admin_event(
                action_id="tailscale-admin.credentials.set",
                title="Save Tailscale admin credentials",
                status="success",
                message=f"Credentials verified for tailnet {request.tailnet}",
                started_at=started_at,
            )
            return {
                "success": True,
                "message": "Credentials saved and verified",
                "tailnet": request.tailnet,
            }
        except Exception as e:
            # Credentials saved but verification failed
            logger.warning(f"Credentials saved but verification failed: {e}")
            _record_tailscale_admin_event(
                action_id="tailscale-admin.credentials.set",
                title="Save Tailscale admin credentials",
                status="success",
                message=f"Credentials saved for tailnet {request.tailnet}, but verification failed: {e}",
                started_at=started_at,
            )
            return {
                "success": True,
                "message": "Credentials saved (verification failed - check API key permissions)",
                "tailnet": request.tailnet,
                "warning": str(e),
            }
            
    except Exception as e:
        logger.error(f"Failed to set credentials: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.credentials.set",
            title="Save Tailscale admin credentials",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/credentials")
async def delete_credentials(admin: dict = Depends(require_admin)):
    """Delete saved API credentials."""
    tailscale_admin_api.config.api_key = None
    tailscale_admin_api.config.tailnet = None
    tailscale_admin_api.save_config()
    _record_tailscale_admin_event(
        action_id="tailscale-admin.credentials.delete",
        title="Delete Tailscale admin credentials",
        status="success",
        message="Deleted saved Tailscale admin credentials",
    )
    
    return {"success": True, "message": "Credentials deleted"}


# =============================================================================
# DNS Management
# =============================================================================

@router.get("/dns", response_model=DNSConfigResponse)
async def get_dns_settings(admin: dict = Depends(require_admin)):
    """
    Get current DNS settings for the tailnet.
    """
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        dns = await tailscale_admin_api.get_dns_settings()
        return DNSConfigResponse(
            nameservers=dns.nameservers,
            magic_dns=dns.magic_dns,
            override_local_dns=dns.override_local_dns,
            search_paths=dns.search_paths,
        )
    except Exception as e:
        logger.error(f"Failed to get DNS settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns")
async def set_dns_settings(
    request: SetDNSRequest,
    admin: dict = Depends(require_admin),
):
    """
    Set DNS settings for the tailnet.
    
    This allows you to set your NetProtection as the DNS server
    for all devices in your Tailnet.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        # Set nameservers
        await tailscale_admin_api.set_dns_nameservers(request.nameservers)
        
        # Set preferences
        await tailscale_admin_api.set_dns_preferences(
            magic_dns=request.magic_dns,
            override_local_dns=request.override_local_dns,
        )
        _record_tailscale_admin_event(
            action_id="tailscale-admin.dns.set",
            title="Update Tailscale DNS settings",
            status="success",
            message=f"Updated nameservers to {', '.join(request.nameservers)}",
            started_at=started_at,
        )
        
        return {
            "success": True,
            "nameservers": request.nameservers,
            "override_local_dns": request.override_local_dns,
            "magic_dns": request.magic_dns,
        }
    except Exception as e:
        logger.error(f"Failed to set DNS settings: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.dns.set",
            title="Update Tailscale DNS settings",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns/setup-NetProtection")
async def setup_NetProtection_dns(
    request: SetupNetProtectionDNSRequest,
    admin: dict = Depends(require_admin),
):
    """
    DEPRECATED: Use /dns/setup-netprotection instead.
    
    This endpoint is kept for backward compatibility.
    Redirects to setup_netprotection_dns().
    """
    # Simply redirect to the new endpoint
    return await setup_netprotection_dns(request, admin)


@router.post("/dns/setup-netprotection")
async def setup_netprotection_dns(
    request: SetupNetProtectionDNSRequest,
    admin: dict = Depends(require_admin),
):
    """
    Configure Tailnet to use EasyPi NetProtection for DNS.
    
    This will:
    1. Set your EasyPi's Tailscale IP as the global nameserver
    2. Enable "Override local DNS" so ALL devices use NetProtection
    3. Keep MagicDNS enabled for Tailscale hostnames
    
    All Tailscale-connected devices will automatically:
    - Have ads and trackers blocked
    - Be protected from malware domains
    - Use NetProtection's Shield profiles
    
    If no Tailscale IP is provided, will try to auto-detect.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    # Get EasyPi IP
    netprotection_ip = request.netprotection_tailscale_ip or request.easypi_tailscale_ip
    
    if not netprotection_ip:
        try:
            status = get_tailscale_service().get_status()
            if status.tailscale_ips:
                netprotection_ip = status.tailscale_ips[0]
            else:
                raise HTTPException(
                    status_code=400,
                    detail="Could not auto-detect Tailscale IP. Please provide netprotection_tailscale_ip.",
                )
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Could not auto-detect Tailscale IP: {e}. Please provide netprotection_tailscale_ip.",
            )
    
    try:
        # Use the new NetProtection DNS setup method
        result = await tailscale_admin_api.setup_netprotection_dns(netprotection_ip)
        
        # Add NetProtection-specific info
        result["dns_engine"] = "netprotection"
        result["message"] = (
            f"NetProtection DNS configured! All Tailscale devices will now use "
            f"EasyPi ({netprotection_ip}) for DNS filtering and protection."
        )
        _record_tailscale_admin_event(
            action_id="tailscale-admin.dns.setup-netprotection",
            title="Setup NetProtection DNS for Tailscale",
            status="success",
            message=f"Configured Tailscale DNS to use EasyPi at {netprotection_ip}",
            started_at=started_at,
        )
        
        return result
    except Exception as e:
        logger.error(f"Failed to setup NetProtection DNS: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.dns.setup-netprotection",
            title="Setup NetProtection DNS for Tailscale",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Device Management
# =============================================================================

@router.get("/devices", response_model=List[DeviceResponse])
async def list_devices(admin: dict = Depends(require_admin)):
    """
    List all devices in the tailnet.
    """
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        devices = await tailscale_admin_api.list_devices()
        return [
            DeviceResponse(
                id=d.id,
                name=d.name,
                hostname=d.hostname,
                user=d.user,
                tailscale_ips=d.tailscale_ips,
                advertised_routes=d.advertised_routes,
                enabled_routes=d.enabled_routes,
                is_exit_node=d.is_exit_node,
                is_exit_node_enabled=d.is_exit_node_enabled,
                last_seen=d.last_seen,
                os=d.os,
            )
            for d in devices
        ]
    except Exception as e:
        logger.error(f"Failed to list devices: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/{device_id}/routes")
async def approve_device_routes(
    device_id: str,
    request: ApproveRoutesRequest,
    admin: dict = Depends(require_admin),
):
    """
    Approve (enable) routes for a device.
    
    This allows the device to act as a subnet router,
    giving VPN clients access to the specified networks.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate device_id to prevent injection
    if not DEVICE_ID_PATTERN.match(device_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID format.",
        )
    
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        result = await tailscale_admin_api.approve_routes(device_id, request.routes)
        _record_tailscale_admin_event(
            action_id="tailscale-admin.routes.approve",
            title="Approve Tailscale device routes",
            status="success",
            message=f"Approved routes for device {device_id}: {', '.join(request.routes)}",
            started_at=started_at,
        )
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"Failed to approve routes: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.routes.approve",
            title="Approve Tailscale device routes",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/{device_id}/exit-node")
async def set_device_exit_node(
    device_id: str,
    request: EnableExitNodeRequest,
    admin: dict = Depends(require_admin),
):
    """
    Enable or disable exit node for a device.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate device_id to prevent injection
    if not DEVICE_ID_PATTERN.match(device_id):
        raise HTTPException(
            status_code=400,
            detail="Invalid device ID format.",
        )
    
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        result = await tailscale_admin_api.enable_exit_node(device_id, request.enable)
        _record_tailscale_admin_event(
            action_id="tailscale-admin.exit-node.set",
            title="Update Tailscale exit node",
            status="success",
            message=f"{'Enabled' if request.enable else 'Disabled'} exit node for device {device_id}",
            started_at=started_at,
        )
        return {"success": True, "result": result}
    except Exception as e:
        logger.error(f"Failed to set exit node: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.exit-node.set",
            title="Update Tailscale exit node",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/devices/auto-approve-routes")
async def auto_approve_routes(admin: dict = Depends(require_admin)):
    """
    Approve pending routes only for this EasyPi node.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    tailscale_admin_api.load_config()
    
    if not tailscale_admin_api.is_configured():
        raise HTTPException(
            status_code=400,
            detail="Tailscale Admin API not configured. Set credentials first.",
        )
    
    try:
        local_status = await asyncio.to_thread(get_tailscale_service().get_status)
        if not local_status.tailscale_ips:
            raise HTTPException(
                status_code=409,
                detail="The local EasyPi Tailscale identity is unavailable.",
            )
        result = await tailscale_admin_api.auto_approve_easypi_routes(
            local_status.tailscale_ips
        )
        _record_tailscale_admin_event(
            action_id="tailscale-admin.routes.auto-approve",
            title="Auto-approve EasyPi routes",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message") or result.get("error") or "Auto-approve finished",
            started_at=started_at,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to auto-approve routes: {e}")
        _record_tailscale_admin_event(
            action_id="tailscale-admin.routes.auto-approve",
            title="Auto-approve EasyPi routes",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))
