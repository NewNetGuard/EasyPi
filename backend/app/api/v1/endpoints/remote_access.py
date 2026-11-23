"""
Remote Access API Endpoints (Tailscale Subnet Router)

Provides endpoints for:
- Installing and configuring Tailscale
- Setting up EasyPi as a subnet router (VPN gateway)
- Managing connected peers
- Enabling Funnel for public access

SECURITY: All endpoints require admin authentication as they execute
privileged system commands (sudo install, tailscale login, etc.)
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional, List
from fastapi import APIRouter, HTTPException, status, Depends

from app.api.deps import require_admin
from app.models.user import User
from app.schemas.tailscale import (
    TailscaleInfo,
    TailscaleInstallRequest,
    TailscaleSetupRequest,
    TailscaleLoginResponse,
    TailscaleConfigUpdate,
    AuthKeyInfo,
    NetworkInfo,
)
from app.services.operation_event_service import OperationEventService
from app.services.remote_access.tailscale_service import get_tailscale_service

router = APIRouter()
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()
tailscale_service = get_tailscale_service()


def _record_remote_access_event(
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
            route="/remote-access",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record remote access event %s: %s", action_id, exc)


def _validate_auth_key(auth_key: Optional[str]) -> Optional[str]:
    """Validate Tailscale auth key format."""
    if auth_key is None:
        return None
    auth_key = auth_key.strip()
    if not auth_key:
        return None
    # Auth key must start with tskey- and contain only alphanumeric + hyphens
    if not re.match(r'^tskey-[a-zA-Z0-9\-]+$', auth_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid auth key format. Must start with 'tskey-'"
        )
    if len(auth_key) < 20 or len(auth_key) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Auth key length invalid"
        )
    return auth_key


def _validate_routes(routes: Optional[List[str]]) -> Optional[List[str]]:
    """Validate CIDR routes format."""
    if not routes:
        return routes
    validated = []
    for route in routes:
        # Basic CIDR validation
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$', route):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid CIDR format: {route}"
            )
        # Validate octets
        parts = route.split('/')[0].split('.')
        for part in parts:
            if int(part) > 255:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid IP in route: {route}"
                )
        # Validate prefix
        prefix = int(route.split('/')[1])
        if prefix > 32:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid prefix in route: {route}"
            )
        validated.append(route)
    return validated


@router.get("/status", response_model=TailscaleInfo)
async def get_status(_admin: User = Depends(require_admin)):
    """
    Get current Tailscale status and configuration.
    
    Returns connection status, advertised routes, connected peers, etc.
    """
    return await tailscale_service.get_detailed_status()


@router.get("/networks", response_model=List[NetworkInfo])
async def get_local_networks(_admin: User = Depends(require_admin)):
    """
    Detect local networks available for subnet routing.
    
    Returns list of network interfaces with their CIDR notations.
    Use these values for the advertise_routes parameter in setup.
    """
    return await tailscale_service.get_local_networks()


@router.post("/install")
async def install_tailscale(
    request: TailscaleInstallRequest = None,
    _admin: User = Depends(require_admin)
):
    """
    Install Tailscale on the system.
    
    Downloads and installs Tailscale using the official install script.
    """
    success, message = await tailscale_service.install()
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    return {"success": True, "message": message}


@router.post("/login", response_model=TailscaleLoginResponse)
async def login(
    auth_key: Optional[str] = None,
    _admin: User = Depends(require_admin)
):
    """
    Login to Tailscale.
    
    If auth_key is provided, performs headless authentication.
    Otherwise, returns a login URL to open in browser.
    
    To get an auth key:
    1. Go to https://login.tailscale.com/admin/settings/keys
    2. Generate a new auth key (reusable + pre-approved for subnet routes)
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate auth key if provided
    validated_key = _validate_auth_key(auth_key)
    
    success, message, login_url = await tailscale_service.login(validated_key)
    
    if not success and not login_url:
        _record_remote_access_event(
            action_id="remote-access.login",
            title="Start Tailscale login",
            subtitle="Remote Access · Tailscale authentication",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )

    display_message = message
    if login_url:
        display_message = f"{message} Login URL ready for approval."
    _record_remote_access_event(
        action_id="remote-access.login",
        title="Start Tailscale login",
        subtitle="Remote Access · Tailscale authentication",
        status="success",
        message=display_message,
        started_at=started_at,
    )
    
    return TailscaleLoginResponse(
        login_url=login_url or "",
        message=message,
    )


@router.post("/setup")
async def setup_subnet_router(
    request: TailscaleSetupRequest,
    _admin: User = Depends(require_admin)
):
    """
    Configure EasyPi as a Tailscale Subnet Router.
    
    This is the main feature that enables:
    - Unlimited clients to connect via EasyPi
    - Access to entire local network through VPN
    - No port forwarding needed
    - MagicDNS for easy device names
    
    Example:
    ```json
    {
        "advertise_routes": ["192.168.1.0/24"],
        "accept_routes": true,
        "enable_exit_node": false,
        "hostname": "easypi"
    }
    ```
    
    After setup, you need to approve the routes in Tailscale admin console:
    https://login.tailscale.com/admin/machines
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate inputs
    validated_key = _validate_auth_key(request.auth_key)
    validated_routes = _validate_routes(request.advertise_routes)
    
    success, message, login_url = await tailscale_service.setup_subnet_router(
        routes=validated_routes,
        auth_key=validated_key,
        accept_routes=request.accept_routes,
        exit_node=request.enable_exit_node,
        hostname=request.hostname,
    )

    if not success and not login_url:
        _record_remote_access_event(
            action_id="remote-access.setup",
            title="Configure subnet router",
            subtitle="Remote Access · Tailscale routing",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )

    display_message = message
    if login_url:
        display_message = f"{message} Open the Tailscale login URL to continue."
    _record_remote_access_event(
        action_id="remote-access.setup",
        title="Configure subnet router",
        subtitle="Remote Access · Tailscale routing",
        status="success",
        message=display_message,
        started_at=started_at,
    )

    return {
        "success": True,
        "message": message,
        "login_url": login_url,
        "next_steps": [
            "Open Tailscale admin console: https://login.tailscale.com/admin/machines",
            "Find your EasyPi device and click on it",
            "Enable the advertised subnet routes",
            "Install Tailscale on your phone/laptop",
            "Connect to the same Tailnet",
            "Access your local network from anywhere!",
        ] if success else None,
    }


@router.patch("/config")
async def update_config(
    request: TailscaleConfigUpdate,
    _admin: User = Depends(require_admin)
):
    """
    Update Tailscale configuration.
    
    Allows changing advertised routes, exit node status, etc.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate routes
    validated_routes = _validate_routes(request.advertise_routes)
    
    success, message = await tailscale_service.update_config(
        advertise_routes=validated_routes,
        accept_routes=request.accept_routes,
        exit_node=request.enable_exit_node,
    )

    if not success:
        _record_remote_access_event(
            action_id="remote-access.update-config",
            title="Update Tailscale settings",
            subtitle="Remote Access · Tailscale routing",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )

    _record_remote_access_event(
        action_id="remote-access.update-config",
        title="Update Tailscale settings",
        subtitle="Remote Access · Tailscale routing",
        status="success",
        message=message,
        started_at=started_at,
    )

    return {"success": True, "message": message}


@router.post("/start")
async def start_tailscale(_admin: User = Depends(require_admin)):
    """Start Tailscale connection"""
    started_at = datetime.now(timezone.utc).isoformat()
    success, message = await tailscale_service.start()
    if not success:
        _record_remote_access_event(
            action_id="remote-access.start",
            title="Start Tailscale",
            subtitle="Remote Access · Tailscale runtime",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    _record_remote_access_event(
        action_id="remote-access.start",
        title="Start Tailscale",
        subtitle="Remote Access · Tailscale runtime",
        status="success",
        message=message,
        started_at=started_at,
    )
    return {"success": True, "message": message}


@router.post("/stop")
async def stop_tailscale(_admin: User = Depends(require_admin)):
    """Stop Tailscale connection (keeps logged in)"""
    started_at = datetime.now(timezone.utc).isoformat()
    success, message = await tailscale_service.stop()
    if not success:
        _record_remote_access_event(
            action_id="remote-access.stop",
            title="Stop Tailscale",
            subtitle="Remote Access · Tailscale runtime",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    _record_remote_access_event(
        action_id="remote-access.stop",
        title="Stop Tailscale",
        subtitle="Remote Access · Tailscale runtime",
        status="success",
        message=message,
        started_at=started_at,
    )
    return {"success": True, "message": message}


@router.post("/logout")
async def logout(_admin: User = Depends(require_admin)):
    """Logout from Tailscale (removes device from tailnet)"""
    started_at = datetime.now(timezone.utc).isoformat()
    success, message = await tailscale_service.logout()
    if not success:
        _record_remote_access_event(
            action_id="remote-access.logout",
            title="Logout from Tailscale",
            subtitle="Remote Access · Tailscale authentication",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    _record_remote_access_event(
        action_id="remote-access.logout",
        title="Logout from Tailscale",
        subtitle="Remote Access · Tailscale authentication",
        status="success",
        message=message,
        started_at=started_at,
    )
    return {"success": True, "message": message}


@router.post("/funnel/enable")
async def enable_funnel(port: int = 443, _admin: User = Depends(require_admin)):
    """
    Enable Tailscale Funnel.
    
    Funnel exposes your service to the public internet via Tailscale's HTTPS proxy.
    This gives you a public URL like: https://easypi.tail12345.ts.net
    
    No port forwarding, no dynamic DNS, automatic HTTPS certificate!
    """
    started_at = datetime.now(timezone.utc).isoformat()
    # Validate port range
    if not (1 <= port <= 65535):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid port number (must be 1-65535)",
        )
    
    success, message, funnel_url = await tailscale_service.setup_funnel(port)
    if not success:
        _record_remote_access_event(
            action_id="remote-access.funnel-enable",
            title="Enable Tailscale Funnel",
            subtitle="Remote Access · Public access",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    display_message = message if not funnel_url else f"{message}: {funnel_url}"
    _record_remote_access_event(
        action_id="remote-access.funnel-enable",
        title="Enable Tailscale Funnel",
        subtitle="Remote Access · Public access",
        status="success",
        message=display_message,
        started_at=started_at,
    )
    return {
        "success": True,
        "message": message,
        "funnel_url": funnel_url,
    }


@router.post("/funnel/disable")
async def disable_funnel(_admin: User = Depends(require_admin)):
    """Disable Tailscale Funnel"""
    started_at = datetime.now(timezone.utc).isoformat()
    success, message = await tailscale_service.disable_funnel()
    if not success:
        _record_remote_access_event(
            action_id="remote-access.funnel-disable",
            title="Disable Tailscale Funnel",
            subtitle="Remote Access · Public access",
            status="failed",
            message=message,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    _record_remote_access_event(
        action_id="remote-access.funnel-disable",
        title="Disable Tailscale Funnel",
        subtitle="Remote Access · Public access",
        status="success",
        message=message,
        started_at=started_at,
    )
    return {"success": True, "message": message}


@router.delete("/uninstall")
async def uninstall_tailscale(_admin: User = Depends(require_admin)):
    """Uninstall Tailscale from the system"""
    success, message = await tailscale_service.uninstall()
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message,
        )
    return {"success": True, "message": message}


@router.get("/auth-key-info", response_model=AuthKeyInfo)
async def get_auth_key_info(_admin: User = Depends(require_admin)):
    """
    Get information about how to create Tailscale auth keys.
    
    Auth keys allow headless (non-interactive) setup.
    """
    return AuthKeyInfo(
        instructions="""
To create a Tailscale auth key:

1. Go to https://login.tailscale.com/admin/settings/keys
2. Click "Generate auth key"
3. Recommended settings:
   - ✓ Reusable (if you might reinstall)
   - ✓ Pre-approved (auto-approve subnet routes)
   - Expiration: 90 days
4. Copy the key (starts with 'tskey-auth-...')
5. Paste it in the setup form

Alternatively, you can login without an auth key by opening the login URL in your browser.
        """.strip(),
        console_url="https://login.tailscale.com/admin/settings/keys",
    )
