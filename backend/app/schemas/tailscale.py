"""
Tailscale Remote Access Schemas
"""
from datetime import datetime
from enum import Enum
from typing import Optional, List
from pydantic import BaseModel, Field


class TailscaleStatus(str, Enum):
    """Tailscale connection status"""
    NOT_INSTALLED = "not_installed"
    STOPPED = "stopped"
    NEEDS_LOGIN = "needs_login"
    RUNNING = "running"
    CONNECTED = "connected"


class SubnetRoute(BaseModel):
    """Subnet route configuration"""
    cidr: str = Field(..., description="CIDR notation, e.g., 192.168.1.0/24")
    enabled: bool = True
    approved: bool = False


class TailscalePeer(BaseModel):
    """Connected peer/device info"""
    id: str
    hostname: str
    dns_name: Optional[str] = None
    tailscale_ip: str
    os: Optional[str] = None
    online: bool
    last_seen: Optional[datetime] = None
    is_exit_node: bool = False
    is_external: bool = False  # External (shared) device


class TailscaleInfo(BaseModel):
    """Current Tailscale status and configuration"""
    status: TailscaleStatus
    version: Optional[str] = None
    hostname: Optional[str] = None
    tailscale_ip: Optional[str] = None
    tailnet_name: Optional[str] = None
    dns_name: Optional[str] = None
    is_subnet_router: bool = False
    is_exit_node: bool = False
    advertised_routes: List[str] = Field(default_factory=list)
    magic_dns_enabled: bool = False
    funnel_enabled: bool = False
    peers: List[TailscalePeer] = Field(default_factory=list)
    login_url: Optional[str] = None
    expires_at: Optional[datetime] = None


class TailscaleInstallRequest(BaseModel):
    """Request to install Tailscale"""
    auth_key: Optional[str] = Field(None, description="Pre-auth key for headless setup")


class TailscaleSetupRequest(BaseModel):
    """Request to configure Tailscale as subnet router"""
    auth_key: Optional[str] = Field(None, description="Auth key (optional if already logged in)")
    advertise_routes: List[str] = Field(
        default_factory=lambda: ["192.168.0.0/24"],
        description="Subnets to advertise (e.g., your local network)"
    )
    accept_routes: bool = Field(True, description="Accept routes from other nodes")
    enable_exit_node: bool = Field(False, description="Act as exit node")
    hostname: Optional[str] = Field(None, description="Custom hostname for this device")


class TailscaleLoginResponse(BaseModel):
    """Response with login URL for browser auth"""
    login_url: str
    message: str = "Open this URL to authenticate"


class FunnelConfig(BaseModel):
    """Tailscale Funnel configuration"""
    enabled: bool = False
    port: int = Field(443, description="Local port to expose")
    funnel_url: Optional[str] = None  # e.g., https://easypi.tail1234.ts.net


class TailscaleConfigUpdate(BaseModel):
    """Update Tailscale configuration"""
    advertise_routes: Optional[List[str]] = None
    accept_routes: Optional[bool] = None
    enable_exit_node: Optional[bool] = None
    enable_funnel: Optional[bool] = None
    funnel_port: Optional[int] = None


class AuthKeyInfo(BaseModel):
    """Information about generating auth keys"""
    instructions: str
    console_url: str = "https://login.tailscale.com/admin/settings/keys"
    key_types: List[dict] = Field(
        default_factory=lambda: [
            {"type": "reusable", "description": "Can be used multiple times"},
            {"type": "ephemeral", "description": "Device auto-removed when offline"},
            {"type": "pre-approved", "description": "Subnet routes auto-approved"},
        ]
    )


class NetworkInfo(BaseModel):
    """Local network information for subnet router setup"""
    interface: str
    ip_address: str
    netmask: str
    cidr: str
    gateway: Optional[str] = None
    is_default: bool = False
