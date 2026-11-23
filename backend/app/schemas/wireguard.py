"""
WireGuard Pydantic schemas for request/response models
"""
import ipaddress
import re
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def validate_wireguard_endpoint(value: str) -> str:
    """Return a normalized host:port endpoint or reject malformed input."""
    endpoint = value.strip()
    if endpoint.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", endpoint)
        if not match:
            raise ValueError("Endpoint must use [IPv6]:port format")
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError as exc:
            raise ValueError("Endpoint contains an invalid IPv6 address") from exc
        if address.version != 6:
            raise ValueError("Bracketed endpoint must contain an IPv6 address")
        host = f"[{address.compressed}]"
        port_text = match.group(2)
    else:
        if endpoint.count(":") != 1:
            raise ValueError("Endpoint must include one port separator")
        host, port_text = endpoint.rsplit(":", 1)
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not _HOSTNAME_RE.fullmatch(host):
                raise ValueError("Endpoint contains an invalid host") from None
        else:
            if address.version != 4:
                raise ValueError("IPv6 endpoints must use [IPv6]:port format")
            host = str(address)

    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("Endpoint port must be a number") from exc
    if not 1 <= port <= 65535:
        raise ValueError("Endpoint port must be between 1 and 65535")
    return f"{host}:{port}"


class WireGuardInstallRequest(BaseModel):
    """Request model for WireGuard installation"""
    port: int = Field(default=51820, ge=1024, le=65535, description="UDP port for WireGuard")
    cidr: str = Field(default="10.8.0.0/24", description="Subnet CIDR for VPN network")
    dns: str = Field(default="1.1.1.1", description="DNS server for clients")
    endpoint: str = Field(..., description="Public endpoint (IP or domain:port)")
    
    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, v):
        """Validate CIDR format"""
        try:
            network = ipaddress.ip_network(v.strip(), strict=True)
        except ValueError as exc:
            raise ValueError("CIDR must be an IPv4 /24 network address") from exc
        if network.version != 4 or network.prefixlen != 24:
            raise ValueError("CIDR must be an IPv4 /24 network address")
        return str(network)
    
    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, v):
        """Validate endpoint format"""
        if not v or not v.strip():
            raise ValueError("Endpoint is required")
        return validate_wireguard_endpoint(v)
    
    @field_validator("dns")
    @classmethod
    def validate_dns(cls, v):
        """Validate DNS server"""
        dns_servers = [item.strip() for item in v.split(",")]
        if not dns_servers or len(dns_servers) > 4 or any(not item for item in dns_servers):
            raise ValueError("DNS must contain one to four IPv4 addresses")
        normalized = []
        for dns in dns_servers:
            try:
                address = ipaddress.ip_address(dns)
            except ValueError as exc:
                raise ValueError(f"Invalid DNS server: {dns}") from exc
            if address.version != 4:
                raise ValueError("DNS servers must be IPv4 addresses")
            normalized.append(str(address))
        return ",".join(normalized)


class WireGuardPeerRequest(BaseModel):
    """Request model for adding a WireGuard peer"""
    name: str = Field(..., min_length=1, max_length=32, description="Peer name/identifier")
    allowed: str = Field(default="0.0.0.0/0", description="Allowed IPs for peer (comma-separated)")
    
    @field_validator("name")
    @classmethod
    def validate_name(cls, v):
        """Validate peer name contains only safe characters"""
        pattern = r'^[a-zA-Z0-9._-]{1,32}$'
        if not re.match(pattern, v):
            raise ValueError(
                'Invalid peer name. Only alphanumeric characters, dots, underscores, '
                'and hyphens are allowed (max 32 chars)'
            )
        return v

    @field_validator("allowed")
    @classmethod
    def validate_allowed(cls, value):
        networks = [item.strip() for item in value.split(",")]
        if not networks or len(networks) > 32 or any(not item for item in networks):
            raise ValueError("Allowed IPs must contain one to 32 networks")
        normalized = []
        for item in networks:
            try:
                normalized.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError as exc:
                raise ValueError(f"Invalid AllowedIPs network: {item}") from exc
        return ",".join(normalized)


class WireGuardPeer(BaseModel):
    """Model representing a WireGuard peer"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "iphone-newnetguard",
                "address": "10.8.0.2/32",
                "public_key": "J1m...",
                "created_at": "2025-11-11T10:00:00Z",
                "rx_bytes": 123456,
                "tx_bytes": 789012,
                "latest_handshake": "2025-11-10T09:00:00Z"
            }
        }
    )

    name: str
    address: str
    public_key: str
    created_at: Optional[str] = None
    rx_bytes: Optional[int] = 0
    tx_bytes: Optional[int] = 0
    latest_handshake: Optional[str] = None


class WireGuardPeerResponse(BaseModel):
    """Response model after adding a peer"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "iphone-newnetguard",
                "address": "10.8.0.2/32",
                "download_url": "/api/v1/wireguard/peers/iphone-newnetguard/config",
                "qr_url": "/api/v1/wireguard/peers/iphone-newnetguard/qr"
            }
        }
    )

    name: str
    address: str
    download_url: str
    qr_url: str


class WireGuardStatus(BaseModel):
    """Status response for WireGuard service"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "installed": True,
                "running": True,
                "port": 51820,
                "cidr": "10.8.0.0/24",
                "dns": "1.1.1.1",
                "endpoint": "pi.local:51820",
                "server_public_key": "J1m...",
                "peers": [
                    {
                        "name": "iphone-newnetguard",
                        "address": "10.8.0.2/32",
                        "public_key": "abc123...",
                        "rx_bytes": 123456,
                        "tx_bytes": 789012,
                        "latest_handshake": "2025-11-10T09:00:00Z"
                    }
                ]
            }
        }
    )

    installed: bool
    running: bool
    port: Optional[int] = None
    cidr: Optional[str] = None
    dns: Optional[str] = None
    endpoint: Optional[str] = None
    server_public_key: Optional[str] = None
    peers: List[WireGuardPeer] = Field(default_factory=list)


class TaskResponse(BaseModel):
    """Response for task-based operations (install, restart)"""
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "123e4567-e89b-12d3-a456-426614174000",
                "status": "started",
                "websocket_url": "/ws/tasks/123e4567-e89b-12d3-a456-426614174000"
            }
        }
    )

    task_id: str
    status: str = "started"
    websocket_url: str
