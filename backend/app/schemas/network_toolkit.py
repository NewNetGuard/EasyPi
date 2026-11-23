from __future__ import annotations

import re
from datetime import datetime
from app.utils.time import utc_now
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


# Shared enums
DeviceStatus = Literal["online", "offline", "limited"]
PortStatus = Literal["open", "closed", "filtered"]
RiskLevel = Literal["low", "medium", "high", "critical"]
# DeviceType includes all types from native_scanner.py get_device_type_hint()
DeviceType = Literal[
    "computer", "phone", "printer", "router", "tv", "console", "pi",
    "nas", "sbc", "iot", "smart-tv", "smart-speaker", "network",
    "gaming", "apple", "google", "virtual", "camera", "tablet",
    "server", "media", "unknown"
]
ConnectionState = Literal["ESTABLISHED", "LISTENING", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECEIVED"]
LayoutType = Literal["radial", "hierarchical", "force-directed", "grid"]


class NetworkApiResponse(BaseModel):
    """Unified response wrapper for Network Toolkit endpoints."""

    model_config = ConfigDict(populate_by_name=True)

    success: bool
    data: Any | None = None
    error: str | None = None
    timestamp: datetime = Field(default_factory=utc_now)


# LAN Scanner
class LANScanConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    networkRange: str = Field(min_length=7, max_length=18)  # e.g. "1.1.1.0/8" to "192.168.178.0/24"
    scanSpeed: Literal["fast", "normal", "deep"] = Field(default="normal")
    detectVendor: bool = Field(default=True)
    resolveHostnames: bool = Field(default=True)
    portDiscovery: bool = Field(default=True)  # Enabled by default for better device type detection

    @field_validator('networkRange')
    @classmethod
    def validate_network_range(cls, v: str) -> str:
        """Validate CIDR notation format."""
        # Must match pattern like 192.168.1.0/24
        pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if not re.match(pattern, v):
            raise ValueError('Invalid network range format. Use CIDR notation (e.g., 192.168.1.0/24)')
        # Additional validation for IP octets
        ip_part, prefix = v.rsplit('/', 1)
        octets = ip_part.split('.')
        for octet in octets:
            if int(octet) > 255:
                raise ValueError(f'Invalid IP octet: {octet}')
        if int(prefix) > 32 or int(prefix) < 8:
            raise ValueError('Prefix must be between /8 and /32')
        return v


class LANDevice(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    customName: str | None = None
    status: DeviceStatus = "online"
    lastSeen: datetime
    ports: list[int] | None = None
    deviceType: DeviceType | None = None
    dhcpVendorClass: str | None = None
    identitySources: list[str] = Field(default_factory=list)
    identityConfidence: float | None = Field(default=None, ge=0, le=1)
    interfaces: list[dict[str, str]] = Field(default_factory=list)
    isLocalDevice: bool = False


class LANScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    devices: list[LANDevice]
    scanTime: float
    networkRange: str
    timestamp: datetime


# Port Scanner
class PortScanConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    targetHost: str = Field(min_length=7, max_length=253)  # IP or hostname
    portRange: str = Field(default="1-1000", max_length=50)
    scanType: Literal["tcp-syn", "tcp-connect", "udp"] = Field(default="tcp-connect")
    timeout: int = Field(default=60, ge=10, le=600)  # Timeout in seconds (10s - 10min)

    @field_validator('targetHost')
    @classmethod
    def validate_target_host(cls, v: str) -> str:
        """Validate target is IP or valid hostname."""
        # Check if it's an IP address
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
        
        if re.match(ip_pattern, v):
            # Validate IP octets
            for octet in v.split('.'):
                if int(octet) > 255:
                    raise ValueError(f'Invalid IP octet: {octet}')
        elif not re.match(hostname_pattern, v):
            raise ValueError('Invalid target host. Use IP address or hostname.')
        
        # Block obviously dangerous inputs
        if any(char in v for char in [';', '|', '&', '$', '`', '\n', '\r']):
            raise ValueError('Invalid characters in target host')
        return v

    @field_validator('portRange')
    @classmethod
    def validate_port_range(cls, v: str) -> str:
        """Validate port range format."""
        # Allowed: "1-1000", "22,80,443", "22", "1-100,443,8080"
        pattern = r'^[\d,\-\s]+$'
        if not re.match(pattern, v):
            raise ValueError('Invalid port range format. Use: "1-1000", "22,80,443", or combinations')
        return v


class PortInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    port: int
    protocol: Literal["TCP", "UDP"]
    status: PortStatus
    service: str | None = None
    riskLevel: RiskLevel = "low"
    description: str | None = None
    version: str | None = None


class PortScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    host: str
    ports: list[PortInfo]
    scanTime: float
    timestamp: datetime
    openCount: int
    closedCount: int
    filteredCount: int


# Speed Test
class SpeedTestServer(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    name: str
    location: str
    country: str
    distance: float


class SpeedTestResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    download: float
    upload: float
    ping: float
    jitter: float
    server: SpeedTestServer
    timestamp: datetime
    isp: str | None = None
    ipAddress: str | None = None


class SpeedTestConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    serverId: str | None = None
    testDownload: bool = Field(default=True)
    testUpload: bool = Field(default=True)
    testPing: bool = Field(default=True)
    testJitter: bool = Field(default=True)


# Network Map
class NetworkNode(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    label: str
    ip: str
    mac: str | None = None
    type: DeviceType
    status: DeviceStatus
    x: float | None = None
    y: float | None = None


class NetworkEdge(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    from_: str = Field(alias="from")
    to: str
    bandwidth: float | None = None
    latency: float | None = None
    traffic: float | None = None


class NetworkMapData(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    nodes: list[NetworkNode]
    edges: list[NetworkEdge]
    layout: LayoutType


class NetworkMapConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    layoutType: LayoutType = Field(default="force-directed")
    showIPs: bool = Field(default=True)
    showNames: bool = Field(default=True)
    showSpeed: bool = Field(default=False)
    showTraffic: bool = Field(default=False)


# Traffic
class TrafficData(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime
    download: float
    upload: float


class TrafficStats(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    currentDownload: float
    currentUpload: float
    totalReceived: int
    totalSent: int
    peakDownload: float
    peakUpload: float


# Active Connections
class ConnectionFilters(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    protocol: Literal["TCP", "UDP"] | None = None
    state: ConnectionState | None = None
    process: str | None = None
    search: str | None = None


class ActiveConnection(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    localAddress: str
    localPort: int
    remoteAddress: str | None
    remotePort: int | None
    protocol: Literal["TCP", "UDP"]
    state: ConnectionState
    processName: str | None = None
    pid: int | None = None


# ARP Scanner
class ARPEntry(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    ip: str
    mac: str
    vendor: str | None = None
    interface: str | None = None
    type: Literal["dynamic", "static"] = "dynamic"
    state: str | None = None  # REACHABLE, STALE, DELAY, etc.
    isNew: bool | None = None


class ARPScanResult(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    entries: list[ARPEntry]
    timestamp: datetime


# Port Alerts
class PortAlert(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    id: str
    port: int
    service: str | None
    protocol: Literal["TCP", "UDP"] = "TCP"
    riskLevel: RiskLevel
    description: str
    recommendation: str
    isMonitored: bool
    lastDetected: datetime


class PortAlertConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    enabled: bool = Field(default=True)
    monitoredPorts: list[int] = Field(default_factory=list)
    checkInterval: int = Field(default=5, ge=1, le=60)
    notifyOnNew: bool = Field(default=True)


__all__ = [
    "NetworkApiResponse",
    "LANScanConfig",
    "LANDevice",
    "LANScanResult",
    "PortScanConfig",
    "PortInfo",
    "PortScanResult",
    "SpeedTestServer",
    "SpeedTestResult",
    "SpeedTestConfig",
    "NetworkNode",
    "NetworkEdge",
    "NetworkMapData",
    "NetworkMapConfig",
    "TrafficData",
    "TrafficStats",
    "ConnectionFilters",
    "ActiveConnection",
    "ARPEntry",
    "ARPScanResult",
    "PortAlert",
    "PortAlertConfig",
    "DeviceType",
    "DeviceStatus",
    "RiskLevel",
    "PortStatus",
    "ConnectionState",
    "LayoutType",
]
