from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class NetworkHost(BaseModel):
    ip: str = Field(min_length=3)
    mac: str | None = Field(default=None)
    vendor: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    custom_name: str | None = Field(default=None)
    device_type: str | None = Field(default=None)
    type_confidence: float | None = Field(default=None, ge=0, le=1)
    dhcp_vendor_class: str | None = Field(default=None)
    identity_sources: list[str] = Field(default_factory=list)
    identity_confidence: float | None = Field(default=None, ge=0, le=1)
    last_seen_timestamp: float | None = Field(default=None)
    status: Literal["online"] = Field(default="online")


class HostScanResponse(BaseModel):
    network: str
    hosts: list[NetworkHost]


class PortInfo(BaseModel):
    port: int = Field(ge=0)
    protocol: str
    state: str
    service: str | None = Field(default=None)
    service_name: str | None = Field(default=None)
    service_version: str | None = Field(default=None)


class PortScanResponse(BaseModel):
    target: str
    mode: Literal["quick", "full", "deep"]
    ports: list[PortInfo]


class PingResponse(BaseModel):
    target: str
    online: bool
    raw_output: str


class DnsLookupResponse(BaseModel):
    domain: str
    addresses: list[str]
    raw_output: str


class SpeedtestResponse(BaseModel):
    ping_ms: float | None
    download_mbps: float | None
    upload_mbps: float | None

class NetworkMapNode(BaseModel):
    name: str
    ip: str
    status: str | None = Field(default=None)
    mac: str | None = Field(default=None)
    vendor: str | None = Field(default=None)
    role: str | None = Field(default=None)


class NetworkMapResponse(BaseModel):
    nodes: list[NetworkMapNode]


class TrafficSample(BaseModel):
    timestamp: float
    rx_kbps: float
    tx_kbps: float


class TrafficResponse(BaseModel):
    samples: list[TrafficSample]


class ConnectionInfo(BaseModel):
    local: str
    remote: str | None
    protocol: str
    state: str | None
    process: str | None


class ConnectionsResponse(BaseModel):
    connections: list[ConnectionInfo]


class ArpEntry(BaseModel):
    ip: str
    mac: str | None
    vendor: str | None
    interface: str | None
    entry_type: str | None


class ArpResponse(BaseModel):
    entries: list[ArpEntry]


class PortAlert(BaseModel):
    port: int
    service: str | None
    level: Literal["Critical", "Warning", "Info"]
    recommendation: str | None


class PortAlertsResponse(BaseModel):
    alerts: list[PortAlert]


__all__ = [
    "NetworkHost",
    "HostScanResponse",
    "PortInfo",
    "PortScanResponse",
    "PingResponse",
    "DnsLookupResponse",
    "SpeedtestResponse",
    "NetworkMapResponse",
    "NetworkMapNode",
    "TrafficResponse",
    "TrafficSample",
    "ConnectionsResponse",
    "ConnectionInfo",
    "ArpResponse",
    "ArpEntry",
    "PortAlertsResponse",
    "PortAlert",
]
