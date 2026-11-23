"""
EasyPi Native Network Scanner
============================

A secure, native Python network scanner designed for home/small office LANs.
Optimized for EasyPi with better performance and IoT device awareness.

Security Features:
- Input validation (private networks only, bounded ranges)
- No shell commands (pure Python sockets)
- Rate limiting to prevent network flooding
- Timeout protection on all operations
- Audit logging for all scan activities
- Sandboxed to local network only

License: Proprietary (EasyPi)
Author: EasyPi Team
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List, Dict, Tuple
from datetime import datetime
import gzip
import hashlib
import os
import secrets
import shutil

logger = logging.getLogger(__name__)


def resolve_arp_scan_binary() -> Optional[str]:
    """Find arp-scan even when a hardened service PATH omits sbin directories."""
    located = shutil.which("arp-scan")
    if located:
        return located
    for candidate in ("/usr/local/sbin/arp-scan", "/usr/sbin/arp-scan"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


# ============================================================================
# SECURITY CONSTANTS
# ============================================================================

# Maximum hosts per scan (DoS protection)
MAX_HOSTS_PER_SCAN = 1024

# Maximum ports per scan
MAX_PORTS_PER_SCAN = 1000

# Maximum concurrent connections (network flood protection)
MAX_CONCURRENT_CONNECTIONS = 50

# Timeouts (seconds)
ARP_TIMEOUT = 2.0
TCP_CONNECT_TIMEOUT = 1.0
BANNER_GRAB_TIMEOUT = 2.0
TOTAL_SCAN_TIMEOUT = 300  # 5 minutes max

# Rate limiting
MIN_SCAN_INTERVAL_MS = 10  # Minimum ms between connection attempts

# Allowed private network ranges (RFC 1918 + link-local)
ALLOWED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # Link-local
]

# Explicitly blocked ranges (even within private)
BLOCKED_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
]


# ============================================================================
# DATA CLASSES
# ============================================================================


class ScanType(Enum):
    """Types of network scans available."""

    HOST_DISCOVERY = "host_discovery"
    PORT_SCAN = "port_scan"
    SERVICE_DETECTION = "service_detection"
    FULL_SCAN = "full_scan"


class HostStatus(Enum):
    """Host online status."""

    ONLINE = "online"
    OFFLINE = "offline"
    FILTERED = "filtered"


class PortState(Enum):
    """Port state."""

    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    """Result of a port scan."""

    port: int
    protocol: str = "tcp"
    state: PortState = PortState.CLOSED
    service: Optional[str] = None
    banner: Optional[str] = None
    version: Optional[str] = None


@dataclass
class HostResult:
    """Result of a host scan."""

    ip: str
    status: HostStatus = HostStatus.OFFLINE
    mac: Optional[str] = None
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    type_confidence: Optional[float] = (
        None  # Confidence score for device_type (0.0-1.0)
    )
    os_guess: Optional[str] = None
    ports: List[PortResult] = field(default_factory=list)
    response_time_ms: Optional[float] = None
    last_seen: Optional[datetime] = None


@dataclass
class ScanResult:
    """Complete scan result."""

    scan_id: str
    network: str
    scan_type: ScanType
    started_at: datetime
    completed_at: Optional[datetime] = None
    hosts: List[HostResult] = field(default_factory=list)
    total_hosts_scanned: int = 0
    hosts_found: int = 0
    error: Optional[str] = None
    warnings: List[str] = field(default_factory=list)


# ============================================================================
# SECURITY VALIDATORS
# ============================================================================


__all__ = [
    "ALLOWED_NETWORKS",
    "ARP_TIMEOUT",
    "BANNER_GRAB_TIMEOUT",
    "BLOCKED_RANGES",
    "Dict",
    "Enum",
    "HostResult",
    "HostStatus",
    "List",
    "MAX_CONCURRENT_CONNECTIONS",
    "MAX_HOSTS_PER_SCAN",
    "MAX_PORTS_PER_SCAN",
    "MIN_SCAN_INTERVAL_MS",
    "Optional",
    "PortResult",
    "PortState",
    "ScanResult",
    "ScanType",
    "TCP_CONNECT_TIMEOUT",
    "TOTAL_SCAN_TIMEOUT",
    "Tuple",
    "asyncio",
    "dataclass",
    "datetime",
    "field",
    "gzip",
    "hashlib",
    "ipaddress",
    "logger",
    "logging",
    "os",
    "re",
    "resolve_arp_scan_binary",
    "secrets",
    "shutil",
    "socket",
    "time",
]
