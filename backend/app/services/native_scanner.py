"""Stable public facade for the native network scanner."""

# ruff: noqa: F401

from app.services.native_scanner_context import (
    ALLOWED_NETWORKS,
    ARP_TIMEOUT,
    BANNER_GRAB_TIMEOUT,
    BLOCKED_RANGES,
    Dict,
    Enum,
    HostResult,
    HostStatus,
    List,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_HOSTS_PER_SCAN,
    MAX_PORTS_PER_SCAN,
    MIN_SCAN_INTERVAL_MS,
    Optional,
    PortResult,
    PortState,
    ScanResult,
    ScanType,
    TCP_CONNECT_TIMEOUT,
    TOTAL_SCAN_TIMEOUT,
    Tuple,
    asyncio,
    dataclass,
    datetime,
    field,
    gzip,
    hashlib,
    ipaddress,
    logger,
    logging,
    os,
    re,
    resolve_arp_scan_binary,
    secrets,
    shutil,
    socket,
    time,
)
from app.services.native_scanner_components.fingerprinter import ServiceFingerprinter
from app.services.native_scanner_components.oui import OUIDatabase
from app.services.native_scanner_components.scanner import NativeNetworkScanner
from app.services.native_scanner_components.security import SecurityValidator

# ============================================================================
# GLOBAL INSTANCE
# ============================================================================

native_scanner = NativeNetworkScanner()


# ============================================================================
# CONVENIENCE FUNCTIONS
# ============================================================================


async def discover_network(network: str) -> ScanResult:
    """Quick host discovery on a network."""
    return await native_scanner.discover_hosts(network)


async def scan_host_ports(ip: str, mode: str = "quick") -> ScanResult:
    """Scan ports on a single host."""
    return await native_scanner.scan_ports(ip, mode=mode)


async def full_network_scan(network: str) -> ScanResult:
    """Full scan: discover hosts + scan ports."""
    return await native_scanner.full_scan(network)
