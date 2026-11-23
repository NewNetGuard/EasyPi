from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime
from app.utils.time import utc_now
from pathlib import Path

import psutil

try:
    import netifaces
except ImportError:  # pragma: no cover - optional in local Windows test envs
    netifaces = None

from app.schemas.network_toolkit import (
    ARPEntry,
    ARPScanResult,
    ActiveConnection,
    ConnectionFilters,
    LANDevice,
    LANScanConfig,
    LANScanResult,
    NetworkApiResponse,
    NetworkEdge,
    NetworkMapConfig,
    NetworkMapData,
    NetworkNode,
    PortAlert,
    PortAlertConfig,
    PortInfo,
    PortScanConfig,
    PortScanResult,
    RiskLevel,
    SpeedTestConfig,
    SpeedTestResult,
    SpeedTestServer,
    TrafficData,
    TrafficStats,
)
from app.schemas.network import NetworkHost
from app.services.dhcp_identity import load_dhcp_identities
from app.services.network_tools import NetworkToolError, NetworkToolsService

# Import native network scanner
from app.services.native_scanner import (
    native_scanner,
    HostStatus,
    PortState,
    OUIDatabase,
    resolve_arp_scan_binary,
)

logger = logging.getLogger(__name__)

# Valid device types from DeviceType Literal
VALID_DEVICE_TYPES = {
    "computer",
    "phone",
    "printer",
    "router",
    "tv",
    "console",
    "pi",
    "nas",
    "sbc",
    "iot",
    "smart-tv",
    "smart-speaker",
    "network",
    "gaming",
    "apple",
    "google",
    "virtual",
    "camera",
    "tablet",
    "server",
    "media",
    "unknown",
}

# XSS/HTML injection pattern
_XSS_PATTERN = re.compile(r'[<>&"\'/\\]')


def _sanitize_string(value: str | None, max_length: int = 256) -> str | None:
    """
    Sanitize string to prevent XSS attacks.
    Removes HTML special characters and limits length.
    """
    if not value:
        return None
    # Remove HTML/script special characters
    value = _XSS_PATTERN.sub("", value)
    # Remove control characters
    value = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", value)
    # Limit length
    if len(value) > max_length:
        value = value[:max_length]
    return value.strip() or None


def _normalize_device_type(device_type: str | None) -> str | None:
    """Normalize device_type to valid DeviceType enum value."""
    if not device_type:
        return None
    device_type = device_type.lower().strip()
    if device_type in VALID_DEVICE_TYPES:
        return device_type
    # Map common aliases
    type_mapping = {
        "smart_tv": "smart-tv",
        "smarttv": "smart-tv",
        "smart_speaker": "smart-speaker",
        "smartspeaker": "smart-speaker",
        "game": "gaming",
        "game-console": "gaming",
        "games": "gaming",
        "raspberry": "sbc",
        "raspberrypi": "sbc",
        "raspberry-pi": "sbc",
        "raspberry_pi": "sbc",
        "single-board": "sbc",
        "iot-device": "iot",
        "smart-home": "iot",
        "smarthome": "iot",
        "switch": "network",
        "access-point": "network",
        "ap": "network",
        "modem": "router",
        "gateway": "router",
        "firewall": "network",
        "mobile": "phone",
        "smartphone": "phone",
        "iphone": "apple",
        "ipad": "apple",
        "macbook": "apple",
        "mac": "apple",
        "chromecast": "google",
        "nest": "google",
        "pixel": "google",
        "android-tv": "tv",
        "streaming": "media",
        "plex": "media",
        "kodi": "media",
        "webcam": "camera",
        "ip-camera": "camera",
        "security-camera": "camera",
        "pc": "computer",
        "laptop": "computer",
        "desktop": "computer",
        "workstation": "computer",
        "vm": "virtual",
    }
    return type_mapping.get(device_type, "unknown")


__all__ = [
    "ARPEntry",
    "ARPScanResult",
    "ActiveConnection",
    "ConnectionFilters",
    "HostStatus",
    "LANDevice",
    "LANScanConfig",
    "LANScanResult",
    "NetworkApiResponse",
    "NetworkEdge",
    "NetworkHost",
    "NetworkMapConfig",
    "NetworkMapData",
    "NetworkNode",
    "NetworkToolError",
    "NetworkToolsService",
    "OUIDatabase",
    "Path",
    "PortAlert",
    "PortAlertConfig",
    "PortInfo",
    "PortScanConfig",
    "PortScanResult",
    "PortState",
    "RiskLevel",
    "SpeedTestConfig",
    "SpeedTestResult",
    "SpeedTestServer",
    "TrafficData",
    "TrafficStats",
    "VALID_DEVICE_TYPES",
    "_XSS_PATTERN",
    "_normalize_device_type",
    "_sanitize_string",
    "asyncio",
    "datetime",
    "ipaddress",
    "json",
    "load_dhcp_identities",
    "logger",
    "logging",
    "native_scanner",
    "netifaces",
    "os",
    "psutil",
    "re",
    "resolve_arp_scan_binary",
    "socket",
    "time",
    "utc_now",
]
