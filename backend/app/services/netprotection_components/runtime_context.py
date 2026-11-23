"""
Shared, acyclic NetProtection runtime dependencies.


Native DNS-based network protection engine.
Built-in DNS protection service:
- DNS filtering with evidence-based verdicts
- Threat intelligence integration
- Real-time query logging with SQLite persistence
- Device fingerprinting
"""

# ruff: noqa: F401

import logging
import asyncio
import os
import subprocess
import sys
import time
import re
import uuid
import fnmatch
import importlib
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pathlib import Path
import json

from app.core.paths import get_easypi_root, get_netprotection_data_dir
from app.utils.sanitize import sanitize_domain, sanitize_mac as _sanitize_mac

logger = logging.getLogger(__name__)


class DeviceAnomalyStoreError(RuntimeError):
    """Raised when persisted anomaly data cannot be read reliably."""


class ScheduleStoreError(RuntimeError):
    """Raised when parental-control schedules cannot be read or saved safely."""


def sanitize_mac(value: Any) -> str:
    """Canonical internal MAC form used by ARP, profiles, and firewall scripts."""
    return _sanitize_mac(value).lower()


def _short_err(value: str, limit: int = 160) -> str:
    text = (value or "").strip()
    if len(text) > limit:
        return text[:limit].rstrip() + "..."
    return text


# Add netprotection to path
EASYPI_ROOT = get_easypi_root()
sys.path.insert(0, str(EASYPI_ROOT))

from prism_dpi.flowgraph.policy import (  # noqa: E402
    CandidateFlow,
    CandidateLogFollower,
    validate_candidate_event as validate_flowgraph_candidate_event,
)
from prism_dpi.modules.apple_music import AppleMusicFlowPolicy  # noqa: E402
from prism_dpi.modules.dailymotion import DailymotionFlowPolicy  # noqa: E402
from prism_dpi.modules.deezer import DeezerFlowPolicy  # noqa: E402
from prism_dpi.modules.disney import DisneyFlowPolicy  # noqa: E402
from prism_dpi.modules.epicgames import EpicGamesFlowPolicy  # noqa: E402
from prism_dpi.modules.facebook import FacebookFlowPolicy  # noqa: E402
from prism_dpi.modules.google_play import GooglePlayFlowPolicy  # noqa: E402
from prism_dpi.modules.hbo import HboFlowPolicy  # noqa: E402
from prism_dpi.modules.instagram import InstagramFlowPolicy  # noqa: E402
from prism_dpi.modules.minecraft import MinecraftFlowPolicy  # noqa: E402
from prism_dpi.modules.pinterest import PinterestFlowPolicy  # noqa: E402
from prism_dpi.modules.playstation import PlayStationFlowPolicy  # noqa: E402
from prism_dpi.modules.prime_video import PrimeVideoFlowPolicy  # noqa: E402
from prism_dpi.modules.roblox import RobloxFlowPolicy  # noqa: E402
from prism_dpi.modules.snapchat import SnapchatFlowPolicy  # noqa: E402
from prism_dpi.modules.signal import SignalFlowPolicy  # noqa: E402
from prism_dpi.modules.soundcloud import SoundCloudFlowPolicy  # noqa: E402
from prism_dpi.modules.spotify import SpotifyFlowPolicy  # noqa: E402
from prism_dpi.modules.steam import SteamFlowPolicy  # noqa: E402
from prism_dpi.modules.tiktok import TikTokFlowPolicy  # noqa: E402
from prism_dpi.modules.tinder import TinderFlowPolicy  # noqa: E402
from prism_dpi.modules.twitch import TwitchFlowPolicy  # noqa: E402
from prism_dpi.modules.tumblr import TumblrFlowPolicy  # noqa: E402
from prism_dpi.modules.vimeo import VimeoFlowPolicy  # noqa: E402
from prism_dpi.modules.wechat import WeChatFlowPolicy  # noqa: E402
from prism_dpi.modules.xbox import XboxFlowPolicy  # noqa: E402

PRISM_FLOW_POLICY_POLL_SECONDS = 0.01
PRISM_FLOW_ENFORCER_RETRY_SECONDS = 1.0
PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS = 60.0
PRISM_FLOW_ENFORCER_STABLE_SECONDS = 30.0

# Import NetProtection modules
NETPROTECTION_AVAILABLE = False
FLOW_LOGGER_AVAILABLE = False
DNS_SHADOW_AVAILABLE = False
NetProtectionServer = None
NetProtectionConfig = None
FlowLogger = None
FlowLogStorage = None
FlowEntry = None
FlowStatus = None
QueryType = None
IPAnonymizer = None
SaltManager = None

try:
    from easypi_netprotection import (
        NetProtectionServer,
        load_config as load_np_config,
    )

    importlib.import_module("easypi_netprotection.threat_intel")
    NETPROTECTION_AVAILABLE = True
    logger.info("NetProtection module loaded successfully")
except ImportError as e:
    logger.warning(f"NetProtection module not fully available: {e}")

# The user's list files are shared with the engine's hit counters: hold the
# shared lock and replace files in one step (easypi_netprotection.list_files).
try:
    from easypi_netprotection.list_files import lists_lock, write_text_atomic
    from easypi_netprotection.verdict.blocklist_filter import MULTI_PART_TLDS
except ImportError:  # No engine package, so no other writer of these files.
    import contextlib as _contextlib

    MULTI_PART_TLDS = frozenset()

    def lists_lock(data_dir):  # type: ignore[no-redef]
        return _contextlib.nullcontext()

    def write_text_atomic(path, text, *, durable=True):  # type: ignore[no-redef]
        Path(path).write_text(text, encoding="utf-8")

# Prefix of the engine's recorded verdict reason in the flow-log categories
# column. Mirrors easypi_netprotection.chronicle.flow_log.FLOW_REASON_PREFIX so
# historical logs stay readable even when the engine package is unavailable.
FLOW_REASON_PREFIX = "reason:"

try:
    from easypi_netprotection.chronicle.flow_log import (  # noqa: F811
        FLOW_REASON_PREFIX,
        FlowLogger,
        FlowLogStorage,
        FlowStatus,  # noqa: F401 - re-exported to the analytics mixin
        QueryType,  # noqa: F401 - re-exported to the analytics mixin
        IPAnonymizer,
    )

    FLOW_LOGGER_AVAILABLE = True
    logger.info("FlowLogger module loaded successfully")
except ImportError as e:
    logger.warning(f"FlowLogger module not available: {e}")

try:
    from easypi_netprotection.heuristics.dns_shadow import (
        DNS_SHADOW_DOMAIN,
        DNS_SHADOW_GROUP,
        DEFAULT_RESOLVED_WINDOW_SEC,
        DEFAULT_MIN_UNEXPLAINED_FLOWS,
        DEFAULT_MIN_WAN_BYTES,
        detect_dns_shadow as _detect_dns_shadow,
        parse_conntrack_snapshot as _parse_conntrack_snapshot,
        compute_windowed_bytes as _compute_windowed_bytes,
        read_recent_resolved_ips as _read_recent_resolved_ips,
    )

    DNS_SHADOW_AVAILABLE = True
    logger.info("DNS-shadow bypass detector loaded successfully")
except ImportError as e:
    DNS_SHADOW_DOMAIN = "__dns_shadow__"
    DNS_SHADOW_GROUP = "dns_shadow"
    DEFAULT_RESOLVED_WINDOW_SEC = 1800.0
    DEFAULT_MIN_UNEXPLAINED_FLOWS = 1
    DEFAULT_MIN_WAN_BYTES = 1_500_000
    _detect_dns_shadow = None
    _parse_conntrack_snapshot = None
    _compute_windowed_bytes = None
    _read_recent_resolved_ips = None
    logger.warning(f"DNS-shadow bypass detector not available: {e}")
# Service domains for parental control
from easypi_netprotection.service_domains import (  # noqa: E402
    ADULT_HEURISTIC_MARKER,
    get_all_domains_for_services,
    get_catalog_categories,
    get_catalog_services,
)
from easypi_netprotection.profiles import trigger_profiles_reload  # noqa: E402

# IP-based app blocking (for apps that bypass DNS)
APP_BLOCKER_AVAILABLE = False
AppBlocker = None
try:
    from easypi_netprotection.parental.app_blocker import AppBlocker

    APP_BLOCKER_AVAILABLE = True
    logger.info("AppBlocker module loaded successfully")
except ImportError as e:
    logger.warning(f"AppBlocker module not available: {e}")

# IP-based blocked services mapping
# Both 'telegram' and 'telegram_ip' trigger IP blocking
# This ensures blocking works whether user selects DNS or IP option
IP_BLOCK_SERVICES = {
    "telegram_ip": "telegram",
    "whatsapp_ip": "whatsapp",
    "signal_ip": "signal",
    "tor_ip": "tor",
    "discord_ip": "discord",
    "snapchat_ip": "snapchat",
    "wechat_ip": "wechat",
    "viber_ip": "viber",
    "line_ip": "line",
    "imessage_ip": "imessage",
    "messenger_ip": "messenger",
    "facebook_ip": "facebook",
    # Treat core app selections as IP-blockable to prevent DNS-only bypass
    "telegram": "telegram",
    "whatsapp": "whatsapp",
    "signal": "signal",
    "tor": "tor",
    "discord": "discord",
    "snapchat": "snapchat",
    "wechat": "wechat",
    "viber": "viber",
    "line": "line",
    "imessage": "imessage",
    "messenger": "messenger",
    "facebook": "facebook",
}
IP_BLOCK_CATALOG_EXCLUSIONS = frozenset(
    {
        "telegram_ip",
        "whatsapp_ip",
        "signal_ip",
    }
)


def _cert_has_san(cert_path: Path) -> bool:
    """True if the certificate carries a SubjectAltName (usable for DoH/DoT TLS).

    Returns True on any uncertainty (openssl missing/old/errored) so a working
    setup is never blocked on a check we couldn't run; returns False only when
    openssl ran cleanly and reported no SAN (e.g. a legacy CN-only cert).
    """
    try:
        proc = subprocess.run(
            [
                "openssl",
                "x509",
                "-in",
                str(cert_path),
                "-noout",
                "-ext",
                "subjectAltName",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return True
    combined = f"{proc.stdout}\n{proc.stderr}"
    if "Subject Alternative Name" in combined:
        return True
    if proc.returncode == 0:
        return False
    return True


__all__ = [
    "ADULT_HEURISTIC_MARKER",
    "APP_BLOCKER_AVAILABLE",
    "Any",
    "AppBlocker",
    "AppleMusicFlowPolicy",
    "CandidateFlow",
    "CandidateLogFollower",
    "DEFAULT_MIN_UNEXPLAINED_FLOWS",
    "DEFAULT_MIN_WAN_BYTES",
    "DEFAULT_RESOLVED_WINDOW_SEC",
    "DNS_SHADOW_AVAILABLE",
    "DNS_SHADOW_DOMAIN",
    "DNS_SHADOW_GROUP",
    "DailymotionFlowPolicy",
    "DeezerFlowPolicy",
    "DeviceAnomalyStoreError",
    "Dict",
    "DisneyFlowPolicy",
    "EASYPI_ROOT",
    "EpicGamesFlowPolicy",
    "FLOW_LOGGER_AVAILABLE",
    "FLOW_REASON_PREFIX",
    "FacebookFlowPolicy",
    "FlowEntry",
    "FlowLogStorage",
    "FlowLogger",
    "FlowStatus",
    "GooglePlayFlowPolicy",
    "HboFlowPolicy",
    "IPAnonymizer",
    "IP_BLOCK_CATALOG_EXCLUSIONS",
    "IP_BLOCK_SERVICES",
    "InstagramFlowPolicy",
    "List",
    "MinecraftFlowPolicy",
    "NETPROTECTION_AVAILABLE",
    "NetProtectionConfig",
    "NetProtectionServer",
    "Optional",
    "PRISM_FLOW_ENFORCER_MAX_RETRY_SECONDS",
    "PRISM_FLOW_ENFORCER_RETRY_SECONDS",
    "PRISM_FLOW_ENFORCER_STABLE_SECONDS",
    "PRISM_FLOW_POLICY_POLL_SECONDS",
    "Path",
    "PinterestFlowPolicy",
    "PlayStationFlowPolicy",
    "PrimeVideoFlowPolicy",
    "QueryType",
    "RobloxFlowPolicy",
    "SaltManager",
    "ScheduleStoreError",
    "SignalFlowPolicy",
    "SnapchatFlowPolicy",
    "SoundCloudFlowPolicy",
    "SpotifyFlowPolicy",
    "SteamFlowPolicy",
    "TikTokFlowPolicy",
    "TinderFlowPolicy",
    "TumblrFlowPolicy",
    "TwitchFlowPolicy",
    "VimeoFlowPolicy",
    "WeChatFlowPolicy",
    "XboxFlowPolicy",
    "_cert_has_san",
    "_compute_windowed_bytes",
    "_detect_dns_shadow",
    "_parse_conntrack_snapshot",
    "_read_recent_resolved_ips",
    "_sanitize_mac",
    "_short_err",
    "asyncio",
    "datetime",
    "fnmatch",
    "get_all_domains_for_services",
    "get_catalog_categories",
    "get_catalog_services",
    "get_easypi_root",
    "get_netprotection_data_dir",
    "importlib",
    "json",
    "logger",
    "logging",
    "os",
    "re",
    "sanitize_domain",
    "sanitize_mac",
    "subprocess",
    "sys",
    "time",
    "timezone",
    "trigger_profiles_reload",
    "uuid",
    "validate_flowgraph_candidate_event",
    "MULTI_PART_TLDS",
    "lists_lock",
    "write_text_atomic",
]
