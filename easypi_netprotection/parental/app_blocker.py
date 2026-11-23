"""
App Blocker - IP-based blocking for apps that bypass DNS.

Some apps (Telegram, WhatsApp, Signal, Tor, Messenger, Snapchat, WeChat, Viber,
iMessage, Discord, LINE) use hardcoded IPs or their own
DNS resolution, making DNS-based blocking ineffective. This module provides
IP/ASN-based blocking via iptables/ipset.

BLOCKED APPS:
- Telegram: Uses hardcoded IPs, CDN, and MTProto proxies
- WhatsApp: Uses Meta infrastructure
- Messenger: Uses Meta infrastructure
- Snapchat: Uses Google infrastructure
- WeChat: Uses Tencent infrastructure
- Viber: Uses AWS infrastructure
- iMessage: Uses APNs ports (shared)
- Discord: Uses shared infrastructure
- Signal: Uses AWS/Cloudflare with certificate pinning
- Tor: Uses entry/exit nodes (already handled by VPN blocker)

BLOCKING METHODS:
1. IP Sets (ipset) - Fast O(1) lookup for large IP lists
2. ASN blocking - Block entire provider networks via BGP AS numbers
3. Port blocking - Block known service ports (MTProto, etc.)
4. DPI markers - Deep packet inspection signatures (future)

ARCHITECTURE:
┌─────────────────────────────────────────────────────────────────┐
│                      App Blocker Flow                           │
│                                                                 │
│  Device Profile → App Block List → IP/ASN Rules → iptables     │
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌─────────────────────┐   │
│  │ devices  │ → │ app_blocker  │ → │ setup_app_blocking  │   │
│  │  .json   │    │    .py       │    │       .sh           │   │
│  └──────────┘    └──────────────┘    └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# APP IP RANGES AND ASN DATA
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AppNetworkInfo:
    """Network information for an app that bypasses DNS."""
    
    name: str
    display_name: str
    description: str
    
    # IP ranges (CIDR notation)
    ip_ranges: list[str] = field(default_factory=list)
    
    # ASN numbers for the app's infrastructure
    asn_list: list[int] = field(default_factory=list)
    
    # Ports used by the app (proto:port format)
    ports: list[str] = field(default_factory=list)
    
    # Whether to also block DNS domains (dual blocking)
    also_block_dns: bool = True
    
    # Update URL for IP list (if available)
    ip_list_url: str | None = None
    
    # Last update timestamp
    last_updated: datetime | None = None


# Telegram IP ranges and ASN
# Sources: 
# - https://core.telegram.org/resources/cidr.txt
# - https://bgp.he.net/search?search%5Bsearch%5D=telegram&commit=Search
TELEGRAM_INFO = AppNetworkInfo(
    name="telegram",
    display_name="Telegram",
    description="Telegram Messenger - uses MTProto protocol with hardcoded IPs",
    ip_ranges=[
        # Telegram's official IP ranges (from core.telegram.org/resources/cidr.txt)
        "91.108.4.0/22",      # DC1
        "91.108.8.0/22",      # DC2  
        "91.108.12.0/22",     # DC3
        "91.108.16.0/22",     # DC4
        "91.108.20.0/22",     # DC5
        "91.108.56.0/22",     # Media
        "91.108.56.0/23",
        "149.154.160.0/20",   # Main range
        "149.154.160.0/22",   # DC1
        "149.154.164.0/22",   # DC2
        "149.154.168.0/22",   # DC3
        "149.154.172.0/22",   # DC4
        "185.76.151.0/24",    # Additional
        # IPv6
        "2001:67c:4e8::/48",
        "2001:b28:f23c::/48",
        "2001:b28:f23d::/48",
        "2001:b28:f23f::/48",
        "2a0a:f280::/32",
    ],
    asn_list=[
        62014,   # AS62014 - Telegram Messenger Inc
        62041,   # AS62041 - Telegram Messenger LLP
        211157,  # AS211157 - Telegram Messenger Inc (new)
    ],
    ports=[
        "tcp:443",    # HTTPS/MTProto
        "tcp:80",     # HTTP fallback
        "tcp:5222",   # XMPP (legacy)
        "udp:443",    # QUIC
    ],
    ip_list_url="https://core.telegram.org/resources/cidr.txt",
)


# WhatsApp IP ranges.
# NOTE:
# Actual enforcement mode (balanced/aggressive) is controlled by
# scripts/settings/setup_app_blocking.sh. This list includes broad Meta
# ranges for aggressive mode readiness.
# Sources:
# - Meta IP allocation (BGP/RADB)
# - Historical WhatsApp/SoftLayer ranges
WHATSAPP_INFO = AppNetworkInfo(
    name="whatsapp",
    display_name="WhatsApp",
    description="WhatsApp Messenger - uses Meta/Facebook infrastructure",
    ip_ranges=[
        # Meta/Facebook core edge (shared infra)
        "157.240.0.0/17",
        "31.13.24.0/21",
        "31.13.64.0/18",
        "129.134.0.0/17",
        "163.70.128.0/17",
        "179.60.192.0/22",
        "185.60.216.0/22",
        "102.132.96.0/20",
        "66.220.144.0/20",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "74.119.76.0/22",
        "173.252.64.0/18",
        "185.89.218.0/23",
        "204.15.20.0/22",
        # WhatsApp specific (IBM/SoftLayer + edge)
        "158.85.0.0/16",
        "158.85.5.0/24",
        "158.85.46.0/24",
        "158.85.48.0/24",
        "158.85.58.0/24",
        "158.85.61.0/24",
        "158.85.224.0/24",
        "158.85.233.0/24",
        # Edge locations
        "50.22.198.0/24",
        "50.22.210.0/24",
        "50.22.225.0/24",
        "50.22.235.0/24",
        "50.22.240.0/24",
        "169.44.82.0/24",
        "169.45.71.0/24",
        "169.45.87.0/24",
        "169.53.29.0/24",
        "169.53.81.0/24",
        "169.54.2.0/24",
        "169.54.51.0/24",
        "169.55.74.0/24",
        "169.55.126.0/24",
        "169.55.210.0/24",
        "173.192.231.0/24",
        "174.37.243.0/24",
        "184.173.136.0/24",
        "184.173.147.0/24",
        # WhatsApp media CDN
        "147.75.208.0/20",
        # Observed WhatsApp endpoints (Meta, /32)
        "157.240.253.13/32",
        "157.240.253.60/32",
        "157.240.253.61/32",
    ],
    asn_list=[
        32934,  # Meta Platforms, Inc.
        63293,  # Meta Platforms (CDN)
    ],
    ports=[
        "tcp:443",
        "tcp:5222",   # XMPP
        "tcp:5223",   # XMPP SSL
        "udp:3478",   # STUN (voice/video)
        "udp:19302",  # STUN Google
    ],
)


# Signal IP ranges
# Signal uses AWS, Cloudflare, and own infrastructure
SIGNAL_INFO = AppNetworkInfo(
    name="signal",
    display_name="Signal",
    description="Signal Messenger - uses AWS/Cloudflare with certificate pinning",
    ip_ranges=[
        # Signal's main infrastructure (textsecure.org)
        "13.248.212.0/24",   # AWS Global Accelerator
        "76.223.92.0/24",
        # Signal CDN (Cloudflare)
        # Note: Can't block all of Cloudflare, would break internet
        # These are Signal-specific
        "104.16.0.0/13",     # Cloudflare (partial, may need refinement)
        # Signal Foundation infrastructure  
        "142.251.0.0/15",    # Google Cloud (partial)
    ],
    asn_list=[
        # Note: Signal uses shared infrastructure, ASN blocking not effective
        # 396982,  # AS396982 - Signal Foundation (if they get their own)
    ],
    ports=[
        "tcp:443",
        "udp:3478",   # TURN
        "udp:10000",  # Voice
    ],
    # Signal's infrastructure is harder to block without collateral damage
    # Focus on DNS + certificate pinning detection
    also_block_dns=True,
)

# Facebook Messenger (Meta)
MESSENGER_INFO = AppNetworkInfo(
    name="messenger",
    display_name="Facebook Messenger",
    description="Facebook Messenger - uses Meta/Facebook infrastructure",
    ip_ranges=[
        "157.240.0.0/16",
        "31.13.0.0/16",
        "129.134.0.0/16",
        "179.60.192.0/22",
        "185.60.216.0/22",
        "66.220.144.0/20",
        "69.63.176.0/20",
        "69.171.224.0/19",
        "74.119.76.0/22",
        "102.132.96.0/20",
    ],
)


FACEBOOK_INFO = AppNetworkInfo(
    name="facebook",
    display_name="Facebook",
    description="Facebook app - precise TLS SNI blocking with Meta QUIC fallback",
    # Meta addresses are shared with Instagram, Messenger, and WhatsApp. The
    # firewall must not reject these ranges for TCP; it uses Facebook SNI after
    # forcing Meta QUIC to fall back to inspectable TCP.
    ip_ranges=[],
)

# Snapchat
SNAPCHAT_INFO = AppNetworkInfo(
    name="snapchat",
    display_name="Snapchat",
    description="Snapchat - uses Google infrastructure",
    ip_ranges=[
        "64.233.160.0/19",
        "216.58.192.0/19",
    ],
)

# WeChat (Tencent)
WECHAT_INFO = AppNetworkInfo(
    name="wechat",
    display_name="WeChat",
    description="WeChat - Tencent infrastructure",
    ip_ranges=[
        "101.32.0.0/16",
        "109.244.0.0/16",
        "203.205.0.0/16",
    ],
)

# Viber
VIBER_INFO = AppNetworkInfo(
    name="viber",
    display_name="Viber",
    description="Viber - uses AWS infrastructure",
    ip_ranges=[
        "54.72.0.0/13",
    ],
)

# iMessage (APNs ports; IP ranges not reliable)
IMESSAGE_INFO = AppNetworkInfo(
    name="imessage",
    display_name="iMessage",
    description="iMessage - relies on APNs; ports may affect other push services",
    ip_ranges=[],
    ports=[
        "tcp:5223",
        "tcp:5228",
        "tcp:5229",
        "tcp:5230",
    ],
)

# Discord (limited ranges; may require extra IPs)
DISCORD_INFO = AppNetworkInfo(
    name="discord",
    display_name="Discord",
    description="Discord - uses shared infrastructure; may require extra IPs",
    ip_ranges=[
        "66.22.196.0/22",
    ],
)

# LINE
LINE_INFO = AppNetworkInfo(
    name="line",
    display_name="LINE",
    description="LINE Messenger",
    ip_ranges=[
        "147.92.0.0/16",
        "203.104.128.0/19",
    ],
)


# Tor (extends existing VPN blocker)
TOR_INFO = AppNetworkInfo(
    name="tor",
    display_name="Tor Browser",
    description="Tor anonymity network - uses relay and exit nodes",
    ip_ranges=[],  # Dynamic, fetched from Tor Project
    asn_list=[],   # No specific ASN
    ports=[
        "tcp:9001",   # OR port
        "tcp:9030",   # Dir port
        "tcp:9050",   # SOCKS
        "tcp:9051",   # Control
        "tcp:9150",   # Browser SOCKS
    ],
    ip_list_url="https://check.torproject.org/torbulkexitlist",
)


# All apps that can be blocked via IP
BLOCKABLE_APPS: dict[str, AppNetworkInfo] = {
    "telegram": TELEGRAM_INFO,
    "whatsapp": WHATSAPP_INFO,
    "signal": SIGNAL_INFO,
    "messenger": MESSENGER_INFO,
    "facebook": FACEBOOK_INFO,
    "snapchat": SNAPCHAT_INFO,
    "wechat": WECHAT_INFO,
    "viber": VIBER_INFO,
    "imessage": IMESSAGE_INFO,
    "discord": DISCORD_INFO,
    "line": LINE_INFO,
    "tor": TOR_INFO,
}


# ═══════════════════════════════════════════════════════════════════════════════
# APP BLOCKER CLASS
# ═══════════════════════════════════════════════════════════════════════════════

class AppBlocker:
    """
    Manages IP-based app blocking for apps that bypass DNS.
    
    This class:
    1. Maintains IP/ASN lists for each app
    2. Generates iptables/ipset rules
    3. Syncs with device profiles
    4. Updates IP lists from external sources
    """
    
    def __init__(self, data_dir: Path | str | None = None):
        if data_dir:
            self._data_dir = Path(data_dir)
        else:
            self._data_dir = Path("/opt/EasyPi/data/netprotection")
        
        self._cache_file = self._data_dir / "app_blocker_cache.json"
        self._runner_path = Path("/opt/EasyPi/scripts/runner")
        self._script_path = "settings/setup_app_blocking.sh"
        
        # Cache of IP ranges (can be updated from external sources)
        self._ip_cache: dict[str, list[str]] = {}
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cached IP lists."""
        if self._cache_file.exists():
            try:
                with open(self._cache_file) as f:
                    data = json.load(f)
                self._ip_cache = data.get("ip_ranges", {})
                logger.info(f"Loaded app blocker cache: {len(self._ip_cache)} apps")
            except Exception as e:
                logger.warning(f"Failed to load app blocker cache: {e}")
    
    def _save_cache(self) -> None:
        """Save IP cache to disk."""
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            with open(self._cache_file, "w") as f:
                json.dump({
                    "ip_ranges": self._ip_cache,
                    "updated_at": datetime.now().isoformat(),
                }, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save app blocker cache: {e}")
    
    def get_app_info(self, app_name: str) -> AppNetworkInfo | None:
        """Get network info for an app."""
        return BLOCKABLE_APPS.get(app_name.lower())
    
    def list_blockable_apps(self) -> list[dict[str, Any]]:
        """List all apps that can be blocked via IP."""
        return [
            {
                "name": info.name,
                "display_name": info.display_name,
                "description": info.description,
                "ip_count": len(info.ip_ranges),
                "asn_count": len(info.asn_list),
                "has_dns_blocking": info.also_block_dns,
            }
            for info in BLOCKABLE_APPS.values()
        ]
    
    def get_ip_ranges_for_app(self, app_name: str) -> list[str]:
        """
        Get IP ranges for an app, using cache if available.
        
        Returns list of CIDR ranges.
        """
        app_name = app_name.lower()
        
        # Check cache first
        if app_name in self._ip_cache:
            return self._ip_cache[app_name]
        
        # Fall back to static list
        app_info = BLOCKABLE_APPS.get(app_name)
        if app_info:
            return app_info.ip_ranges
        
        return []
    
    async def update_ip_list(self, app_name: str) -> bool:
        """
        Update IP list for an app from external source.
        
        Returns True if successful.
        """
        import aiohttp
        
        app_info = BLOCKABLE_APPS.get(app_name.lower())
        if not app_info or not app_info.ip_list_url:
            return False
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(app_info.ip_list_url, timeout=30) as resp:
                    if resp.status != 200:
                        return False
                    
                    text = await resp.text()
                    
            # Parse IP ranges
            ip_ranges = []
            for line in text.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                try:
                    # Validate IP/CIDR
                    ipaddress.ip_network(line, strict=False)
                    ip_ranges.append(line)
                except ValueError:
                    continue
            
            if ip_ranges:
                self._ip_cache[app_name.lower()] = ip_ranges
                self._save_cache()
                logger.info(f"Updated {app_name} IP list: {len(ip_ranges)} ranges")
                return True
            
        except Exception as e:
            logger.error(f"Failed to update {app_name} IP list: {e}")
        
        return False
    
    def enable_blocking(
        self,
        client_ip: str,
        apps: list[str],
        client_mac: str | None = None,
    ) -> bool:
        """
        Enable IP-based blocking for specified apps on a client.
        
        Args:
            client_ip: Client IP to apply blocking to
            apps: List of app names to block (telegram, whatsapp, etc.)
        
        Returns:
            True if successful
        """
        if not apps:
            return True
        
        # Validate apps
        valid_apps = [a for a in apps if a.lower() in BLOCKABLE_APPS]
        if not valid_apps:
            return False
        
        # Call shell script via runner
        try:
            apps_arg = ",".join(valid_apps)
            result = subprocess.run(
                ["sudo", "-n", str(self._runner_path), self._script_path, "add", client_ip, apps_arg, client_mac or ""],
                capture_output=True,
                timeout=30,
                text=True,
            )
            
            if result.returncode == 0:
                logger.info(f"Enabled app blocking for {client_ip}: {valid_apps}")
                return True
            else:
                logger.error(f"Failed to enable app blocking: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to enable app blocking: {e}")
            return False
    
    def disable_blocking(
        self,
        client_ip: str,
        apps: list[str] | None = None,
        client_mac: str | None = None,
    ) -> bool:
        """
        Disable IP-based blocking for a client.
        
        Args:
            client_ip: Client IP to remove blocking from
            apps: Optional list of apps to unblock (None = all)
        
        Returns:
            True if successful
        """
        try:
            if apps:
                apps_arg = ",".join(apps)
            else:
                apps_arg = "all"
            
            result = subprocess.run(
                ["sudo", "-n", str(self._runner_path), self._script_path, "remove", client_ip, apps_arg, client_mac or ""],
                capture_output=True,
                timeout=30,
                text=True,
            )
            
            if result.returncode == 0:
                logger.info(f"Disabled app blocking for {client_ip}")
                return True
            else:
                logger.error(f"Failed to disable app blocking: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to disable app blocking: {e}")
            return False
    
    def sync_from_devices(self) -> bool:
        """
        Sync app blocking rules from devices.json.
        
        Returns:
            True if successful
        """
        try:
            result = subprocess.run(
                ["sudo", "-n", str(self._runner_path), self._script_path, "sync"],
                capture_output=True,
                timeout=60,
                text=True,
            )
            
            if result.returncode == 0:
                logger.info("App blocking sync completed")
                return True
            else:
                logger.error(f"App blocking sync failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"App blocking sync failed: {e}")
            return False
    
    def get_blocking_status(self, client_ip: str, client_mac: str | None = None) -> dict[str, Any]:
        """Get current blocking status for a client."""
        try:
            result = subprocess.run(
                ["sudo", "-n", str(self._runner_path), self._script_path, "status", client_ip, "all", client_mac or ""],
                capture_output=True,
                timeout=10,
                text=True,
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            
        except Exception:
            pass
        
        return {"active": False, "apps": []}


# Singleton
_app_blocker: AppBlocker | None = None


def get_app_blocker(data_dir: str | None = None) -> AppBlocker:
    """Get singleton AppBlocker instance."""
    global _app_blocker
    if _app_blocker is None:
        _app_blocker = AppBlocker(data_dir)
    return _app_blocker
