"""
EasyPi NetProtection — Streaming Apps Blocker.

Comprehensive blocking for streaming services like Netflix, YouTube, TikTok.
Implements multi-layer blocking:
1. DNS domain blocking
2. ASN-based IP blocking (via iptables/ipset)
3. DoH/DoT blocking
4. Force DNS mode

Usage:
    blocker = StreamingBlocker()
    await blocker.block_netflix()
    await blocker.block_youtube()
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

import aiohttp
from ..config import get_settings

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

def _get_data_dir() -> Path:
    return get_settings().NETPROTECTION_DATA_DIR / "streaming"

DATA_DIR = _get_data_dir()
ASN_CACHE_FILE = DATA_DIR / "asn_cache.json"
STREAMING_STATE_FILE = DATA_DIR / "streaming_state.json"

# ASN data sources
BGP_VIEW_API = "https://api.bgpview.io/asn/{asn}/prefixes"
IPINFO_ASN_API = "https://ipinfo.io/widget/demo/{asn}"


# ════════════════════════════════════════════════════════════════════════════════
# STREAMING SERVICE DEFINITIONS
# ════════════════════════════════════════════════════════════════════════════════

class StreamingService(str, Enum):
    """Supported streaming services."""
    
    NETFLIX = "netflix"
    YOUTUBE = "youtube"
    TIKTOK = "tiktok"
    DISNEY_PLUS = "disney_plus"
    AMAZON_PRIME = "amazon_prime"
    TWITCH = "twitch"
    SPOTIFY = "spotify"
    APPLE_TV = "apple_tv"


@dataclass
class ServiceDefinition:
    """Definition of a streaming service for blocking."""
    
    name: str
    display_name: str
    
    # ASN numbers for IP blocking
    asn_list: list[str] = field(default_factory=list)
    
    # DNS domains to block
    domains: list[str] = field(default_factory=list)
    
    # Additional IP ranges (for services without dedicated ASN)
    ip_ranges: list[str] = field(default_factory=list)
    
    # DoH servers used by this service
    doh_domains: list[str] = field(default_factory=list)


# Service definitions with ASNs and domains
STREAMING_SERVICES: dict[StreamingService, ServiceDefinition] = {
    StreamingService.NETFLIX: ServiceDefinition(
        name="netflix",
        display_name="Netflix",
        asn_list=[
            "AS2906",   # Netflix Streaming Services
            "AS40027",  # Netflix Streaming Services (secondary)
        ],
        domains=[
            "netflix.com",
            "www.netflix.com",
            "nflxvideo.net",
            "nflximg.net",
            "nflxso.net",
            "nflxext.com",
            "netflix.net",
            "netflixdnstest0.com",
            "netflixdnstest1.com",
            "netflixdnstest2.com",
            "netflixdnstest3.com",
            "netflixdnstest4.com",
            "netflixdnstest5.com",
            "netflixdnstest6.com",
            "netflixdnstest7.com",
            "netflixdnstest8.com",
            "netflixdnstest9.com",
            "nflximg.com",
            "nflxext.net",
            "customerevents.netflix.com",
            "ichnaea.netflix.com",
            "presentationtracking.netflix.com",
            "*.netflix.com",
            "*.nflxvideo.net",
            "*.nflximg.net",
            "*.nflxso.net",
            "*.nflxext.com",
        ],
        doh_domains=[],  # Netflix doesn't use its own DoH
    ),
    
    StreamingService.YOUTUBE: ServiceDefinition(
        name="youtube",
        display_name="YouTube",
        asn_list=[
            "AS15169",  # Google LLC
            "AS36040",  # Google - YouTube
        ],
        domains=[
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "youtubei.googleapis.com",
            "youtube-nocookie.com",
            "youtube-ui.l.google.com",
            "youtu.be",
            "ytimg.com",
            "yt3.ggpht.com",
            "googlevideo.com",
            "*.youtube.com",
            "*.googlevideo.com",
            "*.ytimg.com",
            "*.youtube-nocookie.com",
            "youtube.googleapis.com",
            "www.youtube-nocookie.com",
            "yt.be",
            "music.youtube.com",
            "tv.youtube.com",
            "kids.youtube.com",
        ],
        doh_domains=[
            "dns.google",
            "dns.google.com",
            "8.8.8.8",
            "8.8.4.4",
        ],
    ),
    
    StreamingService.TIKTOK: ServiceDefinition(
        name="tiktok",
        display_name="TikTok",
        asn_list=[
            "AS138699",  # TikTok
            "AS396986",  # ByteDance
        ],
        domains=[
            "tiktok.com",
            "www.tiktok.com",
            "vm.tiktok.com",
            "m.tiktok.com",
            "tiktokcdn.com",
            "tiktokv.com",
            "musical.ly",
            "muscdn.com",
            "byteoversea.com",
            "ibytedtos.com",
            "ipstatp.com",
            "ibyteimg.com",
            "isnssdk.com",
            "sgpstatp.com",
            "sgsnssdk.com",
            "ttoversea.net",
            "ttlivecdn.com",
            "ttlcntcdn.com",
            "lf16-tiktok-web.ttwstatic.com",
            "*.tiktok.com",
            "*.tiktokcdn.com",
            "*.tiktokv.com",
            "*.byteoversea.com",
            "*.musical.ly",
        ],
        doh_domains=[],
    ),
    
    StreamingService.DISNEY_PLUS: ServiceDefinition(
        name="disney_plus",
        display_name="Disney+",
        asn_list=[
            "AS7575",   # Disney Streaming Services
            "AS201106", # Disney Streaming Services EU
        ],
        domains=[
            "disneyplus.com",
            "www.disneyplus.com",
            "disney-plus.net",
            "dssott.com",
            "bamgrid.com",
            "disney.api.edge.bamgrid.com",
            "*.disneyplus.com",
            "*.disney-plus.net",
            "*.dssott.com",
            "*.bamgrid.com",
            "disneystreaming.com",
            "registerdisney.go.com",
        ],
        doh_domains=[],
    ),
    
    StreamingService.TWITCH: ServiceDefinition(
        name="twitch",
        display_name="Twitch",
        asn_list=[
            "AS46489",  # Twitch
        ],
        domains=[
            "twitch.tv",
            "www.twitch.tv",
            "m.twitch.tv",
            "static.twitchcdn.net",
            "usher.ttvnw.net",
            "video-edge-*.abs.hls.ttvnw.net",
            "jtvnw.net",
            "ttvnw.net",
            "twitchcdn.net",
            "*.twitch.tv",
            "*.jtvnw.net",
            "*.ttvnw.net",
            "*.twitchcdn.net",
        ],
        doh_domains=[],
    ),
    
    StreamingService.SPOTIFY: ServiceDefinition(
        name="spotify",
        display_name="Spotify",
        asn_list=[
            "AS8403",   # Spotify AB
        ],
        domains=[
            "spotify.com",
            "www.spotify.com",
            "open.spotify.com",
            "scdn.co",
            "spoti.fi",
            "spotifycdn.com",
            "audio-ak-spotify-com.akamaized.net",
            "*.spotify.com",
            "*.scdn.co",
            "*.spoti.fi",
            "*.spotifycdn.com",
        ],
        doh_domains=[],
    ),
}


# DoH/DoT servers to block for complete protection
DOH_DOT_DOMAINS = [
    # Google
    "dns.google",
    "dns.google.com",
    "dns64.dns.google",
    
    # Cloudflare
    "cloudflare-dns.com",
    "one.one.one.one",
    "1dot1dot1dot1.cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "dns.cloudflare.com",
    "families.cloudflare-dns.com",
    
    # Quad9
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    
    # NextDNS
    "dns.nextdns.io",
    "*.dns.nextdns.io",
    
    # NetProtection DoH
    "dns.NetProtection.com",
    "dns-family.NetProtection.com",
    "dns-unfiltered.NetProtection.com",
    
    # Cleanbrowsing
    "doh.cleanbrowsing.org",
    "family-filter-dns.cleanbrowsing.org",
    
    # OpenDNS
    "doh.opendns.com",
    "doh.familyshield.opendns.com",
    
    # Comcast
    "doh.xfinity.com",
    
    # Mozilla
    "mozilla.cloudflare-dns.com",
]


# ════════════════════════════════════════════════════════════════════════════════
# ASN TO IP PREFIXES RESOLVER
# ════════════════════════════════════════════════════════════════════════════════

class ASNResolver:
    """Resolves ASN to IP prefixes using public APIs."""
    
    def __init__(self, cache_dir: Path = ASN_CACHE_FILE.parent):
        self.cache_dir = cache_dir
        self.cache_file = cache_dir / "asn_cache.json"
        self._cache: dict[str, dict] = {}
        self._load_cache()
    
    def _load_cache(self) -> None:
        """Load cached ASN prefixes."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file, "r") as f:
                    self._cache = json.load(f)
                logger.info(f"Loaded ASN cache with {len(self._cache)} entries")
        except Exception as e:
            logger.warning(f"Failed to load ASN cache: {e}")
            self._cache = {}
    
    def _save_cache(self) -> None:
        """Save ASN prefixes to cache."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            with open(self.cache_file, "w") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save ASN cache: {e}")
    
    async def get_prefixes(self, asn: str) -> list[str]:
        """
        Get IP prefixes for an ASN.
        
        Args:
            asn: ASN number (e.g., "AS2906" or "2906")
        
        Returns:
            List of IP prefixes (CIDR notation)
        """
        # Normalize ASN format
        asn_num = asn.replace("AS", "").strip()
        cache_key = f"AS{asn_num}"
        
        # Check cache (24h TTL)
        if cache_key in self._cache:
            cached = self._cache[cache_key]
            if time.time() - cached.get("timestamp", 0) < 86400:  # 24 hours
                return cached.get("prefixes", [])
        
        # Fetch from API
        prefixes = await self._fetch_from_bgpview(asn_num)
        
        if prefixes:
            self._cache[cache_key] = {
                "timestamp": time.time(),
                "prefixes": prefixes,
            }
            self._save_cache()
        
        return prefixes
    
    async def _fetch_from_bgpview(self, asn_num: str) -> list[str]:
        """Fetch prefixes from BGPView API."""
        url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as resp:
                    if resp.status != 200:
                        logger.warning(f"BGPView API returned {resp.status} for AS{asn_num}")
                        return []
                    
                    data = await resp.json()
                    
                    prefixes = []
                    
                    # IPv4 prefixes
                    for p in data.get("data", {}).get("ipv4_prefixes", []):
                        prefix = p.get("prefix")
                        if prefix:
                            prefixes.append(prefix)
                    
                    # IPv6 prefixes (optional)
                    for p in data.get("data", {}).get("ipv6_prefixes", []):
                        prefix = p.get("prefix")
                        if prefix:
                            prefixes.append(prefix)
                    
                    logger.info(f"Fetched {len(prefixes)} prefixes for AS{asn_num}")
                    return prefixes
                    
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching prefixes for AS{asn_num}")
            return []
        except Exception as e:
            logger.error(f"Error fetching prefixes for AS{asn_num}: {e}")
            return []


# ════════════════════════════════════════════════════════════════════════════════
# IPSET/IPTABLES MANAGER
# ════════════════════════════════════════════════════════════════════════════════

class IPTablesManager:
    """Manages iptables/ipset rules for IP blocking."""
    
    def __init__(self):
        self._sets_created: set[str] = set()
    
    def _run_cmd(self, cmd: list[str], check: bool = False) -> tuple[int, str, str]:
        """Run a shell command."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return 1, "", "Command timed out"
        except Exception as e:
            return 1, "", str(e)
    
    def create_ipset(self, name: str, family: str = "inet") -> bool:
        """Create an ipset for blocking."""
        # Check if already exists
        ret, _, _ = self._run_cmd(["ipset", "list", name])
        if ret == 0:
            logger.info(f"ipset {name} already exists")
            return True
        
        # Create new ipset
        cmd = ["ipset", "create", name, "hash:net", "family", family, "hashsize", "4096", "maxelem", "65536"]
        ret, stdout, stderr = self._run_cmd(cmd)
        
        if ret == 0:
            logger.info(f"Created ipset {name}")
            self._sets_created.add(name)
            return True
        else:
            logger.error(f"Failed to create ipset {name}: {stderr}")
            return False
    
    def add_to_ipset(self, name: str, prefixes: list[str]) -> int:
        """Add IP prefixes to an ipset."""
        added = 0
        for prefix in prefixes:
            # Skip IPv6 for inet family
            try:
                net = ipaddress.ip_network(prefix, strict=False)
                if net.version == 6:
                    continue  # Skip IPv6 for now
            except ValueError:
                continue
            
            cmd = ["ipset", "add", name, prefix, "-exist"]
            ret, _, _ = self._run_cmd(cmd)
            if ret == 0:
                added += 1
        
        logger.info(f"Added {added} prefixes to ipset {name}")
        return added
    
    def flush_ipset(self, name: str) -> bool:
        """Flush all entries from an ipset."""
        cmd = ["ipset", "flush", name]
        ret, _, stderr = self._run_cmd(cmd)
        if ret == 0:
            logger.info(f"Flushed ipset {name}")
            return True
        else:
            logger.warning(f"Failed to flush ipset {name}: {stderr}")
            return False
    
    def destroy_ipset(self, name: str) -> bool:
        """Destroy an ipset."""
        # First remove from iptables
        self._run_cmd(["iptables", "-D", "OUTPUT", "-m", "set", "--match-set", name, "dst", "-j", "DROP"])
        self._run_cmd(["iptables", "-D", "FORWARD", "-m", "set", "--match-set", name, "dst", "-j", "DROP"])
        
        cmd = ["ipset", "destroy", name]
        ret, _, stderr = self._run_cmd(cmd)
        if ret == 0:
            logger.info(f"Destroyed ipset {name}")
            self._sets_created.discard(name)
            return True
        else:
            logger.warning(f"Failed to destroy ipset {name}: {stderr}")
            return False
    
    def add_iptables_block_rule(self, ipset_name: str) -> bool:
        """Add iptables rule to block traffic to ipset."""
        rules = [
            # Block outgoing to these IPs
            ["iptables", "-I", "OUTPUT", "-m", "set", "--match-set", ipset_name, "dst", "-j", "DROP"],
            # Block forwarded traffic (for router mode)
            ["iptables", "-I", "FORWARD", "-m", "set", "--match-set", ipset_name, "dst", "-j", "DROP"],
        ]
        
        success = True
        for rule in rules:
            ret, _, stderr = self._run_cmd(rule)
            if ret != 0 and "already exists" not in stderr.lower():
                logger.warning(f"Failed to add iptables rule: {stderr}")
                success = False
        
        if success:
            logger.info(f"Added iptables block rules for {ipset_name}")
        
        return success
    
    def remove_iptables_block_rule(self, ipset_name: str) -> bool:
        """Remove iptables rule blocking traffic to ipset."""
        rules = [
            ["iptables", "-D", "OUTPUT", "-m", "set", "--match-set", ipset_name, "dst", "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-m", "set", "--match-set", ipset_name, "dst", "-j", "DROP"],
        ]
        
        for rule in rules:
            self._run_cmd(rule)  # Don't care about errors (rule might not exist)
        
        logger.info(f"Removed iptables block rules for {ipset_name}")
        return True
    
    def block_port(self, port: int, protocol: str = "tcp") -> bool:
        """Block outgoing traffic to a specific port (for DoT)."""
        rules = [
            ["iptables", "-I", "OUTPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"],
            ["iptables", "-I", "FORWARD", "-p", protocol, "--dport", str(port), "-j", "DROP"],
        ]
        
        success = True
        for rule in rules:
            ret, _, stderr = self._run_cmd(rule)
            if ret != 0:
                logger.warning(f"Failed to block port {port}: {stderr}")
                success = False
        
        return success
    
    def unblock_port(self, port: int, protocol: str = "tcp") -> bool:
        """Unblock traffic to a specific port."""
        rules = [
            ["iptables", "-D", "OUTPUT", "-p", protocol, "--dport", str(port), "-j", "DROP"],
            ["iptables", "-D", "FORWARD", "-p", protocol, "--dport", str(port), "-j", "DROP"],
        ]
        
        for rule in rules:
            self._run_cmd(rule)
        
        return True
    
    def setup_force_dns(self, dns_server: str = "127.0.0.1") -> bool:
        """
        Force all DNS traffic through EasyPi.
        Redirects port 53 traffic to local DNS server.
        """
        rules = [
            # Redirect outgoing DNS (UDP)
            ["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "udp", "--dport", "53", 
             "-j", "DNAT", "--to-destination", f"{dns_server}:53"],
            # Redirect outgoing DNS (TCP)
            ["iptables", "-t", "nat", "-I", "PREROUTING", "-p", "tcp", "--dport", "53",
             "-j", "DNAT", "--to-destination", f"{dns_server}:53"],
            # Allow local DNS responses
            ["iptables", "-I", "OUTPUT", "-p", "udp", "--sport", "53", "-j", "ACCEPT"],
            ["iptables", "-I", "OUTPUT", "-p", "tcp", "--sport", "53", "-j", "ACCEPT"],
        ]
        
        success = True
        for rule in rules:
            ret, _, stderr = self._run_cmd(rule)
            if ret != 0:
                logger.warning(f"Failed to setup force DNS: {stderr}")
                success = False
        
        if success:
            logger.info("Force DNS mode enabled")
        
        return success
    
    def disable_force_dns(self, dns_server: str = "127.0.0.1") -> bool:
        """Disable Force DNS mode."""
        rules = [
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53",
             "-j", "DNAT", "--to-destination", f"{dns_server}:53"],
            ["iptables", "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53",
             "-j", "DNAT", "--to-destination", f"{dns_server}:53"],
        ]
        
        for rule in rules:
            self._run_cmd(rule)
        
        logger.info("Force DNS mode disabled")
        return True


# ════════════════════════════════════════════════════════════════════════════════
# STREAMING BLOCKER
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class BlockingState:
    """State of blocking for a service."""
    
    enabled: bool = False
    dns_blocked: bool = False
    asn_blocked: bool = False
    doh_blocked: bool = False
    blocked_at: str | None = None
    prefixes_count: int = 0
    domains_count: int = 0


class StreamingBlocker:
    """
    Comprehensive streaming service blocker.
    
    Implements multi-layer blocking:
    1. DNS domain blocking
    2. ASN-based IP blocking
    3. DoH/DoT blocking
    4. Force DNS mode
    """
    
    def __init__(self, data_dir: Path | None = None):
        self.data_dir = data_dir or DATA_DIR
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.state_file = self.data_dir / "streaming_state.json"
        self.asn_resolver = ASNResolver(self.data_dir)
        self.iptables = IPTablesManager()
        
        self._state: dict[str, BlockingState] = {}
        self._doh_blocked = False
        self._force_dns_enabled = False
        
        self._load_state()
    
    def _load_state(self) -> None:
        """Load blocking state from file."""
        try:
            if self.state_file.exists():
                with open(self.state_file, "r") as f:
                    data = json.load(f)
                
                for service, state_dict in data.get("services", {}).items():
                    self._state[service] = BlockingState(**state_dict)
                
                self._doh_blocked = data.get("doh_blocked", False)
                self._force_dns_enabled = data.get("force_dns_enabled", False)
                
                logger.info(f"Loaded streaming blocker state: {len(self._state)} services")
        except Exception as e:
            logger.warning(f"Failed to load streaming state: {e}")
    
    def _save_state(self) -> None:
        """Save blocking state to file."""
        try:
            data = {
                "services": {},
                "doh_blocked": self._doh_blocked,
                "force_dns_enabled": self._force_dns_enabled,
            }
            
            for service, state in self._state.items():
                data["services"][service] = {
                    "enabled": state.enabled,
                    "dns_blocked": state.dns_blocked,
                    "asn_blocked": state.asn_blocked,
                    "doh_blocked": state.doh_blocked,
                    "blocked_at": state.blocked_at,
                    "prefixes_count": state.prefixes_count,
                    "domains_count": state.domains_count,
                }
            
            with open(self.state_file, "w") as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            logger.error(f"Failed to save streaming state: {e}")
    
    def get_dns_blocklist(self, service: StreamingService) -> list[str]:
        """Get list of domains to block for a service."""
        if service not in STREAMING_SERVICES:
            return []
        
        definition = STREAMING_SERVICES[service]
        return definition.domains
    
    async def block_service(
        self,
        service: StreamingService,
        block_dns: bool = True,
        block_asn: bool = True,
        block_doh: bool = True,
    ) -> dict[str, Any]:
        """
        Block a streaming service comprehensively.
        
        Args:
            service: Service to block
            block_dns: Block DNS domains
            block_asn: Block ASN IP ranges
            block_doh: Block DoH/DoT for this service
        
        Returns:
            Result dict with status and details
        """
        if service not in STREAMING_SERVICES:
            return {"success": False, "error": f"Unknown service: {service}"}
        
        definition = STREAMING_SERVICES[service]
        result = {
            "success": True,
            "service": service.value,
            "display_name": definition.display_name,
            "dns_blocked": 0,
            "asn_prefixes": 0,
            "doh_blocked": False,
            "errors": [],
        }
        
        state = self._state.get(service.value, BlockingState())
        
        # 1. DNS Blocking (via profiles)
        if block_dns:
            result["dns_domains"] = definition.domains
            result["dns_blocked"] = len(definition.domains)
            state.dns_blocked = True
            state.domains_count = len(definition.domains)
        
        # 2. ASN Blocking
        if block_asn and definition.asn_list:
            ipset_name = f"block_{service.value}"
            
            # Create ipset
            if not self.iptables.create_ipset(ipset_name):
                result["errors"].append(f"Failed to create ipset {ipset_name}")
            else:
                # Fetch and add prefixes for each ASN
                total_prefixes = 0
                for asn in definition.asn_list:
                    prefixes = await self.asn_resolver.get_prefixes(asn)
                    if prefixes:
                        added = self.iptables.add_to_ipset(ipset_name, prefixes)
                        total_prefixes += added
                
                # Add static IP ranges if defined
                if definition.ip_ranges:
                    added = self.iptables.add_to_ipset(ipset_name, definition.ip_ranges)
                    total_prefixes += added
                
                # Add iptables rule
                self.iptables.add_iptables_block_rule(ipset_name)
                
                result["asn_prefixes"] = total_prefixes
                state.asn_blocked = True
                state.prefixes_count = total_prefixes
        
        # 3. Block DoH for this service
        if block_doh and definition.doh_domains:
            result["doh_domains"] = definition.doh_domains
            state.doh_blocked = True
            result["doh_blocked"] = True
        
        # Update state
        state.enabled = True
        state.blocked_at = datetime.now().isoformat()
        self._state[service.value] = state
        self._save_state()
        
        logger.info(
            f"Blocked {definition.display_name}: "
            f"{result['dns_blocked']} domains, {result['asn_prefixes']} IP prefixes"
        )
        
        return result
    
    async def unblock_service(self, service: StreamingService) -> dict[str, Any]:
        """Unblock a streaming service."""
        if service not in STREAMING_SERVICES:
            return {"success": False, "error": f"Unknown service: {service}"}
        
        definition = STREAMING_SERVICES[service]
        ipset_name = f"block_{service.value}"
        
        # Remove iptables rules and destroy ipset
        self.iptables.remove_iptables_block_rule(ipset_name)
        self.iptables.destroy_ipset(ipset_name)
        
        # Update state
        if service.value in self._state:
            del self._state[service.value]
        
        self._save_state()
        
        logger.info(f"Unblocked {definition.display_name}")
        
        return {
            "success": True,
            "service": service.value,
            "display_name": definition.display_name,
        }
    
    async def block_doh_dot(self) -> dict[str, Any]:
        """Block all DoH/DoT services globally."""
        result = {
            "success": True,
            "domains_blocked": DOH_DOT_DOMAINS,
            "port_853_blocked": False,      # DoT (TCP 853)
            "port_853_udp_blocked": False,  # DoQ / DNS-over-QUIC (UDP 853)
            "errors": [],
        }

        # DoT (TCP 853) and DoQ / DNS-over-QUIC (UDP 853). Both must be dropped;
        # blocking only TCP left a DNS-over-QUIC bypass open.
        if self.iptables.block_port(853, "tcp"):
            result["port_853_blocked"] = True
        else:
            result["errors"].append("Failed to block port 853/tcp")
        if self.iptables.block_port(853, "udp"):
            result["port_853_udp_blocked"] = True
        else:
            result["errors"].append("Failed to block port 853/udp")

        self._doh_blocked = True
        self._save_state()

        logger.info(f"Blocked DoH/DoT/DoQ: {len(DOH_DOT_DOMAINS)} domains, port 853 tcp+udp")

        return result
    
    async def unblock_doh_dot(self) -> dict[str, Any]:
        """Unblock DoH/DoT/DoQ services."""
        self.iptables.unblock_port(853, "tcp")
        self.iptables.unblock_port(853, "udp")

        self._doh_blocked = False
        self._save_state()

        logger.info("Unblocked DoH/DoT/DoQ")

        return {"success": True}
    
    def enable_force_dns(self, dns_server: str = "127.0.0.1") -> bool:
        """Enable Force DNS mode."""
        if self.iptables.setup_force_dns(dns_server):
            self._force_dns_enabled = True
            self._save_state()
            return True
        return False
    
    def disable_force_dns(self, dns_server: str = "127.0.0.1") -> bool:
        """Disable Force DNS mode."""
        self.iptables.disable_force_dns(dns_server)
        self._force_dns_enabled = False
        self._save_state()
        return True
    
    def get_status(self) -> dict[str, Any]:
        """Get current blocking status."""
        return {
            "blocked_services": {
                name: {
                    "enabled": state.enabled,
                    "dns_blocked": state.dns_blocked,
                    "asn_blocked": state.asn_blocked,
                    "prefixes_count": state.prefixes_count,
                    "domains_count": state.domains_count,
                    "blocked_at": state.blocked_at,
                }
                for name, state in self._state.items()
                if state.enabled
            },
            "doh_dot_blocked": self._doh_blocked,
            "force_dns_enabled": self._force_dns_enabled,
            "available_services": [s.value for s in StreamingService],
        }
    
    def get_all_domains_to_block(self) -> list[str]:
        """Get all domains that should be blocked based on current state."""
        domains = []
        
        for service_name, state in self._state.items():
            if state.enabled and state.dns_blocked:
                try:
                    service = StreamingService(service_name)
                    if service in STREAMING_SERVICES:
                        domains.extend(STREAMING_SERVICES[service].domains)
                except ValueError:
                    pass
        
        # Add DoH domains if DoH blocking is enabled
        if self._doh_blocked:
            domains.extend(DOH_DOT_DOMAINS)
        
        return list(set(domains))


# ════════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ════════════════════════════════════════════════════════════════════════════════

_blocker_instance: StreamingBlocker | None = None


def get_streaming_blocker() -> StreamingBlocker:
    """Get singleton StreamingBlocker instance."""
    global _blocker_instance
    if _blocker_instance is None:
        _blocker_instance = StreamingBlocker()
    return _blocker_instance


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

async def block_netflix() -> dict[str, Any]:
    """Block Netflix completely."""
    blocker = get_streaming_blocker()
    return await blocker.block_service(StreamingService.NETFLIX)


async def unblock_netflix() -> dict[str, Any]:
    """Unblock Netflix."""
    blocker = get_streaming_blocker()
    return await blocker.unblock_service(StreamingService.NETFLIX)


async def block_youtube() -> dict[str, Any]:
    """Block YouTube completely."""
    blocker = get_streaming_blocker()
    return await blocker.block_service(StreamingService.YOUTUBE)


async def block_tiktok() -> dict[str, Any]:
    """Block TikTok completely."""
    blocker = get_streaming_blocker()
    return await blocker.block_service(StreamingService.TIKTOK)


async def block_all_streaming() -> dict[str, Any]:
    """Block all streaming services."""
    blocker = get_streaming_blocker()
    results = {}
    
    for service in StreamingService:
        result = await blocker.block_service(service)
        results[service.value] = result
    
    # Also block DoH/DoT
    doh_result = await blocker.block_doh_dot()
    results["doh_dot"] = doh_result
    
    return results



