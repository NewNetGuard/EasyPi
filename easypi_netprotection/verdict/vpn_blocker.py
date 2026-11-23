"""
VPN/Tor/Proxy Port Blocker for Parental Control

Blocks VPN/Tor ports for devices with active parental restrictions.
This prevents bypass via VPN applications, Tor Browser, etc.

Works for:
- Parental Control (24/7 when blocked_services exist)
- Schedules (during active time windows)
"""

from __future__ import annotations

import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Set

logger = logging.getLogger(__name__)

# VPN/Tor/Proxy ports to block
# NOTE: WireGuard ports NOT blocked because Tailscale uses WireGuard!
VPN_TOR_PORTS: list[tuple[str, int]] = [
    # QUIC (frequently used by browser bypass stacks and encrypted DNS transports)
    ("udp", 443),
    # DNS-over-TLS
    ("tcp", 853),
    ("udp", 853),
    # OpenVPN
    ("udp", 1194),
    ("tcp", 1194),
    ("udp", 1195),
    # WireGuard - DO NOT BLOCK! Tailscale uses WireGuard
    # ("udp", 51820),
    # ("udp", 51821),
    # IPSec/IKEv2
    ("udp", 500),
    ("udp", 4500),
    # PPTP
    ("tcp", 1723),
    # L2TP
    ("udp", 1701),
    # Tor
    ("tcp", 9001),
    ("tcp", 9030),
    ("tcp", 9050),
    ("tcp", 9051),
    ("tcp", 9150),
    # Shadowsocks
    ("tcp", 8388),
    ("udp", 8388),
    # SOCKS proxy common ports
    ("tcp", 1080),
    ("tcp", 1081),
    # HTTP proxy common ports  
    ("tcp", 8080),
    ("tcp", 3128),
    ("tcp", 8118),  # Privoxy
]

# Known Tor relay IP ranges
TOR_IP_RANGES: list[str] = [
    "193.23.244.0/24",    # Tor Project
    "199.58.81.0/24",     # Tor Project
    "204.13.164.0/24",    # Tor Project
]


class VPNBlocker:
    """
    Manages VPN/Tor port blocking for devices with parental restrictions.
    
    Creates iptables chains per device IP and blocks known VPN/Tor ports.
    """
    
    def __init__(self, data_dir: Path | str | None = None):
        from ..config import get_settings
        self._data_dir = Path(data_dir) if data_dir else get_settings().NETPROTECTION_DATA_DIR
        self._devices_file = self._data_dir / "devices.json"
        # Check both common locations for iptables
        self._has_iptables = (
            shutil.which("iptables") is not None or
            Path("/usr/sbin/iptables").exists() or
            Path("/sbin/iptables").exists()
        )
        self._iptables_cmd = "/usr/sbin/iptables"
        self._blocked_ips: Set[str] = set()
        
        if not self._has_iptables:
            logger.warning("iptables not available - VPN blocking disabled")
    
    def _get_chain_name(self, ip: str) -> str:
        """Get iptables chain name for an IP."""
        return f"EASYPI_VPN_{ip.replace('.', '_')}"
    
    def _run_iptables(self, args: list[str]) -> subprocess.CompletedProcess:
        """Run iptables command.
        
        Always uses sudo with NOPASSWD from /etc/sudoers.d/easypi
        """
        # Use sudo (configured with NOPASSWD in sudoers)
        cmd = ["/usr/bin/sudo", self._iptables_cmd] + args
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return result
    
    def _chain_exists(self, chain_name: str) -> bool:
        """Check if iptables chain exists."""
        result = self._run_iptables(["-L", chain_name, "-n"])
        return result.returncode == 0
    
    def setup_vpn_blocking(self, client_ip: str) -> bool:
        """
        Setup VPN/Tor port blocking for a client IP.
        
        Returns True if blocking was set up successfully.
        """
        if not self._has_iptables:
            return False
        
        chain_name = self._get_chain_name(client_ip)
        
        try:
            # Check if already blocked
            if client_ip in self._blocked_ips:
                return True
            
            if self._chain_exists(chain_name):
                self._blocked_ips.add(client_ip)
                return True
            
            # Create new chain
            result = self._run_iptables(["-N", chain_name])
            if result.returncode != 0:
                logger.error(f"Failed to create chain {chain_name}: {result.stderr}")
                return False
            
            # Add port blocking rules
            for proto, port in VPN_TOR_PORTS:
                self._run_iptables(["-A", chain_name, "-p", proto, "--dport", str(port), "-j", "DROP"])
            
            # Block Tor IP ranges
            for ip_range in TOR_IP_RANGES:
                self._run_iptables(["-A", chain_name, "-d", ip_range, "-j", "DROP"])
            
            # Jump to this chain from FORWARD for this client
            result = self._run_iptables(["-I", "FORWARD", "1", "-s", client_ip, "-j", chain_name])
            if result.returncode != 0:
                logger.error(f"Failed to add FORWARD rule: {result.stderr}")
            
            self._blocked_ips.add(client_ip)
            logger.info(f"🔒 VPN/Tor blocking enabled for {client_ip} ({len(VPN_TOR_PORTS)} ports)")
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup VPN blocking for {client_ip}: {e}")
            return False
    
    def remove_vpn_blocking(self, client_ip: str) -> bool:
        """
        Remove VPN/Tor port blocking for a client IP.
        
        Returns True if blocking was removed successfully.
        """
        if not self._has_iptables:
            return False
        
        chain_name = self._get_chain_name(client_ip)
        
        try:
            # Remove from FORWARD
            self._run_iptables(["-D", "FORWARD", "-s", client_ip, "-j", chain_name])
            
            # Flush and delete chain
            self._run_iptables(["-F", chain_name])
            self._run_iptables(["-X", chain_name])
            
            self._blocked_ips.discard(client_ip)
            logger.info(f"🔓 VPN/Tor blocking removed for {client_ip}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove VPN blocking for {client_ip}: {e}")
            return False
    
    def sync_from_devices(self) -> None:
        """
        Sync VPN blocking based on devices.json.
        
        Enables blocking for devices with blocked_services,
        removes blocking for devices without restrictions.
        """
        if not self._has_iptables:
            return
        
        if not self._devices_file.exists():
            return
        
        try:
            devices = json.loads(self._devices_file.read_text())
        except Exception as e:
            logger.error(f"Failed to load devices: {e}")
            return
        
        # Find IPs that should have VPN blocking
        ips_to_block: Set[str] = set()
        bypass_services = {
            "vpn",
            "vpn_services",
            "doh",
            "dns_over_https",
            "dot",
            "dns_over_tls",
            "tor",
            "proxy",
            "web_proxy",
            "web_proxies",
            "smartdns",
            "smart_dns",
            "bypass",
            "strict_parental",
        }
        
        for device in devices:
            if not device.get("enabled", True):
                continue
            
            blocked_services = device.get("blocked_services", []) or []
            device_ip = device.get("ip", "")
            if not isinstance(blocked_services, list):
                blocked_services = []
            normalized_services = {
                str(s).strip().lower()
                for s in blocked_services
                if isinstance(s, str) and str(s).strip()
            }
            restricted_flags = bool(device.get("parental")) or bool(device.get("safesearch")) or bool(device.get("safebrowsing"))
            restricted_services = any(s in bypass_services for s in normalized_services)

            if device_ip and (restricted_flags or restricted_services):
                ips_to_block.add(device_ip)
        
        # Get currently blocked IPs (from our tracking + check chains)
        currently_blocked = self._blocked_ips.copy()
        
        # Remove blocking for IPs that no longer need it
        for ip in currently_blocked - ips_to_block:
            self.remove_vpn_blocking(ip)
        
        # Add blocking for new IPs
        for ip in ips_to_block - currently_blocked:
            self.setup_vpn_blocking(ip)
        
        if ips_to_block:
            logger.debug(f"VPN blocking active for {len(ips_to_block)} devices")
    
    def is_blocked(self, client_ip: str) -> bool:
        """Check if VPN blocking is active for an IP."""
        return client_ip in self._blocked_ips


# Singleton instance
_vpn_blocker: VPNBlocker | None = None


def get_vpn_blocker(data_dir: str | None = None) -> VPNBlocker:
    """Get singleton VPNBlocker instance."""
    global _vpn_blocker
    if _vpn_blocker is None:
        _vpn_blocker = VPNBlocker(data_dir)
    return _vpn_blocker


def sync_vpn_blocking() -> None:
    """Convenience function to sync VPN blocking from devices."""
    get_vpn_blocker().sync_from_devices()
