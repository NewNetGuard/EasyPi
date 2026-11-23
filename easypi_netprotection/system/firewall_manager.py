"""
Firewall Manager for EasyPi NetProtection

Manages iptables rules for complete internet blocking.
Used by schedule_checker when target_type="all" to block all traffic.
"""

from __future__ import annotations

import logging
import subprocess
from typing import Set

logger = logging.getLogger(__name__)

# Chain name for EasyPi rules
EASYPI_CHAIN = "EASYPI_SCHEDULE"


class FirewallManager:
    """
    Manages iptables rules for blocking device internet access.
    
    Uses a custom chain EASYPI_SCHEDULE to manage rules separately
    from other system rules.
    """
    
    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._initialized = False
        self._init_chain()
    
    def _run_iptables(self, args: list[str], check: bool = True) -> bool:
        """Run iptables command."""
        cmd = ["sudo", "iptables"] + args
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0 and check:
                logger.error(f"iptables failed: {' '.join(cmd)} -> {result.stderr}")
                return False
            return result.returncode == 0
        except subprocess.TimeoutExpired:
            logger.error(f"iptables timeout: {' '.join(cmd)}")
            return False
        except Exception as e:
            logger.error(f"iptables error: {e}")
            return False
    
    def _init_chain(self) -> None:
        """Initialize custom chain for EasyPi rules."""
        if self._initialized:
            return
        
        # Check if chain exists
        check = subprocess.run(
            ["sudo", "iptables", "-L", EASYPI_CHAIN, "-n"],
            capture_output=True,
            text=True
        )
        
        if check.returncode != 0:
            # Create chain
            if self._run_iptables(["-N", EASYPI_CHAIN], check=False):
                logger.info(f"Created iptables chain: {EASYPI_CHAIN}")
            
            # Insert jump to our chain at beginning of FORWARD
            self._run_iptables(["-I", "FORWARD", "1", "-j", EASYPI_CHAIN], check=False)
            logger.info(f"Added jump to {EASYPI_CHAIN} in FORWARD chain")
        else:
            # Chain exists, load existing blocked IPs
            self._load_existing_rules()
        
        self._initialized = True
    
    def _load_existing_rules(self) -> None:
        """Load existing blocked IPs from iptables."""
        try:
            result = subprocess.run(
                ["sudo", "iptables", "-L", EASYPI_CHAIN, "-n"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'DROP' in line and 'all' in line:
                        parts = line.split()
                        for part in parts:
                            if '.' in part and part.count('.') == 3:
                                # Looks like IP
                                ip = part.split('/')[0]  # Remove CIDR if present
                                if ip and ip != '0.0.0.0':
                                    self._blocked_ips.add(ip)
                logger.info(f"Loaded {len(self._blocked_ips)} existing blocked IPs")
        except Exception as e:
            logger.error(f"Failed to load existing rules: {e}")
    
    def block_device(self, ip: str) -> bool:
        """
        Block all internet traffic for a device IP.
        
        Args:
            ip: Device IP address to block
            
        Returns:
            True if rule was added (or already exists)
        """
        if not ip or ip in ('0.0.0.0', '127.0.0.1'):
            return False
        
        if ip in self._blocked_ips:
            logger.debug(f"Device already blocked: {ip}")
            return True
        
        # Add DROP rule for this IP
        if self._run_iptables(["-A", EASYPI_CHAIN, "-s", ip, "-j", "DROP"]):
            self._blocked_ips.add(ip)
            logger.info(f"🔒 Firewall BLOCKED device: {ip}")
            return True
        
        return False
    
    def unblock_device(self, ip: str) -> bool:
        """
        Unblock internet traffic for a device IP.
        
        Args:
            ip: Device IP address to unblock
            
        Returns:
            True if rule was removed (or didn't exist)
        """
        if not ip:
            return False
        
        if ip not in self._blocked_ips:
            logger.debug(f"Device not blocked: {ip}")
            return True
        
        # Remove DROP rule for this IP
        if self._run_iptables(["-D", EASYPI_CHAIN, "-s", ip, "-j", "DROP"], check=False):
            self._blocked_ips.discard(ip)
            logger.info(f"🔓 Firewall UNBLOCKED device: {ip}")
            return True
        
        # Rule might not exist, still remove from set
        self._blocked_ips.discard(ip)
        return True
    
    def is_blocked(self, ip: str) -> bool:
        """Check if device is currently blocked."""
        return ip in self._blocked_ips
    
    def get_blocked_devices(self) -> Set[str]:
        """Get set of currently blocked device IPs."""
        return self._blocked_ips.copy()
    
    def unblock_all(self) -> None:
        """Unblock all devices."""
        for ip in list(self._blocked_ips):
            self.unblock_device(ip)
        logger.info("Unblocked all devices")
    
    def cleanup(self) -> None:
        """Remove all rules and chain on shutdown."""
        # Flush our chain
        self._run_iptables(["-F", EASYPI_CHAIN], check=False)
        
        # Remove jump from FORWARD
        self._run_iptables(["-D", "FORWARD", "-j", EASYPI_CHAIN], check=False)
        
        # Delete chain
        self._run_iptables(["-X", EASYPI_CHAIN], check=False)
        
        self._blocked_ips.clear()
        self._initialized = False
        logger.info("Firewall cleanup complete")


# Singleton instance
_firewall_manager: FirewallManager | None = None


def get_firewall_manager() -> FirewallManager:
    """Get singleton FirewallManager instance."""
    global _firewall_manager
    if _firewall_manager is None:
        _firewall_manager = FirewallManager()
    return _firewall_manager
