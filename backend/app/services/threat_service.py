"""
Threat Detection Service

Monitors and detects security threats from:
- Failed SSH login attempts (via journalctl)
- Port scanning (via ss)
- Suspicious connection patterns

Auto-enabled by default, with UI toggle for start/stop.
"""

import asyncio
import json
import re
import logging
import ipaddress
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta, timezone
from app.utils.time import utc_now
from collections import defaultdict
from dataclasses import dataclass

from app.core.paths import get_backend_data_dir

logger = logging.getLogger(__name__)

# Config file for persistent state
BASE_DIR = get_backend_data_dir().parent  # backend/
CONFIG_PATH = get_backend_data_dir() / "threat_monitor_config.json"
# Persistent banned-IP store: survives a backend restart, and is re-applied to
# iptables on startup so bans also survive a reboot.
BANNED_PATH = get_backend_data_dir() / "banned_ips.json"
# How long an unblocked threat record is kept in memory before it is auto-expired
# (the "attack log"). Bans are NOT affected by this and are never auto-removed.
THREAT_RETENTION_HOURS = 168  # 7 days


def is_local_or_private_ip(ip: str) -> bool:
    """Check if IP address is local/private and should not be reported as threat"""
    try:
        addr = ipaddress.ip_address(ip)
        
        # Skip localhost
        if addr.is_loopback:
            return True
        
        # Skip private networks (192.168.x.x, 10.x.x.x, etc.)
        if addr.is_private:
            return True
        
        # Skip link-local (fe80:: for IPv6, 169.254.x.x for IPv4)
        if addr.is_link_local:
            return True
        
        # Skip unique local addresses (ULA) - fd00::/8, fc00::/7
        if isinstance(addr, ipaddress.IPv6Address):
            # ULA addresses start with fd or fc
            first_byte = addr.packed[0]
            if first_byte == 0xfd or first_byte == 0xfc:
                return True
        
        return False
    except (ValueError, TypeError):
        # Invalid IP - skip it
        return True


@dataclass
class Threat:
    """Represents a detected threat"""
    ip: str
    type: str
    severity: str  # critical, high, medium, low
    description: str
    count: int
    first_seen: datetime
    last_seen: datetime
    blocked: bool = False


@dataclass
class BannedThreat:
    """Represents a banned threat"""
    ip: str
    type: str
    reason: str
    banned_at: datetime
    permanent: bool = True


class ThreatDetectionService:
    """Service for detecting and managing security threats"""
    
    def __init__(self):
        self.threats: Dict[str, Threat] = {}
        self.banned_threats: Dict[str, BannedThreat] = {}  # key = f"{ip}_{type}"
        self.ip_counters = defaultdict(lambda: defaultdict(int))
        self.monitoring = False
        self._monitor_tasks: List[asyncio.Task] = []
        
        # Thresholds (configurable)
        self.ssh_fail_threshold = 5
        self.port_scan_threshold = 20
        self.auto_ban_enabled = False  # Don't auto-ban by default
        
        # Load config + persisted bans
        self._load_config()
        self._load_banned()

    def _load_config(self):
        """Load monitoring config from file"""
        try:
            if CONFIG_PATH.exists():
                with open(CONFIG_PATH, 'r') as f:
                    config = json.load(f)
                    self._enabled_on_startup = config.get("enabled", True)
                    self.ssh_fail_threshold = config.get("ssh_threshold", 5)
                    self.auto_ban_enabled = config.get("auto_ban", False)
                    logger.info(f"Loaded threat monitor config: enabled={self._enabled_on_startup}")
            else:
                self._enabled_on_startup = True  # Default: enabled
        except Exception as e:
            logger.error(f"Error loading threat config: {e}")
            self._enabled_on_startup = True
    
    def _save_config(self):
        """Save monitoring config to file"""
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            config = {
                "enabled": self.monitoring,
                "ssh_threshold": self.ssh_fail_threshold,
                "auto_ban": self.auto_ban_enabled,
                "updated_at": utc_now().isoformat()
            }
            with open(CONFIG_PATH, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving threat config: {e}")

    def _load_banned(self):
        """Load the persistent banned-IP list from disk."""
        try:
            if not BANNED_PATH.exists():
                return
            with open(BANNED_PATH, 'r') as f:
                data = json.load(f)
            for entry in data.get("banned", []):
                ip = entry.get("ip")
                if not ip:
                    continue
                btype = entry.get("type") or "manual"
                try:
                    banned_at = datetime.fromisoformat(entry["banned_at"])
                except Exception:
                    banned_at = datetime.now(timezone.utc)
                self.banned_threats[f"{ip}_{btype}"] = BannedThreat(
                    ip=ip,
                    type=btype,
                    reason=entry.get("reason") or "Banned",
                    banned_at=banned_at,
                    permanent=entry.get("permanent", True),
                )
            logger.info(f"Loaded {len(self.banned_threats)} persisted ban(s)")
        except Exception as e:
            logger.error(f"Error loading banned IPs: {e}")

    def _save_banned(self):
        """Persist the banned-IP list to disk."""
        try:
            BANNED_PATH.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "banned": [
                    {
                        "ip": ban.ip,
                        "type": ban.type,
                        "reason": ban.reason,
                        "banned_at": ban.banned_at.isoformat(),
                        "permanent": ban.permanent,
                    }
                    for ban in self.banned_threats.values()
                ],
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            with open(BANNED_PATH, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving banned IPs: {e}")

    async def restore_bans(self):
        """Re-apply persisted bans to the firewall on startup (idempotent).

        iptables rules do not survive a reboot, and the in-memory list does not
        survive a backend restart; re-applying the saved list on startup keeps
        the firewall and the UI in sync after either event.
        """
        if not self.banned_threats:
            return
        from app.services.firewall_service import firewall_service
        applied = 0
        for ban in list(self.banned_threats.values()):
            try:
                await firewall_service.block_ip(ban.ip)
                applied += 1
            except Exception as e:
                logger.error(f"Failed to re-apply ban for {ban.ip}: {e}")
        logger.info(f"Re-applied {applied} persisted ban(s) to firewall")

    async def auto_start_if_enabled(self):
        """Start monitoring if it was enabled (called on backend startup)"""
        if self._enabled_on_startup:
            await self.start_monitoring()
        else:
            logger.info("Threat monitoring disabled by config")
        
    async def start_monitoring(self):
        """Start continuous threat monitoring"""
        if self.monitoring:
            return {"status": "already_running"}
        
        self.monitoring = True
        self._save_config()
        logger.info("Started threat monitoring")
        
        # Start monitoring tasks
        tasks: List[asyncio.Task] = []

        # Connection monitoring works without journal access (best-effort).
        tasks.append(asyncio.create_task(self._monitor_connections()))

        # Periodic cleanup: expire stale threat records + prune counters so the
        # in-memory state stays bounded no matter how many attacks come in.
        tasks.append(asyncio.create_task(self._periodic_cleanup()))

        # SSH brute-force detection uses the system journal. If the service user cannot read
        # journald, don't start journal tasks (prevents tight loops / high CPU on failures).
        if await self._can_read_journalctl():
            tasks.append(asyncio.create_task(self._monitor_journalctl()))
            tasks.append(asyncio.create_task(self._scan_historical_logs()))
        else:
            logger.warning(
                "Threat monitoring: journal access unavailable; SSH auth monitoring disabled. "
                "Hint: run backend with access to journald (e.g. systemd unit SupplementaryGroups=systemd-journal)."
            )

        self._monitor_tasks = tasks
        
        return {"status": "started"}
    
    async def stop_monitoring(self):
        """Stop threat monitoring"""
        if not self.monitoring:
            return {"status": "already_stopped"}
            
        self.monitoring = False
        self._save_config()
        
        # Cancel tasks
        tasks = list(self._monitor_tasks)
        for task in tasks:
            task.cancel()
        self._monitor_tasks = []
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("Stopped threat monitoring")
        return {"status": "stopped"}
    
    async def _scan_historical_logs(self):
        """Scan recent SSH logs on startup"""
        try:
            # Get last 1 hour of SSH failures (cap lines to avoid large memory spikes).
            process = await asyncio.create_subprocess_shell(
                "journalctl -u ssh -u sshd --since '1 hour ago' -n 2000 --no-pager -o cat 2>/dev/null || "
                "journalctl _COMM=sshd --since '1 hour ago' -n 2000 --no-pager -o cat 2>/dev/null",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(process.communicate(), timeout=15)
            
            if stdout:
                lines = stdout.decode().split('\n')
                for line in lines:
                    await self._parse_auth_line(line)
                    
                logger.info(f"Scanned {len(lines)} historical log entries")
                
        except Exception as e:
            logger.debug(f"Error scanning historical logs: {e}")

    async def _can_read_journalctl(self) -> bool:
        """Best-effort check whether journalctl is readable for SSH monitoring."""
        cmd = (
            "journalctl -u ssh -u sshd -n 1 --no-pager -o cat 2>/dev/null || "
            "journalctl _COMM=sshd -n 1 --no-pager -o cat 2>/dev/null"
        )
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.communicate(), timeout=5.0)
            return process.returncode == 0
        except Exception:
            return False
    
    async def _monitor_journalctl(self):
        """Monitor SSH logs via journalctl -f (follow mode)"""
        logger.info("Starting journalctl SSH monitor")
        
        while self.monitoring:
            process = None
            try:
                # Use journalctl -f to follow new entries
                process = await asyncio.create_subprocess_shell(
                    "journalctl -u ssh -u sshd -n 0 -f --no-pager -o cat 2>/dev/null || "
                    "journalctl _COMM=sshd -n 0 -f --no-pager -o cat 2>/dev/null",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                
                while self.monitoring:
                    line = await process.stdout.readline()
                    if not line:
                        # EOF / journalctl exited. Restart with a delay to avoid tight loops.
                        break
                    await self._parse_auth_line(line.decode(errors="ignore"))
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in journalctl monitor: {e}")
            finally:
                if process and process.returncode is None:
                    try:
                        process.kill()
                        await process.wait()
                    except Exception:
                        pass

            # Restart delay (prevents high CPU if journalctl exits immediately)
            if self.monitoring:
                await asyncio.sleep(5)
    
    async def _parse_auth_line(self, line: str):
        """Parse auth line for threats"""
        if not line:
            return
            
        # Failed password attempt
        if "Failed password" in line or "authentication failure" in line.lower():
            ip_match = re.search(r'from\s+([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                await self._record_ssh_failure(ip, "failed_password")
        
        # Invalid user attempt
        elif "Invalid user" in line or "invalid user" in line:
            ip_match = re.search(r'from\s+([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                await self._record_ssh_failure(ip, "invalid_user")
        
        # Connection closed during auth
        elif "Connection closed by authenticating user" in line:
            ip_match = re.search(r'([\d\.]+)\s+port', line)
            if ip_match:
                ip = ip_match.group(1)
                self.ip_counters[ip]['ssh_connections'] += 1
        
        # Preauth disconnection (possible scan)
        elif "Disconnected from" in line and "preauth" in line.lower():
            ip_match = re.search(r'from\s+([\d\.]+)', line)
            if ip_match:
                ip = ip_match.group(1)
                self.ip_counters[ip]['preauth_disconnect'] += 1
                if self.ip_counters[ip]['preauth_disconnect'] >= 10:
                    await self._record_ssh_failure(ip, "scan_detected")
    
    async def _record_ssh_failure(self, ip: str, reason: str = "failed_password"):
        """Record SSH login failure"""
        # Skip local/private IPs to avoid self-blocking or noise from LAN
        if is_local_or_private_ip(ip):
            return
            
        self.ip_counters[ip]['ssh_failures'] += 1
        count = self.ip_counters[ip]['ssh_failures']
        
        threat_key = f"ssh_{ip}"
        now = utc_now()
        
        if threat_key in self.threats:
            # Update existing threat
            threat = self.threats[threat_key]
            threat.count = count
            threat.last_seen = now
            threat.description = f"SSH brute force - {count} failed attempts ({reason})"
            
            # Escalate severity
            if count >= self.ssh_fail_threshold * 3:
                threat.severity = "critical"
            elif count >= self.ssh_fail_threshold * 2:
                threat.severity = "high"
        else:
            # Create new threat if threshold exceeded
            if count >= self.ssh_fail_threshold:
                severity = "critical" if count >= 15 else "high"
                
                self.threats[threat_key] = Threat(
                    ip=ip,
                    type="brute_force",
                    severity=severity,
                    description=f"SSH brute force - {count} failed attempts ({reason})",
                    count=count,
                    first_seen=now,
                    last_seen=now
                )
                
                logger.warning(f"🚨 Detected SSH brute force from {ip}: {count} failures")
                
                # Auto-ban if enabled
                if self.auto_ban_enabled:
                    await self._auto_ban_ip(ip)
    
    async def _auto_ban_ip(self, ip: str, threat_type: str = "brute_force", reason: str = None):
        """Automatically ban an IP using the SAME firewall path as a manual ban
        (iptables), and record it in the persistent banned list so it shows in the
        UI and can be removed with the Unban button."""
        try:
            from app.services.firewall_service import firewall_service
            await firewall_service.block_ip(ip)
            await self.mark_blocked(ip, threat_type=threat_type, reason=reason or "Auto-ban: threshold exceeded")
            logger.warning(f"🔒 Auto-banned IP {ip} ({threat_type})")
        except Exception as e:
            logger.error(f"Failed to auto-ban {ip}: {e}")
    
    async def _monitor_connections(self):
        """Monitor network connections for port scanning using multiple methods"""
        while self.monitoring:
            try:
                # Method 1: Check conntrack for new connections from same IP
                await self._check_conntrack()
                
                # Method 2: Check UFW logs for blocked connection attempts
                await self._check_ufw_logs()
                
                # Method 3: Original ss SYN_RECV check
                process = await asyncio.create_subprocess_shell(
                    "ss -tan 2>/dev/null | grep SYN_RECV",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, _ = await process.communicate()
                
                if stdout:
                    lines = stdout.decode().split('\n')
                    connection_count = defaultdict(int)
                    
                    for line in lines:
                        if not line.strip():
                            continue
                        
                        # Extract source IP
                        parts = line.split()
                        if len(parts) >= 5:
                            source = parts[4]
                            ip_match = re.match(r'([\d\.]+):\d+', source)
                            if ip_match:
                                ip = ip_match.group(1)
                                # Skip local/private IPs
                                if not is_local_or_private_ip(ip):
                                    connection_count[ip] += 1
                    
                    # Check for port scanning
                    for ip, count in connection_count.items():
                        if count >= self.port_scan_threshold:
                            await self._record_port_scan(ip, count)
                
                await asyncio.sleep(5)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring connections: {e}")
                await asyncio.sleep(10)
    
    async def _check_conntrack(self):
        """Check conntrack for port scanning - counts unique destination ports per source IP"""
        try:
            # Get recent connections from conntrack
            process = await asyncio.create_subprocess_shell(
                "/usr/sbin/conntrack -L 2>/dev/null | grep 'tcp.*SYN' || true",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                # Count unique destination ports per source IP
                ip_ports = defaultdict(set)
                
                for line in stdout.decode().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Extract source IP and destination port
                    # Format: tcp  6 117 SYN_SENT src=192.168.1.5 dst=192.168.1.1 sport=45678 dport=22
                    # Support both IPv4 and IPv6
                    src_match = re.search(r'src=([0-9a-fA-F:\.]+)', line)
                    dport_match = re.search(r'dport=(\d+)', line)
                    
                    if src_match and dport_match:
                        src_ip = src_match.group(1)
                        dport = dport_match.group(1)
                        
                        # Skip local/private IPs and obviously invalid IPs
                        if len(src_ip) < 7 or is_local_or_private_ip(src_ip):
                            continue
                        ip_ports[src_ip].add(dport)
                
                # If IP connected to many different ports = port scan
                for ip, ports in ip_ports.items():
                    if len(ports) >= 10:  # 10+ different ports = suspicious
                        await self._record_port_scan(ip, len(ports), "conntrack")
                        
        except Exception as e:
            logger.debug(f"Conntrack check error (may not be installed): {e}")
    
    async def _check_ufw_logs(self):
        """Check kernel logs for blocked connection attempts and port scan markers"""
        try:
            # Check for PORTSCAN markers from iptables recent module
            process = await asyncio.create_subprocess_shell(
                "/usr/bin/dmesg 2>/dev/null | grep -E 'PORTSCAN:.*SRC=' | tail -200",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await process.communicate()
            
            if stdout:
                # Count scanned ports per source IP
                ip_scanned_ports = defaultdict(set)
                
                for line in stdout.decode().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Extract source IP and destination port from PORTSCAN log
                    # Support both IPv4 and IPv6
                    src_match = re.search(r'SRC=([0-9a-fA-F:\.]+)', line)
                    dpt_match = re.search(r'DPT=(\d+)', line)
                    
                    if src_match and dpt_match:
                        src_ip = src_match.group(1)
                        dport = dpt_match.group(1)
                        
                        # Skip local/private IPs and obviously invalid IPs
                        if len(src_ip) < 7 or is_local_or_private_ip(src_ip):
                            continue
                        ip_scanned_ports[src_ip].add(dport)
                
                # Many scanned ports from same IP = port scan detected!
                for ip, ports in ip_scanned_ports.items():
                    if len(ports) >= 10:  # 10+ ports scanned = definitely suspicious
                        await self._record_port_scan(ip, len(ports), "iptables_recent")
            
            # Also check UFW BLOCK logs
            process2 = await asyncio.create_subprocess_shell(
                "/usr/bin/dmesg 2>/dev/null | grep -E 'UFW BLOCK.*SRC=.*DPT=' | tail -100",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout2, _ = await process2.communicate()
            
            if stdout2:
                ip_blocked_ports = defaultdict(set)
                
                for line in stdout2.decode().split('\n'):
                    if not line.strip():
                        continue
                    
                    # Match both IPv4 and IPv6 addresses
                    # IPv4: 192.168.1.1
                    # IPv6: 2001:0db8:0020:0000:0000:0000:0000:0bcf or fe80::1
                    src_match = re.search(r'SRC=([0-9a-fA-F:\.]+)', line)
                    dpt_match = re.search(r'DPT=(\d+)', line)
                    
                    if src_match and dpt_match:
                        src_ip = src_match.group(1)
                        dport = dpt_match.group(1)
                        
                        # Skip local/private IPs and obviously invalid IPs
                        if len(src_ip) < 7 or is_local_or_private_ip(src_ip):
                            continue
                            
                        ip_blocked_ports[src_ip].add(dport)
                
                for ip, ports in ip_blocked_ports.items():
                    if len(ports) >= 5:
                        await self._record_port_scan(ip, len(ports), "ufw_blocked")
                        
        except Exception as e:
            logger.debug(f"Log check error: {e}")
    
    async def _record_port_scan(self, ip: str, connection_count: int, source: str = "ss"):
        """Record potential port scanning activity"""
        threat_key = f"portscan_{ip}"
        now = utc_now()
        
        if threat_key in self.threats:
            threat = self.threats[threat_key]
            threat.count = max(threat.count, connection_count)  # Keep highest count
            threat.last_seen = now
        else:
            severity = "critical" if connection_count >= 50 else "high" if connection_count >= 20 else "medium"
            
            source_desc = {
                "ss": "SYN packets",
                "conntrack": "unique ports scanned",
                "ufw_blocked": "blocked port attempts"
            }.get(source, "connections")
            
            self.threats[threat_key] = Threat(
                ip=ip,
                type="port_scan",
                severity=severity,
                description=f"Port scan detected - {connection_count} {source_desc}",
                count=connection_count,
                first_seen=now,
                last_seen=now
            )
            
            logger.warning(f"🚨 Detected port scan from {ip}: {connection_count} {source_desc} (via {source})")
            
            # Auto-ban if enabled
            if self.auto_ban_enabled:
                await self._auto_ban_ip(ip, threat_type="port_scan")
    
    async def get_threats(
        self,
        severity: Optional[str] = None,
        blocked_only: bool = False,
        include_blocked: bool = False,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get list of detected threats
        
        Args:
            severity: Filter by severity level
            blocked_only: Only return blocked threats
            include_blocked: Include blocked threats (default: False - hide blocked)
            limit: Maximum number of threats to return
        """
        threats = []
        
        for threat in self.threats.values():
            if severity and threat.severity != severity:
                continue
            
            if blocked_only and not threat.blocked:
                continue
            
            # By default, hide blocked threats (they are in banned list)
            if not include_blocked and not blocked_only and threat.blocked:
                continue
            
            threats.append({
                "ip": threat.ip,
                "type": threat.type,
                "severity": threat.severity,
                "description": threat.description,
                "count": threat.count,
                "first_seen": threat.first_seen.isoformat(),
                "last_seen": threat.last_seen.isoformat(),
                "blocked": threat.blocked
            })
        
        # Sort by severity and last seen
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        threats.sort(
            key=lambda x: (severity_order.get(x["severity"], 4), x["last_seen"]),
            reverse=True
        )
        
        return threats[:limit]
    
    async def get_threat_by_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get threat details for specific IP"""
        for threat in self.threats.values():
            if threat.ip == ip:
                return {
                    "ip": threat.ip,
                    "type": threat.type,
                    "severity": threat.severity,
                    "description": threat.description,
                    "count": threat.count,
                    "first_seen": threat.first_seen.isoformat(),
                    "last_seen": threat.last_seen.isoformat(),
                    "blocked": threat.blocked
                }
        return None
    
    async def mark_blocked(self, ip: str, threat_type: str = None, reason: str = None) -> bool:
        """Mark an IP as blocked and add it to the persistent banned list.

        The ban is recorded even if the IP was never a detected threat (e.g. a
        manual ban of an arbitrary IP), so the Banned list always reflects what
        the firewall is actually blocking.
        """
        matched_type = None
        matched_desc = None
        for threat in self.threats.values():
            if threat.ip != ip:
                continue
            if threat_type and threat.type != threat_type:
                continue
            threat.blocked = True
            matched_type = threat.type
            matched_desc = threat.description
            if threat_type:
                break

        ban_type = threat_type or matched_type or "manual"
        ban_key = f"{ip}_{ban_type}"
        self.banned_threats[ban_key] = BannedThreat(
            ip=ip,
            type=ban_type,
            reason=reason or matched_desc or "Manual ban",
            banned_at=datetime.now(timezone.utc),
            permanent=True,
        )
        self._save_banned()
        logger.info(f"Recorded ban for {ip} (type={ban_type})")
        return True
    
    async def mark_unblocked(self, ip: str, threat_type: str = None) -> bool:
        """Mark threat as unblocked and remove from the persistent banned list."""
        found = False
        for threat in list(self.threats.values()):
            if threat.ip == ip:
                if threat_type and threat.type != threat_type:
                    continue
                threat.blocked = False
                logger.info(f"Marked {ip} (type={threat.type}) as unblocked")
                found = True

        # Remove from banned list
        if threat_type:
            if self.banned_threats.pop(f"{ip}_{threat_type}", None) is not None:
                found = True
        else:
            # Remove all bans for this IP
            for k in [k for k in self.banned_threats if k.startswith(f"{ip}_")]:
                del self.banned_threats[k]
                found = True

        self._save_banned()
        return found
    
    async def get_banned_threats(self) -> List[Dict[str, Any]]:
        """Get list of all banned threats"""
        banned_list = []
        for ban_key, ban in self.banned_threats.items():
            banned_list.append({
                "id": ban_key,
                "ip": ban.ip,
                "type": ban.type,
                "reason": ban.reason,
                "bannedAt": ban.banned_at.isoformat(),
                "expiresAt": None,
                "permanent": ban.permanent
            })
        return banned_list
    
    async def clear_threat(self, ip: str) -> bool:
        """Remove threat from list"""
        keys_to_remove = [k for k, t in self.threats.items() if t.ip == ip]
        
        for key in keys_to_remove:
            del self.threats[key]
            logger.info(f"Cleared threat for {ip}")
        
        # Clear counters
        if ip in self.ip_counters:
            del self.ip_counters[ip]
        
        return len(keys_to_remove) > 0
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get threat detection statistics"""
        total = len(self.threats)
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        blocked_count = 0
        
        for threat in self.threats.values():
            by_severity[threat.severity] += 1
            by_type[threat.type] += 1
            if threat.blocked:
                blocked_count += 1
        
        return {
            "total_threats": total,
            "blocked_threats": blocked_count,
            "critical": by_severity.get("critical", 0),
            "high": by_severity.get("high", 0),
            "medium": by_severity.get("medium", 0),
            "low": by_severity.get("low", 0),
            "brute_force": by_type.get("brute_force", 0),
            "port_scan": by_type.get("port_scan", 0),
            "dns_abuse": by_type.get("dns_abuse", 0),
            "monitoring": self.monitoring
        }
    
    async def cleanup_old_threats(self, hours: int = None) -> int:
        """Expire stale (non-banned) threat records and prune their counters.

        Also drops orphan ip_counters (IPs with no active threat and no ban) so the
        per-IP counters can't grow unbounded across a long uptime. Bans are kept.
        """
        hours = hours if hours is not None else THREAT_RETENTION_HOURS
        cutoff = utc_now() - timedelta(hours=hours)

        # 1) Remove stale, non-blocked threats (+ their counters).
        keys_to_remove = [
            key for key, t in self.threats.items()
            if t.last_seen < cutoff and not t.blocked
        ]
        for key in keys_to_remove:
            ip = self.threats[key].ip
            del self.threats[key]
            self.ip_counters.pop(ip, None)

        # 2) Drop orphan counters: IPs that are neither an active threat nor banned.
        active_ips = {t.ip for t in self.threats.values()}
        banned_ips = {b.ip for b in self.banned_threats.values()}
        for ip in [ip for ip in self.ip_counters if ip not in active_ips and ip not in banned_ips]:
            del self.ip_counters[ip]

        if keys_to_remove:
            logger.info(f"Cleaned up {len(keys_to_remove)} old threat(s)")
        return len(keys_to_remove)

    async def _periodic_cleanup(self, interval_seconds: int = 3600):
        """Run cleanup_old_threats on a fixed interval while monitoring is on."""
        while self.monitoring:
            try:
                await asyncio.sleep(interval_seconds)
                if self.monitoring:
                    await self.cleanup_old_threats()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in periodic threat cleanup: {e}")

    async def clear_threats(self) -> int:
        """Manually clear all non-banned threat records now (UI 'Clear' button).

        Bans are left intact (use Unban to remove a ban). Returns the count cleared.
        """
        banned_ips = {b.ip for b in self.banned_threats.values()}
        keys_to_remove = [key for key, t in self.threats.items() if not t.blocked]
        for key in keys_to_remove:
            ip = self.threats[key].ip
            del self.threats[key]
            if ip not in banned_ips:
                self.ip_counters.pop(ip, None)
        logger.info(f"Manually cleared {len(keys_to_remove)} threat(s)")
        return len(keys_to_remove)
    
    async def get_status(self) -> Dict[str, Any]:
        """Get monitoring status for UI"""
        return {
            "enabled": self.monitoring,
            "ssh_threshold": self.ssh_fail_threshold,
            "auto_ban": self.auto_ban_enabled,
            "threats_count": len(self.threats),
            "uptime": None  # Could track start time
        }
    
    async def update_settings(
        self,
        ssh_threshold: Optional[int] = None,
        auto_ban: Optional[bool] = None
    ) -> Dict[str, Any]:
        """Update monitoring settings"""
        if ssh_threshold is not None:
            self.ssh_fail_threshold = max(1, min(100, ssh_threshold))
        
        if auto_ban is not None:
            self.auto_ban_enabled = auto_ban
        
        self._save_config()
        
        return await self.get_status()


# Global instance
threat_service = ThreatDetectionService()
