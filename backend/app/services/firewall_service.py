"""
Firewall Service

Handles UFW firewall rule management.
"""

import asyncio
import subprocess
import logging
import re
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.core.paths import get_easypi_root
from app.models.security import FirewallRule
from app.schemas.security import FirewallRuleResponse, FirewallRuleCreate

logger = logging.getLogger(__name__)


class FirewallService:
    """Service for managing firewall rules"""

    def __init__(self):
        pass

    @staticmethod
    def _network_control_cmd(*args: str) -> list[str]:
        return [
            "sudo", "-n", str(get_easypi_root() / "scripts" / "runner"),
            "settings/network_firewall.sh", *args,
        ]

    # --- Pi-Guard helpers (async, no DB) ---

    async def get_rules(self) -> List[Dict[str, Any]]:
        """Return parsed UFW rules (numbered status)."""
        return await asyncio.to_thread(self._get_rules_sync)

    def _get_rules_sync(self) -> List[Dict[str, Any]]:
        rules: List[Dict[str, Any]] = []
        try:
            result = subprocess.run(
                self._network_control_cmd("ufw-status", "numbered"),
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.error("Failed to get UFW status: %s", result.stderr)
                return []

            for line in result.stdout.splitlines():
                if not line.strip() or "Status:" in line or "To" in line or "---" in line:
                    continue

                # Parse rule number
                rule_match = re.search(r"\[\s*(\d+)\]", line)
                if not rule_match:
                    continue
                
                rule_id = int(rule_match.group(1))
                is_ipv6 = "(v6)" in line
                
                # Determine action
                target = "allow"
                if "DENY" in line.upper():
                    target = "deny"
                elif "LIMIT" in line.upper():
                    target = "limit"
                elif "REJECT" in line.upper():
                    target = "reject"

                # Direction (IN / OUT / FWD) and bound interface ("... on eth0 ...")
                dir_match = re.search(r"\b(?:ALLOW|DENY|LIMIT|REJECT)\s+(IN|OUT|FWD)\b", line, re.IGNORECASE)
                direction = dir_match.group(1).upper() if dir_match else "IN"
                # Interface the rule is bound to. For FWD rules the SOURCE (incoming)
                # interface sits after "FWD" (the From side) and is what iptables'
                # forward chain matches on (-i); for IN/OUT it's the first "on <iface>".
                ifaces = re.findall(r"\bon\s+(\w+)", line)
                interface = (ifaces[-1] if direction == "FWD" else ifaces[0]) if ifaces else ""

                # Try to parse port/protocol rules: "[ 1] 22/tcp ALLOW IN Anywhere"
                port_match = re.search(r"\[\s*\d+\]\s+([\w\-]+)/(tcp|udp)", line, re.IGNORECASE)
                if port_match:
                    port = port_match.group(1)
                    protocol = port_match.group(2).lower()
                else:
                    port = "any"
                    protocol = "any"
                
                # Parse source IP - look for IP address pattern
                source = "any"
                # Pattern for "from IP" or IP at end of line
                source_match = re.search(r"(?:from\s+|IN\s+)([\d\.]+(?:/\d+)?)\s*(?:#|$)", line, re.IGNORECASE)
                if source_match:
                    source = source_match.group(1)
                # Also check for IP-based deny rules like "Anywhere DENY IN 198.51.100.25"
                elif "DENY" in line.upper():
                    ip_match = re.search(r"([\d]+\.[\d]+\.[\d]+\.[\d]+(?:/\d+)?)", line)
                    if ip_match:
                        source = ip_match.group(1)

                # Create description with IPv6 indicator
                description = f"{'IPv6 ' if is_ipv6 else ''}Rule {rule_id}"

                rules.append(
                    {
                        "id": rule_id,
                        "description": description,
                        "target": target,
                        "protocol": protocol,
                        "port": port,
                        "source": source,
                        "destination": "any",
                        "direction": direction,
                        "interface": interface,
                        "ipv6": is_ipv6,
                        "created_at": None,
                        "hits": 0,
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Error parsing UFW rules: %s", exc)

        # Fill in real per-rule packet counts from the underlying iptables chains.
        try:
            self._attach_hits(rules)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Could not attach firewall hit counts: %s", exc)

        return rules

    def _collect_ufw_hit_entries(self, ipv6: bool) -> List[Dict[str, Any]]:
        """Read packet counters from the ufw-user-* iptables chains."""
        cmd_name = "ip6tables" if ipv6 else "iptables"
        chains = {"ufw-user-input": "IN", "ufw-user-forward": "FWD", "ufw-user-output": "OUT"}
        entries: List[Dict[str, Any]] = []
        for chain, direction in chains.items():
            try:
                result = subprocess.run(
                    ["sudo", cmd_name, "-L", chain, "-n", "-v", "-x"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            except Exception:
                continue
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 8 or not parts[0].isdigit():
                    continue
                proto = parts[3].lower()
                if proto in ("0", "all"):
                    proto = "any"
                in_if = parts[5]
                dport_match = re.search(r"dpt:(\d+)", line)
                entries.append(
                    {
                        "direction": direction,
                        "proto": proto,
                        "dport": dport_match.group(1) if dport_match else "",
                        "iface": "" if in_if == "*" else in_if,
                        "pkts": int(parts[0]),
                    }
                )
        return entries

    def _attach_hits(self, rules: List[Dict[str, Any]]) -> None:
        """Match each UFW rule to its iptables counter and set rule['hits']."""
        cache: Dict[bool, List[Dict[str, Any]]] = {}
        for rule in rules:
            ipv6 = bool(rule.get("ipv6"))
            if ipv6 not in cache:
                cache[ipv6] = self._collect_ufw_hit_entries(ipv6)
            direction = rule.get("direction", "IN")
            proto = rule.get("protocol", "any")
            port = rule.get("port", "any")
            iface = rule.get("interface", "")
            total = 0
            for e in cache[ipv6]:
                if e["direction"] != direction:
                    continue
                if port == "any":
                    if e["dport"]:
                        continue
                elif e["dport"] != port:
                    continue
                if proto != "any" and e["proto"] != proto:
                    continue
                if e["iface"] != iface:
                    continue
                total += e["pkts"]
            rule["hits"] = total

    async def block_ip(self, ip: str, duration: Optional[int] = None) -> Dict[str, str]:
        """Add deny rule for IP using iptables (works even when UFW is disabled)."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo", "-n", str(get_easypi_root() / "scripts" / "runner"),
                    "settings/network_firewall.sh", "block-ip", "add", ip,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Failed to block IP")
            
            if duration:
                logger.warning("Duration is not supported; ignoring value=%s", duration)
            
            logger.info("Blocked IP %s", ip)
            return {"status": "success", "message": f"IP {ip} blocked"}
        except Exception as exc:
            logger.error("Error blocking IP %s: %s", ip, exc)
            raise

    async def unblock_ip(self, ip: str) -> Dict[str, str]:
        """Remove deny rule for IP using iptables."""
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo", "-n", str(get_easypi_root() / "scripts" / "runner"),
                    "settings/network_firewall.sh", "block-ip", "remove", ip,
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.strip() or "Failed to unblock IP")
            logger.info("Unblocked IP %s", ip)
            return {"status": "success", "message": f"IP {ip} unblocked"}
        except Exception as exc:
            logger.error("Error unblocking IP %s: %s", ip, exc)
            raise

    async def get_blocked_ips(self) -> List[str]:
        """Return list of source IPs blocked via iptables/ip6tables DROP rules."""
        import ipaddress

        def _source_ip(line: str) -> Optional[str]:
            # A per-IP DROP rule looks like: "DROP  all  --  198.51.100.7  0.0.0.0/0"
            # The chain header ("Chain INPUT (policy DROP)") also contains "DROP" but
            # has no source IP, so we validate the source column before accepting it.
            if "DROP" not in line or line.startswith("Chain") or line.startswith("target"):
                return None
            parts = line.split()
            if len(parts) < 4:
                return None
            candidate = parts[3].split("/")[0]
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                return None
            if candidate in ("0.0.0.0", "::"):
                return None
            return parts[3]

        ips: List[str] = []
        try:
            for cmd in (["sudo", "iptables", "-L", "INPUT", "-n"],
                        ["sudo", "ip6tables", "-L", "INPUT", "-n"]):
                result = await asyncio.to_thread(
                    subprocess.run, cmd, capture_output=True, text=True, timeout=10,
                )
                if result.returncode != 0:
                    continue
                for line in result.stdout.splitlines():
                    ip = _source_ip(line)
                    if ip:
                        ips.append(ip)
        except Exception as exc:
            logger.error("Error getting blocked IPs: %s", exc)
        return ips

    async def add_rule_simple(
        self,
        action: str,
        protocol: str,
        port: str,
        source: str = "any",
    ) -> Dict[str, str]:
        """Add a simple UFW rule (allow/deny/limit/reject)."""
        action = action.lower()
        if action not in {"allow", "deny", "limit", "reject"}:
            raise ValueError("Invalid action")
        cmd = self._network_control_cmd(
            "ufw-rule", "add", action, protocol, str(port), source,
        )
        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to add rule")
        return {"status": "success", "message": result.stdout.strip() or "Rule added"}

    async def toggle_firewall(self, enabled: bool) -> Dict[str, str]:
        """Enable or disable UFW."""
        cmd = self._network_control_cmd(
            "ufw-toggle", "enable" if enabled else "disable",
        )
        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to toggle firewall")
        return {"status": "success", "message": result.stdout.strip() or f"Firewall {'enabled' if enabled else 'disabled'}"}

    async def delete_rule_simple(self, rule_number: int) -> Dict[str, str]:
        """Delete a UFW rule by its numbered index."""
        result = await asyncio.to_thread(
            subprocess.run,
            self._network_control_cmd("ufw-delete-number", str(rule_number)),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to delete rule")
        return {"status": "success", "message": result.stdout.strip() or "Rule deleted"}

    async def delete_rule_by_params(
        self,
        action: str,
        protocol: str,
        port: str,
        source: str = "any",
    ) -> Dict[str, str]:
        """Delete a UFW rule by the same parameters used to add it."""
        action = action.lower()
        cmd = self._network_control_cmd(
            "ufw-rule", "delete", action, protocol, str(port), source,
        )
        result = await asyncio.to_thread(
            subprocess.run,
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Failed to delete rule")
        return {"status": "success", "message": result.stdout.strip() or "Rule deleted"}

    def get_all_rules(self, db: Session) -> List[FirewallRuleResponse]:
        """Get all firewall rules from UFW"""
        try:
            # Get UFW status numbered
            result = subprocess.run(
                self._network_control_cmd("ufw-status", "numbered"),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.error("Failed to get UFW status")
                return []
            
            rules = []
            lines = result.stdout.split('\n')
            
            # Parse UFW output
            # Format: [ 1] 22/tcp                     ALLOW IN    Anywhere
            for line in lines:
                if not line.strip() or 'Status:' in line or '---' in line or 'To' in line:
                    continue
                
                # Extract rule number and details
                match = re.search(r'\[\s*(\d+)\]\s+(\d+)/(tcp|udp)\s+(ALLOW|DENY)', line)
                if match:
                    port = int(match.group(2))
                    protocol = match.group(3)
                    action = match.group(4).lower()
                    
                    # Extract source if present
                    source = "any"
                    if 'from' in line.lower():
                        source_match = re.search(r'from\s+([\d\./]+)', line.lower())
                        if source_match:
                            source = source_match.group(1)
                    
                    # Check if rule exists in DB
                    db_rule = db.query(FirewallRule).filter(
                        FirewallRule.port == port,
                        FirewallRule.protocol == protocol
                    ).first()
                    
                    if not db_rule:
                        # Create in DB
                        db_rule = FirewallRule(
                            port=port,
                            protocol=protocol,
                            source=source,
                            action=action,
                            is_active=True
                        )
                        db.add(db_rule)
                        db.commit()
                        db.refresh(db_rule)
                    
                    rules.append(FirewallRuleResponse(
                        id=db_rule.id,
                        port=port,
                        protocol=protocol,
                        source=source,
                        action=action,
                        created_at=db_rule.created_at
                    ))
            
            return rules
            
        except Exception as e:
            logger.error(f"Error getting firewall rules: {e}")
            return []

    def add_rule(self, rule_data: FirewallRuleCreate, db: Session) -> FirewallRuleResponse:
        """Add new firewall rule"""
        try:
            # Build UFW command
            cmd = self._network_control_cmd(
                "ufw-rule", "add", "allow", rule_data.protocol,
                str(rule_data.port), rule_data.source,
            )
            
            # Execute command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise Exception(f"Failed to add rule: {result.stderr}")
            
            # Save to database
            db_rule = FirewallRule(
                port=rule_data.port,
                protocol=rule_data.protocol,
                source=rule_data.source,
                action="allow",
                is_active=True
            )
            db.add(db_rule)
            db.commit()
            db.refresh(db_rule)
            
            logger.info(f"Added firewall rule: {rule_data.port}/{rule_data.protocol}")
            
            return FirewallRuleResponse(
                id=db_rule.id,
                port=db_rule.port,
                protocol=db_rule.protocol,
                source=db_rule.source,
                action=db_rule.action,
                created_at=db_rule.created_at
            )
            
        except Exception as e:
            logger.error(f"Error adding firewall rule: {e}")
            raise

    def delete_rule(self, rule_id: int, db: Session) -> Dict[str, str]:
        """Delete firewall rule"""
        try:
            # Get rule from database
            db_rule = db.query(FirewallRule).filter(FirewallRule.id == rule_id).first()
            
            if not db_rule:
                raise Exception("Rule not found")
            
            # Delete from UFW
            # First, find the rule number in UFW
            result = subprocess.run(
                self._network_control_cmd("ufw-status", "numbered"),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.split('\n')
                ufw_rule_num = None
                
                for line in lines:
                    if f"{db_rule.port}/{db_rule.protocol}" in line:
                        match = re.search(r'\[\s*(\d+)\]', line)
                        if match:
                            ufw_rule_num = match.group(1)
                            break
                
                if ufw_rule_num:
                    # Delete using rule number
                    delete_result = subprocess.run(
                        self._network_control_cmd("ufw-delete-number", ufw_rule_num),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    
                    if delete_result.returncode != 0:
                        logger.warning(f"Failed to delete from UFW: {delete_result.stderr}")
            
            # Delete from database
            db.delete(db_rule)
            db.commit()
            
            logger.info(f"Deleted firewall rule: {db_rule.port}/{db_rule.protocol}")
            
            return {"status": "success", "message": "Rule deleted successfully"}
            
        except Exception as e:
            logger.error(f"Error deleting firewall rule: {e}")
            raise


# Create singleton instance
firewall_service = FirewallService()
