"""NetworkGatewayMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.network_toolkit_context import (
    ARPEntry,
    ARPScanResult,
    ActiveConnection,
    ConnectionFilters,
    HostStatus,
    LANDevice,
    LANScanConfig,
    LANScanResult,
    NetworkApiResponse,
    NetworkEdge,
    NetworkHost,
    NetworkMapConfig,
    NetworkMapData,
    NetworkNode,
    NetworkToolError,
    NetworkToolsService,
    OUIDatabase,
    Path,
    PortAlert,
    PortAlertConfig,
    PortInfo,
    PortScanConfig,
    PortScanResult,
    PortState,
    RiskLevel,
    SpeedTestConfig,
    SpeedTestResult,
    SpeedTestServer,
    TrafficData,
    TrafficStats,
    VALID_DEVICE_TYPES,
    _XSS_PATTERN,
    _normalize_device_type,
    _sanitize_string,
    asyncio,
    datetime,
    ipaddress,
    json,
    load_dhcp_identities,
    logger,
    logging,
    native_scanner,
    netifaces,
    os,
    psutil,
    re,
    resolve_arp_scan_binary,
    socket,
    time,
    utc_now,
)
from app.services.unknown_device_admission_service import (
    unknown_device_admission_service,
)


class NetworkGatewayMixin:
    async def get_gateway_mode_status(self) -> dict:
        """Return current gateway mode status without raising."""
        try:
            route = await self._get_default_route()
            interface = route.get("interface") or ""
            gateway_ip = route.get("gateway") or ""
            ip_forward = await self._read_ip_forward()
            current_ip, is_static = (
                await self._get_interface_ip(interface) if interface else ("", None)
            )
            nat_enabled = (
                await self._has_nat_masquerade(interface) if interface else False
            )
            enabled = bool(ip_forward and nat_enabled and is_static is True)
            return {
                "enabled": enabled,
                "static_ip": is_static,
                "nat_enabled": nat_enabled,
                "ip_forward": ip_forward,
                "current_ip": current_ip or None,
                "current_gateway": gateway_ip or None,
                "interface": interface or None,
            }
        except Exception as exc:
            return {"enabled": False, "error": str(exc)}

    async def verify_gateway_effective(self) -> dict:
        """Verify whether devices are ACTUALLY routing through EasyPi — not just
        whether gateway mode is enabled on the Pi. Counts distinct LAN devices
        whose internet traffic EasyPi is currently forwarding (conntrack), but
        only those PRESENT on the LAN right now (cross-checked against the
        neighbour table) and collapsed by MAC — so stale multi-day conntrack
        flows from devices that have left don't inflate the number.
        DNS-only mode yields 0 (the Pi only sees DNS to itself, no forwarding)."""
        status = await self.get_gateway_mode_status()
        route = await self._get_default_route()
        interface = route.get("interface") or ""
        router_ip = route.get("gateway") or ""
        pi_ip, _ = await self._get_interface_ip(interface) if interface else ("", None)
        pi_ip = pi_ip or ""

        # LAN IPs for which EasyPi has seen a *completed, bidirectional* internet
        # flow.  A packet rejected later by the admission firewall still creates
        # an UNREPLIED conntrack entry, so merely finding a LAN and WAN address is
        # not evidence that internet access worked.
        candidates: set[str] = set()
        verification_available = True
        if pi_ip and "." in pi_ip:
            lan_prefix = ".".join(pi_ip.split(".")[:3]) + "."
            ignore = {pi_ip, router_ip}
            rc, out, _ = await self._run_cmd(["sudo", "conntrack", "-L"], timeout=8)
            if rc != 0:
                verification_available = False
            elif out:
                for line in out.splitlines():
                    if "[ASSURED]" not in line:
                        continue
                    ips = re.findall(r"\d+\.\d+\.\d+\.\d+", line)
                    lan_ips = {
                        ip
                        for ip in ips
                        if ip.startswith(lan_prefix) and ip not in ignore
                    }
                    wan_ips = {
                        ip
                        for ip in ips
                        if not ip.startswith(lan_prefix) and not ip.startswith("127.")
                    }
                    if lan_ips and wan_ips:
                        candidates |= lan_ips

        # conntrack keeps TCP flows for days, so `candidates` includes devices that
        # have long since left. Require confirmed neighbour reachability and
        # count distinct MACs so cached addresses do not imply current presence.
        present_mac: dict[str, str] = {}
        neighbour_table_available = False
        if interface:
            rc, out, _ = await self._run_cmd(
                ["ip", "neigh", "show", "dev", interface], timeout=5
            )
            neighbour_table_available = rc == 0
            if neighbour_table_available and out:
                for line in out.splitlines():
                    ipm = re.match(r"(\d+\.\d+\.\d+\.\d+)\b", line)
                    macm = re.search(r"\blladdr\s+([0-9a-fA-F:]{17})", line)
                    if not ipm or not macm:
                        continue  # no resolved MAC -> not currently present
                    if "REACHABLE" not in line.split():
                        continue
                    ip = ipm.group(1)
                    if ip not in {pi_ip, router_ip}:
                        present_mac[ip] = macm.group(1).lower()

        if neighbour_table_available:
            # one representative IP per present device (MAC), so device_ips lines
            # up 1:1 with the count even when a device holds several leases.
            by_mac: dict[str, str] = {}
            for ip in sorted(
                ip
                for ip in candidates
                if ip in present_mac
                and self._gateway_pair_allowed(present_mac[ip], ip)
            ):
                by_mac.setdefault(present_mac[ip], ip)
            routing_ips = sorted(by_mac.values())
            device_count = len(by_mac)
        else:
            verification_available = False
            routing_ips = []
            device_count = 0

        visible_by_mac: dict[str, str] = {}
        for ip in sorted(present_mac):
            visible_by_mac.setdefault(present_mac[ip], ip)
        visible_ips = sorted(visible_by_mac.values())

        return {
            "configured": bool(status.get("enabled")),
            "effective": device_count > 0,
            "verification_available": verification_available,
            "devices_routed": device_count,
            "device_ips": routing_ips[:20],
            "devices_present": len(visible_by_mac),
            "present_ips": visible_ips[:20],
            "easypi_ip": pi_ip or None,
            "router_ip": router_ip or None,
            "ip_forward": status.get("ip_forward"),
            "nat_enabled": status.get("nat_enabled"),
            "static_ip": status.get("static_ip"),
        }

    @staticmethod
    def _gateway_pair_allowed(mac: str, ip: str) -> bool:
        return unknown_device_admission_service.is_pair_allowed(mac, ip)

    async def enable_gateway_mode(self) -> dict:
        """Enable gateway mode (IP forwarding + NAT) on the default interface."""
        route = await self._get_default_route()
        interface = route.get("interface") or ""
        if not interface:
            return {"success": False, "error": "Default interface not found"}

        current_ip, _ = await self._get_interface_ip(interface)
        gateway_ip = route.get("gateway") or ""
        lan_iface, wan_iface = await self._detect_lan_wan_interfaces(interface)
        if not wan_iface:
            wan_iface = interface

        # Persist gateway-mode context so gateway_fix.sh can recover even if
        # router DHCP starts advertising EasyPi as gateway (loop).
        prefix_len = await self._get_interface_prefix_len(interface)
        self._write_gateway_state(
            {
                "version": 1,
                "enabled": True,
                "updated_at": utc_now().isoformat() + "Z",
                "interface": interface,
                "lan_iface": lan_iface or interface,
                "wan_iface": wan_iface or interface,
                "easypi_ip": current_ip or None,
                "prefix_len": prefix_len,
                "real_gateway": gateway_ip or None,
            }
        )

        await self._persist_ip_forward(True)

        ok, err = await self._run_runner(
            "settings/network_firewall.sh",
            ["gateway-enable", wan_iface, lan_iface or wan_iface],
            timeout=15,
        )
        if not ok:
            return {
                "success": False,
                "error": err or "Failed to configure gateway firewall",
            }

        # Ensure UFW allows routed traffic (otherwise FORWARD policy may drop)
        await self._configure_ufw_route(lan_iface or wan_iface, wan_iface, enable=True)
        await self._persist_firewall_rules()
        await self._ensure_gateway_fix_timer(enable=True)

        # Ensure static IP is actually set (critical for gateway stability).
        # Give NetworkManager a moment to apply changes.
        current_ip, is_static = (
            await self._get_interface_ip(interface) if interface else ("", None)
        )
        if not is_static:
            for _ in range(3):
                await asyncio.sleep(1)
                current_ip, is_static = (
                    await self._get_interface_ip(interface) if interface else ("", None)
                )
                if is_static:
                    break
        if not is_static:
            return {
                "success": False,
                "error": "Failed to set static IP for gateway mode. NetworkManager did not switch to manual IP.",
                "details": {
                    "interface": interface or None,
                    "current_ip": current_ip or None,
                    "current_gateway": gateway_ip or None,
                },
            }

        status = await self.get_gateway_mode_status()
        verification = await self.verify_gateway_effective()
        return {
            "success": True,
            "easypi_ip": current_ip or None,
            "real_gateway": gateway_ip or None,
            "status": status,
            "verification": verification,
            "router_instructions": {
                "dhcp_gateway": current_ip or "",
                "dhcp_dns": current_ip or "",
                "note": "Set DHCP gateway and DNS to EasyPi IP for full gateway mode.",
            },
        }

    async def disable_gateway_mode(self) -> dict:
        """Disable gateway mode (remove NAT + forwarding)."""
        route = await self._get_default_route()
        interface = route.get("interface") or ""
        lan_iface, wan_iface = await self._detect_lan_wan_interfaces(interface)
        if not wan_iface:
            wan_iface = interface

        if wan_iface:
            await self._run_runner(
                "settings/network_firewall.sh",
                ["gateway-disable", wan_iface, lan_iface or wan_iface],
                timeout=15,
            )

        await self._configure_ufw_route(lan_iface or wan_iface, wan_iface, enable=False)
        await self._persist_firewall_rules()
        await self._ensure_gateway_fix_timer(enable=False)

        await self._persist_ip_forward(False)

        self._write_gateway_state(
            {
                "version": 1,
                "enabled": False,
                "updated_at": utc_now().isoformat() + "Z",
            }
        )

        return {"success": True, "status": await self.get_gateway_mode_status()}

    async def fix_gateway_mode(self) -> dict:
        """
        Run gateway repair script (best-effort) and return updated status.

        This is used by UI when full gateway mode is enabled but internet is down.
        """
        script_path = "/opt/EasyPi/scripts/setup/gateway_fix.sh"
        if not os.path.exists(script_path):
            return {"success": False, "error": f"Missing script: {script_path}"}

        ok, err = await self._run_sudo([script_path], timeout=60)
        status = await self.get_gateway_mode_status()

        log_tail = ""
        rc, out, _ = await self._run_cmd(
            ["tail", "-n", "80", "/var/log/easypi/gateway_fix.log"], timeout=5
        )
        if rc == 0:
            log_tail = out

        return {
            "success": ok,
            "error": err if not ok else None,
            "status": status,
            "log_tail": log_tail,
        }

    async def _get_default_route(self) -> dict:
        rc, out, _ = await self._run_cmd(["ip", "route", "show", "default"])
        gateway = ""
        interface = ""
        if rc == 0 and out:
            for line in out.splitlines():
                parts = line.strip().split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        gateway = parts[idx + 1]
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        interface = parts[idx + 1]
                if interface:
                    break

        if not interface:
            rc, out, _ = await self._run_cmd(["ip", "route", "get", "1.1.1.1"])
            if rc == 0 and out:
                parts = out.split()
                if "via" in parts:
                    idx = parts.index("via")
                    if idx + 1 < len(parts):
                        gateway = parts[idx + 1]
                if "dev" in parts:
                    idx = parts.index("dev")
                    if idx + 1 < len(parts):
                        interface = parts[idx + 1]

        return {"gateway": gateway, "interface": interface}

    async def _get_interface_ip(self, interface: str) -> tuple[str, bool | None]:
        if not interface:
            return "", None
        rc, out, _ = await self._run_cmd(["ip", "-o", "-4", "addr", "show", interface])
        if rc != 0 or not out:
            return "", None
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        ip_addr = match.group(1) if match else ""
        is_static = None
        if out:
            is_static = "dynamic" not in out
        return ip_addr, is_static

    async def _get_interface_cidr(self, interface: str) -> str:
        if not interface:
            return ""
        rc, out, _ = await self._run_cmd(["ip", "-o", "-4", "addr", "show", interface])
        if rc != 0 or not out:
            return ""
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not match:
            return ""
        ip_addr = match.group(1)
        prefix = match.group(2)
        try:
            return str(ipaddress.ip_network(f"{ip_addr}/{prefix}", strict=False))
        except Exception:
            return ""

    async def _detect_lan_wan_interfaces(self, wan_iface: str) -> tuple[str, str]:
        """Detect LAN/WAN interfaces. WAN from default route; LAN from private IPv4 interface."""
        lan_iface = ""
        if not wan_iface:
            return lan_iface, wan_iface
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}

        candidates: list[str] = []
        for iface in self._interface_names():
            if self._is_virtual_iface(iface):
                continue
            if iface == wan_iface:
                continue
            if iface in stats and not stats[iface].isup:
                continue
            addrs = self._ipv4_addresses(iface)
            if not addrs:
                continue
            ip_addr = addrs[0].get("addr")
            if not ip_addr:
                continue
            try:
                if ipaddress.ip_address(ip_addr).is_private:
                    candidates.append(iface)
            except ValueError:
                continue

        lan_iface = candidates[0] if candidates else wan_iface
        return lan_iface, wan_iface

    def _guess_lan_interface(self, wan_iface: str) -> str:
        try:
            stats = psutil.net_if_stats()
        except Exception:
            stats = {}

        candidates: list[str] = []
        for iface in self._interface_names():
            if self._is_virtual_iface(iface):
                continue
            if iface == wan_iface:
                continue
            if iface in stats and not stats[iface].isup:
                continue
            addrs = self._ipv4_addresses(iface)
            if not addrs:
                continue
            candidates.append(iface)

        return candidates[0] if candidates else wan_iface

    def _is_virtual_iface(self, iface: str) -> bool:
        prefixes = (
            "lo",
            "docker",
            "br-",
            "veth",
            "virbr",
            "vmnet",
            "zt",
            "tailscale",
            "wg",
            "tun",
            "tap",
            "lxc",
        )
        return iface == "lo" or iface.startswith(prefixes)

    async def _read_ip_forward(self) -> bool:
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "r", encoding="utf-8") as handle:
                return handle.read().strip() == "1"
        except Exception:
            return False

    async def _has_nat_masquerade(self, interface: str) -> bool:
        if not interface:
            return False
        rc, out, _ = await self._run_cmd(
            ["sudo", "iptables", "-t", "nat", "-S", "POSTROUTING"]
        )
        if rc != 0:
            return False
        # Only consider gateway-mode NAT (no source subnet restriction).
        # This avoids treating VPN NAT rules (e.g. -s 10.8.0.0/24) as gateway mode.
        target = f"-o {interface} -j MASQUERADE"
        return any(target in line and " -s " not in line for line in out.splitlines())

    async def _ufw_active(self) -> bool:
        runner = os.getenv("EASYPI_RUNNER", "/opt/EasyPi/scripts/runner")
        rc, out, _ = await self._run_cmd(
            [
                "sudo",
                "-n",
                runner,
                "settings/network_firewall.sh",
                "ufw-status",
                "verbose",
            ]
        )
        return rc == 0 and "Status: active" in out

    async def _configure_ufw_route(
        self, lan_iface: str, wan_iface: str, enable: bool
    ) -> None:
        if not lan_iface or not wan_iface:
            return
        if not await self._ufw_active():
            return
        await self._run_runner(
            "settings/network_firewall.sh",
            ["ufw-route", "add" if enable else "delete", lan_iface, wan_iface],
            timeout=10,
        )
        if enable:
            await self._run_runner(
                "settings/network_firewall.sh",
                ["ufw-reload"],
                timeout=10,
            )

    async def _persist_firewall_rules(self) -> None:
        """Persist firewall rules through the fixed root-owned serializer."""
        await self._run_runner(
            "settings/network_firewall.sh",
            ["persist"],
            timeout=10,
        )

    async def _ensure_gateway_fix_timer(self, enable: bool) -> None:
        service_src = "/opt/EasyPi/templates/systemd/easypi-gateway-fix.service"
        timer_src = "/opt/EasyPi/templates/systemd/easypi-gateway-fix.timer"
        script_path = "/opt/EasyPi/scripts/setup/gateway_fix.sh"

        if enable:
            if os.path.exists(service_src):
                await self._run_runner(
                    "settings/gateway_config.sh",
                    ["install-gateway-service"],
                    timeout=10,
                )
            if os.path.exists(timer_src):
                await self._run_runner(
                    "settings/gateway_config.sh", ["install-gateway-timer"], timeout=10
                )
            if os.path.exists(script_path):
                await self._run_runner(
                    "settings/gateway_config.sh", ["chmod-gateway-fix"], timeout=10
                )
                await self._run_sudo(["systemctl", "daemon-reload"])
                await self._run_sudo(
                    ["systemctl", "enable", "--now", "easypi-gateway-fix.timer"]
                )
                await self._run_sudo([script_path])
        else:
            await self._run_sudo(
                ["systemctl", "disable", "--now", "easypi-gateway-fix.timer"]
            )

    async def _persist_ip_forward(self, enabled: bool) -> None:
        """Persist IP forwarding across reboots without sudo shell redirection."""
        value = "1" if enabled else "0"
        await self._run_runner(
            "settings/gateway_config.sh", ["persist-ip-forward", value], timeout=10
        )

    async def _run_cmd(self, args: list[str], timeout: int = 5) -> tuple[int, str, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return 124, "", "timeout"
            return proc.returncode, stdout.decode().strip(), stderr.decode().strip()
        except Exception as exc:
            return 1, "", str(exc)

    async def _run_sudo(self, args: list[str], timeout: int = 5) -> tuple[bool, str]:
        rc, _, err = await self._run_cmd(["sudo"] + args, timeout=timeout)
        return rc == 0, err

    async def _run_runner(
        self, script: str, args: list[str] | None = None, timeout: int = 5
    ) -> tuple[bool, str]:
        runner = os.getenv("EASYPI_RUNNER", "/opt/EasyPi/scripts/runner")
        rc, _, err = await self._run_cmd(
            ["sudo", "-n", runner, script] + (args or []), timeout=timeout
        )
        return rc == 0, err
