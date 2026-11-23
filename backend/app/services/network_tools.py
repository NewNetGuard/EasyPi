"""
EasyPi Network Tools Service
============================

Network diagnostic utilities for LAN scanning, port scanning, and network monitoring.
Uses native Python scanner for network discovery and analysis.

License: Proprietary (EasyPi)
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import re
import subprocess
import time
from typing import Iterable, Optional

import psutil
import socket

# Import native network scanner
from app.services.native_scanner import (
    native_scanner,
    PortResult,
    HostStatus,
    PortState,
)

logger = __import__("logging").getLogger(__name__)

# ARP cache with TTL (avoid repeated calls during batch operations)
_arp_cache: dict[str, str] = {}
_arp_cache_time: float = 0.0
_ARP_CACHE_TTL: float = 30.0  # seconds

# OUI (Organizationally Unique Identifier) to vendor mapping
# First 6 hex chars of MAC address (uppercase, no separators)
OUI_VENDOR_HINTS = {
    # Single-board computers
    "B827EB": "Raspberry Pi",
    "DC4A3E": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "2CCF67": "Raspberry Pi",
    # Apple
    "D8BBC1": "Apple",
    "F4F5D8": "Apple",
    "F0DCE2": "Apple",
    "A4B197": "Apple",
    "78CA39": "Apple",
    "AC87A3": "Apple",
    # Samsung
    "BC307D": "Samsung",
    "6405BE": "Samsung",
    "A0CBFD": "Samsung",
    "C45006": "Samsung",
    # LG
    "0016B6": "LG",
    "00256C": "LG",
    "A8233C": "LG",
    # Network equipment
    "000C43": "Cisco",
    "0018BA": "Cisco",
    "D85D4C": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "788A20": "Ubiquiti",
    "B8B42E": "Aruba",
    "001E58": "Asus",
    "2CFDA1": "Asus",
    "1C872C": "Asus",
    "14DDA9": "Asus",
    "B0D59D": "TP-Link",
    "50C7BF": "TP-Link",
    "EC086B": "TP-Link",
    "6466B3": "Mikrotik",
    "C4AD34": "Mikrotik",
    # Xiaomi/Huawei
    "D4C1FC": "Xiaomi",
    "9C65F9": "Xiaomi",
    "64B473": "Xiaomi",
    "A4C138": "Huawei",
    "C8D719": "Huawei",
    "5C7D5E": "Huawei",
    # Sony/Playstation
    "001B63": "Sony",
    "6CF049": "Sony",
    "F8D0AC": "Sony PlayStation",
    "28987B": "Sony PlayStation",
    # Other devices
    "001A11": "HP",
    "3C4A92": "HP",
    "001B78": "Canon",
    "B0C4E7": "Google",
    "F4F5E8": "Google",
    "3C5AB4": "Amazon",
    "F0272D": "Amazon",
    "00E04C": "Realtek",
    "001C23": "Dell",
    "FCAA14": "Synology",
    "001320": "Intel",
    "8C8CAA": "Intel",
    "3C970E": "Intel",
    "A44CC8": "Microsoft",
    "7C1E52": "Microsoft",
    "000F00": "Roku",
    "B840E6": "Roku",
    "001E8C": "Hisense",
    "00215A": "Vizio",
}
from app.schemas.network import (  # noqa: E402
    ArpEntry,
    ArpResponse,
    ConnectionInfo,
    ConnectionsResponse,
    DnsLookupResponse,
    HostScanResponse,
    NetworkHost,
    NetworkMapNode,
    NetworkMapResponse,
    PingResponse,
    PortAlert,
    PortAlertsResponse,
    PortInfo,
    PortScanResponse,
    SpeedtestResponse,
    TrafficResponse,
    TrafficSample,
)


class NetworkToolError(Exception):
    """Custom error for network tool failures."""

    def __init__(self, message: str, status_code: int = 500):
        super().__init__(message)
        self.status_code = status_code


class NetworkToolsService:
    """
    Service wrapper for network diagnostic utilities.
    Uses native Python scanner for host/port scanning.
    """

    def __init__(self):
        self.default_timeout = 60
        self.deep_semaphore = asyncio.Semaphore(1)
        self.deep_wait_timeout = 5.0  # seconds
        # Use native scanner instance
        self._scanner = native_scanner

    async def scan_hosts(self, network: str, deep: bool = False) -> HostScanResponse:
        """
        Scan network for hosts using native Python scanner.
        """
        # Use native scanner for host discovery
        try:
            scan_result = await self._scanner.discover_hosts(network)
        except ValueError as e:
            raise NetworkToolError(str(e), status_code=400)
        except Exception as e:
            raise NetworkToolError(f"Host scan failed: {e}", status_code=500)
        
        if scan_result.error:
            raise NetworkToolError(scan_result.error, status_code=400)
        
        # Convert to legacy format
        hosts = []
        for host in scan_result.hosts:
            hosts.append(NetworkHost(
                ip=host.ip,
                mac=host.mac,
                vendor=host.vendor,
                hostname=host.hostname,
                device_type=host.device_type,
                type_confidence=host.device_confidence,
                status="online" if host.status == HostStatus.ONLINE else "offline",
            ))
        
        # Optional deep mode: port scan on discovered hosts
        if deep:
            try:
                await asyncio.wait_for(self.deep_semaphore.acquire(), timeout=self.deep_wait_timeout)
            except asyncio.TimeoutError as exc:
                raise NetworkToolError("Deep scan is busy. Try again later.", status_code=429) from exc
            try:
                hosts = await self._deep_enrich_native(hosts)
            finally:
                self.deep_semaphore.release()
        
        return HostScanResponse(network=network, hosts=hosts)

    async def _deep_enrich_native(self, hosts: list[NetworkHost]) -> list[NetworkHost]:
        """Deep enrich hosts with port scanning using native scanner."""
        enriched = []
        # Limit to first 16 hosts for performance
        for host in hosts[:16]:
            try:
                port_result = await self._scanner.scan_ports(host.ip, mode="quick")
                if port_result.hosts and port_result.hosts[0].ports:
                    # Update device type based on open ports
                    device_type, confidence = self._guess_device_from_ports(
                        port_result.hosts[0].ports, host.vendor
                    )
                    if device_type:
                        host = NetworkHost(
                            ip=host.ip,
                            mac=host.mac,
                            vendor=host.vendor,
                            hostname=host.hostname,
                            device_type=device_type,
                            type_confidence=confidence,
                            status=host.status,
                        )
            except Exception as e:
                logger.debug(f"Deep scan failed for {host.ip}: {e}")
            enriched.append(host)
        
        # Add remaining hosts without deep scan
        enriched.extend(hosts[16:])
        return enriched
    
    def _guess_device_from_ports(
        self, ports: list[PortResult], vendor: Optional[str]
    ) -> tuple[Optional[str], Optional[float]]:
        """Guess device type from open ports."""
        open_ports = {p.port for p in ports if p.state == PortState.OPEN}
        
        # Check for specific services
        if 32400 in open_ports:
            return "media-server", 0.9  # Plex
        if 8123 in open_ports:
            return "home-assistant", 0.9
        if 5000 in open_ports or 5001 in open_ports:
            if vendor and "synology" in vendor.lower():
                return "nas", 0.9
        if 9100 in open_ports or 631 in open_ports:
            return "printer", 0.8
        if 445 in open_ports and 139 in open_ports:
            return "file-server", 0.7
        if 3389 in open_ports:
            return "windows", 0.7
        if 22 in open_ports and 80 not in open_ports:
            return "server", 0.6
        if 80 in open_ports or 443 in open_ports:
            return "web-device", 0.5
        
        return None, None

    async def scan_ports(self, target: str, mode: str) -> PortScanResponse:
        """
        Scan ports on target using native Python scanner.
        """
        # Map mode to native scanner
        try:
            scan_result = await self._scanner.scan_ports(target, mode=mode)
        except ValueError as e:
            raise NetworkToolError(str(e), status_code=400)
        except Exception as e:
            raise NetworkToolError(f"Port scan failed: {e}", status_code=500)
        
        if scan_result.error:
            raise NetworkToolError(scan_result.error, status_code=400)
        
        # Convert to legacy format
        ports = []
        if scan_result.hosts and scan_result.hosts[0].ports:
            for port in scan_result.hosts[0].ports:
                if port.state == PortState.OPEN:
                    ports.append(PortInfo(
                        port=port.port,
                        protocol=port.protocol,
                        state="open",
                        service=port.service,
                        service_name=port.service,
                        service_version=port.version,
                    ))
        
        return PortScanResponse(target=target, mode=mode, ports=ports)

    async def ping_host(self, target: str) -> PingResponse:
        try:
            result = await asyncio.to_thread(
                subprocess.run,
                ["ping", "-c", "2", "-W", "2", target],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except FileNotFoundError as exc:
            raise NetworkToolError("ping command not found on this system", status_code=500) from exc
        except subprocess.TimeoutExpired:
            return PingResponse(target=target, online=False, raw_output="Ping timed out")

        combined_output = (result.stdout + result.stderr).strip()
        return PingResponse(
            target=target,
            online=result.returncode == 0,
            raw_output=combined_output or "No output",
        )

    async def dns_lookup(self, domain: str) -> DnsLookupResponse:
        addresses: list[str] = []
        stdout = ""

        try:
            stdout = await self._run_command(["dig", "+short", domain], timeout=15)
            addresses = self._extract_ips(stdout.splitlines())
        except NetworkToolError as exc:
            if "Command not found: dig" in str(exc):
                stdout = ""
            else:
                raise exc

        if not addresses:
            stdout = await self._run_command(["nslookup", domain], timeout=15)
            addresses = self._extract_ips(stdout.splitlines())

        return DnsLookupResponse(domain=domain, addresses=addresses, raw_output=stdout.strip())

    async def speedtest(self) -> SpeedtestResponse:
        stdout = await self._run_command(["speedtest-cli", "--json"], timeout=120)

        try:
            data = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise NetworkToolError("Failed to parse speedtest output", status_code=500) from exc

        ping_ms = float(data.get("ping")) if data.get("ping") is not None else None
        download = data.get("download")
        upload = data.get("upload")

        download_mbps = float(download) / 1_000_000 if download is not None else None
        upload_mbps = float(upload) / 1_000_000 if upload is not None else None

        return SpeedtestResponse(
            ping_ms=ping_ms,
            download_mbps=round(download_mbps, 2) if download_mbps is not None else None,
            upload_mbps=round(upload_mbps, 2) if upload_mbps is not None else None,
        )

    async def _run_command(self, command: list[str], timeout: int | None = None) -> str:
        effective_timeout = timeout or self.default_timeout

        try:
            result = await asyncio.to_thread(
                subprocess.run,
                command,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
        except FileNotFoundError as exc:
            raise NetworkToolError(f"Command not found: {command[0]}", status_code=500) from exc
        except subprocess.TimeoutExpired as exc:
            raise NetworkToolError(f"Command timed out after {effective_timeout} seconds", status_code=504) from exc

        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip() or "Command failed"
            raise NetworkToolError(detail, status_code=500)

        return result.stdout

    # Legacy parsing methods removed - using native_scanner now

    def _validate_network(self, network: str) -> None:
        try:
            net = ipaddress.ip_network(network, strict=False)
        except Exception as exc:  # pragma: no cover - invalid user input
            raise NetworkToolError("Invalid network format. Use CIDR, e.g. 192.168.1.0/24", status_code=400) from exc

        if not net.is_private:
            raise NetworkToolError("Scanning is only allowed on private networks", status_code=400)

        # Limit network size (max ~4096 hosts, i.e., /20)
        if net.num_addresses > 4096:
            raise NetworkToolError("Network range too large. Use subnet no wider than /20", status_code=400)

    async def _get_arp_table(self) -> dict[str, str]:
        """Collect ARP/neigh entries to enrich MAC addresses. Uses cache to avoid repeated calls."""
        global _arp_cache, _arp_cache_time
        
        # Return cached data if still fresh
        if _arp_cache and (time.time() - _arp_cache_time) < _ARP_CACHE_TTL:
            return _arp_cache
        
        commands = [
            ["ip", "neigh", "show"],
            ["arp", "-an"],
        ]
        for cmd in commands:
            try:
                output = await self._run_command(cmd, timeout=5)
            except NetworkToolError:
                continue

            entries: dict[str, str] = {}
            for line in output.splitlines():
                line = line.strip()
                if not line:
                    continue
                # ip neigh: 192.168.1.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                m = re.match(r"(?P<ip>\d+\.\d+\.\d+\.\d+) .* lladdr (?P<mac>[0-9a-fA-F:]{17})", line)
                if m:
                    entries[m.group("ip")] = m.group("mac")
                    continue
                # arp -an: ? (192.168.1.5) at aa:bb:cc:dd:ee:ff [ether] on eth0
                m = re.match(r".*\((?P<ip>\d+\.\d+\.\d+\.\d+)\) at (?P<mac>[0-9a-fA-F:]{17})", line)
                if m:
                    entries[m.group("ip")] = m.group("mac")
            if entries:
                # Update cache
                _arp_cache.clear()
                _arp_cache.update(entries)
                _arp_cache_time = time.time()
                return entries
        return {}

    def _resolve_hostname(self, ip: str) -> str | None:
        """Try reverse DNS lookup to get hostname for IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            # Filter out generic PTR records
            if hostname and not hostname.endswith('.in-addr.arpa'):
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        return None

    def _merge_with_arp(self, hosts: list[NetworkHost], arp: dict[str, str]) -> list[NetworkHost]:
        """Enrich hosts with MAC addresses from ARP table and resolve missing hostnames."""
        enriched: list[NetworkHost] = []
        for host in hosts:
            mac = host.mac
            if not mac and host.ip in arp:
                mac = arp[host.ip]
            if not mac:
                logger.debug(f"No MAC for host {host.ip} (ARP/neigh empty)")
            
            # Try reverse DNS if hostname is missing
            hostname = getattr(host, "hostname", None)
            if not hostname:
                hostname = self._resolve_hostname(host.ip)
            
            vendor = host.vendor or self._vendor_from_mac(mac)
            enriched.append(
                NetworkHost(
                    ip=host.ip,
                    mac=mac,
                    vendor=vendor,
                    hostname=hostname,
                    device_type=getattr(host, "device_type", None),
                    type_confidence=getattr(host, "type_confidence", None),
                    status=host.status,
                )
            )
        return enriched

    def _vendor_from_mac(self, mac: str | None) -> str | None:
        if not mac:
            return None
        normalized = self._normalize_mac(mac)
        if len(normalized) < 6:
            return None
        prefix = normalized[:6]
        return OUI_VENDOR_HINTS.get(prefix)

    def _normalize_mac(self, mac: str) -> str:
        return mac.replace(":", "").replace("-", "").upper()

    def _guess_device_type(self, vendor: str | None, hostname: str | None) -> tuple[str | None, float | None]:
        hints = (vendor or "").lower() + " " + (hostname or "").lower()
        if any(x in hints for x in ["iphone", "ipad", "ios", "apple"]):
            return "phone/tablet", 0.7
        if any(x in hints for x in ["samsung", "android"]):
            return "phone/tablet", 0.6
        if any(x in hints for x in ["lg", "tv", "hisense", "roku", "chromecast"]):
            return "tv/media", 0.6
        if any(x in hints for x in ["ubiquiti", "tplink", "tp-link", "cisco", "mikrotik"]):
            return "network", 0.6
        if any(x in hints for x in ["raspberry", "pi"]):
            return "raspberry-pi", 0.8
        return None, None

    def _enrich_host_metadata(self, host: NetworkHost) -> NetworkHost:
        vendor = host.vendor or self._vendor_from_mac(host.mac)
        hostname = getattr(host, "hostname", None)
        device_type: str | None = None
        confidence: float | None = None

        # Only guess device type if we have at least some identifying info
        if vendor or hostname:
            device_type, confidence = self._guess_device_type(vendor, hostname)

        return NetworkHost(
            ip=host.ip,
            mac=host.mac,
            vendor=vendor,
            hostname=hostname,
            device_type=device_type,
            type_confidence=confidence,
            status=host.status,
        )

    def _extract_ips(self, lines: Iterable[str]) -> list[str]:
        ips: list[str] = []
        for raw_line in lines:
            line = raw_line.strip()
            if not line or line.lower().startswith((";", ";;", "server:", "non-authoritative")):
                continue

            for match in re.finditer(r"(\d{1,3}\.){3}\d{1,3}", line):
                ips.append(match.group(0))

        # Remove duplicates while keeping order
        seen = set()
        unique_ips = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                unique_ips.append(ip)

        return unique_ips

    async def get_network_map(self, network: str | None = None) -> NetworkMapResponse:
        target_network = network or "192.168.1.0/24"
        host_scan = await self.scan_hosts(target_network)
        nodes = [
          NetworkMapNode(
              name=host.vendor or host.ip,
              ip=host.ip,
              status=host.status,
              mac=host.mac,
              vendor=host.vendor,
              role="device",
          )
          for host in host_scan.hosts
        ]
        if not nodes:
            nodes.append(NetworkMapNode(name="Gateway", ip="0.0.0.0", status="unknown", role="gateway"))
        return NetworkMapResponse(nodes=nodes)

    async def traffic_samples(self, sample_count: int = 5, interval: float = 0.2) -> TrafficResponse:
        samples: list[TrafficSample] = []
        prev = psutil.net_io_counters()
        prev_time = time.time()

        for _ in range(sample_count):
            await asyncio.sleep(interval)
            current = psutil.net_io_counters()
            current_time = time.time()
            elapsed = current_time - prev_time
            if elapsed <= 0:
                continue

            rx_bytes = current.bytes_recv - prev.bytes_recv
            tx_bytes = current.bytes_sent - prev.bytes_sent

            samples.append(
                TrafficSample(
                    timestamp=current_time,
                    rx_kbps=round((rx_bytes / 1024) / elapsed, 2),
                    tx_kbps=round((tx_bytes / 1024) / elapsed, 2),
                )
            )
            prev, prev_time = current, current_time

        return TrafficResponse(samples=samples)

    async def active_connections(self) -> ConnectionsResponse:
        conns = []
        for c in psutil.net_connections(kind="inet"):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None
            proto = "TCP" if c.type == psutil.SOCK_STREAM else "UDP"
            proc_name = None
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                except Exception:
                    proc_name = None
            conns.append(
                ConnectionInfo(
                    local=laddr,
                    remote=raddr,
                    protocol=proto,
                    state=c.status if hasattr(c, "status") else None,
                    process=proc_name,
                )
            )
        return ConnectionsResponse(connections=conns)

    async def arp_table(self) -> ArpResponse:
        try:
            result = await self._run_command(["ip", "neigh"], timeout=5)
            lines = result.splitlines()
        except NetworkToolError:
            try:
                result = await self._run_command(["arp", "-an"], timeout=5)
                lines = result.splitlines()
            except NetworkToolError as exc:
                raise exc

        entries: list[ArpEntry] = []
        for line in lines:
            parts = line.split()
            if not parts:
                continue
            
            # Skip FAILED entries (no MAC address available)
            if "FAILED" in parts:
                continue
                
            if "dev" in parts:
                ip = parts[0]
                # Skip IPv6 addresses
                if ":" in ip and "." not in ip:
                    continue
                mac = parts[4] if len(parts) > 4 else None
                interface = parts[2] if len(parts) > 2 else None
                entry_type = parts[-1] if parts else None
            else:
                # arp -an format
                ip = parts[1].strip("()") if len(parts) > 1 else parts[0]
                # Skip IPv6 addresses
                if ":" in ip and "." not in ip:
                    continue
                mac = parts[3] if len(parts) > 3 else None
                interface = parts[-1] if parts else None
                entry_type = None

            # Only include entries with valid MAC addresses
            if mac and mac != "(incomplete)":
                entries.append(
                    ArpEntry(
                        ip=ip,
                        mac=mac,
                        vendor=None,
                        interface=interface,
                        entry_type=entry_type,
                    )
                )
        return ArpResponse(entries=entries)

    async def port_alerts(self) -> PortAlertsResponse:
        alerts: list[PortAlert] = []
        seen_ports: set[int] = set()  # Deduplicate IPv4/IPv6 sockets
        try:
            output = await self._run_command(["ss", "-lnt"], timeout=5)
            lines = output.splitlines()[1:]
            for line in lines:
                parts = line.split()
                if len(parts) < 5:
                    continue
                local = parts[3]
                if ":" not in local:
                    continue
                port_str = local.split(":")[-1]
                if not port_str.isdigit():
                    continue
                port = int(port_str)
                # Skip if we already have this port (IPv4/IPv6 duplicate)
                if port in seen_ports:
                    continue
                seen_ports.add(port)
                service = self._guess_service(port)
                level, rec = self._risk_for_port(port, service)
                alerts.append(PortAlert(port=port, service=service, level=level, recommendation=rec))
        except NetworkToolError:
            pass
        return PortAlertsResponse(alerts=alerts)

    def _guess_service(self, port: int) -> str | None:
        common = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            6379: "Redis",
            3389: "RDP",
        }
        return common.get(port)

    def _risk_for_port(self, port: int, service: str | None) -> tuple[str, str]:
        if port in (23, 3389):
            return "Critical", "Restrict access or close the port. Use VPN/Firewall."
        if port in (22, 3306, 5432, 6379):
            return "Warning", "Restrict access by IP and enable authentication."
        return "Info", "Ensure the service is updated and secured."


__all__ = ["NetworkToolsService", "NetworkToolError"]
