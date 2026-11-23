# ruff: noqa: F401

from app.services.native_scanner_context import (
    ALLOWED_NETWORKS,
    ARP_TIMEOUT,
    BANNER_GRAB_TIMEOUT,
    BLOCKED_RANGES,
    Dict,
    Enum,
    HostResult,
    HostStatus,
    List,
    MAX_CONCURRENT_CONNECTIONS,
    MAX_HOSTS_PER_SCAN,
    MAX_PORTS_PER_SCAN,
    MIN_SCAN_INTERVAL_MS,
    Optional,
    PortResult,
    PortState,
    ScanResult,
    ScanType,
    TCP_CONNECT_TIMEOUT,
    TOTAL_SCAN_TIMEOUT,
    Tuple,
    asyncio,
    dataclass,
    datetime,
    field,
    gzip,
    hashlib,
    ipaddress,
    logger,
    logging,
    os,
    re,
    resolve_arp_scan_binary,
    secrets,
    shutil,
    socket,
    time,
)

from app.services.native_scanner_components.fingerprinter import ServiceFingerprinter
from app.services.native_scanner_components.oui import OUIDatabase
from app.services.native_scanner_components.security import SecurityValidator


class NativeNetworkScanner:
    """
    A secure, native Python network scanner for LAN environments.

    Security features:
    - Input validation on all parameters
    - Rate limiting
    - Private network restriction
    - Timeout protection
    - No shell execution
    - Audit logging
    """

    def __init__(self):
        self._scan_semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)
        self._rate_limiter = asyncio.Lock()
        self._last_scan_time = 0.0
        self._active_scan_id: Optional[str] = None

    def _generate_scan_id(self) -> str:
        """Generate unique scan ID for tracking."""
        return hashlib.sha256(
            f"{time.time()}-{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]

    async def _rate_limit(self):
        """Enforce minimum interval between operations."""
        async with self._rate_limiter:
            now = time.time() * 1000  # ms
            elapsed = now - self._last_scan_time
            if elapsed < MIN_SCAN_INTERVAL_MS:
                await asyncio.sleep((MIN_SCAN_INTERVAL_MS - elapsed) / 1000)
            self._last_scan_time = time.time() * 1000

    # ========== HOST DISCOVERY ==========

    async def discover_hosts(
        self, network: str, timeout: float = ARP_TIMEOUT
    ) -> ScanResult:
        """
        Discover hosts on a network using multiple methods:
        1. ARP table lookup (fastest)
        2. ICMP ping sweep
        3. TCP SYN probe on common ports

        Args:
            network: CIDR notation (e.g., "192.168.1.0/24")
            timeout: Timeout per host in seconds

        Returns:
            ScanResult with discovered hosts
        """
        # Validate input
        net = SecurityValidator.validate_network(network)

        scan_id = self._generate_scan_id()
        logger.info(f"[SCAN:{scan_id}] Starting host discovery on {network}")

        result = ScanResult(
            scan_id=scan_id,
            network=network,
            scan_type=ScanType.HOST_DISCOVERY,
            started_at=datetime.now(),
        )

        try:
            # Get all host IPs to scan
            hosts_to_scan = [str(ip) for ip in net.hosts()]
            result.total_hosts_scanned = len(hosts_to_scan)

            # Method 1: Get ARP cache first (instant results)
            arp_hosts = await self._get_arp_cache()

            # Method 2: Parallel ping sweep
            ping_tasks = []
            for ip in hosts_to_scan:
                task = asyncio.create_task(self._ping_host(ip, timeout))
                ping_tasks.append((ip, task))

            # Collect results with timeout
            discovered: Dict[str, HostResult] = {}

            # Add ARP cache results
            for ip, mac in arp_hosts.items():
                if ip in [str(h) for h in net.hosts()]:
                    vendor = OUIDatabase.get_vendor(mac)
                    device_type, confidence = OUIDatabase.get_device_type_hint(vendor)
                    hostname = await self._resolve_hostname(ip)

                    discovered[ip] = HostResult(
                        ip=ip,
                        status=HostStatus.ONLINE,
                        mac=mac,
                        vendor=vendor,
                        hostname=hostname,
                        device_type=device_type,
                        type_confidence=confidence,
                        last_seen=datetime.now(),
                    )

            # Wait for ping results
            try:
                done, pending = await asyncio.wait(
                    [t for _, t in ping_tasks], timeout=TOTAL_SCAN_TIMEOUT
                )

                # Cancel pending tasks
                for task in pending:
                    task.cancel()

            except asyncio.CancelledError:
                logger.warning(f"[SCAN:{scan_id}] Scan cancelled")
                result.error = "Scan cancelled"
                return result

            # Process ping results
            for ip, task in ping_tasks:
                try:
                    is_online, response_time = task.result()
                    if is_online and ip not in discovered:
                        hostname = await self._resolve_hostname(ip)
                        discovered[ip] = HostResult(
                            ip=ip,
                            status=HostStatus.ONLINE,
                            hostname=hostname,
                            response_time_ms=response_time,
                            last_seen=datetime.now(),
                        )
                    elif is_online and ip in discovered:
                        discovered[ip].response_time_ms = response_time
                except asyncio.CancelledError:
                    pass
                except Exception as e:
                    logger.debug(f"[SCAN:{scan_id}] Ping failed for {ip}: {e}")

            # Re-fetch ARP cache after pinging (may have new entries)
            updated_arp = await self._get_arp_cache()

            # Update discovered hosts with MAC/vendor if missing
            for ip, host in discovered.items():
                if not host.mac and ip in updated_arp:
                    host.mac = updated_arp[ip]
                    host.vendor = OUIDatabase.get_vendor(host.mac)
                    device_type, confidence = OUIDatabase.get_device_type_hint(
                        host.vendor
                    )
                    if not host.device_type:
                        host.device_type = device_type
                        host.type_confidence = confidence

            result.hosts = list(discovered.values())
            result.hosts_found = len(result.hosts)
            result.completed_at = datetime.now()

            logger.info(
                f"[SCAN:{scan_id}] Completed: {result.hosts_found}/{result.total_hosts_scanned} hosts found"
            )

        except ValueError as e:
            result.error = str(e)
            logger.warning(f"[SCAN:{scan_id}] Validation error: {e}")
        except Exception as e:
            result.error = f"Scan failed: {e}"
            logger.error(f"[SCAN:{scan_id}] Error: {e}", exc_info=True)

        return result

    async def _get_arp_cache(self) -> Dict[str, str]:
        """
        Read ARP cache from multiple sources.
        Returns: Dict[ip] = mac
        """
        arp_entries: Dict[str, str] = {}

        # Method 0: Try arp-scan first (best results, requires sudo)
        # arp-scan actively sends ARP requests to all hosts
        try:
            import subprocess

            arp_scan_binary = resolve_arp_scan_binary()
            if not arp_scan_binary:
                raise FileNotFoundError("arp-scan not installed")
            result = await asyncio.to_thread(
                subprocess.run,
                [arp_scan_binary, "--localnet", "--quiet", "--ignoredups"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                import re

                for line in result.stdout.splitlines():
                    # Format: 192.168.1.1	aa:bb:cc:dd:ee:ff	Vendor Name
                    match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)", line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).upper()
                        if mac != "00:00:00:00:00:00":
                            arp_entries[ip] = mac
                if arp_entries:
                    logger.debug(f"arp-scan found {len(arp_entries)} hosts")
                    return arp_entries
        except FileNotFoundError:
            logger.debug("arp-scan not installed")
        except subprocess.TimeoutExpired:
            logger.debug("arp-scan timed out")
        except Exception as e:
            logger.debug(f"arp-scan failed: {e}")

        # Method 1: Try mounted host /proc/net/arp
        for arp_path in ["/host_proc_net_arp", "/proc/net/arp"]:
            try:
                with open(arp_path, "r") as f:
                    lines = f.readlines()[1:]  # Skip header
                    for line in lines:
                        parts = line.split()
                        if len(parts) >= 6:
                            ip = parts[0]
                            try:
                                flags = int(parts[2], 0)
                            except ValueError:
                                continue
                            mac = parts[3]
                            # Linux can retain failed ARP probes with the old MAC
                            # address for hours. Only ATF_COM (0x2) entries have a
                            # completed address resolution and may represent a live
                            # host.
                            if (
                                flags & 0x2
                                and mac != "00:00:00:00:00:00"
                                and mac != "<incomplete>"
                            ):
                                arp_entries[ip] = mac.upper()
                if arp_entries:
                    logger.debug(f"Read {len(arp_entries)} ARP entries from {arp_path}")
                    break
            except FileNotFoundError:
                continue
            except Exception as e:
                logger.debug(f"Could not read {arp_path}: {e}")

        # Method 2: Try 'ip neigh' command
        if not arp_entries:
            try:
                import subprocess

                result = await asyncio.to_thread(
                    subprocess.run,
                    ["ip", "neigh"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        # Format: 192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                        parts = line.split()
                        if len(parts) >= 5 and "lladdr" in parts:
                            ip = parts[0]
                            lladdr_idx = parts.index("lladdr")
                            if lladdr_idx + 1 < len(parts):
                                mac = parts[lladdr_idx + 1].upper()
                                if mac != "00:00:00:00:00:00":
                                    arp_entries[ip] = mac
            except Exception as e:
                logger.debug(f"Could not run 'ip neigh': {e}")

        # Method 3: Try 'arp -a' command (fallback)
        if not arp_entries:
            try:
                import subprocess

                result = await asyncio.to_thread(
                    subprocess.run,
                    ["arp", "-a"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        # Format varies: hostname (192.168.1.1) at aa:bb:cc:dd:ee:ff ...
                        import re

                        match = re.search(
                            r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)", line
                        )
                        if match:
                            ip = match.group(1)
                            mac = match.group(2).upper()
                            if mac != "00:00:00:00:00:00" and mac != "(INCOMPLETE)":
                                arp_entries[ip] = mac
            except Exception as e:
                logger.debug(f"Could not run 'arp -a': {e}")

        return arp_entries

    async def _ping_host(
        self, ip: str, timeout: float = ARP_TIMEOUT
    ) -> Tuple[bool, Optional[float]]:
        """
        Check if host is online using TCP connect to common ports.
        Pure Python, no ICMP (would require root).

        Returns: (is_online, response_time_ms)
        """
        await self._rate_limit()

        # Quick ports to try (most likely to be open on any device)
        quick_ports = [80, 443, 22, 445, 139, 8080, 21, 23]

        start_time = time.time()

        async with self._scan_semaphore:
            for port in quick_ports:
                try:
                    # Create connection with timeout
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, port),
                        timeout=timeout / len(quick_ports),
                    )
                    writer.close()
                    await writer.wait_closed()

                    response_time = (time.time() - start_time) * 1000
                    return True, response_time

                except ConnectionRefusedError:
                    # An RST reply proves the host is ALIVE — this port is just closed.
                    # (Previously treated as offline, so a host refusing all probed ports
                    # was wrongly dropped.)
                    return True, (time.time() - start_time) * 1000
                except (asyncio.TimeoutError, OSError):
                    continue
                except Exception:
                    continue

        return False, None

    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Reverse DNS lookup for hostname."""
        try:
            hostname, _, _ = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyaddr, ip
            )
            # Filter out generic PTR records
            if hostname and not hostname.endswith(".in-addr.arpa"):
                return hostname
        except (socket.herror, socket.gaierror, socket.timeout):
            pass
        return None

    # ========== PORT SCANNING ==========

    async def scan_ports(
        self,
        target: str,
        ports: Optional[List[int]] = None,
        mode: str = "quick",
        include_udp: bool = True,
    ) -> ScanResult:
        """
        Scan ports on a target host.

        Args:
            target: IP address to scan
            ports: Specific ports to scan (optional)
            mode: "quick" (top 100), "standard" (top 1000), "custom" (use ports list)

        Returns:
            ScanResult with port information
        """
        # Validate target
        SecurityValidator.validate_ip(target)

        scan_id = self._generate_scan_id()
        logger.info(f"[SCAN:{scan_id}] Starting port scan on {target} (mode={mode})")

        result = ScanResult(
            scan_id=scan_id,
            network=target,
            scan_type=ScanType.PORT_SCAN,
            started_at=datetime.now(),
        )

        try:
            # Determine ports to scan
            if ports:
                ports_to_scan = SecurityValidator.validate_ports(ports)
            elif mode == "quick":
                ports_to_scan = self._get_top_ports(100)
            elif mode == "standard":
                ports_to_scan = self._get_top_ports(1000)
            else:
                ports_to_scan = self._get_top_ports(100)

            result.total_hosts_scanned = len(ports_to_scan)

            # Parallel TCP port scan
            tasks = []
            for port in ports_to_scan:
                task = asyncio.create_task(self._scan_single_port(target, port))
                tasks.append((port, "tcp", task))

            # Add UDP port scan for common UDP services
            if include_udp:
                udp_ports = self._get_top_udp_ports()
                for port in udp_ports:
                    task = asyncio.create_task(self._scan_udp_port(target, port))
                    tasks.append((port, "udp", task))

            # Wait for results
            host_result = HostResult(ip=target, status=HostStatus.ONLINE)

            done, pending = await asyncio.wait(
                [t for _, _, t in tasks], timeout=TOTAL_SCAN_TIMEOUT
            )

            for task in pending:
                task.cancel()

            # Collect open ports
            for port, proto, task in tasks:
                try:
                    port_result = task.result()
                    if port_result and port_result.state == PortState.OPEN:
                        host_result.ports.append(port_result)
                except (asyncio.CancelledError, Exception):
                    pass

            result.hosts = [host_result]
            result.hosts_found = len(host_result.ports)
            result.completed_at = datetime.now()

            logger.info(
                f"[SCAN:{scan_id}] Completed: {len(host_result.ports)} open ports found"
            )

        except ValueError as e:
            result.error = str(e)
        except Exception as e:
            result.error = f"Port scan failed: {e}"
            logger.error(f"[SCAN:{scan_id}] Error: {e}", exc_info=True)

        return result

    async def _scan_single_port(
        self, ip: str, port: int, grab_banner: bool = True
    ) -> Optional[PortResult]:
        """Scan a single port and optionally grab banner."""
        await self._rate_limit()

        async with self._scan_semaphore:
            try:
                # Attempt connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=TCP_CONNECT_TIMEOUT
                )

                result = PortResult(
                    port=port,
                    state=PortState.OPEN,
                    service=ServiceFingerprinter.identify_from_port(port),
                )

                # Banner grabbing
                if grab_banner:
                    try:
                        # Send probe if available
                        probe = ServiceFingerprinter.get_probe(port)
                        if probe:
                            writer.write(probe)
                            await writer.drain()

                        # Read banner
                        banner_data = await asyncio.wait_for(
                            reader.read(512), timeout=BANNER_GRAB_TIMEOUT
                        )

                        if banner_data:
                            banner = SecurityValidator.sanitize_banner(banner_data)
                            result.banner = banner

                            # Identify service from banner
                            service, version = (
                                ServiceFingerprinter.identify_from_banner(banner)
                            )
                            if service:
                                result.service = service
                            if version:
                                result.version = version

                    except asyncio.TimeoutError:
                        pass  # No banner available
                    except Exception:
                        pass

                writer.close()
                await writer.wait_closed()

                return result

            except (asyncio.TimeoutError, ConnectionRefusedError):
                return PortResult(port=port, state=PortState.CLOSED)
            except OSError as e:
                if "Network is unreachable" in str(e):
                    return PortResult(port=port, state=PortState.FILTERED)
                return PortResult(port=port, state=PortState.CLOSED)
            except Exception:
                return None

    async def _scan_udp_port(self, ip: str, port: int) -> Optional[PortResult]:
        """
        Scan a single UDP port.

        UDP scanning is inherently unreliable because:
        - Open ports typically don't respond
        - Only closed ports send ICMP "port unreachable"
        - Firewalls may drop packets silently

        We use service-specific probes for better detection.
        """
        await self._rate_limit()

        async with self._scan_semaphore:
            try:
                import socket as sock

                # Create UDP socket
                udp_sock = sock.socket(sock.AF_INET, sock.SOCK_DGRAM)
                udp_sock.setblocking(False)
                udp_sock.settimeout(2.0)

                # Get service-specific probe
                probe = self._get_udp_probe(port)

                try:
                    # Send probe
                    udp_sock.sendto(probe, (ip, port))

                    # Try to receive response
                    loop = asyncio.get_event_loop()
                    try:
                        data = await asyncio.wait_for(
                            loop.sock_recv(udp_sock, 1024), timeout=2.0
                        )

                        if data:
                            # Got response - port is open
                            service = ServiceFingerprinter.identify_from_port(
                                port
                            ) or self._udp_service_name(port)
                            return PortResult(
                                port=port,
                                protocol="udp",
                                state=PortState.OPEN,
                                service=service,
                                banner=SecurityValidator.sanitize_banner(data[:128])
                                if data
                                else None,
                            )
                    except asyncio.TimeoutError:
                        # No response - could be open (filtered) or closed
                        # For common UDP services, assume open|filtered
                        if port in self._get_top_udp_ports():
                            return PortResult(
                                port=port,
                                protocol="udp",
                                state=PortState.FILTERED,
                                service=self._udp_service_name(port),
                            )
                        return None

                except sock.error as e:
                    # ICMP port unreachable = closed
                    if "refused" in str(e).lower() or e.errno == 111:
                        return PortResult(
                            port=port, protocol="udp", state=PortState.CLOSED
                        )
                    return None
                finally:
                    udp_sock.close()

            except Exception as e:
                logger.debug(f"UDP scan error on {ip}:{port}: {e}")
                return None

        return None

    def _get_udp_probe(self, port: int) -> bytes:
        """Get service-specific UDP probe."""
        probes = {
            53: b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS query
            67: b"\x01\x01\x06\x00" + b"\x00" * 236,  # DHCP discover
            68: b"\x01\x01\x06\x00" + b"\x00" * 236,  # DHCP
            69: b"\x00\x01test\x00octet\x00",  # TFTP read request
            123: b"\xe3\x00\x04\xfa\x00\x01\x00\x00" + b"\x00" * 40,  # NTP
            137: b"\x80\xf0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",  # NetBIOS
            161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04"
            + b"\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09"
            + b"\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP get-request
            500: b"\x00" * 28,  # IKE
            514: b"<14>test",  # Syslog
            520: b"\x01\x01\x00\x00" + b"\x00" * 20,  # RIP
            1194: b"\x38" + b"\x00" * 37,  # OpenVPN
            1900: b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
            + b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n',  # SSDP/UPnP
            5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + b"\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",  # mDNS
        }
        return probes.get(port, b"\x00")

    def _udp_service_name(self, port: int) -> str:
        """Get UDP service name by port."""
        services = {
            53: "dns",
            67: "dhcp-server",
            68: "dhcp-client",
            69: "tftp",
            123: "ntp",
            137: "netbios-ns",
            138: "netbios-dgm",
            161: "snmp",
            162: "snmp-trap",
            500: "isakmp",
            514: "syslog",
            520: "rip",
            1194: "openvpn",
            1900: "ssdp",
            4500: "nat-t-ike",
            5353: "mdns",
            5355: "llmnr",
        }
        return services.get(port, "unknown")

    def _get_top_ports(self, count: int) -> List[int]:
        """Get top N most common TCP ports."""
        # Ordered by frequency of use
        top_ports = [
            80,
            443,
            22,
            21,
            25,
            3389,
            110,
            445,
            139,
            143,
            53,
            135,
            3306,
            8080,
            1723,
            111,
            995,
            993,
            5900,
            1025,
            587,
            8888,
            199,
            1720,
            465,
            548,
            113,
            81,
            6001,
            10000,
            514,
            5060,
            179,
            1026,
            2000,
            8443,
            8000,
            32768,
            554,
            26,
            1433,
            49152,
            2001,
            515,
            8008,
            49154,
            1027,
            5666,
            646,
            5000,
            5631,
            631,
            49153,
            8081,
            2049,
            88,
            79,
            5800,
            106,
            2121,
            1110,
            49155,
            6000,
            513,
            990,
            5357,
            427,
            49156,
            543,
            544,
            5101,
            144,
            7,
            389,
            8009,
            3128,
            444,
            9999,
            5009,
            7070,
            5190,
            3000,
            5432,
            1900,
            3986,
            13,
            1029,
            9,
            5051,
            6646,
            49157,
            1028,
            873,
            1755,
            2717,
            4899,
            9100,
            119,
            37,
        ]
        return top_ports[: min(count, len(top_ports))]

    def _get_top_udp_ports(self) -> List[int]:
        """Get common UDP ports to scan."""
        return [
            53,  # DNS
            67,  # DHCP server
            68,  # DHCP client
            69,  # TFTP
            123,  # NTP
            137,  # NetBIOS Name Service
            138,  # NetBIOS Datagram
            161,  # SNMP
            162,  # SNMP Trap
            500,  # IKE/IPsec
            514,  # Syslog
            520,  # RIP
            1194,  # OpenVPN
            1900,  # SSDP/UPnP
            4500,  # NAT-T
            5353,  # mDNS
            5355,  # LLMNR
        ]

    # ========== FULL SCAN ==========

    async def full_scan(
        self, network: str, scan_ports: bool = True, port_mode: str = "quick"
    ) -> ScanResult:
        """
        Full network scan: discovery + port scan on discovered hosts.

        Args:
            network: CIDR notation
            scan_ports: Whether to scan ports on discovered hosts
            port_mode: "quick" or "standard"
        """
        # First, discover hosts
        discovery_result = await self.discover_hosts(network)

        if discovery_result.error or not scan_ports:
            return discovery_result

        # Then scan ports on each discovered host
        for host in discovery_result.hosts:
            if host.status == HostStatus.ONLINE:
                port_result = await self.scan_ports(host.ip, mode=port_mode)
                if port_result.hosts and port_result.hosts[0].ports:
                    host.ports = port_result.hosts[0].ports

        discovery_result.scan_type = ScanType.FULL_SCAN
        return discovery_result
