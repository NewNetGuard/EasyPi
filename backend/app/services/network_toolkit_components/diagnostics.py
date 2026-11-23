"""NetworkDiagnosticsMixin implementation."""

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


class NetworkDiagnosticsMixin:
    async def scan_ports(self, config: PortScanConfig) -> NetworkApiResponse:
        start = time.perf_counter()

        # Parse port range for native scanner
        ports_to_scan = self._parse_port_range(config.portRange)

        try:
            # Use native scanner for port scanning
            scan_result = await self._scanner.scan_ports(
                config.targetHost,
                ports=ports_to_scan if ports_to_scan else None,
                mode="standard" if not ports_to_scan else "custom",
            )
        except ValueError as exc:
            return self._error(str(exc))
        except Exception as exc:
            return self._error(f"Port scan failed: {exc}")

        if scan_result.error:
            return self._error(scan_result.error)

        # Convert to PortInfo format
        ports: list[PortInfo] = []
        if scan_result.hosts and scan_result.hosts[0].ports:
            for port_result in scan_result.hosts[0].ports:
                status = (
                    "open"
                    if port_result.state == PortState.OPEN
                    else (
                        "closed"
                        if port_result.state == PortState.CLOSED
                        else "filtered"
                    )
                )
                risk, description = self._risk_for_port(
                    port_result.port, status, port_result.service
                )
                # Sanitize service name and version to prevent XSS
                service = _sanitize_string(port_result.service, max_length=64)
                version = _sanitize_string(port_result.version, max_length=128)
                ports.append(
                    PortInfo(
                        port=port_result.port,
                        protocol=port_result.protocol.upper(),
                        status=status,
                        service=service,
                        riskLevel=risk,
                        description=description,
                        version=version,
                    )
                )

        # For local host scans, enhance with ss data for accurate results
        is_local = await self._is_local_host(config.targetHost)
        if is_local:
            local_ports = await self._get_local_listening_ports(config.scanType)
            ports = self._enhance_with_local_data(ports, local_ports, config.scanType)

        open_count = len([p for p in ports if p.status == "open"])
        closed_count = len([p for p in ports if p.status == "closed"])
        filtered_count = len([p for p in ports if p.status == "filtered"])

        result = PortScanResult(
            host=config.targetHost,
            ports=ports,
            scanTime=round(time.perf_counter() - start, 2),
            timestamp=utc_now(),
            openCount=open_count,
            closedCount=closed_count,
            filteredCount=filtered_count,
        )
        return self._success(result)

    def _parse_port_range(self, port_range: str) -> list[int] | None:
        """Parse port range string like '1-1000' or '22,80,443' into list of ports."""
        if not port_range or port_range == "-":
            return None  # Use default ports

        ports = []
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    start = int(start) if start else 1
                    end = int(end) if end else 65535
                    # Limit range size for performance
                    if end - start > 1000:
                        end = start + 1000
                    ports.extend(range(start, end + 1))
                except ValueError:
                    continue
            else:
                try:
                    ports.append(int(part))
                except ValueError:
                    continue

        return ports[:1000] if ports else None  # Limit to 1000 ports

    async def _is_local_host(self, host: str) -> bool:
        """Check if target is local machine."""
        if host in ("localhost", "127.0.0.1", "::1"):
            return True

        # Get local IPs
        try:
            proc = await asyncio.create_subprocess_exec(
                "hostname",
                "-I",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            local_ips = stdout.decode().strip().split()
            return host in local_ips
        except Exception:
            return False

    async def _get_local_listening_ports(self, scan_type: str) -> dict[int, str]:
        """Get locally listening ports using ss command."""
        listening: dict[int, str] = {}

        try:
            # -l = listening, -n = numeric, -u = UDP, -t = TCP
            flag = "-u" if scan_type == "udp" else "-t"
            proc = await asyncio.create_subprocess_exec(
                "ss",
                "-ln",
                flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            for line in stdout.decode().splitlines()[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    # Local address is usually in 4th column (index 3)
                    local_addr = parts[4] if len(parts) > 4 else parts[3]
                    # Parse port from address like "0.0.0.0:22" or "*:51820" or "[::]:22"
                    if ":" in local_addr:
                        port_str = local_addr.rsplit(":", 1)[-1]
                        try:
                            port = int(port_str)
                            # Try to get process name if available
                            process = ""
                            if len(parts) > 6:
                                process = parts[-1]
                            listening[port] = process
                        except ValueError:
                            continue
        except Exception:
            pass

        return listening

    def _enhance_with_local_data(
        self, ports: list[PortInfo], local_ports: dict[int, str], scan_type: str
    ) -> list[PortInfo]:
        """Enhance scan results with local ss data."""
        enhanced = []
        protocol = "UDP" if scan_type == "udp" else "TCP"

        for port_info in ports:
            if port_info.port in local_ports and port_info.status in (
                "closed",
                "filtered",
            ):
                # Port is actually listening locally - scanner couldn't detect it
                risk, description = self._risk_for_port(
                    port_info.port, "open", port_info.service
                )
                enhanced.append(
                    PortInfo(
                        port=port_info.port,
                        protocol=port_info.protocol,
                        status="open",
                        service=port_info.service or "unknown",
                        riskLevel=risk,
                        description=description + " (detected via local check)",
                        version=port_info.version,
                    )
                )
            else:
                enhanced.append(port_info)

        # Also add ports that are listening but weren't in scan range
        scanned_ports = {p.port for p in ports}
        for port, process in local_ports.items():
            if port not in scanned_ports:
                # This port is listening but wasn't scanned - add it
                risk, description = self._risk_for_port(port, "open", None)
                enhanced.append(
                    PortInfo(
                        port=port,
                        protocol=protocol,
                        status="open",
                        service="unknown",
                        riskLevel=risk,
                        description=description + " (detected via local check)",
                        version=None,
                    )
                )

        # Sort by port number
        enhanced.sort(key=lambda p: p.port)
        return enhanced

    def _is_root(self) -> bool:
        try:
            return hasattr(os, "geteuid") and os.geteuid() == 0
        except Exception:
            return False

    def _has_arp_scan(self) -> bool:
        return resolve_arp_scan_binary() is not None

    def _risk_for_port(
        self, port: int, status: str, service: str | None
    ) -> tuple[RiskLevel, str]:
        if status != "open":
            return "low", "Port is not open"

        sensitive = {
            22: ("high", "SSH is open — restrict access or configure key-based auth"),
            23: ("critical", "Telnet is insecure — close or restrict access"),
            3389: ("critical", "RDP detected — protect with firewall or VPN"),
            3306: ("high", "MySQL is open — restrict by IP and use strong password"),
            5432: (
                "high",
                "PostgreSQL is open — restrict by IP and use strong password",
            ),
            6379: ("high", "Redis without auth is vulnerable — restrict access"),
        }
        if port in sensitive:
            level, desc = sensitive[port]
            return level, desc

        if service:
            return (
                "medium",
                f"Service {service} is open — verify authentication and updates",
            )
        return "low", "Open port detected"

    # Speed Test
    async def speed_test(self, config: SpeedTestConfig) -> NetworkApiResponse:
        try:
            output = await self.tools._run_command(
                ["speedtest-cli", "--json"], timeout=120
            )
        except NetworkToolError as exc:
            return self._error(str(exc))

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return self._error("Failed to parse speedtest-cli output")

        download = float(data.get("download") or 0) / 1_000_000
        upload = float(data.get("upload") or 0) / 1_000_000
        ping = float(data.get("ping") or 0)
        jitter = float(data.get("jitter") or 0)

        server_data = data.get("server") or {}
        server = SpeedTestServer(
            id=str(server_data.get("id") or "unknown"),
            name=server_data.get("name") or "Unknown server",
            location=server_data.get("sponsor") or server_data.get("name") or "Unknown",
            country=server_data.get("country") or "Unknown",
            distance=float(server_data.get("d") or 0.0),
        )

        client = data.get("client") or {}
        result = SpeedTestResult(
            download=round(download, 2),
            upload=round(upload, 2),
            ping=round(ping, 2),
            jitter=round(jitter, 2),
            server=server,
            timestamp=utc_now(),
            isp=client.get("isp"),
            ipAddress=client.get("ip"),
        )
        return self._success(result)

    # Network Map
    async def network_map(self, config: NetworkMapConfig) -> NetworkApiResponse:
        try:
            host_scan = await self.tools.scan_hosts("192.168.1.0/24")
        except NetworkToolError as exc:
            return self._error(str(exc))

        nodes: list[NetworkNode] = []
        edges: list[NetworkEdge] = []

        for idx, host in enumerate(host_scan.hosts):
            node_id = host.ip
            # Try to get hostname for better device type detection
            hostname = None
            try:
                hostname = socket.gethostbyaddr(host.ip)[0]
            except Exception:
                pass

            nodes.append(
                NetworkNode(
                    id=node_id,
                    label=hostname or host.vendor or host.ip,
                    ip=host.ip,
                    mac=host.mac,
                    type=self._guess_device_type(host, None, hostname),
                    status=host.status
                    if host.status in ("online", "offline", "limited")
                    else "online",
                    x=None,
                    y=None,
                )
            )
            if idx > 0:
                edges.append(NetworkEdge(from_=nodes[0].id, to=node_id))

        if not nodes:
            nodes.append(
                NetworkNode(
                    id="gateway",
                    label="Gateway",
                    ip="0.0.0.0",
                    mac=None,
                    type="router",
                    status="offline",
                    x=None,
                    y=None,
                )
            )

        result = NetworkMapData(nodes=nodes, edges=edges, layout=config.layoutType)
        return self._success(result)

    # Traffic
    async def traffic_samples(self, duration: int = 60) -> NetworkApiResponse:
        sample_count = max(3, min(20, duration // 5 or 5))
        interval = 0.2

        samples: list[TrafficData] = []
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
                TrafficData(
                    timestamp=utc_now(),
                    download=round((rx_bytes / 1024) / elapsed, 2),
                    upload=round((tx_bytes / 1024) / elapsed, 2),
                )
            )
            prev, prev_time = current, current_time

        return self._success(samples)

    async def traffic_stats(self) -> NetworkApiResponse:
        current = psutil.net_io_counters()
        now = time.time()
        elapsed = now - self._prev_sample_time
        if elapsed <= 0:
            elapsed = 1

        download = (current.bytes_recv - self._prev_io.bytes_recv) / 1024 / elapsed
        upload = (current.bytes_sent - self._prev_io.bytes_sent) / 1024 / elapsed

        self._peak_download = max(self._peak_download, download)
        self._peak_upload = max(self._peak_upload, upload)

        self._prev_io = current
        self._prev_sample_time = now

        stats = TrafficStats(
            currentDownload=round(download, 2),
            currentUpload=round(upload, 2),
            totalReceived=current.bytes_recv,
            totalSent=current.bytes_sent,
            peakDownload=round(self._peak_download, 2),
            peakUpload=round(self._peak_upload, 2),
        )
        return self._success(stats)

    # Active Connections
    async def active_connections(
        self, filters: ConnectionFilters | None = None
    ) -> NetworkApiResponse:
        filters = filters or ConnectionFilters()

        try:
            raw_conns = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            try:
                proc = psutil.Process()
                raw_conns = proc.connections(kind="inet")
            except Exception:
                return self._error(
                    "Insufficient permissions to read network connections"
                )
        except Exception as exc:  # pragma: no cover - defensive
            return self._error(f"Failed to get connections: {exc}")

        conns: list[ActiveConnection] = []
        for idx, c in enumerate(raw_conns):
            protocol = (
                "TCP" if getattr(c, "type", None) == socket.SOCK_STREAM else "UDP"
            )
            raw_state = c.status if hasattr(c, "status") and c.status else "LISTENING"
            state = (
                raw_state
                if raw_state
                in (
                    "ESTABLISHED",
                    "LISTENING",
                    "TIME_WAIT",
                    "CLOSE_WAIT",
                    "SYN_SENT",
                    "SYN_RECEIVED",
                )
                else "LISTENING"
            )

            if filters.protocol and protocol != filters.protocol:
                continue
            if filters.state and state != filters.state:
                continue

            process_name = None
            if c.pid:
                try:
                    proc_name = psutil.Process(c.pid).name()
                    # Sanitize process name to prevent XSS
                    process_name = _sanitize_string(proc_name, max_length=64)
                except Exception:
                    process_name = None
            else:
                process_name = None

            local_addr = c.laddr.ip if c.laddr else ""
            local_port = c.laddr.port if c.laddr else 0
            remote_addr = c.raddr.ip if c.raddr else None
            remote_port = c.raddr.port if c.raddr else None

            if filters.process and process_name:
                if filters.process.lower() not in process_name.lower():
                    continue

            if filters.search:
                target = filters.search.lower()
                addresses = (
                    f"{local_addr}:{local_port} {remote_addr}:{remote_port}".lower()
                )
                if target not in addresses:
                    continue

            conns.append(
                ActiveConnection(
                    id=f"{protocol}-{local_addr}-{local_port}-{idx}",
                    localAddress=local_addr,
                    localPort=local_port,
                    remoteAddress=remote_addr,
                    remotePort=remote_port,
                    protocol=protocol,
                    state=state,  # type: ignore[arg-type]
                    processName=process_name,
                    pid=c.pid,
                )
            )

        return self._success(conns)

    # Network Info
    async def get_network_info(self) -> NetworkApiResponse:
        """Get local network information using system commands."""
        try:
            # Get default route info using `ip route`
            proc = await asyncio.create_subprocess_exec(
                "ip",
                "route",
                "show",
                "default",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            gateway_ip = ""
            interface = ""

            if stdout:
                # Parse: default via 192.168.178.1 dev eth0 proto dhcp ...
                route_line = stdout.decode().strip()
                parts = route_line.split()
                if "via" in parts:
                    via_idx = parts.index("via")
                    gateway_ip = parts[via_idx + 1] if via_idx + 1 < len(parts) else ""
                if "dev" in parts:
                    dev_idx = parts.index("dev")
                    interface = parts[dev_idx + 1] if dev_idx + 1 < len(parts) else ""

            # Get interface IP and netmask using `ip addr show`
            local_ip = ""
            netmask = "255.255.255.0"
            prefix_len = 24

            if interface:
                proc = await asyncio.create_subprocess_exec(
                    "ip",
                    "-o",
                    "-4",
                    "addr",
                    "show",
                    interface,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await proc.communicate()

                if stdout:
                    # Parse: 2: eth0    inet 192.168.1.100/24 brd 192.168.1.255 ...
                    addr_line = stdout.decode().strip()
                    import re

                    match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", addr_line)
                    if match:
                        local_ip = match.group(1)
                        prefix_len = int(match.group(2))
                        # Convert prefix to netmask
                        netmask = str(
                            ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask
                        )

            # Calculate network range
            if local_ip:
                network = ipaddress.IPv4Network(
                    f"{local_ip}/{prefix_len}", strict=False
                )
                network_range = str(network)
            elif gateway_ip:
                # Fallback: use gateway with /24
                network_range = f"{gateway_ip.rsplit('.', 1)[0]}.0/24"
            else:
                # Last fallback
                network_range = "192.168.1.0/24"

            # If we still don't have gateway, try to guess from network
            if not gateway_ip and local_ip:
                gateway_ip = f"{local_ip.rsplit('.', 1)[0]}.1"

            result = {
                "localIp": local_ip or "unknown",
                "gateway": gateway_ip or "unknown",
                "netmask": netmask,
                "interface": interface or "unknown",
                "networkRange": network_range,
            }
            return self._success(result)

        except Exception as e:
            # Final fallback using socket
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                network_range = f"{local_ip.rsplit('.', 1)[0]}.0/24"
                return self._success(
                    {
                        "localIp": local_ip,
                        "gateway": f"{local_ip.rsplit('.', 1)[0]}.1",
                        "netmask": "255.255.255.0",
                        "interface": "unknown",
                        "networkRange": network_range,
                    }
                )
            except Exception as fallback_error:
                return self._error(
                    f"Network detection error: {e}, fallback error: {fallback_error}"
                )

    # ARP Scanner
    async def arp_scan(self) -> NetworkApiResponse:
        try:
            arp_response = await self.tools.arp_table()
        except NetworkToolError as exc:
            return self._error(str(exc))

        entries: list[ARPEntry] = []
        for idx, entry in enumerate(arp_response.entries):
            # Lookup vendor by MAC address and sanitize
            vendor = None
            if entry.mac:
                vendor = _sanitize_string(
                    OUIDatabase.get_vendor(entry.mac), max_length=128
                )

            # Get state from entry_type (REACHABLE, STALE, DELAY, etc.)
            state = entry.entry_type.upper() if entry.entry_type else None

            # Sanitize interface name
            interface = _sanitize_string(entry.interface, max_length=32)

            entries.append(
                ARPEntry(
                    id=f"{entry.ip}-{idx}",
                    ip=entry.ip,
                    mac=entry.mac or "",
                    vendor=vendor,
                    interface=interface,
                    type="dynamic",
                    state=state,
                    isNew=False,
                )
            )

        result = ARPScanResult(entries=entries, timestamp=utc_now())
        return self._success(result)

    # Port Alerts
    async def port_alerts(self) -> NetworkApiResponse:
        if not self.port_alert_config.enabled:
            return self._success([])

        try:
            alerts_response = await self.tools.port_alerts()
        except NetworkToolError as exc:
            return self._error(str(exc))

        alerts: list[PortAlert] = []
        level_map = {"Critical": "critical", "Warning": "high", "Info": "low"}

        for alert in alerts_response.alerts:
            alert_id = f"{alert.port}-TCP"
            if alert_id in self.dismissed_alerts:
                continue

            risk = level_map.get(alert.level, "medium")  # type: ignore[assignment]
            description = (
                f"Service {alert.service or 'unknown'} listening on port {alert.port}"
            )

            alerts.append(
                PortAlert(
                    id=alert_id,
                    port=alert.port,
                    service=alert.service,
                    protocol="TCP",
                    riskLevel=risk,  # type: ignore[arg-type]
                    description=description,
                    recommendation=alert.recommendation
                    or "Verify if the open port is necessary",
                    isMonitored=alert.port in self.port_alert_config.monitoredPorts,
                    lastDetected=utc_now(),
                )
            )

        return self._success(alerts)

    def update_port_alert_config(self, config: PortAlertConfig) -> NetworkApiResponse:
        self.port_alert_config = config
        return self._success(config)

    def dismiss_port_alert(self, alert_id: str) -> NetworkApiResponse:
        self.dismissed_alerts.add(alert_id)
        return self._success()
