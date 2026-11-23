"""NetworkDiscoveryMixin implementation."""

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


class NetworkDiscoveryMixin:
    MANAGED_DEVICE_PATHS = (
        Path("/opt/EasyPi/data/netprotection/clients.json"),
        Path("/opt/EasyPi/data/netprotection/devices.json"),
        Path(__file__).resolve().parents[4] / "data" / "netprotection" / "clients.json",
        Path(__file__).resolve().parents[4] / "data" / "netprotection" / "devices.json",
    )

    async def scan_lan(self, config: LANScanConfig) -> NetworkApiResponse:
        start = time.perf_counter()

        # Method 0: ARP-prime the whole subnet so EVERY live L2 device lands in the neighbor
        # table — a real sweep that TCP-port probing alone misses (idle / firewalled devices,
        # not already in the ARP cache), and without needing root / arp-scan.
        await self._arp_prime(config.networkRange)

        # Use multiple methods to find all devices
        hosts_by_ip: dict[str, NetworkHost] = {}

        # Method 1: Native Python scanner
        try:
            scan_result = await self._scanner.discover_hosts(config.networkRange)
            if not scan_result.error:
                for host in scan_result.hosts:
                    if host.status == HostStatus.ONLINE:
                        # Copy all fields including device_type and confidence from native scanner
                        hosts_by_ip[host.ip] = NetworkHost(
                            ip=host.ip,
                            mac=host.mac,
                            vendor=host.vendor,
                            hostname=host.hostname,
                            device_type=host.device_type,
                            type_confidence=host.type_confidence,
                            identity_sources=["active-scan"],
                            identity_confidence=0.75,
                            status="online",
                        )
        except Exception as exc:
            # Continue with other methods even if native scan fails
            logger.warning("Native LAN discovery failed: %s", exc)

        # Method 2: ARP table (already known devices)
        try:
            arp_hosts = await self._get_arp_hosts()
            for host in arp_hosts:
                hosts_by_ip[host.ip] = self._merge_host(hosts_by_ip.get(host.ip), host)
        except Exception as exc:
            logger.warning("ARP neighbor discovery failed: %s", exc)

        # Method 3: arp-scan (if available). Works without root when setcap is applied.
        if self._has_arp_scan():
            try:
                arpscan_hosts = await self._run_arp_scan(config.networkRange)
                for host in arpscan_hosts:
                    hosts_by_ip[host.ip] = self._merge_host(
                        hosts_by_ip.get(host.ip), host
                    )
            except Exception as exc:
                logger.warning("arp-scan discovery failed: %s", exc)

        self._enrich_from_dhcp_observations(hosts_by_ip)
        self._enrich_from_known_devices(hosts_by_ip)

        # Filter hosts by network range - only IPv4
        hosts = [h for h in hosts_by_ip.values() if self._is_ipv4(h.ip)]

        if not hosts:
            return self._error(
                "No devices found on the network. Check the network range."
            )

        # Build devices in parallel for speed (limit concurrency to 20)
        semaphore = asyncio.Semaphore(20)

        async def build_with_limit(host: NetworkHost) -> LANDevice:
            async with semaphore:
                return await self._build_lan_device(host, config)

        devices = await asyncio.gather(*[build_with_limit(h) for h in hosts])
        devices = self._merge_local_device_rows(list(devices), config.networkRange)

        # Sort by IP (IPv4 only)
        devices.sort(key=lambda d: self._ip_sort_key(d.ip))

        result = LANScanResult(
            devices=devices,
            scanTime=round(time.perf_counter() - start, 2),
            networkRange=config.networkRange,
            timestamp=utc_now(),
        )

        # Cache the results for schedule device selection
        self._last_scan_devices = [
            {
                "ip": d.ip,
                "mac": d.mac,
                "hostname": d.customName or d.hostname,
                "network_hostname": d.hostname,
                "custom_name": d.customName,
                "vendor": d.vendor,
                "device_type": d.deviceType,
                "dhcp_vendor_class": d.dhcpVendorClass,
                "identity_sources": d.identitySources,
                "identity_confidence": d.identityConfidence,
            }
            for d in devices
        ]
        self._last_scan_time = utc_now()
        self._persist_scan_cache()

        return self._success(result)

    @staticmethod
    def _own_lan_interfaces(network_range: str) -> list[dict[str, str]]:
        """Return physical interfaces of this EasyPi inside the scanned network."""
        try:
            network = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            return []

        ignored_prefixes = (
            "lo",
            "docker",
            "br-",
            "veth",
            "virbr",
            "tailscale",
            "wg",
            "tun",
            "tap",
            "chameleon",
        )
        interfaces: list[dict[str, str]] = []
        link_family = getattr(psutil, "AF_LINK", None)
        for name, addresses in psutil.net_if_addrs().items():
            if name.lower().startswith(ignored_prefixes):
                continue
            mac = next(
                (
                    str(address.address).upper()
                    for address in addresses
                    if address.family == link_family
                    and re.fullmatch(
                        r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}",
                        str(address.address),
                    )
                    and str(address.address) != "00:00:00:00:00:00"
                ),
                "",
            )
            if not mac:
                continue
            for address in addresses:
                if address.family != socket.AF_INET:
                    continue
                try:
                    ip = ipaddress.ip_address(str(address.address))
                except ValueError:
                    continue
                if ip in network and not ip.is_loopback:
                    interfaces.append({"name": name, "ip": str(ip), "mac": mac})

        def sort_key(item: dict[str, str]) -> tuple[int, str, tuple[int, ...]]:
            name = item["name"].lower()
            priority = 0 if name.startswith(("eth", "en")) else 1
            return priority, name, tuple(int(part) for part in item["ip"].split("."))

        return sorted(interfaces, key=sort_key)

    def _merge_local_device_rows(
        self, devices: list[LANDevice], network_range: str
    ) -> list[LANDevice]:
        interfaces = self._own_lan_interfaces(network_range)
        if not interfaces:
            return devices

        own_ips = {item["ip"] for item in interfaces}
        own_macs = {item["mac"].upper() for item in interfaces}
        local_rows = [
            device
            for device in devices
            if device.ip in own_ips
            or bool(device.mac and device.mac.upper() in own_macs)
        ]
        remaining = [device for device in devices if device not in local_rows]
        primary = interfaces[0]
        representative = next(
            (device for device in local_rows if device.ip == primary["ip"]),
            local_rows[0] if local_rows else None,
        )
        ports = sorted(
            {
                port
                for device in local_rows
                for port in (device.ports or [])
            }
        )
        sources = list(
            dict.fromkeys(
                source
                for device in local_rows
                for source in device.identitySources
            )
        )
        sources.append("local-interface")
        remaining.append(
            LANDevice(
                id="local-easypi",
                ip=primary["ip"],
                mac=primary["mac"],
                vendor=representative.vendor if representative else "Raspberry Pi",
                hostname=(
                    representative.hostname
                    if representative and representative.hostname
                    else socket.gethostname()
                ),
                customName="This EasyPi",
                status="online",
                lastSeen=utc_now(),
                ports=ports or None,
                deviceType="pi",
                dhcpVendorClass=(
                    representative.dhcpVendorClass if representative else None
                ),
                identitySources=sources,
                identityConfidence=1.0,
                interfaces=interfaces,
                isLocalDevice=True,
            )
        )
        return remaining

    @staticmethod
    def _merge_host(
        existing: NetworkHost | None, candidate: NetworkHost
    ) -> NetworkHost:
        if existing is None:
            return candidate
        sources = list(
            dict.fromkeys(existing.identity_sources + candidate.identity_sources)
        )
        confidences = [
            value
            for value in (existing.identity_confidence, candidate.identity_confidence)
            if value is not None
        ]
        seen = [
            value
            for value in (existing.last_seen_timestamp, candidate.last_seen_timestamp)
            if value is not None
        ]
        return NetworkHost(
            ip=existing.ip,
            mac=existing.mac or candidate.mac,
            vendor=existing.vendor or candidate.vendor,
            hostname=existing.hostname or candidate.hostname,
            custom_name=existing.custom_name or candidate.custom_name,
            device_type=existing.device_type or candidate.device_type,
            type_confidence=existing.type_confidence or candidate.type_confidence,
            dhcp_vendor_class=existing.dhcp_vendor_class or candidate.dhcp_vendor_class,
            identity_sources=sources,
            identity_confidence=max(confidences) if confidences else None,
            last_seen_timestamp=max(seen) if seen else None,
            status="online",
        )

    def _enrich_from_dhcp_observations(
        self, hosts_by_ip: dict[str, NetworkHost]
    ) -> None:
        hosts_by_mac = {
            host.mac.upper(): host for host in hosts_by_ip.values() if host.mac
        }
        for identity in load_dhcp_identities(self.DHCP_OBSERVATION_PATHS):
            existing = hosts_by_ip.get(identity.ip) or hosts_by_mac.get(identity.mac)
            if existing is None and not identity.recently_observed:
                continue
            candidate = NetworkHost(
                ip=existing.ip if existing else identity.ip,
                mac=identity.mac,
                hostname=identity.hostname,
                dhcp_vendor_class=identity.vendor_class,
                identity_sources=["dhcp-observer"],
                identity_confidence=0.9 if identity.hostname else 0.75,
                last_seen_timestamp=identity.last_seen_timestamp,
                status="online",
            )
            merged = self._merge_host(existing, candidate)
            hosts_by_ip[merged.ip] = merged
            hosts_by_mac[identity.mac] = merged

    def _load_known_devices(self) -> list[NetworkHost]:
        for path in self.KNOWN_DEVICE_PATHS:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except FileNotFoundError:
                continue
            except Exception as exc:
                logger.warning("Cannot read known-device inventory %s: %s", path, exc)
                continue
            if not isinstance(raw, list):
                continue
            devices: list[NetworkHost] = []
            for item in raw:
                if not isinstance(item, dict):
                    continue
                ip = str(item.get("ip") or "").strip()
                if not self._is_ipv4(ip):
                    continue
                mac = str(item.get("mac") or "").strip() or None
                name = str(item.get("name") or "").strip() or None
                devices.append(
                    NetworkHost(ip=ip, mac=mac, custom_name=name, status="online")
                )
            return devices
        return []

    def _enrich_from_known_devices(self, hosts_by_ip: dict[str, NetworkHost]) -> None:
        hosts_by_mac = {
            host.mac.upper(): host for host in hosts_by_ip.values() if host.mac
        }
        for known in self._load_known_devices():
            existing = hosts_by_ip.get(known.ip)
            if existing is None and known.mac:
                existing = hosts_by_mac.get(known.mac.upper())
            if existing is None:
                continue
            sources = list(
                dict.fromkeys(existing.identity_sources + ["user-inventory"])
            )
            merged = existing.model_copy(
                update={
                    "mac": existing.mac or known.mac,
                    "custom_name": known.custom_name or existing.custom_name,
                    "identity_sources": sources,
                    "identity_confidence": 1.0
                    if known.custom_name
                    else existing.identity_confidence,
                }
            )
            hosts_by_ip[existing.ip] = merged
            if merged.mac:
                hosts_by_mac[merged.mac.upper()] = merged

    def _scan_cache_path(self) -> Path:
        base = Path("/opt/EasyPi/data")
        if not base.exists():
            base = Path("data")
        return base / "network" / "lan_devices.json"

    def _persist_scan_cache(self) -> None:
        """Save the last LAN scan to disk so the device picker survives a backend restart.
        The in-memory cache alone was wiped on every restart, emptying the picker until a
        re-scan."""
        try:
            path = self._scan_cache_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "devices": self._last_scan_devices,
                "scan_time": self._last_scan_time.isoformat()
                if self._last_scan_time
                else None,
            }
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            pass

    def _load_scan_cache(self) -> tuple[list[dict], datetime | None]:
        """Load the persisted LAN scan → (devices, scan_time)."""
        try:
            data = json.loads(self._scan_cache_path().read_text(encoding="utf-8"))
        except Exception:
            return [], None
        devices = data.get("devices", []) if isinstance(data, dict) else []
        if not isinstance(devices, list):
            devices = []
        scan_time = None
        raw_ts = data.get("scan_time") if isinstance(data, dict) else None
        if raw_ts:
            try:
                scan_time = datetime.fromisoformat(str(raw_ts))
            except Exception:
                scan_time = None
        return devices, scan_time

    def _load_managed_picker_devices(self) -> list[dict]:
        """Load administrator-approved devices for every policy picker.

        ``clients.json`` is the canonical Guard Security inventory.  The older
        ``devices.json`` projection remains a compatibility fallback.  Entries
        are deduplicated by MAC, with the canonical client record taking
        precedence over its legacy projection.
        """
        result: list[dict] = []
        seen_macs: set[str] = set()
        for path in self.MANAGED_DEVICE_PATHS:
            try:
                if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, ValueError, TypeError):
                continue

            records = payload.get("clients", []) if isinstance(payload, dict) else payload
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, dict):
                    continue
                mac = str(record.get("mac") or "").strip().lower()
                if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                    continue
                if mac in seen_macs:
                    continue
                raw_ip = record.get("ip")
                if not raw_ip and isinstance(record.get("ids"), list) and record["ids"]:
                    raw_ip = record["ids"][0]
                ip = str(raw_ip or "").strip()
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                except ipaddress.AddressValueError:
                    continue
                if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast:
                    continue
                name = str(record.get("name") or "").strip()[:128] or None
                result.append(
                    {
                        "ip": str(ip_obj),
                        "mac": mac,
                        "hostname": name,
                        "vendor": None,
                        "source": "managed",
                    }
                )
                seen_macs.add(mac)
        return result

    def _own_ipv4_addresses(self) -> set[str]:
        """This box's own IPv4 addresses — never offered as a routable target."""
        own: set[str] = set()
        try:
            for iface in self._interface_names():
                for addr in self._ipv4_addresses(iface):
                    ip = str(addr.get("addr") or "").strip()
                    if ip and not ip.startswith("127."):
                        own.add(ip)
        except Exception:
            pass
        return own

    @staticmethod
    def _live_ipv4_by_mac() -> dict[str, str]:
        """Current kernel ARP entries keyed by canonical MAC address."""
        result: dict[str, str] = {}
        try:
            with Path("/proc/net/arp").open(encoding="utf-8") as handle:
                next(handle, None)
                for line in handle:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ip, flags, mac = parts[0], parts[2], parts[3].lower()
                    if flags in {"0x0", "0x00"}:
                        continue
                    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                        continue
                    try:
                        if ipaddress.ip_address(ip).version == 4:
                            result[mac] = ip
                    except ValueError:
                        continue
        except Exception:
            pass
        return result

    @staticmethod
    def _retired_prism_aliases() -> dict[str, str]:
        """Map retired randomized MACs to current MACs for inventory display."""
        candidates = (
            Path("/opt/EasyPi/data/netprotection/prism_identity.json"),
            Path("data/netprotection/prism_identity.json"),
        )
        for path in candidates:
            try:
                if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
                    continue
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (FileNotFoundError, OSError, ValueError, TypeError):
                continue
            profiles = payload.get("profiles", {}) if isinstance(payload, dict) else {}
            if not isinstance(profiles, dict):
                continue
            aliases: dict[str, str] = {}
            for profile in profiles.values():
                if not isinstance(profile, dict):
                    continue
                active_mac = str(profile.get("active_mac") or "").strip().lower()
                if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", active_mac):
                    continue
                for alias in profile.get("aliases", []) or []:
                    if not isinstance(alias, dict) or alias.get("status") != "retired":
                        continue
                    retired_mac = str(alias.get("mac") or "").strip().lower()
                    if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", retired_mac):
                        aliases[retired_mac] = active_mac
            return aliases
        return {}

    async def get_cached_devices(self) -> dict:
        """Return one shared inventory for all device policy pickers.

        Administrator-approved Guard Security devices are always included, so
        Parental Controls, Schedules, Internet Encryption and Stealth do not
        require a second LAN scan.  A scan still enriches the inventory with
        unapproved discoveries, vendor details and additional live devices.
        """
        gateway_ip = self._default_gateway_ip()
        own_ips = self._own_ipv4_addresses()

        devices = self._last_scan_devices
        scan_time = self._last_scan_time
        if not devices:
            devices, scan_time = self._load_scan_cache()

        # Merge the scan with the administrator-approved inventory.  The
        # approved name is authoritative; scan metadata fills everything else.
        merged_by_mac: dict[str, dict] = {}
        devices_without_mac: list[dict] = []
        for device in devices:
            item = dict(device)
            mac = str(item.get("mac") or "").lower().strip()
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                item["mac"] = mac
                merged_by_mac[mac] = item
            else:
                devices_without_mac.append(item)
        for managed in self._load_managed_picker_devices():
            mac = managed["mac"]
            existing = merged_by_mac.get(mac, {})
            merged_by_mac[mac] = {
                **managed,
                **existing,
                "ip": managed.get("ip") or existing.get("ip"),
                "mac": mac,
                "hostname": managed.get("hostname") or existing.get("hostname"),
                "vendor": existing.get("vendor") or managed.get("vendor"),
                "source": "managed+scan" if existing else "managed",
            }
        # Process managed records first.  If a stale scanned MAC and a current
        # PRISM identity later collapse to the same active MAC, the approved
        # name and identity must win the deduplication below.
        merged_devices = sorted(
            merged_by_mac.values(),
            key=lambda item: 0
            if str(item.get("source") or "").startswith("managed")
            else 1,
        )
        devices = [*merged_devices, *devices_without_mac]

        live_by_mac = self._live_ipv4_by_mac()
        retired_aliases = self._retired_prism_aliases()
        seen_macs: set[str] = set()
        devices_with_router_flag = []
        for device in devices:
            item = dict(device)
            mac = str(item.get("mac") or "").lower().strip()
            # Phones may rotate their private Wi-Fi MAC. PRISM has already
            # authenticated this migration; use it only to refresh inventory
            # display while firewall policy keeps its stricter path.
            current_mac = retired_aliases.get(mac)
            if mac not in live_by_mac and current_mac in live_by_mac:
                mac = current_mac
            if mac and mac in seen_macs:
                continue
            if mac:
                seen_macs.add(mac)
                item["mac"] = mac
                item["ip"] = live_by_mac.get(mac, item.get("ip"))
            item["is_online"] = bool(mac and mac in live_by_mac)
            if item["is_online"]:
                item["last_seen"] = utc_now().isoformat()
            ip = item.get("ip")
            if ip in own_ips:
                continue  # never offer the EasyPi box itself as a Stealth/VPN target
            item["is_router"] = bool(gateway_ip) and ip == gateway_ip
            devices_with_router_flag.append(item)

        return {
            "devices": devices_with_router_flag,
            "last_scan_time": scan_time.isoformat() if scan_time else None,
            "gateway_ip": gateway_ip,
        }

    def clear_cached_devices(self) -> dict:
        """Clear the cached devices list."""
        self._last_scan_devices = []
        self._last_scan_time = None
        try:
            self._scan_cache_path().unlink(missing_ok=True)
        except Exception:
            pass
        return {"success": True, "message": "Device cache cleared"}

    def _is_ipv4(self, ip: str) -> bool:
        """Check if string is a valid IPv4 address."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False

    def _ip_sort_key(self, ip: str) -> tuple:
        """Get sort key for IPv4 address."""
        try:
            return tuple(int(p) for p in ip.split("."))
        except ValueError:
            return (999, 999, 999, 999)

    async def _arp_prime(self, network_range: str) -> None:
        """Force the kernel to ARP-resolve every host in the subnet, so the neighbor table
        then lists EVERY live L2 device. Sending any UDP datagram to a local-subnet IP makes
        the kernel ARP for it first; live devices reply and land in `ip neigh`. A real sweep
        that the TCP-port probe misses (idle / firewalled devices), and needs no root."""
        try:
            net = ipaddress.ip_network(network_range, strict=False)
        except Exception:
            return
        hosts = [str(h) for h in net.hosts()]
        if not hosts or len(hosts) > 1024:  # only sweep real LAN-sized ranges
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            for ip in hosts:
                try:
                    sock.sendto(b"\x00", (ip, 40000))
                except Exception:
                    pass
        finally:
            sock.close()
        await asyncio.sleep(1.5)  # allow ARP replies to populate the neighbor table

    async def _get_arp_hosts(self) -> list[NetworkHost]:
        """Get hosts from system ARP table."""
        hosts: list[NetworkHost] = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "ip",
                "neigh",
                "show",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()

            for line in stdout.decode().splitlines():
                # Parse: 192.168.178.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
                parts = line.split()
                if len(parts) >= 4 and "lladdr" in parts:
                    ip = parts[0]

                    # Skip IPv6 addresses
                    if ":" in ip and "." not in ip:
                        continue

                    lladdr_idx = parts.index("lladdr")
                    mac = parts[lladdr_idx + 1] if lladdr_idx + 1 < len(parts) else None

                    # Check state (REACHABLE, STALE, DELAY are usually valid)
                    state = parts[-1] if parts else ""
                    if state in ("FAILED", "INCOMPLETE"):
                        continue

                    if ip and mac and self._is_ipv4(ip):
                        hosts.append(
                            NetworkHost(
                                ip=ip,
                                mac=mac.upper(),
                                vendor=None,
                                identity_sources=["arp-neighbor"],
                                identity_confidence=0.8,
                                status="online",
                            )
                        )
        except Exception as exc:
            logger.warning("Could not read ARP neighbor table: %s", exc)

        return hosts

    async def _run_arp_scan(self, network_range: str) -> list[NetworkHost]:
        """Run arp-scan for more complete discovery."""
        hosts: list[NetworkHost] = []
        try:
            arp_scan_binary = resolve_arp_scan_binary()
            if not arp_scan_binary:
                return hosts
            proc = await asyncio.create_subprocess_exec(
                arp_scan_binary,
                "--localnet",
                "-q",
                "--timeout=500",
                "--retry=2",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

            for line in stdout.decode().splitlines():
                # Parse: 192.168.178.1   aa:bb:cc:dd:ee:ff   Vendor Name
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip() if len(parts) > 1 else None
                    vendor = parts[2].strip() if len(parts) > 2 else None

                    if ip and re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        hosts.append(
                            NetworkHost(
                                ip=ip,
                                mac=mac,
                                vendor=vendor,
                                identity_sources=["arp-scan"],
                                identity_confidence=0.85,
                                status="online",
                            )
                        )
        except Exception as exc:
            logger.warning("arp-scan execution failed: %s", exc)

        return hosts

    def _host_scan_timeout(self, speed: str) -> int:
        if speed == "fast":
            return 45
        if speed == "deep":
            return 120
        return 90

    async def _resolve_hostname(self, ip: str) -> str | None:
        """Try multiple methods to resolve hostname for an IP address."""
        # Validate IP format to prevent command injection
        if not self._is_ipv4(ip):
            return None

        hostname = None

        # Method 1: Query router/gateway DNS directly (most reliable for home networks)
        # Get gateway IP from the target IP (assume .1 or .254)
        ip_parts = ip.rsplit(".", 1)
        gateway_candidates = [f"{ip_parts[0]}.1", f"{ip_parts[0]}.254"]

        for gateway in gateway_candidates:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig",
                    "-x",
                    ip,
                    f"@{gateway}",
                    "+short",
                    "+timeout=1",
                    "+tries=1",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.5)
                output = stdout.decode().strip()
                if output and not output.startswith(";"):
                    # Take only the first line (dig may return multiple PTR records)
                    first_line = output.split("\n")[0].strip()
                    # Remove trailing dot
                    hostname = first_line.rstrip(".")
                    # Remove common domain suffixes for cleaner display
                    for suffix in [
                        ".fritz.box",
                        ".local",
                        ".lan",
                        ".home",
                        ".localdomain",
                        ".home.arpa",
                        ".internal",
                    ]:
                        if hostname.lower().endswith(suffix):
                            hostname = hostname[: -len(suffix)]
                            break
                    # Limit length to prevent UI overflow
                    if hostname and len(hostname) > 32:
                        hostname = hostname[:32]
                    if hostname:
                        return hostname
            except Exception:
                pass

        # Method 2: Standard DNS reverse lookup (PTR record) - run in executor to not block
        try:
            loop = asyncio.get_event_loop()
            hostname = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0]),
                timeout=1.0,
            )
            if hostname:
                return hostname
        except Exception:
            pass

        # Method 3: mDNS/Avahi lookup (.local names) - reduced timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                "avahi-resolve",
                "-a",
                ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.0)
            output = stdout.decode().strip()
            if output:
                # Format: "192.168.178.21    hostname.local"
                parts = output.split()
                if len(parts) >= 2:
                    hostname = parts[1]
                    return hostname
        except Exception:
            pass

        # Method 4: NetBIOS name lookup (Windows devices) - reduced timeout
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmblookup",
                "-A",
                ip,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=1.5)
            output = stdout.decode()
            # Parse nmblookup output - look for <00> entries (workstation name)
            for line in output.splitlines():
                line = line.strip()
                if "<00>" in line and "GROUP" not in line:
                    # Format: "HOSTNAME        <00> -         B <ACTIVE>"
                    parts = line.split()
                    if parts:
                        hostname = parts[0]
                        return hostname
        except Exception:
            pass

        # Method 5: Check /etc/hosts
        try:
            with open("/etc/hosts", "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[0] == ip:
                            return parts[1]
        except Exception:
            pass

        # Method 6: Check DHCP leases (dnsmasq, dhcpd, NetworkManager)
        for lease_file in [
            "/var/lib/misc/dnsmasq.leases",
            "/var/lib/dnsmasq/dnsmasq.leases",
            "/tmp/dnsmasq.leases",
            "/var/lib/dhcp/dhcpd.leases",
            "/var/lib/NetworkManager/dnsmasq-*.leases",
        ]:
            try:
                import glob

                files = glob.glob(lease_file) if "*" in lease_file else [lease_file]
                for f in files:
                    try:
                        with open(f, "r") as fh:
                            for line in fh:
                                parts = line.strip().split()
                                # dnsmasq format: timestamp mac ip hostname client-id
                                if len(parts) >= 4 and parts[2] == ip:
                                    name = parts[3]
                                    if name and name != "*":
                                        return name
                    except Exception:
                        pass
            except Exception:
                pass

        # NOTE: deliberately NO passive DNS-log correlation. Inferring a device's NAME
        # from the .local/.lan domains it QUERIED is unsound: a device that opens the
        # EasyPi panel (easypi.local), a NAS or a printer would be mislabeled with THAT
        # name — that is exactly how the box's own client got shown as "easypi".
        # Hostnames come only from real identity sources (rDNS/mDNS/NetBIOS/DHCP/hosts).

        return hostname

    async def _build_lan_device(
        self, host: NetworkHost, config: LANScanConfig
    ) -> LANDevice:
        # Handle hostname resolution
        hostname: str | None = None
        if config.resolveHostnames:
            # Use existing hostname from native scanner
            hostname = host.hostname
            if not hostname:
                # Try multiple methods to resolve hostname
                hostname = await self._resolve_hostname(host.ip)

        # Sanitize hostname to prevent XSS
        hostname = _sanitize_string(hostname, max_length=128)

        ports: list[int] | None = None
        # Port discovery is the slow part: an asleep / firewalled device answers every one
        # of the ~100 probed ports with a full timeout (~80s/host), which is what turned a
        # 5-device scan into ~3 minutes. Skip it in "fast" mode (just list the devices), and
        # hard-cap it per host so one unresponsive device can't stretch the whole scan.
        if config.portDiscovery and config.scanSpeed != "fast":
            try:
                ports = await asyncio.wait_for(
                    self._discover_ports_native(host.ip), timeout=8.0
                )
            except Exception:
                ports = None

        # Handle vendor detection
        vendor: str | None = None
        if config.detectVendor:
            # Use existing vendor from arp-scan/native scanner, or look up in OUI database
            vendor = host.vendor
            if not vendor and host.mac:
                vendor = OUIDatabase.get_vendor(host.mac)

        # Sanitize vendor to prevent XSS
        vendor = _sanitize_string(vendor, max_length=128)

        # Determine device type:
        # 1. Use native scanner's device_type if available and confident
        # 2. Otherwise compute using our _guess_device_type with COMPUTED vendor
        device_type = (
            host.device_type
            if host.device_type and (host.type_confidence or 0) >= 0.8
            else None
        )
        if not device_type or device_type == "unknown":
            # Create a temporary host with computed vendor for type guessing
            host_with_vendor = NetworkHost(
                ip=host.ip,
                mac=host.mac,
                vendor=vendor,  # Use computed vendor, not host.vendor
                hostname=hostname,
                status=host.status,
            )
            device_type = self._guess_device_type(host_with_vendor, ports, hostname)

        # Normalize device_type to valid DeviceType enum value to prevent validation errors
        device_type = _normalize_device_type(device_type)

        return LANDevice(
            id=host.ip,
            ip=host.ip,
            mac=host.mac,
            vendor=vendor,
            hostname=hostname,
            customName=_sanitize_string(host.custom_name, max_length=128),
            status=host.status
            if host.status in ("online", "offline", "limited")
            else "online",
            lastSeen=(
                datetime.fromtimestamp(host.last_seen_timestamp)
                if host.last_seen_timestamp is not None
                else utc_now()
            ),
            ports=ports,
            deviceType=device_type,
            dhcpVendorClass=_sanitize_string(host.dhcp_vendor_class, max_length=128),
            identitySources=host.identity_sources,
            identityConfidence=host.identity_confidence,
        )

    async def _discover_ports_native(self, ip: str) -> list[int]:
        """Lightweight port discovery using native scanner."""
        try:
            scan_result = await self._scanner.scan_ports(ip, mode="quick")
            if scan_result.error:
                return []

            open_ports: list[int] = []
            if scan_result.hosts and scan_result.hosts[0].ports:
                for port in scan_result.hosts[0].ports:
                    if port.state == PortState.OPEN:
                        open_ports.append(port.port)
            return sorted(set(open_ports))
        except Exception:
            return []

    def _guess_device_type(
        self,
        host: NetworkHost,
        ports: list[int] | None = None,
        hostname: str | None = None,
    ) -> str:
        """Guess device type based on vendor, hostname, MAC and open ports."""
        vendor = (host.vendor or "").lower()
        hostname = (hostname or host.hostname or "").lower()
        mac = (host.mac or "").upper()
        ports = ports or []
        ip = host.ip or ""
        identity_hint = f"{hostname} {host.dhcp_vendor_class or ''}".lower()

        # === First check by open ports (most reliable) ===
        if ports:
            # Routers typically have DNS (53) or DHCP (67) or web interface
            if 53 in ports or 67 in ports:
                return "router"
            if (80 in ports or 443 in ports) and ip.endswith((".1", ".254")):
                return "router"
            # Printers
            if 9100 in ports or 631 in ports:
                return "printer"
            # NAS / Servers
            if 445 in ports and 139 in ports:
                return "nas"
            # SSH without web = likely computer/server
            if 22 in ports and 80 not in ports:
                return "computer"

        # === Check by IP address ===
        if ip.endswith(".1") or ip.endswith(".254"):
            return "router"

        # Hostname and DHCP client class describe the operating device more
        # reliably than the manufacturer of its Wi-Fi/Ethernet chipset.
        if any(
            hint in identity_hint
            for hint in ("iphone", "ipad", "android", "galaxy", "pixel", "phone")
        ):
            return "phone"
        if any(
            hint in identity_hint
            for hint in (
                "msft",
                "windows",
                "desktop",
                "laptop",
                "workstation",
                "macbook",
                "imac",
            )
        ):
            return "computer"

        # === Check by vendor name ===
        # Raspberry Pi
        if any(x in vendor for x in ["raspberry", "raspberr"]):
            return "pi"

        # Private/randomized MAC - likely a phone
        if "private" in vendor or "randomized" in vendor:
            return "phone"

        # Routers / Network equipment
        router_vendors = [
            "cisco",
            "netgear",
            "tp-link",
            "tplink",
            "linksys",
            "d-link",
            "dlink",
            "zyxel",
            "mikrotik",
            "ubiquiti",
            "fritz",
            "avm",
            "arris",
            "motorola",
            "belkin",
            "buffalo",
        ]
        if any(x in vendor for x in router_vendors):
            return "router"

        # ASUS can be router or computer
        if "asus" in vendor:
            if any(x in hostname for x in ["router", "rt-", "gt-"]):
                return "router"
            return "computer"

        # Huawei - check if it's network equipment or phone
        if "huawei" in vendor:
            # Network equipment indicators
            if any(
                x in hostname
                for x in ["router", "modem", "gateway", "hg", "b535", "cpe"]
            ):
                return "router"
            # If no hostname clues and has web ports, likely network device
            if ports and (80 in ports or 443 in ports):
                return "router"
            # Huawei manufactures phones, laptops and network equipment. The
            # OUI alone does not identify which product owns the interface.
            return "unknown"

        # Phones / Mobile devices
        phone_vendors = [
            "apple",
            "samsung",
            "xiaomi",
            "oneplus",
            "oppo",
            "vivo",
            "realme",
            "google",
            "pixel",
            "motorola",
            "nokia",
            "sony mobile",
            "lg electronics",
            "htc",
            "zte",
            "meizu",
            "honor",
            "poco",
            "redmi",
            "iphone",
            "mobile",
            "wireless",
        ]
        if any(x in vendor for x in phone_vendors):
            # Check if it's likely a phone vs computer
            if "apple" in vendor:
                # Apple could be iPhone, iPad, Mac, Apple TV
                if any(x in hostname for x in ["iphone", "ipad", "ipod"]):
                    return "phone"
                if any(x in hostname for x in ["macbook", "imac", "mac-", "mac."]):
                    return "computer"
                if any(x in hostname for x in ["apple-tv", "appletv"]):
                    return "tv"
                # Default Apple to phone (most common)
                return "phone"
            return "phone"

        # TVs / Smart TVs
        tv_vendors = [
            "samsung tv",
            "lg tv",
            "sony tv",
            "philips",
            "tcl",
            "hisense",
            "vizio",
            "roku",
            "fire tv",
            "chromecast",
            "android tv",
            "smart tv",
            "toshiba",
            "panasonic",
            "sharp",
        ]
        if any(x in vendor for x in tv_vendors):
            return "tv"

        # Game consoles
        console_vendors = [
            "sony computer",
            "playstation",
            "microsoft xbox",
            "nintendo",
            "xbox",
            "valve",
            "steam",
        ]
        if any(x in vendor for x in console_vendors):
            return "console"

        # Printers
        printer_vendors = [
            "hp ",
            "hewlett",
            "canon",
            "epson",
            "brother",
            "xerox",
            "lexmark",
            "ricoh",
            "kyocera",
            "konica",
        ]
        if any(x in vendor for x in printer_vendors):
            return "printer"

        # Computers
        computer_vendors = [
            "dell",
            "lenovo",
            "intel",
            "amd",
            "gigabyte",
            "asrock",
            "msi",
            "asus computer",
            "acer",
            "toshiba computer",
            "microsoft",
            "vmware",
            "parallels",
            "virtualbox",
        ]
        if any(x in vendor for x in computer_vendors):
            return "computer"

        # === Check by hostname ===
        if hostname:
            # Phones
            if any(
                x in hostname
                for x in [
                    "iphone",
                    "ipad",
                    "android",
                    "galaxy",
                    "pixel",
                    "xiaomi",
                    "phone",
                    "mobile",
                    "sm-",
                    "gt-",
                    "tab-",
                ]
            ):
                return "phone"

            # Computers
            if any(
                x in hostname
                for x in [
                    "pc",
                    "desktop",
                    "laptop",
                    "macbook",
                    "imac",
                    "workstation",
                    "server",
                    "windows",
                    "linux",
                    "ubuntu",
                ]
            ):
                return "computer"

            # TVs
            if any(
                x in hostname
                for x in [
                    "tv",
                    "roku",
                    "firetv",
                    "chromecast",
                    "androidtv",
                    "smarttv",
                    "bravia",
                ]
            ):
                return "tv"

            # Printers
            if any(
                x in hostname
                for x in [
                    "printer",
                    "print",
                    "epson",
                    "canon",
                    "hp-",
                    "laserjet",
                    "deskjet",
                    "officejet",
                ]
            ):
                return "printer"

            # Raspberry Pi
            if any(
                x in hostname for x in ["raspberry", "raspberrypi", "rpi", "easypi"]
            ):
                return "pi"

            # Routers
            if any(x in hostname for x in ["router", "gateway", "fritz", "modem"]):
                return "router"

            # Game consoles
            if any(
                x in hostname for x in ["playstation", "xbox", "nintendo", "ps4", "ps5"]
            ):
                return "console"

        # === Check by MAC OUI (first 3 bytes) ===
        if mac and len(mac) >= 8:
            oui = mac[:8].replace(":", "").replace("-", "")[:6]

            # Some common OUIs
            apple_ouis = [
                "00A040",
                "000A27",
                "000A95",
                "000D93",
                "001124",
                "001451",
                "0016CB",
                "0017F2",
                "0019E3",
                "001B63",
                "001CB3",
                "001D4F",
                "001E52",
                "001EC2",
                "001F5B",
                "001FF3",
                "00236C",
                "002332",
                "002436",
                "002500",
                "002608",
                "00264A",
                "003065",
                "003EE1",
                "0050E4",
                "005882",
                "006171",
                "008865",
                "009027",
                "00A040",
                "00B362",
                "00C610",
                "00CDFE",
                "00F4B9",
                "00F76F",
                "041E64",
                "04489A",
                "044BED",
                "04521C",
                "045453",
                "04D3CF",
                "04DB56",
                "04E536",
                "04F7E4",
                "080007",
                "086698",
                "08F69C",
                "0C1539",
                "0C3021",
                "0C4DE9",
                "0C5101",
                "0C74C2",
                "0C771A",
                "0CBC9F",
                "0CD746",
                "0CDFA4",
                "100723",
                "100B58",
                "101C0C",
                "10417F",
                "1040F3",
                "1041BC",
                "1093E9",
                "10DD35",
                "1094BB",
                "10DDB1",
                "14109F",
                "14205E",
                "142D27",
                "1478E2",
                "148FC6",
                "14998B",
                "1499E2",
                "14BD61",
                "14C213",
                "14F65A",
                "182032",
                "1831BF",
                "183451",
                "189EFC",
                "18AF61",
                "18AF8F",
                "18E7F4",
                "18EE69",
                "18F643",
                "1C1AC0",
                "1C36BB",
                "1C5CF2",
                "1C69A5",
                "1C9148",
                "1C9E46",
                "1CABA7",
                "1CE62B",
                "1CF5E3",
                "200BC7",
                "2030AB",
            ]

            samsung_ouis = [
                "002119",
                "002490",
                "00265D",
                "10D38A",
                "1C62B8",
                "1C66AA",
                "2C4401",
                "30CBF8",
                "3423BA",
                "380A94",
                "3C5A37",
                "4018B1",
                "4844F7",
                "50017F",
                "50756C",
                "54FA3E",
                "5CAF06",
                "6077E2",
                "645AED",
                "6C2F2C",
                "70F927",
                "74458A",
                "78321B",
                "78471D",
                "78D6F0",
                "842519",
                "88329B",
                "8879C7",
                "8C77B8",
                "90F1AA",
                "94350A",
                "9463D1",
                "9852B1",
                "9C0298",
                "9C02B1",
                "A47E39",
                "A4EBAA",
                "A82BB9",
                "ACEE9E",
                "B499BA",
                "B83A5A",
                "BC14EF",
                "BC4760",
                "C08997",
                "C0BDD1",
                "C4731E",
                "CC051B",
                "CC07AB",
                "D022BE",
                "D0176A",
                "D0C1B1",
                "D4878B",
                "D8F0E5",
                "E432CB",
                "E440E2",
                "E89D87",
                "EC9BF3",
                "F02A61",
                "F0B479",
                "F4428F",
                "F47B5E",
                "F8042E",
                "FC1F19",
                "FCDB96",
                "FCD6BD",
            ]

            if oui.upper() in apple_ouis:
                return "phone"  # Most Apple devices are mobile

            if oui.upper() in samsung_ouis:
                return "phone"  # Most Samsung devices are phones/tablets

        # === Check by open ports ===
        if ports:
            # Routers typically have these ports
            if 80 in ports or 443 in ports:
                if 53 in ports or 67 in ports:  # DNS or DHCP
                    return "router"

            # Printers
            if 9100 in ports or 631 in ports:  # Raw print / IPP
                return "printer"

            # Windows computers
            if 445 in ports or 3389 in ports:  # SMB / RDP
                return "computer"

            # Linux/Unix computers
            if 22 in ports:  # SSH
                if 80 not in ports and 443 not in ports:
                    return "computer"

        # === Default: check if it's likely a router ===
        if host.ip.endswith(".1") or host.ip.endswith(".254"):
            return "router"

        return "unknown"
