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


class SecurityValidator:
    """Validates all inputs for security."""

    @staticmethod
    def validate_network(network: str) -> ipaddress.IPv4Network:
        """
        Validate network is private and within allowed size.

        Security checks:
        1. Valid CIDR notation
        2. Private network only (RFC 1918)
        3. Not in blocked ranges
        4. Reasonable size (max /20 = 4096 hosts)

        Raises:
            ValueError: If validation fails
        """
        # Parse and validate format
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            logger.warning(f"SECURITY: Invalid network format rejected: {network}")
            raise ValueError(
                f"Invalid network format: {network}. Use CIDR notation (e.g., 192.168.1.0/24)"
            ) from e

        # Must be IPv4 for ARP scanning
        if not isinstance(net, ipaddress.IPv4Network):
            logger.warning(f"SECURITY: IPv6 network rejected: {network}")
            raise ValueError("Only IPv4 networks are supported for LAN scanning")

        # Check if private
        is_private = any(net.subnet_of(allowed) for allowed in ALLOWED_NETWORKS)
        if not is_private:
            logger.warning(f"SECURITY: Non-private network rejected: {network}")
            raise ValueError(
                f"Scanning is only allowed on private networks (RFC 1918). "
                f"Network {network} is not in allowed ranges."
            )

        # Check blocked ranges
        for blocked in BLOCKED_RANGES:
            if net.overlaps(blocked):
                logger.warning(f"SECURITY: Blocked network range rejected: {network}")
                raise ValueError(
                    f"Network {network} overlaps with blocked range {blocked}"
                )

        # Check size
        if net.num_addresses > MAX_HOSTS_PER_SCAN:
            logger.warning(
                f"SECURITY: Network too large rejected: {network} ({net.num_addresses} hosts)"
            )
            raise ValueError(
                f"Network too large: {net.num_addresses} hosts. "
                f"Maximum allowed is {MAX_HOSTS_PER_SCAN} hosts (/22 or smaller)."
            )

        logger.info(
            f"SECURITY: Network validated: {network} ({net.num_addresses} hosts)"
        )
        return net

    @staticmethod
    def validate_ip(ip: str) -> ipaddress.IPv4Address:
        """Validate single IP address."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError as e:
            logger.warning(f"SECURITY: Invalid IP rejected: {ip}")
            raise ValueError(f"Invalid IP address: {ip}") from e

        if not isinstance(addr, ipaddress.IPv4Address):
            raise ValueError("Only IPv4 addresses are supported")

        # Check if private
        if not addr.is_private:
            logger.warning(f"SECURITY: Non-private IP rejected: {ip}")
            raise ValueError(
                f"Scanning is only allowed on private IPs. {ip} is public."
            )

        return addr

    @staticmethod
    def validate_port(port: int) -> int:
        """Validate port number."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}. Must be 1-65535.")
        return port

    @staticmethod
    def validate_ports(ports: List[int]) -> List[int]:
        """Validate list of ports."""
        if len(ports) > MAX_PORTS_PER_SCAN:
            raise ValueError(
                f"Too many ports: {len(ports)}. Maximum is {MAX_PORTS_PER_SCAN}."
            )
        return [SecurityValidator.validate_port(p) for p in ports]

    @staticmethod
    def sanitize_banner(banner: bytes, max_length: int = 256) -> str:
        """
        Sanitize banner data - remove control characters and limit length.
        Prevents log injection and display issues.
        """
        try:
            # Try UTF-8 first, then latin-1 as fallback
            text = banner.decode("utf-8", errors="replace")
        except Exception:
            text = banner.decode("latin-1", errors="replace")

        # Remove control characters except newline/tab
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]", "", text)

        # Limit length
        if len(text) > max_length:
            text = text[:max_length] + "..."

        return text.strip()
