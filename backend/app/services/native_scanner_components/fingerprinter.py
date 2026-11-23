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


class ServiceFingerprinter:
    """
    Identifies services running on ports via banner grabbing and probes.
    """

    # Well-known port to service mapping
    COMMON_PORTS: Dict[int, str] = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        67: "dhcp",
        68: "dhcp",
        69: "tftp",
        80: "http",
        110: "pop3",
        123: "ntp",
        137: "netbios-ns",
        138: "netbios-dgm",
        139: "netbios-ssn",
        143: "imap",
        161: "snmp",
        162: "snmp-trap",
        389: "ldap",
        443: "https",
        445: "microsoft-ds",
        465: "smtps",
        500: "isakmp",
        514: "syslog",
        515: "printer",
        587: "submission",
        631: "ipp",  # Internet Printing Protocol (CUPS)
        636: "ldaps",
        993: "imaps",
        995: "pop3s",
        1080: "socks",
        1194: "openvpn",
        1433: "mssql",
        1521: "oracle",
        1723: "pptp",
        1883: "mqtt",
        1900: "upnp",
        2049: "nfs",
        3000: "dev-server",  # Common for Node.js
        3306: "mysql",
        3389: "rdp",
        4443: "pharos",
        5000: "upnp",  # Also common for Flask
        5001: "commplex-link",  # Or Synology
        5060: "sip",
        5353: "mdns",
        5432: "postgresql",
        5672: "amqp",
        5900: "vnc",
        5901: "vnc-1",
        6379: "redis",
        6667: "irc",
        8000: "http-alt",
        8008: "http-alt",
        8080: "http-proxy",
        8081: "http-alt",
        8123: "home-assistant",
        8443: "https-alt",
        8883: "mqtt-tls",
        8888: "http-alt",
        9000: "cslistener",
        9090: "prometheus",
        9100: "jetdirect",
        9200: "elasticsearch",
        10000: "webmin",
        27017: "mongodb",
        32400: "plex",
        51820: "wireguard",
    }

    # Quick probes for common services
    SERVICE_PROBES: Dict[str, bytes] = {
        "http": b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        "ftp": b"",  # FTP sends banner on connect
        "ssh": b"",  # SSH sends banner on connect
        "smtp": b"",  # SMTP sends banner on connect
        "mysql": b"",  # MySQL sends banner on connect
        "redis": b"PING\r\n",
    }

    # Banner patterns for service identification
    BANNER_PATTERNS: List[Tuple[str, str, Optional[str]]] = [
        # (regex pattern, service name, version group name)
        (r"SSH-[\d.]+-OpenSSH[_\s]*([\d.p]+)?", "ssh", "OpenSSH"),
        (r"SSH-[\d.]+-dropbear[_\s]*([\d.]+)?", "ssh", "Dropbear"),
        (r"220.*FTP", "ftp", None),
        (r"220.*ESMTP", "smtp", None),
        (r"220.*Microsoft", "smtp", "Microsoft"),
        (r"HTTP/1\.[01]\s+\d+", "http", None),
        (r"Server:\s*nginx/([\d.]+)?", "http", "nginx"),
        (r"Server:\s*Apache/([\d.]+)?", "http", "Apache"),
        (r"Server:\s*lighttpd/([\d.]+)?", "http", "lighttpd"),
        (r"mysql|MariaDB", "mysql", None),
        (r"PostgreSQL", "postgresql", None),
        (r"\+PONG", "redis", None),
        (r"Synology", "synology", None),
        (r"QNAP", "qnap", None),
        (r"220.*Pure-FTPd", "ftp", "Pure-FTPd"),
        (r"220.*ProFTPD", "ftp", "ProFTPD"),
        (r"220.*vsftpd", "ftp", "vsftpd"),
    ]

    @classmethod
    def identify_from_port(cls, port: int) -> Optional[str]:
        """Get likely service name from port number."""
        return cls.COMMON_PORTS.get(port)

    @classmethod
    def identify_from_banner(cls, banner: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Identify service and version from banner.
        Returns (service_name, version_info).
        """
        if not banner:
            return None, None

        for pattern, service, version_hint in cls.BANNER_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = None
                if match.lastindex and match.lastindex >= 1:
                    version = match.group(1)
                if version_hint and not version:
                    version = version_hint
                return service, version

        return None, None

    @classmethod
    def get_probe(cls, port: int) -> bytes:
        """Get probe bytes for a port."""
        service = cls.COMMON_PORTS.get(port)
        if service and service in cls.SERVICE_PROBES:
            return cls.SERVICE_PROBES[service]
        return b""
