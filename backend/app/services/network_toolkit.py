"""Stable facade for the Network Toolkit service."""

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

from app.services.network_toolkit_components.diagnostics import (
    NetworkDiagnosticsMixin,
)
from app.services.network_toolkit_components.discovery import (
    NetworkDiscoveryMixin,
)
from app.services.network_toolkit_components.gateway import NetworkGatewayMixin


class NetworkToolkitService(
    NetworkDiscoveryMixin, NetworkDiagnosticsMixin, NetworkGatewayMixin
):
    """Backend implementation for the Network Toolkit endpoints.

    Uses native Python scanner for network discovery and port scanning.
    """

    DHCP_OBSERVATION_PATHS: tuple[Path, ...] | None = None
    KNOWN_DEVICE_PATHS = (
        Path("/opt/EasyPi/data/netprotection/devices.json"),
        Path(__file__).resolve().parents[3] / "data" / "netprotection" / "devices.json",
    )

    def __init__(self) -> None:
        self.tools = NetworkToolsService()
        self.port_alert_config = PortAlertConfig()
        self.dismissed_alerts: set[str] = set()
        # Native scanner instance
        self._scanner = native_scanner
        self._gateway_state_path = self._default_gateway_state_path()

        # Traffic stats tracking
        self._prev_io = psutil.net_io_counters()
        self._prev_sample_time = time.time()
        self._peak_download = 0.0
        self._peak_upload = 0.0

        # Cache for last LAN scan results
        self._last_scan_devices: list[dict] = []
        self._last_scan_time: datetime | None = None

    @staticmethod
    def _default_gateway_state_path() -> Path:
        # Prefer production install path, fallback to repo-local data dir.
        base = Path("/opt/EasyPi/data")
        if base.exists():
            return base / "network" / "gateway_mode.json"
        return Path("data") / "network" / "gateway_mode.json"

    def _write_gateway_state(self, state: dict) -> None:
        try:
            path = self._gateway_state_path
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            tmp.replace(path)
        except Exception:
            # Best-effort; gateway mode should still work even if state cannot be persisted.
            pass

    def _interface_names(self) -> list[str]:
        if netifaces is not None:
            try:
                return list(netifaces.interfaces())
            except Exception:
                pass
        return list(psutil.net_if_addrs().keys())

    def _ipv4_addresses(self, interface: str) -> list[dict[str, str | None]]:
        if netifaces is not None:
            try:
                return list(netifaces.ifaddresses(interface).get(netifaces.AF_INET, []))
            except Exception:
                return []

        addresses = []
        for addr in psutil.net_if_addrs().get(interface, []):
            if addr.family == socket.AF_INET:
                addresses.append(
                    {
                        "addr": addr.address,
                        "netmask": addr.netmask,
                    }
                )
        return addresses

    def _default_gateway_ip(self) -> str | None:
        if netifaces is not None:
            try:
                gateways = netifaces.gateways()
                default_gw = gateways.get("default", {}).get(netifaces.AF_INET)
                if default_gw:
                    return default_gw[0]
            except Exception:
                return None
        return None

    async def _get_interface_prefix_len(self, interface: str) -> int | None:
        if not interface:
            return None
        rc, out, _ = await self._run_cmd(["ip", "-o", "-4", "addr", "show", interface])
        if rc != 0 or not out:
            return None
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not match:
            return None
        try:
            return int(match.group(2))
        except Exception:
            return None

    # Helpers
    def _success(self, data: object | None = None) -> NetworkApiResponse:
        return NetworkApiResponse(success=True, data=data)

    def _error(self, message: str) -> NetworkApiResponse:
        return NetworkApiResponse(success=False, error=message)


__all__ = ["NetworkToolkitService"]
