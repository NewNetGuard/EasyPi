"""
Tailscale Admin API Client

Provides integration with Tailscale Admin API for managing:
- DNS settings (Global nameservers, Override local DNS)
- Devices (approve routes, enable exit node)
- ACLs and tags

Requires:
- Tailscale API Key (generated from https://login.tailscale.com/admin/settings/keys)
- Tailnet name (found in admin console, e.g., "mycompany.com" or "tail12345.ts.net")

Documentation: https://tailscale.com/api
"""

import logging
import os
import asyncio
import httpx
import ipaddress
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path
import json
import tempfile

from app.core.encryption import decrypt_password, encrypt_password, is_encrypted

logger = logging.getLogger("easypi.tailscale_admin")

# Config file for storing API credentials
CONFIG_FILENAME = "tailscale_admin.json"


@dataclass
class TailscaleAdminConfig:
    """Configuration for Tailscale Admin API."""
    api_key: Optional[str] = None
    tailnet: Optional[str] = None  # e.g., "mycompany.com" or "tail12345.ts.net"


@dataclass
class DNSConfig:
    """DNS configuration for Tailnet."""
    nameservers: List[str] = field(default_factory=list)  # Global nameservers
    magic_dns: bool = True  # Enable MagicDNS
    override_local_dns: bool = False  # Override local DNS on all devices
    search_paths: List[str] = field(default_factory=list)  # Search domains


@dataclass
class DeviceInfo:
    """Information about a Tailscale device."""
    id: str
    name: str
    hostname: str
    user: str
    tailscale_ips: List[str]
    advertised_routes: List[str]
    enabled_routes: List[str]
    is_exit_node: bool
    is_exit_node_enabled: bool
    last_seen: Optional[str] = None
    os: Optional[str] = None
    client_version: Optional[str] = None


class TailscaleAdminAPI:
    """
    Client for Tailscale Admin API.
    
    Usage:
        api = TailscaleAdminAPI()
        api.load_config()
        
        # Set DNS
        await api.set_dns_nameservers(["100.100.100.100"])  # Your NetProtection IP
        await api.enable_override_local_dns()
        
        # Manage devices
        devices = await api.list_devices()
        await api.approve_routes(device_id, ["192.168.1.0/24"])
    """
    
    BASE_URL = "https://api.tailscale.com/api/v2"
    
    def __init__(self):
        self.config = TailscaleAdminConfig()
        self._client: Optional[httpx.AsyncClient] = None
        self._config_path: Optional[Path] = None

    def _get_project_root(self) -> Optional[Path]:
        from app.core.paths import get_easypi_root
        return get_easypi_root()

    def _candidate_data_dirs(self) -> list[Path]:
        from app.core.paths import get_data_dir, get_backend_data_dir
        data_dirs: list[Path] = []
        env_data_dir = os.environ.get("EASYPI_DATA_DIR")
        if env_data_dir:
            data_dirs.append(Path(env_data_dir))

        # Use centralized paths
        data_dirs.append(get_data_dir())
        data_dirs.append(get_backend_data_dir())

        unique: list[Path] = []
        seen: set[str] = set()
        for data_dir in data_dirs:
            key = str(data_dir)
            if key in seen:
                continue
            seen.add(key)
            unique.append(data_dir)
        return unique

    def _candidate_config_paths(self) -> list[Path]:
        return [data_dir / "user" / CONFIG_FILENAME for data_dir in self._candidate_data_dirs()]

    def _resolve_config_path(self) -> Path:
        for config_path in self._candidate_config_paths():
            try:
                config_path.parent.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                continue
            if os.access(config_path.parent, os.W_OK):
                return config_path
        raise RuntimeError("No writable EasyPi data directory for Tailscale credentials")

    def _get_config_path(self) -> Path:
        if self._config_path is None:
            self._config_path = self._resolve_config_path()
        return self._config_path
    
    def load_config(self, *, migrate_plaintext: bool = True) -> TailscaleAdminConfig:
        """Load API configuration from file."""
        for config_path in self._candidate_config_paths():
            if not config_path.exists():
                continue
            try:
                data = json.loads(config_path.read_text())
                stored_api_key = data.get("api_key")
                self.config = TailscaleAdminConfig(
                    api_key=decrypt_password(stored_api_key)
                    if isinstance(stored_api_key, str)
                    else None,
                    tailnet=data.get("tailnet"),
                )
                self._config_path = config_path
                if migrate_plaintext and stored_api_key and not is_encrypted(stored_api_key):
                    self.save_config()
                return self.config
            except PermissionError:
                continue
            except Exception as e:
                logger.error(f"Failed to load Tailscale Admin config: {e}")
                self._config_path = config_path
                return self.config
        if migrate_plaintext:
            self._config_path = self._resolve_config_path()
        return self.config
    
    def save_config(self) -> None:
        """Save API configuration to file."""
        data = {
            "api_key": encrypt_password(self.config.api_key)
            if self.config.api_key
            else None,
            "tailnet": self.config.tailnet,
        }
        config_path = self._get_config_path()
        temporary_path: Optional[Path] = None
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".tailscale-admin.",
                dir=config_path.parent,
                text=True,
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(data, indent=2))
                handle.flush()
                os.fsync(handle.fileno())
            temporary_path.chmod(0o600)
            temporary_path.replace(config_path)
            config_path.chmod(0o600)
        except OSError as exc:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)
            raise RuntimeError("Tailscale credential store is not writable") from exc
        logger.info("Tailscale Admin config saved")
    
    def set_credentials(self, api_key: str, tailnet: str) -> None:
        """Set API credentials."""
        self.config.api_key = api_key
        self.config.tailnet = tailnet
        self.save_config()
    
    def is_configured(self) -> bool:
        """Check if API is configured."""
        return bool(self.config.api_key and self.config.tailnet)
    
    @property
    def _headers(self) -> Dict[str, str]:
        """Get API headers."""
        if not self.config.api_key:
            raise ValueError("Tailscale API key not configured")
        return {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }
    
    def _url(self, path: str) -> str:
        """Build API URL."""
        if not self.config.tailnet:
            raise ValueError("Tailnet not configured")
        # Replace {tailnet} in path if present
        path = path.replace("{tailnet}", self.config.tailnet)
        return f"{self.BASE_URL}{path}"
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None

    async def create_mobile_auth_key(self, *, expiry_seconds: int = 600) -> str:
        """Create a short-lived, single-use key for one EasyPi Mobile device.

        The tailnet administration credential never leaves EasyPi.  Only the
        resulting ``tskey-auth`` value is returned to the pairing request and
        Tailscale invalidates it after its first successful use.
        """
        if not 60 <= expiry_seconds <= 3600:
            raise ValueError("Mobile auth-key expiry must be between 60 and 3600 seconds")
        if not self.is_configured():
            self.load_config()
        if not self.is_configured():
            raise RuntimeError("Tailscale Admin API is not configured")

        client = await self._get_client()
        response = await client.post(
            self._url("/tailnet/{tailnet}/keys"),
            headers=self._headers,
            json={
                "capabilities": {
                    "devices": {
                        "create": {
                            "reusable": False,
                            "ephemeral": False,
                            "preauthorized": True,
                            "tags": [],
                        }
                    }
                },
                "expirySeconds": expiry_seconds,
                "description": "EasyPi Mobile one-time pairing key",
            },
        )
        response.raise_for_status()
        key = response.json().get("key")
        if not isinstance(key, str) or not key.startswith("tskey-auth-"):
            raise RuntimeError("Tailscale did not return a valid device auth key")
        return key
    
    # =========================================================================
    # DNS Management
    # =========================================================================

    def _get_dns_config_container(self, config: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(config.get("dnsConfig"), dict):
            return config["dnsConfig"]
        if isinstance(config.get("config"), dict):
            return config["config"]
        return config

    def _extract_nameservers(self, config: Dict[str, Any]) -> List[str]:
        nameservers: List[str] = []
        resolvers = config.get("resolvers")
        if isinstance(resolvers, list):
            for resolver in resolvers:
                if isinstance(resolver, dict):
                    addr = resolver.get("addr")
                    if isinstance(addr, str):
                        nameservers.append(addr)
                elif isinstance(resolver, str):
                    nameservers.append(resolver)
        legacy = config.get("nameservers")
        if isinstance(legacy, list):
            for addr in legacy:
                if isinstance(addr, str):
                    nameservers.append(addr)
        return [ns for ns in nameservers if ns]

    def _extract_bool_value(
        self,
        data: Dict[str, Any],
        keys: List[str],
    ) -> Optional[bool]:
        for key in keys:
            if key in data and isinstance(data[key], bool):
                return data[key]
        for value in data.values():
            if isinstance(value, dict):
                result = self._extract_bool_value(value, keys)
                if result is not None:
                    return result
        return None

    def _apply_bool_value(
        self,
        data: Dict[str, Any],
        keys: List[str],
        value: bool,
    ) -> bool:
        for key in keys:
            if key in data:
                data[key] = value
                return True
        for nested in data.values():
            if isinstance(nested, dict) and self._apply_bool_value(nested, keys, value):
                return True
        return False

    async def _get_dns_config(self) -> Optional[Dict[str, Any]]:
        client = await self._get_client()
        response = await client.get(
            self._url("/tailnet/{tailnet}/dns/config"),
            headers=self._headers,
        )
        if response.status_code in {404, 405}:
            return None
        response.raise_for_status()
        return response.json()

    async def _set_dns_config(self, config: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        client = await self._get_client()
        for method in ("POST", "PUT"):
            response = await client.request(
                method,
                self._url("/tailnet/{tailnet}/dns/config"),
                headers=self._headers,
                json=config,
            )
            if response.status_code in {404, 405}:
                continue
            response.raise_for_status()
            if response.content:
                return response.json()
            return {}
        return None
    
    async def get_dns_settings(self) -> DNSConfig:
        """
        Get current DNS settings for the tailnet.
        
        API: GET /api/v2/tailnet/{tailnet}/dns/nameservers
        """
        client = await self._get_client()
        
        # Get nameservers
        response = await client.get(
            self._url("/tailnet/{tailnet}/dns/nameservers"),
            headers=self._headers,
        )
        response.raise_for_status()
        ns_data = response.json()
        
        # Get DNS preferences (override local DNS)
        pref_data: Dict[str, Any] = {}
        response = await client.get(
            self._url("/tailnet/{tailnet}/dns/preferences"),
            headers=self._headers,
        )
        if response.status_code not in {404, 405}:
            response.raise_for_status()
            pref_data = response.json()
        
        # Get search paths
        search_data: Dict[str, Any] = {}
        response = await client.get(
            self._url("/tailnet/{tailnet}/dns/searchpaths"),
            headers=self._headers,
        )
        if response.status_code not in {404, 405}:
            response.raise_for_status()
            search_data = response.json()

        config_data: Optional[Dict[str, Any]] = None
        dns_config = await self._get_dns_config()
        if dns_config:
            config_data = self._get_dns_config_container(dns_config)

        override_local_dns = None
        if config_data:
            override_local_dns = self._extract_bool_value(
                config_data,
                ["overrideLocalDNS", "overrideLocalDns", "override_local_dns"],
            )
            if override_local_dns is None:
                override_local_dns = bool(self._extract_nameservers(config_data))
        if override_local_dns is None:
            override_local_dns = pref_data.get("overrideLocalDNS", False)

        magic_dns = pref_data.get("magicDNS")
        if magic_dns is None and config_data:
            magic_dns = self._extract_bool_value(
                config_data,
                ["magicDNS", "magicDns", "MagicDNS", "magic_dns", "proxied", "Proxied"],
            )
        if magic_dns is None:
            magic_dns = True
        
        return DNSConfig(
            nameservers=ns_data.get("dns", []),
            magic_dns=bool(magic_dns),
            override_local_dns=bool(override_local_dns),
            search_paths=search_data.get("searchPaths", []),
        )
    
    async def set_dns_nameservers(self, nameservers: List[str]) -> Dict[str, Any]:
        """
        Set global DNS nameservers for the tailnet.
        
        This is where you set your NetProtection IP as the DNS server
        so all Tailscale clients use your Pi's DNS.
        
        Example:
            await api.set_dns_nameservers(["100.100.100.100"])  # Pi's Tailscale IP
        
        API: POST /api/v2/tailnet/{tailnet}/dns/nameservers
        """
        client = await self._get_client()
        
        response = await client.post(
            self._url("/tailnet/{tailnet}/dns/nameservers"),
            headers=self._headers,
            json={"dns": nameservers},
        )
        response.raise_for_status()
        return response.json()
    
    async def set_dns_preferences(
        self,
        magic_dns: Optional[bool] = None,
        override_local_dns: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Set DNS preferences.
        
        - magic_dns: Enable MagicDNS (use Tailscale hostnames)
        - override_local_dns: Force all DNS through Tailscale nameservers
          (IMPORTANT: Set this to True so NetProtection handles all DNS!)
        
        API: POST /api/v2/tailnet/{tailnet}/dns/preferences
        """
        client = await self._get_client()

        dns_config = await self._get_dns_config()
        config_data = self._get_dns_config_container(dns_config) if dns_config else None

        payload: Dict[str, Any] = {}
        if magic_dns is not None:
            payload["magicDNS"] = magic_dns
        if override_local_dns is not None and config_data is None:
            payload["overrideLocalDNS"] = override_local_dns

        pref_response: Dict[str, Any] = {}
        if payload:
            response = await client.post(
                self._url("/tailnet/{tailnet}/dns/preferences"),
                headers=self._headers,
                json=payload,
            )
            response.raise_for_status()
            pref_response = response.json() if response.content else {}

        if config_data is not None and (magic_dns is not None or override_local_dns is not None):
            updated = False
            if override_local_dns is not None:
                nameservers: List[str] = []
                if override_local_dns:
                    nameservers = self._extract_nameservers(config_data)
                    if not nameservers:
                        response = await client.get(
                            self._url("/tailnet/{tailnet}/dns/nameservers"),
                            headers=self._headers,
                        )
                        if response.status_code not in {404, 405}:
                            response.raise_for_status()
                            ns_data = response.json()
                            nameservers = ns_data.get("dns", [])
                    config_data["resolvers"] = [{"addr": ns} for ns in nameservers if ns]
                    if "nameservers" in config_data:
                        config_data["nameservers"] = []
                    override_applied = bool(config_data.get("resolvers"))
                else:
                    config_data["resolvers"] = []
                    override_applied = True

                override_flag_applied = self._apply_bool_value(
                    config_data,
                    ["overrideLocalDNS", "overrideLocalDns", "override_local_dns"],
                    override_local_dns,
                )
                if not override_flag_applied and "overrideLocalDNS" in config_data:
                    config_data["overrideLocalDNS"] = override_local_dns
                    override_flag_applied = True
                override_applied = override_applied or override_flag_applied
                updated = updated or override_applied
            if magic_dns is not None:
                magic_applied = self._apply_bool_value(
                    config_data,
                    ["magicDNS", "magicDns", "MagicDNS", "magic_dns", "proxied", "Proxied"],
                    magic_dns,
                )
                if not magic_applied:
                    if "proxied" in config_data or "Proxied" in config_data:
                        config_data["proxied"] = magic_dns
                    else:
                        config_data["magicDNS"] = magic_dns
                    magic_applied = True
                updated = updated or magic_applied
            if updated:
                await self._set_dns_config(config_data)

        return pref_response
    
    async def set_search_paths(self, paths: List[str]) -> Dict[str, Any]:
        """
        Set DNS search paths (domains).
        
        API: POST /api/v2/tailnet/{tailnet}/dns/searchpaths
        """
        client = await self._get_client()
        
        response = await client.post(
            self._url("/tailnet/{tailnet}/dns/searchpaths"),
            headers=self._headers,
            json={"searchPaths": paths},
        )
        response.raise_for_status()
        return response.json()

    async def _verify_dns_settings(
        self,
        expected_nameserver: str,
        attempts: int = 10,
        delay_seconds: float = 1.0,
    ) -> DNSConfig:
        last_config: Optional[DNSConfig] = None
        for attempt in range(attempts):
            if attempt:
                await asyncio.sleep(delay_seconds)
            last_config = await self.get_dns_settings()
            nameserver_ok = expected_nameserver in last_config.nameservers
            override_ok = bool(last_config.override_local_dns)
            if nameserver_ok and override_ok:
                return last_config
        if last_config is None:
            raise RuntimeError("Failed to read DNS settings after update.")
        raise RuntimeError(
            "NetProtection DNS not fully applied. "
            f"nameservers={last_config.nameservers} override_local_dns={last_config.override_local_dns}"
        )

    async def _wait_for_nameserver(
        self,
        expected_nameserver: str,
        attempts: int = 5,
        delay_seconds: float = 0.5,
    ) -> DNSConfig:
        last_config: Optional[DNSConfig] = None
        for attempt in range(attempts):
            if attempt:
                await asyncio.sleep(delay_seconds)
            last_config = await self.get_dns_settings()
            if expected_nameserver in last_config.nameservers:
                return last_config
        if last_config is None:
            raise RuntimeError("Failed to read DNS settings after nameserver update.")
        raise RuntimeError(
            "NetProtection DNS nameserver not applied. "
            f"nameservers={last_config.nameservers}"
        )
    
    # =========================================================================
    # Device Management
    # =========================================================================
    
    async def list_devices(self) -> List[DeviceInfo]:
        """
        List all devices in the tailnet.
        
        API: GET /api/v2/tailnet/{tailnet}/devices
        """
        client = await self._get_client()
        
        response = await client.get(
            self._url("/tailnet/{tailnet}/devices"),
            headers=self._headers,
        )
        response.raise_for_status()
        data = response.json()
        
        devices = []
        for d in data.get("devices", []):
            devices.append(DeviceInfo(
                id=d.get("id", ""),
                name=d.get("name", ""),
                hostname=d.get("hostname", ""),
                user=d.get("user", ""),
                tailscale_ips=d.get("addresses", []),
                advertised_routes=d.get("advertisedRoutes", []) or [],
                enabled_routes=d.get("enabledRoutes", []) or [],
                is_exit_node=d.get("advertisedExitNode", False),
                is_exit_node_enabled=d.get("allowedExitNode", False),
                last_seen=d.get("lastSeen"),
                os=d.get("os"),
                client_version=d.get("clientVersion"),
            ))
        
        return devices
    
    async def get_device(self, device_id: str) -> DeviceInfo:
        """
        Get device by ID.
        
        API: GET /api/v2/device/{deviceId}
        """
        client = await self._get_client()
        
        response = await client.get(
            f"{self.BASE_URL}/device/{device_id}",
            headers=self._headers,
        )
        response.raise_for_status()
        d = response.json()
        
        return DeviceInfo(
            id=d.get("id", ""),
            name=d.get("name", ""),
            hostname=d.get("hostname", ""),
            user=d.get("user", ""),
            tailscale_ips=d.get("addresses", []),
            advertised_routes=d.get("advertisedRoutes", []) or [],
            enabled_routes=d.get("enabledRoutes", []) or [],
            is_exit_node=d.get("advertisedExitNode", False),
            is_exit_node_enabled=d.get("allowedExitNode", False),
            last_seen=d.get("lastSeen"),
            os=d.get("os"),
            client_version=d.get("clientVersion"),
        )
    
    async def approve_routes(self, device_id: str, routes: List[str]) -> Dict[str, Any]:
        """
        Approve (enable) advertised routes for a device.
        
        This allows the device to act as a subnet router.
        
        API: POST /api/v2/device/{deviceId}/routes
        """
        device = await self.get_device(device_id)
        advertised = {
            str(ipaddress.ip_network(route, strict=False))
            for route in device.advertised_routes
        }
        requested = {
            str(ipaddress.ip_network(route, strict=True))
            for route in routes
        }
        unadvertised = requested - advertised
        if unadvertised:
            raise ValueError(
                f"Device is not advertising requested routes: {', '.join(sorted(unadvertised))}"
            )
        enabled = {
            str(ipaddress.ip_network(route, strict=False))
            for route in device.enabled_routes
            if str(ipaddress.ip_network(route, strict=False)) in advertised
        }
        routes_to_enable = sorted(enabled | requested)

        client = await self._get_client()
        
        response = await client.post(
            f"{self.BASE_URL}/device/{device_id}/routes",
            headers=self._headers,
            json={"routes": routes_to_enable},
        )
        response.raise_for_status()
        return response.json()
    
    async def enable_exit_node(self, device_id: str, enable: bool = True) -> Dict[str, Any]:
        """
        Enable or disable exit node for a device.
        
        API: POST /api/v2/device/{deviceId}/routes
        """
        client = await self._get_client()
        
        # Get current routes first
        await self.get_device(device_id)
        
        # Set exit node attribute
        response = await client.post(
            f"{self.BASE_URL}/device/{device_id}/attributes/allowedExitNode",
            headers=self._headers,
            json={"value": enable},
        )
        response.raise_for_status()
        return response.json()
    
    async def delete_device(self, device_id: str) -> None:
        """
        Delete a device from the tailnet.
        
        API: DELETE /api/v2/device/{deviceId}
        """
        client = await self._get_client()
        
        response = await client.delete(
            f"{self.BASE_URL}/device/{device_id}",
            headers=self._headers,
        )
        response.raise_for_status()
    
    # =========================================================================
    # Quick Setup Methods
    # =========================================================================
    
    async def setup_netprotection_dns(self, netprotection_tailscale_ip: str) -> Dict[str, Any]:
        """
        Quick setup: Configure Tailnet to use NetProtection DNS.
        
        This sets:
        1. Global nameserver to NetProtection's Tailscale IP
        2. Override local DNS = True (so all clients use NetProtection)
        3. MagicDNS = True (keep Tailscale hostnames working)
        
        Args:
            netprotection_tailscale_ip: The Tailscale IP of EasyPi running NetProtection
                                  (e.g., "100.100.100.100")
        
        Returns:
            dict with status
        """
        logger.info(f"Setting up NetProtection DNS: {netprotection_tailscale_ip}")
        
        # Step 1: Set nameserver to NetProtection
        await self.set_dns_nameservers([netprotection_tailscale_ip])
        logger.info("DNS nameserver set")
        await self._wait_for_nameserver(netprotection_tailscale_ip)
        
        # Step 2: Ensure MagicDNS is enabled before forcing override
        current_dns = await self.get_dns_settings()
        if not current_dns.magic_dns:
            await self.set_dns_preferences(magic_dns=True, override_local_dns=None)
            logger.info("MagicDNS enabled")

        # Step 3: Enable override (force all DNS through NetProtection)
        await self.set_dns_preferences(magic_dns=None, override_local_dns=True)
        logger.info("Override local DNS enabled")
        try:
            verified = await self._verify_dns_settings(netprotection_tailscale_ip)
        except RuntimeError:
            # Retry preferences once if nameserver is already applied.
            current = await self.get_dns_settings()
            if netprotection_tailscale_ip in current.nameservers and not current.override_local_dns:
                await self.set_dns_preferences(magic_dns=None, override_local_dns=True)
                verified = await self._verify_dns_settings(netprotection_tailscale_ip)
            else:
                raise
        return {
            "success": True,
            "nameservers": verified.nameservers,
            "override_local_dns": verified.override_local_dns,
            "magic_dns": verified.magic_dns,
        }
    
    async def auto_approve_easypi_routes(self, local_tailscale_ips: List[str]) -> Dict[str, Any]:
        """
        Find EasyPi device and approve its routes automatically.
        
        Identifies the local node by exact Tailscale IP and approves only its
        advertised routes. It never grants routes to another tailnet device.
        """
        devices = await self.list_devices()
        
        local_ips = {str(ipaddress.ip_address(value)) for value in local_tailscale_ips}
        matches = [
            device
            for device in devices
            if local_ips.intersection(
                str(ipaddress.ip_address(value)) for value in device.tailscale_ips
            )
        ]
        if len(matches) != 1:
            raise RuntimeError(
                "Could not uniquely match the local EasyPi node in the Tailscale device list"
            )

        device = matches[0]
        pending_routes = [
            route for route in device.advertised_routes if route not in device.enabled_routes
        ]
        results = []
        if pending_routes:
            logger.info("Approving local EasyPi routes for device %s", device.id)
            await self.approve_routes(device.id, pending_routes)
            results.append({
                "device": device.hostname,
                "routes_approved": pending_routes,
            })
        
        return {
            "success": True,
            "approved": results,
        }


# Global instance
tailscale_admin_api = TailscaleAdminAPI()
