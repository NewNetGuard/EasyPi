"""Stable public facade for the Stealth VPN service."""

# ruff: noqa: F401

# ruff: noqa: F401

from app.services.stealth_components.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    detect_routing_conflict,
    get_easypi_root,
    get_netprotection_data_dir,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    posixpath,
    re,
    require_public_ipv4,
    routing_claim,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)

from app.services.stealth_components.client import StealthClientMixin
from app.services.stealth_components.mobile import StealthMobileMixin
from app.services.stealth_components.deployment import StealthDeploymentMixin
from app.services.stealth_components.runtime import StealthRuntimeMixin
from app.services.stealth_components.ssh import StealthSshMixin
from app.services.stealth_components.tls import StealthTlsMixin


class StealthService(
    StealthMobileMixin,
    StealthClientMixin,
    StealthSshMixin,
    StealthTlsMixin,
    StealthDeploymentMixin,
    StealthRuntimeMixin,
):
    def __init__(self) -> None:
        self._data_dir = Path(get_netprotection_data_dir())
        self._conf_path = self._data_dir / CONFIG_NAME
        self._meta_path = self._data_dir / META_NAME
        self._applied_ips: set[str] = set()
        # Serialize client lifecycle changes with the watchdog reconciliation.
        # Concurrent privileged up/down operations can otherwise replace the
        # protected runtime config while systemd is opening it.
        self._runtime_lock = asyncio.Lock()


_service: Optional[StealthService] = None


def get_stealth_service() -> StealthService:
    global _service
    if _service is None:
        _service = StealthService()
    return _service
