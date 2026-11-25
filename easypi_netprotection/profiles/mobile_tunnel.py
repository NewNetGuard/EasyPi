"""Identity of phones that reach EasyPi through the Mobile home tunnel.

A home-tunnel phone arrives through a layer-3 TUN (``easypi-mobile0``), so the
DNS server never sees an Ethernet MAC for it. The backend publishes the live
peer registry (``mobile-home-tunnel-peers.json``: enrolled phone UUID and the
tunnel address assigned to it), and the admission firewall and the approval UI
derive a locally administered pseudo-MAC from that UUID. Resolving the same
pseudo-MAC here lets the DNS filter apply the same MAC+IP identity check the
firewall applies: an approved phone is recognised, while an address the
registry does not assign (a removed or never-enrolled phone) stays unknown.

Keep the derivation identical to
``UnknownDeviceAdmissionService.mobile_tunnel_mac`` and the copy in
``scripts/settings/setup_vpn_blocking.sh``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import stat
import threading
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)

MOBILE_TUNNEL_NETWORK = ipaddress.IPv4Network("10.77.0.0/24")
REGISTRY_FILE = "mobile-home-tunnel-peers.json"
_MAX_REGISTRY_BYTES = 64 * 1024
_RESERVED_ADDRESSES = frozenset({"10.77.0.0", "10.77.0.1", "10.77.0.255"})


def is_mobile_tunnel_address(client_ip: str) -> bool:
    try:
        return ipaddress.IPv4Address(client_ip) in MOBILE_TUNNEL_NETWORK
    except ValueError:
        return False


def mobile_tunnel_mac(device_id: str) -> str:
    """Return the pseudo-MAC for one enrolled phone UUID (lowercase)."""
    identity = str(uuid.UUID(str(device_id)))
    digest = hashlib.sha256(
        ("easypi/mobile-tunnel-identity/v1/" + identity).encode("ascii")
    ).digest()
    return ":".join(f"{byte:02x}" for byte in bytes([0x02]) + digest[:5])


class MobileTunnelPeers:
    """Read-only view of the live peer registry, re-parsed when it changes."""

    def __init__(self, data_dir: str | Path):
        self._path = Path(data_dir) / REGISTRY_FILE
        self._lock = threading.Lock()
        self._signature: tuple[int, int] | None = None
        self._macs: dict[str, str] = {}

    def mac_for(self, client_ip: str) -> str | None:
        """Return the pseudo-MAC assigned to this tunnel address, or None."""
        if not is_mobile_tunnel_address(client_ip):
            return None
        with self._lock:
            self._refresh()
            return self._macs.get(client_ip)

    def _refresh(self) -> None:
        try:
            info = self._path.lstat()
        except OSError:
            self._signature = None
            self._macs = {}
            return
        signature = (info.st_mtime_ns, info.st_size)
        if signature == self._signature:
            return
        self._signature = signature
        # Any defect admits no tunnel peer, like the admission firewall.
        self._macs = {}
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size > _MAX_REGISTRY_BYTES
        ):
            logger.warning("Mobile tunnel registry is unsafe; no tunnel peer is known")
            return
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
            self._macs = self._parse(payload)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            logger.warning("Mobile tunnel registry is invalid; no tunnel peer is known: %s", exc)

    @staticmethod
    def _parse(payload: object) -> dict[str, str]:
        if not isinstance(payload, dict) or payload.get("version") != 1:
            raise ValueError("unsupported registry version")
        devices = payload.get("devices")
        if not isinstance(devices, list):
            raise ValueError("devices is not a list")
        macs: dict[str, str] = {}
        for item in devices:
            if not isinstance(item, dict) or set(item) != {"id", "address"}:
                raise ValueError("malformed device entry")
            identity = str(uuid.UUID(str(item["id"])))
            address = str(ipaddress.IPv4Address(str(item["address"])))
            if (
                identity != item["id"]
                or ipaddress.IPv4Address(address) not in MOBILE_TUNNEL_NETWORK
                or address in _RESERVED_ADDRESSES
                or address in macs
            ):
                raise ValueError("invalid device entry")
            macs[address] = mobile_tunnel_mac(identity)
        return macs
