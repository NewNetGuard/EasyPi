from __future__ import annotations

import ipaddress
import json
import math
import time
from dataclasses import dataclass
from pathlib import Path


MAX_OBSERVATION_FILE_BYTES = 4 * 1024 * 1024
RECENT_DEVICE_SECONDS = 15 * 60
TRUSTED_STORE_VERSIONS = {3, 4, 5}


@dataclass(frozen=True)
class DHCPIdentity:
    ip: str
    mac: str
    hostname: str | None
    vendor_class: str | None
    last_seen_timestamp: float
    ip_first_seen_timestamp: float
    lease_expires_timestamp: float | None
    client_id: str | None = None
    parameter_request_list: tuple[int, ...] = ()
    dhcp_fingerprint: str | None = None
    ownership_verified: bool = False
    ownership_last_seen_timestamp: float | None = None

    @property
    def recently_observed(self) -> bool:
        age = time.time() - self.last_seen_timestamp
        return 0 <= age <= RECENT_DEVICE_SECONDS

    @property
    def ownership_recently_verified(self) -> bool:
        if not self.ownership_verified or self.ownership_last_seen_timestamp is None:
            return False
        age = time.time() - self.ownership_last_seen_timestamp
        return 0 <= age <= RECENT_DEVICE_SECONDS


@dataclass(frozen=True)
class DHCPAddressBinding:
    """A MAC+IP ownership interval observed from real IPv4 traffic."""

    ip: str
    mac: str
    assigned_at_timestamp: float
    last_seen_timestamp: float

    @property
    def recently_observed(self) -> bool:
        age = time.time() - self.last_seen_timestamp
        return 0 <= age <= RECENT_DEVICE_SECONDS


def default_observation_paths() -> tuple[Path, ...]:
    return (
        Path("/opt/EasyPi/data/network/dhcp_observations.json"),
        Path(__file__).resolve().parents[3] / "data" / "network" / "dhcp_observations.json",
    )


def load_dhcp_identities(paths: tuple[Path, ...] | None = None) -> list[DHCPIdentity]:
    for path in paths or default_observation_paths():
        try:
            if path.is_symlink() or path.stat().st_size > MAX_OBSERVATION_FILE_BYTES:
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            continue
        records = raw.get("devices", []) if isinstance(raw, dict) else []
        if not isinstance(records, list):
            continue
        raw_owners = raw.get("address_owners", {}) if isinstance(raw, dict) else {}
        store_version = raw.get("version") if isinstance(raw, dict) else None
        owners = (
            raw_owners
            if isinstance(store_version, int)
            and store_version in TRUSTED_STORE_VERSIONS
            and isinstance(raw_owners, dict)
            else {}
        )

        identities: list[DHCPIdentity] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                ip = str(ipaddress.IPv4Address(str(record.get("ipv4") or "")))
                mac = str(record.get("mac") or "").upper()
                last_seen = float(record.get("last_seen_timestamp"))
                ip_first_seen = float(
                    record.get("ip_first_seen_timestamp") or last_seen
                )
            except (
                ipaddress.AddressValueError,
                TypeError,
                ValueError,
                OverflowError,
            ):
                continue
            mac_parts = mac.split(":")
            if (
                not math.isfinite(last_seen)
                or not math.isfinite(ip_first_seen)
                or last_seen <= 0
                or ip_first_seen <= 0
                or len(mac_parts) != 6
                or any(
                    len(part) != 2
                    or not all(char in "0123456789ABCDEF" for char in part)
                    for part in mac_parts
                )
            ):
                continue
            raw_owner = owners.get(ip)
            ownership_verified = False
            ownership_last_seen: float | None = None
            if isinstance(raw_owner, dict):
                owner_mac = str(raw_owner.get("mac") or "").upper()
                try:
                    owner_start = float(raw_owner.get("assigned_at_timestamp"))
                    owner_last_seen = float(raw_owner.get("last_seen_timestamp"))
                except (TypeError, ValueError, OverflowError):
                    owner_start = 0.0
                    owner_last_seen = 0.0
                if (
                    owner_mac == mac
                    and math.isfinite(owner_start)
                    and math.isfinite(owner_last_seen)
                    and owner_start > 0
                    and owner_last_seen >= owner_start
                ):
                    ownership_verified = True
                    ownership_last_seen = owner_last_seen
                    ip_first_seen = max(ip_first_seen, owner_start)
            hostname = _clean_text(record.get("hostname"), 128)
            vendor_class = _clean_text(record.get("vendor_class"), 128)
            client_id = _clean_hex(record.get("client_id"), 256)
            dhcp_fingerprint = _clean_hex(record.get("dhcp_fingerprint"), 64)
            raw_parameter_request = record.get("parameter_request_list")
            parameter_request_list: tuple[int, ...] = ()
            if isinstance(raw_parameter_request, list):
                cleaned_options: list[int] = []
                for value in raw_parameter_request[:128]:
                    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
                        cleaned_options.append(value)
                parameter_request_list = tuple(cleaned_options)
            try:
                lease_expires = float(record["lease_expires_timestamp"])
            except (KeyError, TypeError, ValueError):
                lease_expires = None
            identities.append(
                DHCPIdentity(
                    ip=ip,
                    mac=mac,
                    hostname=hostname,
                    vendor_class=vendor_class,
                    last_seen_timestamp=last_seen,
                    ip_first_seen_timestamp=ip_first_seen,
                    lease_expires_timestamp=lease_expires,
                    client_id=client_id,
                    parameter_request_list=parameter_request_list,
                    dhcp_fingerprint=dhcp_fingerprint,
                    ownership_verified=ownership_verified,
                    ownership_last_seen_timestamp=ownership_last_seen,
                )
            )
        return identities
    return []


def load_dhcp_address_bindings(
    paths: tuple[Path, ...] | None = None,
) -> list[DHCPAddressBinding]:
    """Load traffic-observed address ownership intervals."""
    for path in paths or default_observation_paths():
        try:
            if path.is_symlink() or path.stat().st_size > MAX_OBSERVATION_FILE_BYTES:
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            continue
        if not isinstance(raw, dict) or raw.get("version") != 5:
            continue
        raw_bindings = raw.get("address_bindings", {})
        if not isinstance(raw_bindings, dict):
            continue

        bindings: list[DHCPAddressBinding] = []
        for raw_ip, raw_binding in raw_bindings.items():
            if not isinstance(raw_binding, dict):
                continue
            try:
                ip = str(ipaddress.IPv4Address(str(raw_ip)))
                mac = str(raw_binding.get("mac") or "").upper()
                assigned_at = float(raw_binding.get("assigned_at_timestamp"))
                last_seen = float(raw_binding.get("last_seen_timestamp"))
            except (
                ipaddress.AddressValueError,
                TypeError,
                ValueError,
                OverflowError,
            ):
                continue
            mac_parts = mac.split(":")
            if (
                not math.isfinite(assigned_at)
                or not math.isfinite(last_seen)
                or assigned_at <= 0
                or last_seen < assigned_at
                or len(mac_parts) != 6
                or any(
                    len(part) != 2
                    or not all(char in "0123456789ABCDEF" for char in part)
                    for part in mac_parts
                )
            ):
                continue
            bindings.append(
                DHCPAddressBinding(
                    ip=ip,
                    mac=mac,
                    assigned_at_timestamp=assigned_at,
                    last_seen_timestamp=last_seen,
                )
            )
        return bindings
    return []


def _clean_text(value: object, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = "".join(char for char in value if char.isprintable()).strip()
    return cleaned[:max_length] or None


def _clean_hex(value: object, max_length: int) -> str | None:
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower()[:max_length]
    if not cleaned or len(cleaned) % 2 or any(char not in "0123456789abcdef" for char in cleaned):
        return None
    return cleaned


# A router repeats its advertisement every few minutes (RFC 4861 allows up to
# 30); older observations no longer prove that IPv6 is offered on the LAN.
RECENT_IPV6_ROUTER_SECONDS = 2 * 60 * 60


def load_ipv6_bypass_routers(
    paths: tuple[Path, ...] | None = None,
    now: float | None = None,
) -> list[dict[str, object]]:
    """Return LAN routers recently offering a default IPv6 route with global addresses.

    Hosts behind such a router can reach the internet over IPv6 directly,
    without passing through EasyPi.
    """
    moment = time.time() if now is None else now
    for path in paths or default_observation_paths():
        try:
            if path.is_symlink() or path.stat().st_size > MAX_OBSERVATION_FILE_BYTES:
                continue
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            continue
        routers = raw.get("ipv6_routers", []) if isinstance(raw, dict) else []
        if not isinstance(routers, list):
            return []
        exposed: list[dict[str, object]] = []
        for router in routers:
            if not isinstance(router, dict):
                continue
            try:
                last_seen = float(router.get("last_seen_timestamp"))
                lifetime = int(router.get("router_lifetime"))
            except (TypeError, ValueError, OverflowError):
                continue
            prefixes = router.get("global_prefixes")
            if not isinstance(prefixes, list):
                continue
            if not (math.isfinite(last_seen) and 0 <= moment - last_seen <= RECENT_IPV6_ROUTER_SECONDS):
                continue
            if lifetime > 0 and (prefixes or router.get("managed")):
                exposed.append(
                    {
                        "router_mac": str(router.get("router_mac") or ""),
                        "global_prefixes": [str(item) for item in prefixes[:8]],
                        "managed": bool(router.get("managed")),
                    }
                )
        return exposed
    return []
