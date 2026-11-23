from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import select
import signal
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ICMPV6_PROTOCOL = 58
ICMPV6_ROUTER_ADVERTISEMENT = 134
IPV6_RA_PREFIX_OPTION = 3
IPV6_RA_MANAGED_FLAG = 0x80
IPV6_ROUTER_RETENTION_SECONDS = 24 * 60 * 60
MAX_IPV6_ROUTERS = 16
IPV6_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
DHCP_MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_CLIENT_PORT = 68
DHCP_SERVER_PORT = 67
BOOTP_REQUEST = 1
BOOTP_REPLY = 2
MAX_STORE_BYTES = 4 * 1024 * 1024
MAX_DEVICES = 2048
MAX_ADDRESS_OWNERS = 4096
RETENTION_SECONDS = 90 * 24 * 60 * 60
FLUSH_INTERVAL_SECONDS = 1.0
ADDRESS_HEARTBEAT_SECONDS = 60.0
STORE_VERSION = 5
TRUSTED_OWNER_STORE_VERSIONS = {3, 4, 5}
PACKET_HOST = getattr(socket, "PACKET_HOST", 0)
PACKET_BROADCAST = getattr(socket, "PACKET_BROADCAST", 1)
PACKET_MULTICAST = getattr(socket, "PACKET_MULTICAST", 2)
PACKET_OUTGOING = getattr(socket, "PACKET_OUTGOING", 4)
DHCP_INGRESS_PACKET_TYPES = {PACKET_HOST, PACKET_BROADCAST, PACKET_MULTICAST}
AUTO_EXCLUDED_INTERFACE_PREFIXES = (
    "lo",
    "docker",
    "veth",
    "virbr",
    "tailscale",
    "wg",
    "tun",
    "tap",
    "chameleon",
    "easypi-mobile",
    "lxc",
)
ALLOWED_LAN_SUPERNETS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("100.64.0.0/10"),
)

DHCP_MESSAGE_TYPES = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}


@dataclass(frozen=True)
class CaptureScope:
    interface: str
    networks: tuple[ipaddress.IPv4Network, ...]
    local_addresses: frozenset[ipaddress.IPv4Address]


def _is_auto_excluded_interface(interface: str) -> bool:
    if interface.startswith(AUTO_EXCLUDED_INTERFACE_PREFIXES):
        return True
    if interface.startswith("br-"):
        suffix = interface[3:]
        return len(suffix) >= 12 and all(
            character in "0123456789abcdefABCDEF" for character in suffix
        )
    return False


def _utc_now(timestamp: float | None = None) -> str:
    value = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def _safe_text(raw: bytes | None, max_length: int = 128) -> str | None:
    if not raw:
        return None
    value = raw.decode("utf-8", errors="replace")
    value = "".join(char for char in value if char.isprintable())
    value = value.strip().strip(".")[:max_length]
    return value or None


def _decode_fqdn(raw: bytes | None) -> str | None:
    if not raw or len(raw) <= 3:
        return None
    value = raw[3:]
    labels: list[str] = []
    offset = 0
    while offset < len(value):
        length = value[offset]
        if length == 0:
            break
        if length > 63 or offset + 1 + length > len(value):
            return _safe_text(value)
        label = _safe_text(value[offset + 1 : offset + 1 + length], 63)
        if label:
            labels.append(label)
        offset += 1 + length
    return ".".join(labels) if labels else _safe_text(value)


def _parse_options(raw: bytes) -> dict[int, list[bytes]] | None:
    options: dict[int, list[bytes]] = {}
    offset = 0
    while offset < len(raw):
        code = raw[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            return options
        if offset >= len(raw):
            return None
        length = raw[offset]
        offset += 1
        if offset + length > len(raw):
            return None
        options.setdefault(code, []).append(raw[offset : offset + length])
        offset += length
    return options


def _first_option(options: dict[int, list[bytes]], code: int) -> bytes | None:
    values = options.get(code)
    return values[0] if values else None


def _ipv4(raw: bytes) -> str | None:
    if len(raw) != 4 or raw == b"\x00\x00\x00\x00":
        return None
    return str(ipaddress.IPv4Address(raw))


def _mac(raw: bytes) -> str:
    return ":".join(f"{part:02X}" for part in raw)


def _valid_mac(value: object) -> str | None:
    mac = str(value or "").upper()
    parts = mac.split(":")
    if len(parts) != 6 or any(
        len(part) != 2 or not all(char in "0123456789ABCDEF" for char in part)
        for part in parts
    ):
        return None
    return mac


def _valid_ipv4(value: object) -> str | None:
    try:
        return str(ipaddress.IPv4Address(str(value or "")))
    except ipaddress.AddressValueError:
        return None


def _parse_requested_networks(values: tuple[str, ...]) -> tuple[ipaddress.IPv4Network, ...]:
    networks: list[ipaddress.IPv4Network] = []
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise RuntimeError(f"Invalid LAN network: {value}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or not any(
            network.subnet_of(allowed) for allowed in ALLOWED_LAN_SUPERNETS
        ):
            raise RuntimeError(f"LAN network is outside private address space: {value}")
        networks.append(network)
    return tuple(dict.fromkeys(networks))


def parse_capture_scopes(
    payload: object,
    requested_interfaces: tuple[str, ...] = (),
    requested_networks: tuple[str, ...] = (),
    default_route_interfaces: tuple[str, ...] = (),
) -> tuple[CaptureScope, ...]:
    """Build fail-closed capture scopes from ``ip -j address`` output."""
    if not isinstance(payload, list):
        raise RuntimeError("Unable to read local IPv4 interfaces")

    interface_filter = {value.strip() for value in requested_interfaces if value.strip()}
    requested = _parse_requested_networks(requested_networks)
    scopes: list[CaptureScope] = []
    covered_interfaces: set[str] = set()
    covered_networks: set[ipaddress.IPv4Network] = set()

    for entry in payload:
        if not isinstance(entry, dict):
            continue
        interface = str(entry.get("ifname") or "").strip()
        if not interface or (interface_filter and interface not in interface_filter):
            continue
        if not interface_filter and _is_auto_excluded_interface(interface):
            continue
        # The decoder expects an Ethernet header. A routed tunnel cannot
        # supply a source MAC and must not displace a shared LAN uplink.
        link_type = entry.get("link_type")
        if link_type and link_type != "ether":
            continue

        local_addresses: set[ipaddress.IPv4Address] = set()
        connected_networks: set[ipaddress.IPv4Network] = set()
        address_info = entry.get("addr_info", [])
        if not isinstance(address_info, list):
            continue
        for address in address_info:
            if not isinstance(address, dict) or address.get("family") != "inet":
                continue
            try:
                local_ip = ipaddress.IPv4Address(str(address.get("local") or ""))
                prefix_length = int(address.get("prefixlen"))
                connected = ipaddress.IPv4Network(
                    f"{local_ip}/{prefix_length}", strict=False
                )
            except (ipaddress.AddressValueError, TypeError, ValueError):
                continue
            if not any(connected.subnet_of(allowed) for allowed in ALLOWED_LAN_SUPERNETS):
                continue
            local_addresses.add(local_ip)
            connected_networks.add(connected)

        if connected_networks:
            covered_interfaces.add(interface)

        if requested:
            selected_networks = {
                network
                for network in requested
                if any(network.subnet_of(connected) for connected in connected_networks)
            }
        else:
            selected_networks = connected_networks
        if not selected_networks:
            continue

        covered_networks.update(selected_networks)
        scopes.append(
            CaptureScope(
                interface=interface,
                networks=tuple(sorted(selected_networks, key=str)),
                local_addresses=frozenset(local_addresses),
            )
        )

    missing_interfaces = interface_filter - covered_interfaces
    if missing_interfaces:
        raise RuntimeError(
            "Requested LAN interface has no private IPv4 network: "
            + ", ".join(sorted(missing_interfaces))
        )
    missing_networks = set(requested) - covered_networks
    if missing_networks:
        raise RuntimeError(
            "Requested LAN network is not directly connected: "
            + ", ".join(str(network) for network in sorted(missing_networks, key=str))
        )
    if not scopes:
        raise RuntimeError("No directly connected private IPv4 LAN was found")
    if not interface_filter and len(scopes) > 1:
        default_routes = set(default_route_interfaces)
        non_wan_scopes = [
            scope for scope in scopes if scope.interface not in default_routes
        ]
        if non_wan_scopes:
            scopes = non_wan_scopes
    return tuple(sorted(scopes, key=lambda scope: scope.interface))


def discover_capture_scopes(
    requested_interfaces: tuple[str, ...] = (),
    requested_networks: tuple[str, ...] = (),
) -> tuple[CaptureScope, ...]:
    try:
        result = subprocess.run(
            ["ip", "-j", "-4", "address", "show", "up"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("Unable to inspect local IPv4 interfaces") from exc
    if result.returncode != 0:
        raise RuntimeError("Unable to inspect local IPv4 interfaces")
    try:
        payload = json.loads(result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Invalid IPv4 interface data") from exc
    try:
        route_result = subprocess.run(
            ["ip", "-j", "-4", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError("Unable to inspect the default IPv4 route") from exc
    if route_result.returncode != 0:
        raise RuntimeError("Unable to inspect the default IPv4 route")
    try:
        route_payload = json.loads(route_result.stdout)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Invalid default IPv4 route data") from exc
    if not isinstance(route_payload, list):
        raise RuntimeError("Invalid default IPv4 route data")
    default_route_interfaces = tuple(
        str(route.get("dev") or "")
        for route in route_payload
        if isinstance(route, dict) and route.get("dev")
    )
    return parse_capture_scopes(
        payload,
        requested_interfaces,
        requested_networks,
        default_route_interfaces,
    )


def parse_ipv4_source_frame(
    frame: bytes,
    *,
    allowed_networks: tuple[ipaddress.IPv4Network, ...],
    local_addresses: frozenset[ipaddress.IPv4Address] = frozenset(),
    observed_at: float | None = None,
) -> dict[str, Any] | None:
    """Extract actual IPv4 source use, excluding DHCP client requests."""
    if len(frame) < 14:
        return None
    source_mac_bytes = frame[6:12]
    if (
        source_mac_bytes == b"\x00" * 6
        or source_mac_bytes == b"\xff" * 6
        or source_mac_bytes[0] & 1
    ):
        return None
    source_mac = _mac(source_mac_bytes)

    ether_type = struct.unpack_from("!H", frame, 12)[0]
    ip_offset = 14
    vlan_depth = 0
    while ether_type in {ETH_P_8021Q, ETH_P_8021AD} and vlan_depth < 2:
        if len(frame) < ip_offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, ip_offset + 2)[0]
        ip_offset += 4
        vlan_depth += 1
    if ether_type != ETH_P_IP or len(frame) < ip_offset + 20:
        return None

    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(frame) < ip_offset + ip_header_length:
        return None
    total_length = struct.unpack_from("!H", frame, ip_offset + 2)[0]
    if total_length < ip_header_length or len(frame) < ip_offset + total_length:
        return None

    source_ip = ipaddress.IPv4Address(frame[ip_offset + 12 : ip_offset + 16])
    if (
        source_ip in local_addresses
        or not allowed_networks
        or not any(source_ip in network for network in allowed_networks)
        or any(
            source_ip in {network.network_address, network.broadcast_address}
            for network in allowed_networks
        )
    ):
        return None

    # A DHCP REQUEST is only a request for an address. It must never establish
    # or move an ownership boundary, even when it carries a non-zero ciaddr.
    fragment = struct.unpack_from("!H", frame, ip_offset + 6)[0]
    if frame[ip_offset + 9] == socket.IPPROTO_UDP and fragment & 0x1FFF == 0:
        udp_offset = ip_offset + ip_header_length
        if len(frame) >= udp_offset + 4:
            source_port, destination_port = struct.unpack_from("!HH", frame, udp_offset)
            if (source_port, destination_port) == (
                DHCP_CLIENT_PORT,
                DHCP_SERVER_PORT,
            ):
                return None

    seen = time.time() if observed_at is None else observed_at
    return {
        "mac": source_mac,
        "ipv4": str(source_ip),
        "observed_timestamp": seen,
    }


def parse_router_advertisement(
    frame: bytes, observed_at: float | None = None
) -> dict[str, Any] | None:
    """Parse an IPv6 Router Advertisement (RFC 4861) heard on the LAN.

    A router that offers itself as the default IPv6 gateway and hands out
    global addresses lets hosts reach the internet over IPv6 without passing
    through EasyPi at all, which would bypass the Stealth tunnel.
    """
    if len(frame) < 14:
        return None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    vlan_depth = 0
    while ether_type in {ETH_P_8021Q, ETH_P_8021AD} and vlan_depth < 2:
        if len(frame) < offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
        vlan_depth += 1
    if ether_type != ETH_P_IPV6 or len(frame) < offset + 40:
        return None
    # Genuine Router Advertisements are link-local, never forwarded: the hop
    # limit must still be 255 and ICMPv6 must follow the fixed header.
    if (
        frame[offset] >> 4 != 6
        or frame[offset + 6] != ICMPV6_PROTOCOL
        or frame[offset + 7] != 255
    ):
        return None
    payload_length = struct.unpack_from("!H", frame, offset + 4)[0]
    icmp = offset + 40
    end = icmp + payload_length
    if payload_length < 16 or len(frame) < end:
        return None
    if frame[icmp] != ICMPV6_ROUTER_ADVERTISEMENT or frame[icmp + 1] != 0:
        return None
    router_mac = _valid_mac(":".join(f"{byte:02X}" for byte in frame[6:12]))
    if not router_mac:
        return None
    managed = bool(frame[icmp + 5] & IPV6_RA_MANAGED_FLAG)
    router_lifetime = struct.unpack_from("!H", frame, icmp + 6)[0]
    prefixes: set[str] = set()
    option = icmp + 16
    while option + 2 <= end:
        option_type, option_units = frame[option], frame[option + 1]
        if option_units == 0:
            return None
        option_end = option + option_units * 8
        if option_end > end:
            return None
        if option_type == IPV6_RA_PREFIX_OPTION and option_units == 4:
            prefix_length = frame[option + 2]
            valid_lifetime = struct.unpack_from("!I", frame, option + 4)[0]
            try:
                network = ipaddress.IPv6Network(
                    (bytes(frame[option + 16 : option + 32]), prefix_length),
                    strict=False,
                )
            except ValueError:
                network = None
            if (
                network is not None
                and valid_lifetime
                and network.subnet_of(IPV6_GLOBAL_UNICAST)
            ):
                prefixes.add(str(network))
        option = option_end
    return {
        "router_mac": router_mac,
        "router_lifetime": router_lifetime,
        "managed": managed,
        "global_prefixes": sorted(prefixes),
        "last_seen_timestamp": observed_at if observed_at is not None else time.time(),
    }


def parse_dhcp_frame(frame: bytes, observed_at: float | None = None) -> dict[str, Any] | None:
    """Parse selected identity metadata from an Ethernet DHCPv4 frame."""
    if len(frame) < 14:
        return None

    ether_type = struct.unpack_from("!H", frame, 12)[0]
    ip_offset = 14
    vlan_depth = 0
    while ether_type in {ETH_P_8021Q, ETH_P_8021AD} and vlan_depth < 2:
        if len(frame) < ip_offset + 4:
            return None
        ether_type = struct.unpack_from("!H", frame, ip_offset + 2)[0]
        ip_offset += 4
        vlan_depth += 1
    if ether_type != ETH_P_IP or len(frame) < ip_offset + 20:
        return None

    version_ihl = frame[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(frame) < ip_offset + ip_header_length + 8:
        return None
    if frame[ip_offset + 9] != socket.IPPROTO_UDP:
        return None

    fragment = struct.unpack_from("!H", frame, ip_offset + 6)[0]
    if fragment & 0x1FFF:
        return None
    total_length = struct.unpack_from("!H", frame, ip_offset + 2)[0]
    if total_length < ip_header_length + 8 or len(frame) < ip_offset + total_length:
        return None
    packet_end = ip_offset + total_length

    udp_offset = ip_offset + ip_header_length
    source_port, destination_port, udp_length = struct.unpack_from("!HHH", frame, udp_offset)
    if (source_port, destination_port) not in {
        (DHCP_CLIENT_PORT, DHCP_SERVER_PORT),
        (DHCP_SERVER_PORT, DHCP_CLIENT_PORT),
    }:
        return None
    if udp_length < 8 + 240 or udp_offset + udp_length > packet_end:
        return None
    payload_start = udp_offset + 8
    payload_end = udp_offset + udp_length
    payload = frame[payload_start:payload_end]
    if len(payload) < 240 or payload[236:240] != DHCP_MAGIC_COOKIE:
        return None

    bootp_op = payload[0]
    if (
        bootp_op == BOOTP_REQUEST
        and (source_port, destination_port) != (DHCP_CLIENT_PORT, DHCP_SERVER_PORT)
    ) or (
        bootp_op == BOOTP_REPLY
        and (source_port, destination_port) != (DHCP_SERVER_PORT, DHCP_CLIENT_PORT)
    ):
        return None
    if bootp_op not in {BOOTP_REQUEST, BOOTP_REPLY}:
        return None

    hardware_type = payload[1]
    hardware_length = payload[2]
    if hardware_type != 1 or hardware_length != 6:
        return None
    client_mac = _mac(payload[28:34])
    if client_mac == "00:00:00:00:00:00":
        return None

    options = _parse_options(payload[240:])
    if options is None:
        return None
    message_raw = _first_option(options, 53)
    message_code = message_raw[0] if message_raw and len(message_raw) == 1 else None

    assigned_ip = _ipv4(payload[16:20])
    requested_raw = _first_option(options, 50)
    requested_ip = _ipv4(requested_raw) if requested_raw else None
    client_ip = _ipv4(payload[12:16])
    ipv4 = assigned_ip or requested_ip or client_ip

    hostname = _safe_text(_first_option(options, 12))
    fqdn = _decode_fqdn(_first_option(options, 81))
    parameter_request = _first_option(options, 55) or b""
    client_identifier = _first_option(options, 61)
    server_identifier = _first_option(options, 54)
    lease_raw = _first_option(options, 51)
    lease_seconds = struct.unpack("!I", lease_raw)[0] if lease_raw and len(lease_raw) == 4 else None

    seen = time.time() if observed_at is None else observed_at
    observation: dict[str, Any] = {
        "mac": client_mac,
        "ipv4": ipv4,
        "hostname": hostname or fqdn,
        "fqdn": fqdn,
        "vendor_class": _safe_text(_first_option(options, 60)),
        "user_class": _safe_text(_first_option(options, 77)),
        "client_id": client_identifier.hex()[:256] if client_identifier else None,
        "parameter_request_list": list(parameter_request[:128]),
        "dhcp_fingerprint": hashlib.sha256(parameter_request).hexdigest()[:16] if parameter_request else None,
        "message_type": DHCP_MESSAGE_TYPES.get(message_code, f"unknown-{message_code}" if message_code else "unknown"),
        "ownership_confirmed": (
            bootp_op == BOOTP_REPLY
            and source_port == DHCP_SERVER_PORT
            and destination_port == DHCP_CLIENT_PORT
            and message_code == 5
            and assigned_ip is not None
        ),
        "server_id": _ipv4(server_identifier) if server_identifier else None,
        "lease_seconds": lease_seconds,
        "observed_at": _utc_now(seen),
        "observed_timestamp": seen,
    }
    if lease_seconds is not None and observation["message_type"] in {"offer", "ack"}:
        observation["lease_expires_at"] = _utc_now(seen + lease_seconds)
        observation["lease_expires_timestamp"] = seen + lease_seconds
    return observation


class DHCPObservationStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.devices: dict[str, dict[str, Any]] = {}
        self.address_owners: dict[str, dict[str, Any]] = {}
        self.address_bindings: dict[str, dict[str, Any]] = {}
        self.ipv6_routers: dict[str, dict[str, Any]] = {}
        self.dirty = False
        self.load()

    def load(self) -> None:
        try:
            if self.path.is_symlink() or self.path.stat().st_size > MAX_STORE_BYTES:
                return
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError, TypeError):
            return
        records = raw.get("devices", []) if isinstance(raw, dict) else []
        if not isinstance(records, list):
            return
        for record in records[:MAX_DEVICES]:
            if not isinstance(record, dict):
                continue
            mac = _valid_mac(record.get("mac"))
            try:
                last_seen = float(record.get("last_seen_timestamp"))
            except (TypeError, ValueError, OverflowError):
                continue
            if not mac or not math.isfinite(last_seen) or last_seen <= 0:
                continue
            normalized_record = dict(record)
            normalized_record["mac"] = mac
            normalized_record["last_seen_timestamp"] = last_seen
            self.devices[mac] = normalized_record

        raw_owners = raw.get("address_owners", {}) if isinstance(raw, dict) else {}
        store_version = raw.get("version") if isinstance(raw, dict) else None
        if (
            isinstance(raw_owners, dict)
            and isinstance(store_version, int)
            and store_version in TRUSTED_OWNER_STORE_VERSIONS
        ):
            for raw_ip, raw_owner in list(raw_owners.items())[:MAX_ADDRESS_OWNERS]:
                if not isinstance(raw_owner, dict):
                    continue
                ipv4 = _valid_ipv4(raw_ip)
                mac = _valid_mac(raw_owner.get("mac"))
                try:
                    assigned_at = float(raw_owner.get("assigned_at_timestamp"))
                    last_seen = float(raw_owner.get("last_seen_timestamp"))
                except (TypeError, ValueError, OverflowError):
                    continue
                if (
                    not ipv4
                    or not mac
                    or not math.isfinite(assigned_at)
                    or not math.isfinite(last_seen)
                    or assigned_at <= 0
                    or last_seen < assigned_at
                ):
                    continue
                self.address_owners[ipv4] = {
                    "mac": mac,
                    "assigned_at_timestamp": assigned_at,
                    "last_seen_timestamp": last_seen,
                }

        raw_bindings = (
            raw.get("address_bindings", {}) if isinstance(raw, dict) else {}
        )
        if isinstance(raw_bindings, dict) and store_version == STORE_VERSION:
            for raw_ip, raw_binding in list(raw_bindings.items())[
                :MAX_ADDRESS_OWNERS
            ]:
                if not isinstance(raw_binding, dict):
                    continue
                ipv4 = _valid_ipv4(raw_ip)
                mac = _valid_mac(raw_binding.get("mac"))
                try:
                    assigned_at = float(raw_binding.get("assigned_at_timestamp"))
                    last_seen = float(raw_binding.get("last_seen_timestamp"))
                except (TypeError, ValueError, OverflowError):
                    continue
                if (
                    not ipv4
                    or not mac
                    or not math.isfinite(assigned_at)
                    or not math.isfinite(last_seen)
                    or assigned_at <= 0
                    or last_seen < assigned_at
                ):
                    continue
                self.address_bindings[ipv4] = {
                    "mac": mac,
                    "assigned_at_timestamp": assigned_at,
                    "last_seen_timestamp": last_seen,
                }

        raw_routers = raw.get("ipv6_routers", []) if isinstance(raw, dict) else []
        if isinstance(raw_routers, list):
            for raw_router in raw_routers[:MAX_IPV6_ROUTERS]:
                if not isinstance(raw_router, dict):
                    continue
                router_mac = _valid_mac(raw_router.get("router_mac"))
                prefixes = raw_router.get("global_prefixes")
                try:
                    last_seen = float(raw_router.get("last_seen_timestamp"))
                    lifetime = int(raw_router.get("router_lifetime"))
                except (TypeError, ValueError, OverflowError):
                    continue
                if (
                    not router_mac
                    or not math.isfinite(last_seen)
                    or not isinstance(prefixes, list)
                    or not all(isinstance(item, str) for item in prefixes)
                ):
                    continue
                self.ipv6_routers[router_mac] = {
                    "router_mac": router_mac,
                    "router_lifetime": lifetime,
                    "managed": bool(raw_router.get("managed")),
                    "global_prefixes": prefixes[:8],
                    "last_seen_timestamp": last_seen,
                }

        # Versions 3-4 may contain server-ACK ownership. Preserve only that
        # stronger evidence; request-derived v4 candidates are discarded.
        if store_version in {3, 4}:
            for ipv4, owner in self.address_owners.items():
                self.address_bindings[ipv4] = dict(owner)

        # Versions 1-2 could update owners from an unconfirmed client request.
        # Keep their device metadata, but discard their ownership history.
        if store_version != STORE_VERSION:
            self.dirty = True

        for mac, record in self.devices.items():
            ipv4 = _valid_ipv4(record.get("ipv4"))
            if not ipv4:
                continue
            owner = self.address_owners.get(ipv4)
            if owner is not None and owner["mac"] == mac:
                owner_start = float(owner["assigned_at_timestamp"])
                try:
                    recorded_start = float(
                        record.get("ip_first_seen_timestamp")
                        or record["last_seen_timestamp"]
                    )
                except (TypeError, ValueError, OverflowError):
                    recorded_start = owner_start
                if not math.isfinite(recorded_start) or recorded_start <= 0:
                    recorded_start = owner_start
                trusted_start = max(recorded_start, owner_start)
                if record.get("ip_first_seen_timestamp") != trusted_start:
                    record["ip_first_seen_timestamp"] = trusted_start
                    self.dirty = True

    def observe(self, observation: dict[str, Any]) -> None:
        mac = _valid_mac(observation.get("mac"))
        if not mac:
            return
        try:
            now = float(observation.get("observed_timestamp") or time.time())
        except (TypeError, ValueError, OverflowError):
            return
        if not math.isfinite(now) or now <= 0:
            return
        existing = self.devices.get(mac, {})
        if now < float(existing.get("last_seen_timestamp") or 0.0):
            return
        merged = dict(existing)
        assignment_fields = {
            "ipv4",
            "ip_first_seen_timestamp",
            "lease_expires_at",
            "lease_expires_timestamp",
            "ownership_confirmed",
        }
        for key, value in observation.items():
            if (
                key not in assignment_fields
                and value is not None
                and value != ""
                and value != []
            ):
                merged[key] = value
        merged["mac"] = mac
        merged["first_seen"] = existing.get("first_seen") or observation.get("observed_at") or _utc_now(now)
        merged["first_seen_timestamp"] = existing.get("first_seen_timestamp") or now
        ownership_confirmed = (
            observation.get("ownership_confirmed") is True
            and observation.get("message_type") == "ack"
        )
        effective_ipv4 = (
            _valid_ipv4(observation.get("ipv4"))
            if ownership_confirmed
            else None
        )
        if effective_ipv4:
            owner = self.address_owners.get(effective_ipv4)
            current_binding = self.address_bindings.get(effective_ipv4)
            if owner and now < float(owner.get("last_seen_timestamp") or 0.0):
                return
            if (
                existing.get("ipv4") != effective_ipv4
                or owner is None
                or owner.get("mac") != mac
                or (
                    current_binding is not None
                    and current_binding.get("mac") != mac
                )
            ):
                assignment_start = now
            else:
                assignment_start = float(owner["assigned_at_timestamp"])
            merged["ipv4"] = effective_ipv4
            merged["ip_first_seen_timestamp"] = assignment_start
            for key in ("lease_expires_at", "lease_expires_timestamp"):
                value = observation.get(key)
                if value is not None and value != "":
                    merged[key] = value
            self.address_owners[effective_ipv4] = {
                "mac": mac,
                "assigned_at_timestamp": assignment_start,
                "last_seen_timestamp": now,
            }
            self.address_bindings[effective_ipv4] = {
                "mac": mac,
                "assigned_at_timestamp": assignment_start,
                "last_seen_timestamp": now,
            }
        merged["last_seen"] = observation.get("observed_at") or _utc_now(now)
        merged["last_seen_timestamp"] = now
        self.devices[mac] = merged
        self._prune(now)
        self.dirty = True

    def observe_address_usage(self, observation: dict[str, Any]) -> None:
        """Record a MAC actively sending non-DHCP IPv4 traffic from an IP."""
        mac = _valid_mac(observation.get("mac"))
        ipv4 = _valid_ipv4(observation.get("ipv4"))
        try:
            now = float(observation.get("observed_timestamp") or time.time())
        except (TypeError, ValueError, OverflowError):
            return
        if not mac or not ipv4 or not math.isfinite(now) or now <= 0:
            return

        binding = self.address_bindings.get(ipv4)
        if binding and now < float(binding.get("last_seen_timestamp") or 0.0):
            return
        transitioned = binding is None or binding.get("mac") != mac
        if transitioned:
            assigned_at = now
        else:
            assigned_at = float(binding["assigned_at_timestamp"])

        device_changed = False
        device = self.devices.get(mac)
        if device is not None and device.get("ipv4") != ipv4:
            device["ipv4"] = ipv4
            device["ip_first_seen_timestamp"] = assigned_at
            device_changed = True

        last_seen = float(binding.get("last_seen_timestamp") or 0.0) if binding else 0.0
        if (
            not transitioned
            and not device_changed
            and now - last_seen < ADDRESS_HEARTBEAT_SECONDS
        ):
            return
        self.address_bindings[ipv4] = {
            "mac": mac,
            "assigned_at_timestamp": assigned_at,
            "last_seen_timestamp": now,
        }
        self._prune(now)
        self.dirty = True

    def observe_router_advertisement(self, advertisement: dict[str, Any]) -> None:
        router_mac = advertisement["router_mac"]
        previous = self.ipv6_routers.get(router_mac)
        self.ipv6_routers[router_mac] = dict(advertisement)

        def essentials(record: dict[str, Any]) -> dict[str, Any]:
            return {k: v for k, v in record.items() if k != "last_seen_timestamp"}

        # Routers repeat advertisements every few minutes; persist changes and
        # a periodic heartbeat rather than every identical frame.
        if (
            previous is None
            or essentials(previous) != essentials(advertisement)
            or advertisement["last_seen_timestamp"]
            - float(previous["last_seen_timestamp"])
            >= ADDRESS_HEARTBEAT_SECONDS
        ):
            self._prune(advertisement["last_seen_timestamp"])
            self.dirty = True
        else:
            self.ipv6_routers[router_mac]["last_seen_timestamp"] = previous[
                "last_seen_timestamp"
            ]

    def _prune(self, now: float) -> None:
        router_cutoff = now - IPV6_ROUTER_RETENTION_SECONDS
        recent_routers = sorted(
            self.ipv6_routers.items(),
            key=lambda item: float(item[1].get("last_seen_timestamp") or 0),
            reverse=True,
        )
        self.ipv6_routers = {
            mac: router
            for mac, router in recent_routers[:MAX_IPV6_ROUTERS]
            if float(router.get("last_seen_timestamp") or 0) >= router_cutoff
        }
        cutoff = now - RETENTION_SECONDS
        ordered = sorted(
            self.devices.items(),
            key=lambda item: float(item[1].get("last_seen_timestamp") or 0),
            reverse=True,
        )
        self.devices = {
            mac: record
            for mac, record in ordered[:MAX_DEVICES]
            if float(record.get("last_seen_timestamp") or 0) >= cutoff
        }
        ordered_owners = sorted(
            self.address_owners.items(),
            key=lambda item: float(item[1].get("last_seen_timestamp") or 0),
            reverse=True,
        )
        self.address_owners = {
            ipv4: owner
            for ipv4, owner in ordered_owners[:MAX_ADDRESS_OWNERS]
            if float(owner.get("last_seen_timestamp") or 0) >= cutoff
        }
        ordered_bindings = sorted(
            self.address_bindings.items(),
            key=lambda item: float(item[1].get("last_seen_timestamp") or 0),
            reverse=True,
        )
        self.address_bindings = {
            ipv4: binding
            for ipv4, binding in ordered_bindings[:MAX_ADDRESS_OWNERS]
            if float(binding.get("last_seen_timestamp") or 0) >= cutoff
        }

    def flush(self) -> None:
        if not self.dirty:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": STORE_VERSION,
            "updated_at": _utc_now(),
            "devices": sorted(
                self.devices.values(),
                key=lambda record: float(record.get("last_seen_timestamp") or 0),
                reverse=True,
            ),
            "address_owners": dict(sorted(self.address_owners.items())),
            "address_bindings": dict(sorted(self.address_bindings.items())),
            "ipv6_routers": sorted(
                self.ipv6_routers.values(), key=lambda router: router["router_mac"]
            ),
        }
        temporary = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.path)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        self.dirty = False


def process_captured_frame(
    store: DHCPObservationStore,
    frame: bytes,
    packet_type: int,
    scope: CaptureScope,
    observed_at: float | None = None,
) -> None:
    """Process only inbound packets from one explicitly trusted LAN scope."""
    if packet_type not in DHCP_INGRESS_PACKET_TYPES or packet_type == PACKET_OUTGOING:
        return
    if packet_type == PACKET_HOST:
        address_usage = parse_ipv4_source_frame(
            frame,
            allowed_networks=scope.networks,
            local_addresses=scope.local_addresses,
            observed_at=observed_at,
        )
        if address_usage:
            store.observe_address_usage(address_usage)
    observation = parse_dhcp_frame(frame, observed_at=observed_at)
    if observation:
        store.observe(observation)


def process_ipv6_frame(
    store: DHCPObservationStore,
    frame: bytes,
    packet_type: int,
    observed_at: float | None = None,
) -> None:
    """Record Router Advertisements received from the LAN, never our own."""
    if packet_type not in DHCP_INGRESS_PACKET_TYPES or packet_type == PACKET_OUTGOING:
        return
    advertisement = parse_router_advertisement(frame, observed_at=observed_at)
    if advertisement:
        store.observe_router_advertisement(advertisement)


def run(
    output: Path,
    interfaces: tuple[str, ...] = (),
    networks: tuple[str, ...] = (),
) -> None:
    store = DHCPObservationStore(output)
    scopes = discover_capture_scopes(interfaces, networks)
    packet_sockets: dict[socket.socket, CaptureScope] = {}
    ipv6_sockets: set[socket.socket] = set()
    try:
        for scope in scopes:
            packet_socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_IP),
            )
            packet_socket.bind((scope.interface, 0))
            packet_socket.setblocking(False)
            packet_sockets[packet_socket] = scope
            ipv6_socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(ETH_P_IPV6),
            )
            ipv6_socket.bind((scope.interface, 0))
            ipv6_socket.setblocking(False)
            packet_sockets[ipv6_socket] = scope
            ipv6_sockets.add(ipv6_socket)
    except Exception:
        for packet_socket in packet_sockets:
            packet_socket.close()
        raise

    stopping = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    last_flush = time.monotonic()
    try:
        while not stopping:
            readable, _, _ = select.select(list(packet_sockets), [], [], 1.0)
            for packet_socket in readable:
                frame, packet_address = packet_socket.recvfrom(65535)
                if not isinstance(packet_address, tuple) or len(packet_address) < 3:
                    continue
                try:
                    packet_type = int(packet_address[2])
                except (TypeError, ValueError):
                    continue
                if packet_socket in ipv6_sockets:
                    process_ipv6_frame(store, frame, packet_type)
                    continue
                process_captured_frame(
                    store,
                    frame,
                    packet_type,
                    packet_sockets[packet_socket],
                )
            if store.dirty and time.monotonic() - last_flush >= FLUSH_INTERVAL_SECONDS:
                store.flush()
                last_flush = time.monotonic()
    finally:
        for packet_socket in packet_sockets:
            packet_socket.close()
        store.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="EasyPi passive DHCPv4 identity observer")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("/opt/EasyPi/data/network/dhcp_observations.json"),
    )
    default_interfaces = tuple(
        value
        for value in (os.getenv("EASYPI_DHCP_OBSERVER_INTERFACE") or "")
        .replace(",", " ")
        .split()
        if value
    )
    default_networks = tuple(
        value
        for value in (os.getenv("EASYPI_DHCP_OBSERVER_NETWORKS") or "")
        .replace(",", " ")
        .split()
        if value
    )
    parser.add_argument(
        "--interface",
        action="append",
        dest="interfaces",
        default=list(default_interfaces),
    )
    parser.add_argument(
        "--network",
        action="append",
        dest="networks",
        default=list(default_networks),
    )
    args = parser.parse_args()
    run(args.output, tuple(args.interfaces), tuple(args.networks))


if __name__ == "__main__":
    main()
