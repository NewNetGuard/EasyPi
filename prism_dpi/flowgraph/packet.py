"""Ethernet, IP, TCP, and DNS metadata parsing for PRISM FlowGraph."""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

from .events import Direction, FlowKey, TlsClientHello
from .quic import decrypt_quic_initial, parse_quic_initial_client_hello


ETHERNET = 1
LINUX_SLL = 113
LINUX_SLL2 = 276


@dataclass(frozen=True)
class TcpPacket:
    timestamp: float
    flow: FlowKey
    direction: Direction
    sequence: int
    syn: bool
    fin: bool
    rst: bool
    payload: bytes


@dataclass(frozen=True)
class DnsMessage:
    timestamp: float
    client_ip: str
    transaction_id: int
    query_name: str
    is_response: bool
    blocked: bool


@dataclass(frozen=True)
class QuicInitialPacket:
    timestamp: float
    flow: FlowKey
    version: int
    destination_connection_id: bytes
    packet_number: int
    crypto_fragments: tuple[tuple[int, bytes], ...]
    hello: TlsClientHello | None


@dataclass(frozen=True)
class OpaqueQuicFlowPacket:
    timestamp: float
    flow: FlowKey
    datagram_bytes: int
    header_form: str


@dataclass(frozen=True)
class UnclassifiedUdp443Packet:
    timestamp: float
    flow: FlowKey
    datagram_bytes: int


def parse_link_packet(
    timestamp: float,
    frame: bytes,
    *,
    link_type: int = ETHERNET,
    ignored_client_ips: frozenset[str] = frozenset(),
) -> (
    TcpPacket
    | DnsMessage
    | QuicInitialPacket
    | OpaqueQuicFlowPacket
    | UnclassifiedUdp443Packet
    | None
):
    network = _network_payload(frame, link_type)
    if network is None:
        return None
    ether_type, payload = network
    if ether_type == 0x0800:
        parsed = _parse_ipv4(payload)
    elif ether_type == 0x86DD:
        parsed = _parse_ipv6(payload)
    else:
        return None
    if parsed is None:
        return None
    source, destination, protocol, transport = parsed
    if protocol == 6:
        event = _parse_tcp(timestamp, source, destination, transport)
        if event is not None and event.flow.client_ip in ignored_client_ips:
            return None
        return event
    if protocol == 17:
        event = _parse_quic_initial(timestamp, source, destination, transport)
        if event is not None:
            if event.flow.client_ip in ignored_client_ips:
                return None
            return event
        opaque_event = _parse_opaque_quic_flow(
            timestamp,
            source,
            destination,
            transport,
        )
        if opaque_event is not None:
            if opaque_event.flow.client_ip in ignored_client_ips:
                return None
            return opaque_event
        udp443_event = _parse_unclassified_udp443_flow(
            timestamp,
            source,
            destination,
            transport,
        )
        if udp443_event is not None:
            if udp443_event.flow.client_ip in ignored_client_ips:
                return None
            return udp443_event
        event = _parse_dns(timestamp, source, destination, transport)
        if event is not None and event.client_ip in ignored_client_ips:
            return None
        return event
    return None


def _parse_quic_initial(
    timestamp: float,
    source: str,
    destination: str,
    datagram: bytes,
) -> QuicInitialPacket | None:
    if len(datagram) < 8:
        return None
    source_port, destination_port, length = struct.unpack("!HHH", datagram[:6])
    if (
        destination_port != 443
        or not _is_client_address(source)
        or length < 8
        or length > len(datagram)
    ):
        return None
    payload = datagram[8:length]
    crypto = decrypt_quic_initial(payload)
    if crypto is None:
        return None
    initial = parse_quic_initial_client_hello(payload)
    return QuicInitialPacket(
        timestamp=timestamp,
        flow=FlowKey(source, source_port, destination, destination_port, protocol="udp"),
        version=crypto.version,
        destination_connection_id=crypto.destination_connection_id,
        packet_number=crypto.packet_number,
        crypto_fragments=crypto.fragments,
        hello=initial.hello if initial is not None else None,
    )


def _parse_opaque_quic_flow(
    timestamp: float,
    source: str,
    destination: str,
    datagram: bytes,
) -> OpaqueQuicFlowPacket | None:
    if len(datagram) < 9:
        return None
    source_port, destination_port, length = struct.unpack("!HHH", datagram[:6])
    if (
        destination_port != 443
        or not _is_client_address(source)
        or length < 9
        or length > len(datagram)
    ):
        return None
    payload = datagram[8:length]
    if not payload or payload[0] & 0x40 == 0:
        return None
    header_form = "long" if payload[0] & 0x80 else "short"
    return OpaqueQuicFlowPacket(
        timestamp=timestamp,
        flow=FlowKey(
            source,
            source_port,
            destination,
            destination_port,
            protocol="udp",
        ),
        datagram_bytes=len(payload),
        header_form=header_form,
    )


def _parse_unclassified_udp443_flow(
    timestamp: float,
    source: str,
    destination: str,
    datagram: bytes,
) -> UnclassifiedUdp443Packet | None:
    if len(datagram) < 9:
        return None
    source_port, destination_port, length = struct.unpack("!HHH", datagram[:6])
    if (
        destination_port != 443
        or not _is_client_address(source)
        or length < 9
        or length > len(datagram)
    ):
        return None
    return UnclassifiedUdp443Packet(
        timestamp=timestamp,
        flow=FlowKey(
            source,
            source_port,
            destination,
            destination_port,
            protocol="udp",
        ),
        datagram_bytes=length - 8,
    )


def _network_payload(frame: bytes, link_type: int) -> tuple[int, bytes] | None:
    if link_type == ETHERNET:
        if len(frame) < 14:
            return None
        offset = 14
        ether_type = int.from_bytes(frame[12:14], "big")
        while ether_type in (0x8100, 0x88A8):
            if len(frame) < offset + 4:
                return None
            ether_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        return ether_type, frame[offset:]
    if link_type == LINUX_SLL:
        if len(frame) < 16:
            return None
        return int.from_bytes(frame[14:16], "big"), frame[16:]
    if link_type == LINUX_SLL2:
        if len(frame) < 20:
            return None
        return int.from_bytes(frame[:2], "big"), frame[20:]
    return None


def _parse_ipv4(packet: bytes) -> tuple[str, str, int, bytes] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if header_length < 20 or total_length < header_length or len(packet) < total_length:
        return None
    fragment = int.from_bytes(packet[6:8], "big")
    if fragment & 0x1FFF:
        return None
    source = socket.inet_ntoa(packet[12:16])
    destination = socket.inet_ntoa(packet[16:20])
    return source, destination, packet[9], packet[header_length:total_length]


def _parse_ipv6(packet: bytes) -> tuple[str, str, int, bytes] | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    payload_length = int.from_bytes(packet[4:6], "big")
    end = 40 + payload_length
    if len(packet) < end:
        return None
    next_header = packet[6]
    if next_header not in (6, 17):
        return None
    source = socket.inet_ntop(socket.AF_INET6, packet[8:24])
    destination = socket.inet_ntop(socket.AF_INET6, packet[24:40])
    return source, destination, next_header, packet[40:end]


def _is_client_address(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return address.is_private and not address.is_loopback and not address.is_link_local


def _parse_tcp(
    timestamp: float,
    source: str,
    destination: str,
    segment: bytes,
) -> TcpPacket | None:
    if len(segment) < 20:
        return None
    source_port, destination_port, sequence = struct.unpack("!HHI", segment[:8])
    header_length = (segment[12] >> 4) * 4
    if header_length < 20 or len(segment) < header_length:
        return None
    flags = segment[13]
    if destination_port == 443 and _is_client_address(source):
        flow = FlowKey(source, source_port, destination, destination_port)
        direction = Direction.CLIENT_TO_SERVER
    elif source_port == 443 and _is_client_address(destination):
        flow = FlowKey(destination, destination_port, source, source_port)
        direction = Direction.SERVER_TO_CLIENT
    else:
        return None
    return TcpPacket(
        timestamp=timestamp,
        flow=flow,
        direction=direction,
        sequence=sequence,
        syn=bool(flags & 0x02),
        fin=bool(flags & 0x01),
        rst=bool(flags & 0x04),
        payload=segment[header_length:],
    )


def _parse_dns(
    timestamp: float,
    source: str,
    destination: str,
    datagram: bytes,
) -> DnsMessage | None:
    if len(datagram) < 20:
        return None
    source_port, destination_port, length = struct.unpack("!HHH", datagram[:6])
    if length < 20 or length > len(datagram):
        return None
    payload = datagram[8:length]
    if destination_port == 53 and _is_client_address(source):
        client_ip = source
    elif source_port == 53 and _is_client_address(destination):
        client_ip = destination
    else:
        return None
    if len(payload) < 12:
        return None
    transaction_id, flags, questions, answers = struct.unpack("!HHHH", payload[:8])
    if questions < 1:
        return None
    query_name, offset = _dns_name(payload, 12)
    if not query_name or offset + 4 > len(payload):
        return None
    is_response = bool(flags & 0x8000)
    rcode = flags & 0x000F
    blocked = is_response and rcode != 0
    offset += 4
    if is_response and not blocked:
        for _ in range(answers):
            _, offset = _dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            record_type, _, _, data_length = struct.unpack("!HHIH", payload[offset:offset + 10])
            offset += 10
            end = offset + data_length
            if end > len(payload):
                break
            if record_type == 1 and data_length == 4 and payload[offset:end] == b"\0\0\0\0":
                blocked = True
            elif record_type == 28 and data_length == 16 and not any(payload[offset:end]):
                blocked = True
            offset = end
    return DnsMessage(timestamp, client_ip, transaction_id, query_name, is_response, blocked)


def _dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    cursor = offset
    next_offset = offset
    jumped = False
    seen: set[int] = set()
    while cursor < len(message):
        if cursor in seen:
            return "", next_offset
        seen.add(cursor)
        length = message[cursor]
        if length == 0:
            if not jumped:
                next_offset = cursor + 1
            break
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                return "", next_offset
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if not jumped:
                next_offset = cursor + 2
                jumped = True
            cursor = pointer
            continue
        if length > 63 or cursor + 1 + length > len(message):
            return "", next_offset
        raw = message[cursor + 1 : cursor + 1 + length]
        try:
            labels.append(raw.decode("ascii").lower())
        except UnicodeDecodeError:
            return "", next_offset
        cursor += 1 + length
        if not jumped:
            next_offset = cursor
    return ".".join(labels), next_offset


__all__ = [
    "DnsMessage",
    "ETHERNET",
    "LINUX_SLL",
    "LINUX_SLL2",
    "OpaqueQuicFlowPacket",
    "QuicInitialPacket",
    "TcpPacket",
    "UnclassifiedUdp443Packet",
    "parse_link_packet",
]
