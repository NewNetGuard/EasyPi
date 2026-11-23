"""Strict IPv4 transport extraction for packets delivered by NFQUEUE."""

from __future__ import annotations

import ipaddress
import socket
import struct
from dataclasses import dataclass

from prism_dpi.flowgraph.events import FlowKey, TlsClientHello
from prism_dpi.flowgraph.tls import TlsRecord, parse_client_hello


@dataclass(frozen=True)
class QueuedClientHello:
    flow: FlowKey
    hello: TlsClientHello


@dataclass(frozen=True)
class QueuedTransportPacket:
    flow: FlowKey
    client_to_server: bool
    payload: bytes
    syn: bool
    ack: bool
    fin: bool
    rst: bool
    server_name: str = ""
    sequence: int = 0


def parse_queued_ipv4_transport(packet: bytes) -> QueuedTransportPacket | None:
    if len(packet) < 28 or packet[0] >> 4 != 4:
        return None
    ip_header_length = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    protocol = packet[9]
    minimum_transport = 20 if protocol == 6 else 8 if protocol == 17 else 0
    if (
        ip_header_length < 20
        or not minimum_transport
        or total_length < ip_header_length + minimum_transport
        or total_length > len(packet)
    ):
        return None
    fragment = int.from_bytes(packet[6:8], "big")
    if fragment & 0x3FFF:
        return None

    source_ip = socket.inet_ntoa(packet[12:16])
    destination_ip = socket.inet_ntoa(packet[16:20])
    source_address = ipaddress.ip_address(source_ip)
    destination_address = ipaddress.ip_address(destination_ip)
    segment = packet[ip_header_length:total_length]
    source_port, destination_port = struct.unpack("!HH", segment[:4])
    if destination_port == 443 and source_address.is_private and destination_address.is_global:
        client_ip, client_port = source_ip, source_port
        server_ip, server_port = destination_ip, destination_port
        client_to_server = True
    elif source_port == 443 and destination_address.is_private and source_address.is_global:
        client_ip, client_port = destination_ip, destination_port
        server_ip, server_port = source_ip, source_port
        client_to_server = False
    else:
        return None

    if protocol == 6:
        header_length = (segment[12] >> 4) * 4
        if header_length < 20 or len(segment) < header_length:
            return None
        flags = segment[13]
        sequence = int.from_bytes(segment[4:8], "big")
        payload = segment[header_length:]
        protocol_name = "tcp"
        fin = bool(flags & 0x01)
        syn = bool(flags & 0x02)
        rst = bool(flags & 0x04)
        ack = bool(flags & 0x10)
    else:
        udp_length = int.from_bytes(segment[4:6], "big")
        if udp_length < 8 or udp_length > len(segment):
            return None
        payload = segment[8:udp_length]
        protocol_name = "udp"
        sequence = 0
        syn = ack = fin = rst = False
    server_name = ""
    if protocol_name == "tcp" and client_to_server:
        hello = _parse_client_hello_payload(payload)
        if hello is not None:
            server_name = hello.server_name
    return QueuedTransportPacket(
        flow=FlowKey(
            client_ip,
            client_port,
            server_ip,
            server_port,
            protocol=protocol_name,
        ),
        client_to_server=client_to_server,
        payload=payload,
        syn=syn,
        ack=ack,
        fin=fin,
        rst=rst,
        server_name=server_name,
        sequence=sequence,
    )


def parse_queued_ipv4_client_hello(packet: bytes) -> QueuedClientHello | None:
    transport = parse_queued_ipv4_transport(packet)
    if (
        transport is None
        or transport.flow.protocol != "tcp"
        or not transport.client_to_server
    ):
        return None
    hello = _parse_client_hello_payload(transport.payload)
    if hello is None:
        return None
    return QueuedClientHello(
        flow=transport.flow,
        hello=hello,
    )


def _parse_client_hello_payload(payload: bytes) -> TlsClientHello | None:
    if len(payload) < 5 or payload[0] != 22 or payload[1] != 3:
        return None
    record_length = int.from_bytes(payload[3:5], "big")
    record_end = 5 + record_length
    if record_end > len(payload):
        return None

    hello = parse_client_hello(
        TlsRecord(
            content_type=payload[0],
            legacy_version=payload[1:3],
            payload=payload[5:record_end],
        )
    )
    if hello is None:
        return None
    return hello


__all__ = [
    "QueuedClientHello",
    "QueuedTransportPacket",
    "parse_queued_ipv4_client_hello",
    "parse_queued_ipv4_transport",
]
