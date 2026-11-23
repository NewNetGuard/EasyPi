"""Live AF_PACKET and classic-PCAP sources for PRISM FlowGraph."""

from __future__ import annotations

import socket
import struct
import time
from collections.abc import Iterator
from pathlib import Path

from .packet import ETHERNET


class RawSocketSource:
    link_type = ETHERNET

    def __init__(self, interface: str, *, timeout: float = 1.0) -> None:
        if not interface or socket.if_nametoindex(interface) <= 0:
            raise ValueError("capture interface does not exist")
        self._socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003),
        )
        self._socket.bind((interface, 0))
        self._socket.settimeout(timeout)
        self.local_addresses = _interface_addresses(interface)

    def receive(self) -> tuple[float, bytes] | None:
        try:
            frame = self._socket.recv(65_535)
        except TimeoutError:
            return None
        return time.time(), frame

    def close(self) -> None:
        self._socket.close()


class PcapReader:
    """Read libpcap files without a third-party packet library."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def __iter__(self) -> Iterator[tuple[float, bytes, int]]:
        with self.path.open("rb") as source:
            header = source.read(24)
            if len(header) != 24:
                raise ValueError("truncated pcap header")
            magic = header[:4]
            if magic == b"\xd4\xc3\xb2\xa1":
                byte_order, divisor = "<", 1_000_000
            elif magic == b"\xa1\xb2\xc3\xd4":
                byte_order, divisor = ">", 1_000_000
            elif magic == b"\x4d\x3c\xb2\xa1":
                byte_order, divisor = "<", 1_000_000_000
            elif magic == b"\xa1\xb2\x3c\x4d":
                byte_order, divisor = ">", 1_000_000_000
            else:
                raise ValueError("unsupported capture format; classic pcap required")
            link_type = struct.unpack(f"{byte_order}I", header[20:24])[0]
            while True:
                packet_header = source.read(16)
                if not packet_header:
                    return
                if len(packet_header) != 16:
                    raise ValueError("truncated pcap packet header")
                seconds, fraction, captured, _ = struct.unpack(
                    f"{byte_order}IIII", packet_header
                )
                if captured > 16_777_216:
                    raise ValueError("invalid pcap packet length")
                frame = source.read(captured)
                if len(frame) != captured:
                    raise ValueError("truncated pcap packet")
                yield seconds + (fraction / divisor), frame, link_type


def _interface_addresses(interface: str) -> frozenset[str]:
    addresses: set[str] = set()
    try:
        import fcntl

        control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            request = struct.pack("256s", interface.encode("ascii")[:15])
            response = fcntl.ioctl(control.fileno(), 0x8915, request)
            addresses.add(socket.inet_ntoa(response[20:24]))
        finally:
            control.close()
    except (ImportError, OSError, UnicodeEncodeError):
        pass
    return frozenset(addresses)


__all__ = ["PcapReader", "RawSocketSource"]
