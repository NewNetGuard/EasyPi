"""Bounded classic-PCAP stream reader; no packet capture or forwarding on import."""

import struct


class CaptureError(ValueError):
    pass


def exact(source, size, allow_eof=False):
    result = bytearray()
    while len(result) < size:
        part = source.read(size - len(result))
        if not part:
            if allow_eof and not result:
                return None
            raise CaptureError("truncated capture")
        result.extend(part)
    return bytes(result)


class PcapStream:
    def __init__(self, source):
        self.source = source
        header = exact(source, 24)
        if header[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            self.endian = "<"
        elif header[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            self.endian = ">"
        else:
            raise CaptureError("unsupported capture format")
        major, minor, _, _, snap, self.link = struct.unpack(
            self.endian + "HHIIII", header[4:]
        )
        if (
            (major, minor) != (2, 4)
            or not 1 <= snap <= 262144
            or self.link not in (1, 101, 113, 276)
        ):
            raise CaptureError("unsupported capture header")

    def read(self):
        header = exact(self.source, 16, True)
        if header is None:
            return None
        _, _, size, original = struct.unpack(self.endian + "IIII", header)
        if not 1 <= size <= 65575 or size != original:
            raise CaptureError("truncated or oversized capture packet")
        packet = exact(self.source, size)
        offset = {1: 14, 101: 0, 113: 16, 276: 20}[self.link]
        if len(packet) <= offset:
            raise CaptureError("truncated link header")
        if self.link == 1:
            protocol = int.from_bytes(packet[12:14], "big")
        elif self.link == 113:
            protocol = int.from_bytes(packet[14:16], "big")
        elif self.link == 276:
            protocol = int.from_bytes(packet[:2], "big")
        else:
            protocol = 0x86DD if packet[0] >> 4 == 6 else 0x800
        if protocol not in (0x800, 0x86DD):
            return b""
        ip = packet[offset:]
        total = (
            int.from_bytes(ip[2:4], "big")
            if ip[0] >> 4 == 4
            else 40 + int.from_bytes(ip[4:6], "big")
        )
        if total > len(ip) or total < 20:
            raise CaptureError("truncated IP packet")
        return ip[:total]
