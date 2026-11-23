"""Bounded TCP sequence reassembly and strict IP transport extraction."""

from dataclasses import dataclass
import ipaddress
import struct
from .models import Endpoint


class InputError(ValueError):
    pass


class TCPAssembler:
    def __init__(self, limit=65536, history=8192, segments=128):
        self.limit, self.history_limit, self.segment_limit = limit, history, segments
        self.base = None
        self.next = 0
        self.pending = []
        self.history = bytearray()
        self.gap_since = None
        self.fin_at = None
        self.closed = False

    @property
    def resident_bytes(self):
        return len(self.history) + sum(len(data) for _, data in self.pending)

    def feed(self, sequence, data, now, syn=False, fin=False):
        if not 0 <= sequence < 1 << 32 or len(data) > self.limit:
            raise InputError("tcp_window_limit")
        if syn:
            initial = (sequence + 1) & 0xFFFFFFFF
            if self.base is not None and initial != self.base:
                raise InputError("tcp_tuple_reused")
            if self.base is None:
                self.base = initial
            elif not data and not fin:
                return []
            sequence = initial
        if self.base is None:
            raise InputError("tcp_missing_syn")
        expected = (self.base + self.next) & 0xFFFFFFFF
        delta = (sequence - expected) & 0xFFFFFFFF
        if delta >= 1 << 31:
            delta -= 1 << 32
        start = self.next + delta
        end = start + len(data)
        if start < self.next - len(self.history) or end > self.next + self.limit:
            raise InputError("tcp_retransmission_outside_window")
        if self.closed and end > self.next:
            raise InputError("tcp_data_after_fin")
        if start < self.next:
            overlap = min(len(data), self.next - start)
            history_start = start - (self.next - len(self.history))
            if (
                bytes(self.history[history_start : history_start + overlap])
                != data[:overlap]
            ):
                raise InputError("tcp_conflicting_retransmission")
            data = data[overlap:]
            start += overlap
        pieces = [(start, bytes(data))] if data else []
        for old_start, old_data in self.pending:
            old_end = old_start + len(old_data)
            overlap_start = max(start, old_start)
            overlap_end = min(start + len(data), old_end)
            if (
                overlap_start < overlap_end
                and data[overlap_start - start : overlap_end - start]
                != old_data[overlap_start - old_start : overlap_end - old_start]
            ):
                raise InputError("tcp_conflicting_retransmission")
            next_pieces = []
            for point, value in pieces:
                stop = point + len(value)
                if stop <= old_start or point >= old_end:
                    next_pieces.append((point, value))
                else:
                    if point < old_start:
                        next_pieces.append((point, value[: old_start - point]))
                    if stop > old_end:
                        next_pieces.append((old_end, value[old_end - point :]))
            pieces = next_pieces
        combined = sorted(self.pending + pieces)
        if (
            len(combined) > self.segment_limit
            or sum(len(value) for _, value in combined) > self.limit
        ):
            raise InputError("tcp_reassembly_limit")
        self.pending = combined
        if fin:
            if self.fin_at is not None and self.fin_at != end:
                raise InputError("tcp_conflicting_fin")
            self.fin_at = end
        output = []
        while self.pending and self.pending[0][0] == self.next:
            _, value = self.pending.pop(0)
            self.next += len(value)
            output.append(value)
            self.history.extend(value)
            if len(self.history) > self.history_limit:
                del self.history[: -self.history_limit]
        if self.fin_at is not None and self.next == self.fin_at:
            self.closed = True
        if self.pending and self.pending[0][0] > self.next:
            if self.gap_since is None:
                self.gap_since = now
        else:
            self.gap_since = None
        return output


@dataclass(frozen=True)
class TransportPacket:
    protocol: str
    source: Endpoint
    destination: Endpoint
    payload: bytes
    sequence: int = 0
    syn: bool = False
    fin: bool = False
    rst: bool = False


def parse_ip_packet(packet):
    if not isinstance(packet, bytes) or not 20 <= len(packet) <= 65535:
        raise InputError("invalid_packet_size")
    version = packet[0] >> 4
    if version == 4:
        offset = (packet[0] & 15) * 4
        total = int.from_bytes(packet[2:4], "big")
        if offset < 20 or total != len(packet) or total < offset:
            raise InputError("invalid_ipv4_length")
        if int.from_bytes(packet[6:8], "big") & 0x3FFF:
            raise InputError("ip_fragment_unsupported")
        protocol = packet[9]
        source = str(ipaddress.ip_address(packet[12:16]))
        destination = str(ipaddress.ip_address(packet[16:20]))
    elif version == 6:
        if len(packet) < 40 or 40 + int.from_bytes(packet[4:6], "big") != len(packet):
            raise InputError("invalid_ipv6_length")
        offset, protocol = 40, packet[6]
        source = str(ipaddress.ip_address(packet[8:24]))
        destination = str(ipaddress.ip_address(packet[24:40]))
        if protocol not in (6, 17):
            raise InputError("ipv6_extension_unsupported")
    else:
        raise InputError("unsupported_ip_version")
    transport = packet[offset:]
    if protocol == 6:
        if len(transport) < 20:
            raise InputError("truncated_tcp")
        sport, dport, sequence = struct.unpack("!HHI", transport[:8])
        header = (transport[12] >> 4) * 4
        if header < 20 or header > len(transport):
            raise InputError("invalid_tcp_header")
        flags = transport[13]
        return TransportPacket(
            "tcp",
            Endpoint(source, sport),
            Endpoint(destination, dport),
            transport[header:],
            sequence,
            bool(flags & 2),
            bool(flags & 1),
            bool(flags & 4),
        )
    if protocol == 17:
        if len(transport) < 8:
            raise InputError("truncated_udp")
        sport, dport, size = struct.unpack("!HHH", transport[:6])
        if size != len(transport):
            raise InputError("invalid_udp_length")
        return TransportPacket(
            "quic", Endpoint(source, sport), Endpoint(destination, dport), transport[8:]
        )
    raise InputError("unsupported_transport")
