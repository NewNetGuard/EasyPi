"""Experimental QUIC v1 client-direction / HTTP3 decoder for a single opt-in lab session.

Uses aioquic for packet protection and pylsqpack for QPACK. The fixed loopback control and the AEAD-correlating Firefox adapter are separate
classes. Neither is a general QUIC sniffer.
"""

from collections import deque
from .qpack_guard import Guard
from .qpack_budget import TABLE_CAPACITY, qpack_reservation
from .decode_errors import DecodeError, safe_error_code
from aioquic.quic.crypto import next_key_phase
import time
from aioquic.buffer import Buffer, BufferReadError
from aioquic.quic.crypto import CryptoContext, CryptoError
from aioquic.quic.packet import pull_quic_header, QuicPacketType, QuicProtocolVersion
from aioquic.tls import CipherSuite
import pylsqpack


class QUICSession:
    def __init__(self, secrets, emit, limits=None, clock=time.monotonic):
        self.clock = clock
        self.buffer_limit = limits.decoder_buffer_bytes if limits else 1024 * 1024
        self.stream_limit = limits.max_streams if limits else 32
        self.stream_bytes = limits.stream_bytes if limits else 65536
        self.packet_limit = limits.max_packets if limits else 4096
        self.header_limit = limits.header_bytes if limits else 16384
        self.previous_key_seconds = limits.previous_quic_key_seconds if limits else 3
        self.previous_crypto = None
        self.previous_expires = 0
        self.update_pn = -1
        self.phase_highest = -1
        self.generation = 0
        self.last_packet_old = False
        self.secrets, self.emit = secrets, emit
        self.crypto = None
        self.pending = deque()
        self.pending_bytes = 0
        self.expected = 0
        self.seen_packets = set()
        self.streams = {}
        self.qpack_reserved_bytes = qpack_reservation(
            self.stream_bytes, self.header_limit,
            limits.max_header_fields if limits else 64)
        self.qpack = pylsqpack.Decoder(TABLE_CAPACITY, 0)
        self.guard = Guard(
            capacity=TABLE_CAPACITY,
            maximum=self.header_limit, fields=limits.max_header_fields if limits else 64
        )
        self.blocked_headers = {}
        self.encoder_stream_id = None
        self.received_at = None
        self.failed = False
        self.decode_stage = "packet"

    def feed(self, data):
        if self.failed:
            return
        if self.pending_bytes + len(data) > self.buffer_limit:
            self.fail(DecodeError("limits.pending_bytes"))
            return
        self.pending.append((data, self.clock()))
        self.pending_bytes += len(data)
        self.retry()

    def retry(self):
        if self.failed:
            return
        if self.crypto is None:
            with self.secrets.lock:
                values = [
                    secret
                    for (label, _), secret in self.secrets.values.items()
                    if label == "CLIENT_TRAFFIC_SECRET_0"
                ]
            if len(values) != 1:
                return
            self.crypto = CryptoContext()
            self.crypto.setup(
                cipher_suite=CipherSuite.AES_128_GCM_SHA256,
                secret=values[0],
                version=QuicProtocolVersion.VERSION_1,
            )
        try:
            while self.pending:
                datagram, self.received_at = self.pending.popleft()
                self.pending_bytes -= len(datagram)
                offset = 0
                while offset < len(datagram):
                    if not any(datagram[offset:]):
                        break
                    buf = Buffer(data=datagram[offset:])
                    self.decode_stage = "packet"
                    header = pull_quic_header(buf, host_cid_length=8)
                    if not 0 < header.packet_length <= len(datagram) - offset:
                        raise DecodeError("reassembly.invalid_length")
                    packet = datagram[offset : offset + header.packet_length]
                    offset += header.packet_length
                    if header.packet_type != QuicPacketType.ONE_RTT:
                        continue
                    _, plain, number, key_phase = self.crypto.decrypt_packet(
                        packet, buf.tell(), self.expected
                    )
                    if key_phase:
                        raise DecodeError("aead.key_update_unsupported")
                    self.expected = max(self.expected, number + 1)
                    if number in self.seen_packets:
                        continue
                    if len(self.seen_packets) >= self.packet_limit:
                        raise DecodeError("limits.packet_count")
                    self.seen_packets.add(number)
                    self.frames(plain)
        except Exception as error:
            self.fail(error)

    def fail(self, error):
        self.failed = True
        code = safe_error_code(error, self.decode_stage)
        event = {"type": "quic_analysis_unavailable", "reason": code,
                 "error_code": code, "error_category": code.split(".", 1)[0]}
        if isinstance(error, DecodeError):
            event.update(error.measurements)
        self.emit(event)

    def timeout_code(self):
        if self.blocked_headers or self.guard.buffer:
            return "timeouts.qpack"
        if any(state["end"] < len(state["seen"]) for state in self.streams.values()):
            return "timeouts.stream_gap"
        if getattr(self, "authenticated_packets", 0):
            return "timeouts.headers"
        with self.secrets.lock:
            has_key = any(label == "CLIENT_TRAFFIC_SECRET_0" for label, _ in self.secrets.values)
        return "timeouts.no_authenticated_packet" if has_key else "timeouts.missing_key"

    def frames(self, plain):
        self.decode_stage = "frame"
        b = Buffer(data=plain)
        while not b.eof():
            kind = b.pull_uint_var()
            if kind in (0, 1, 30):
                continue
            if kind in (2, 3):
                b.pull_uint_var()
                b.pull_uint_var()
                ranges = b.pull_uint_var()
                b.pull_uint_var()
                if ranges > 256:
                    raise DecodeError("limits.ack_ranges")
                for _ in range(ranges):
                    b.pull_uint_var()
                    b.pull_uint_var()
                if kind == 3:
                    for _ in range(3):
                        b.pull_uint_var()
            elif kind == 6:
                b.pull_uint_var()
                b.pull_bytes(b.pull_uint_var())
            elif 8 <= kind <= 15:
                stream = b.pull_uint_var()
                offset = b.pull_uint_var() if kind & 4 else 0
                size = b.pull_uint_var() if kind & 2 else b.capacity - b.tell()
                self.stream(stream, offset, b.pull_bytes(size))
                self.decode_stage = "frame"
            elif kind in (4, 5, 16, 17, 18, 19, 20, 21, 22, 23, 25):
                count = 3 if kind == 4 else 2 if kind in (5, 17, 21) else 1
                for _ in range(count):
                    b.pull_uint_var()
            elif kind == 7:
                b.pull_bytes(b.pull_uint_var())
            elif kind == 24:
                b.pull_uint_var()
                b.pull_uint_var()
                b.pull_bytes(b.pull_uint8() + 16)
            elif kind in (26, 27):
                b.pull_bytes(8)
            elif kind in (28, 29):
                b.pull_uint_var()
                if kind == 28:
                    b.pull_uint_var()
                b.pull_bytes(b.pull_uint_var())
            elif kind in (48, 49):
                b.pull_bytes(b.pull_uint_var() if kind == 49 else b.capacity - b.tell())
            else:
                raise DecodeError("frame.unsupported")

    def stream(self, number, offset, data):
        self.decode_stage = "stream"
        if offset + len(data) > self.stream_bytes:
            raise DecodeError("limits.stream_bytes")
        if number not in self.streams and len(self.streams) >= self.stream_limit:
            raise DecodeError("limits.stream_count")
        state = self.streams.setdefault(
            number,
            {
                "data": bytearray(),
                "seen": bytearray(),
                "end": 0,
                "buffer": bytearray(),
                "kind": None,
            },
        )
        end = offset + len(data)
        grow = max(0, end - len(state["data"]))
        state["data"].extend(bytes(grow))
        state["seen"].extend(bytes(grow))
        for index, value in enumerate(data, offset):
            if state["seen"][index] and state["data"][index] != value:
                raise DecodeError("stream.conflicting_retransmission")
            state["data"][index], state["seen"][index] = value, 1
        previous = state["end"]
        while state["end"] < len(state["seen"]) and state["seen"][state["end"]]:
            state["end"] += 1
        state["buffer"].extend(state["data"][previous : state["end"]])
        if number & 2:
            if state["kind"] is None:
                b = Buffer(data=bytes(state["buffer"]))
                try:
                    state["kind"] = b.pull_uint_var()
                except BufferReadError:
                    return
                del state["buffer"][: b.tell()]
            if state["kind"] == 2:
                # RFC 9204 permits one encoder stream per peer. Besides being
                # invalid protocol input, extra encoder streams would defeat
                # the single-stream bound used for native allocation budgeting.
                if self.encoder_stream_id is None:
                    self.encoder_stream_id = number
                elif self.encoder_stream_id != number:
                    raise DecodeError("qpack.encoder")
                self.decode_stage = "qpack"
                validated = self.guard.feed_encoder(bytes(state["buffer"]))
                if validated:
                    self.qpack.feed_encoder(validated)
                for resumed, block in tuple(self.blocked_headers.items()):
                    if self.guard.check(block):
                        del self.blocked_headers[resumed]
                        _, headers = self.qpack.feed_header(resumed, block)
                        self.request(resumed, headers)
            state["buffer"].clear()
            return
        while state["buffer"]:
            b = Buffer(data=bytes(state["buffer"]))
            try:
                kind, size = b.pull_uint_var(), b.pull_uint_var()
                if size > self.stream_bytes:
                    raise DecodeError("limits.http3_frame")
                body = b.pull_bytes(size)
            except BufferReadError:
                return
            del state["buffer"][: b.tell()]
            if kind == 1:
                self.decode_stage = "qpack"
                if self.guard.check(body):
                    _, headers = self.qpack.feed_header(number, body)
                    self.request(number, headers)
                else:
                    if (
                        number in self.blocked_headers
                        or len(self.blocked_headers) >= self.stream_limit
                    ):
                        raise DecodeError("limits.qpack_blocked")
                    self.blocked_headers[number] = body

    def request(self, stream, headers):
        headers = {
            k.decode("ascii"): v.decode("utf-8", errors="replace") for k, v in headers
        }
        if ":method" in headers:
            self.emit(
                {
                    "type": "http_request",
                    "protocol": "h3",
                    "stream_id": stream,
                    "method": headers.get(":method"),
                    "authority": headers.get(":authority"),
                    "path": headers.get(":path"),
                    "decode_delay_ms": round(
                        (time.monotonic() - self.received_at) * 1000, 3
                    ),
                }
            )


class AdaptiveQUICSession(QUICSession):
    """Associate an opt-in client's QUIC keys, cipher and CID length by AEAD.

    This remains one bounded experiment connection, not a general QUIC sensor.
    Long-header metadata is observed; TLS is never terminated by this class.
    """

    def __init__(self, secrets, emit, limits=None, clock=time.monotonic):
        super().__init__(secrets, emit, limits, clock)
        self.version = QuicProtocolVersion.VERSION_1
        self.cid_lengths = [8, 20] + [n for n in range(21) if n not in (8, 20)]
        self.cid_length = None
        self.last_attempt = None
        self.authenticated_packets = 0

    def commit_update(self, number):
        if number <= self.phase_highest:
            raise DecodeError("aead.key_phase_order")
        previous = self.crypto
        updated = next_key_phase(previous)
        # RFC 9001: header-protection keys are not updated with packet keys.
        updated.hp = previous.hp
        if self.previous_crypto is not None:
            self.previous_crypto.teardown()
        self.previous_crypto = previous
        self.previous_expires = self.clock() + self.previous_key_seconds
        self.crypto = updated
        self.update_pn = number
        self.generation += 1
        self.emit(
            {
                "type": "quic_key_update",
                "generation": self.generation,
                "direction": "client",
            }
        )

    def decrypt_with_history(self, packet, offset):
        self.last_packet_old = False
        if self.previous_crypto is not None and self.clock() > self.previous_expires:
            self.previous_crypto.teardown()
            self.previous_crypto = None
        try:
            return self.crypto.decrypt_packet(packet, offset, self.expected)
        except CryptoError:
            if self.previous_crypto is None:
                raise
            result = self.previous_crypto.decrypt_packet(packet, offset, self.expected)
            if result[3] or result[2] >= self.update_pn:
                raise CryptoError("invalid previous key phase packet")
            self.last_packet_old = True
            return result

    def observe_server(self, data):
        if not data or not data[0] & 128:
            return
        try:
            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
            size = len(header.source_cid)
            if (
                header.packet_type == QuicPacketType.INITIAL
                and size in self.cid_lengths
            ):
                self.cid_lengths.remove(size)
                self.cid_lengths.insert(0, size)
        except (ValueError, BufferReadError):
            pass

    def select_crypto(self, packet):
        with self.secrets.lock:
            candidates = [
                (random, secret)
                for (label, random), secret in self.secrets.values.items()
                if label == "CLIENT_TRAFFIC_SECRET_0"
            ][:8]
            revision = self.secrets.revision
        marker = (
            revision,
            self.version,
            tuple(self.cid_lengths),
            packet[:32],
        )
        if marker == self.last_attempt:
            return None
        self.last_attempt = marker
        for random, secret in candidates:
            suites = (
                [CipherSuite.AES_256_GCM_SHA384]
                if len(secret) == 48
                else [
                    CipherSuite.AES_128_GCM_SHA256,
                    CipherSuite.CHACHA20_POLY1305_SHA256,
                ]
            )
            for suite in suites:
                for size in self.cid_lengths:
                    if len(packet) < 1 + size + 20:
                        continue
                    context = CryptoContext()
                    context.setup(
                        cipher_suite=suite, secret=secret, version=self.version
                    )
                    try:
                        result = context.decrypt_packet(packet, 1 + size, self.expected)
                    except (CryptoError, ValueError):
                        continue
                    self.secrets.confirm("CLIENT_TRAFFIC_SECRET_0", random, secret)
                    self.crypto, self.cid_length = context, size
                    self.emit(
                        {
                            "type": "quic_key_correlation",
                            "method": "AEAD-authenticated",
                            "version": hex(self.version),
                            "cipher_suite": hex(suite),
                            "cid_length": size,
                        }
                    )
                    return result
        return None

    def retry(self):
        if self.failed:
            return
        try:
            while self.pending:
                datagram, self.received_at = self.pending[0]
                offset = 0
                while offset < len(datagram):
                    remaining = datagram[offset:]
                    if not any(remaining):
                        break
                    self.decode_stage = "packet"
                    if remaining[0] & 128:
                        header = pull_quic_header(
                            Buffer(data=remaining), host_cid_length=8
                        )
                        if not 0 < header.packet_length <= len(remaining):
                            raise DecodeError("reassembly.invalid_length")
                        if header.packet_type == QuicPacketType.INITIAL:
                            if header.version not in (
                                QuicProtocolVersion.VERSION_1,
                                QuicProtocolVersion.VERSION_2,
                            ):
                                raise DecodeError("frame.unsupported_version")
                            self.version = header.version
                        offset += header.packet_length
                        continue
                    if self.crypto is None:
                        result = self.select_crypto(remaining)
                        if result is None:
                            return
                    else:
                        try:
                            result = self.decrypt_with_history(
                                remaining, 1 + self.cid_length
                            )
                        except CryptoError:
                            result = None
                            for size in self.cid_lengths:
                                if len(remaining) < 1 + size + 20:
                                    continue
                                try:
                                    result = self.decrypt_with_history(
                                        remaining, 1 + size
                                    )
                                    self.cid_length = size
                                    break
                                except (CryptoError, ValueError):
                                    continue
                            if result is None:
                                raise DecodeError("aead.authentication_failed")
                    _, plain, number, key_phase = result
                    if key_phase:
                        self.commit_update(number)
                    if not self.last_packet_old:
                        self.phase_highest = max(self.phase_highest, number)
                    self.expected = max(self.expected, number + 1)
                    if number not in self.seen_packets:
                        if len(self.seen_packets) >= self.packet_limit:
                            raise DecodeError("limits.packet_count")
                        self.seen_packets.add(number)
                        self.authenticated_packets += 1
                        self.frames(plain)
                    offset = len(datagram)
                self.pending.popleft()
                self.pending_bytes -= len(datagram)
        except Exception as error:
            self.fail(error)
