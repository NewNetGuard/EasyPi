"""Bounded passive TLS 1.3 / HTTP/2 decoder for an opt-in test client."""

from collections import deque
import hashlib
import hmac
import re
import struct
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from hpack import Decoder

LIMIT = 1024 * 1024
LABELS = {
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "CLIENT_TRAFFIC_SECRET_0",
    "SERVER_TRAFFIC_SECRET_0",
}


def expand_label(secret, label, length, digest="sha256"):
    label = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(label)]) + label + b"\x00"
    result = previous = b""
    for index in range(
        1,
        (length + hashlib.new(digest).digest_size - 1)
        // hashlib.new(digest).digest_size
        + 1,
    ):
        previous = hmac.digest(secret, previous + info + bytes([index]), digest)
        result += previous
    return result[:length]


def decrypt_record(secret, suite, sequence, record):
    digest, size = (
        ("sha384", 32) if suite == 0x1302 else ("sha256", 32 if suite == 0x1303 else 16)
    )
    key = expand_label(secret, b"key", size, digest)
    iv = expand_label(secret, b"iv", 12, digest)
    nonce = bytes(a ^ b for a, b in zip(iv, sequence.to_bytes(12, "big")))
    cipher = ChaCha20Poly1305(key) if suite == 0x1303 else AESGCM(key)
    return cipher.decrypt(nonce, record[5:], record[:5])


class Secrets:
    def __init__(self, maximum=256, scoped=False, expected_random=None):
        self.maximum = maximum
        if expected_random is not None and (
            not isinstance(expected_random, str)
            or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_random)
        ):
            raise ValueError("invalid key session identifier")
        self.expected_random = expected_random.lower() if expected_random else None
        self.scoped = scoped
        self.observed_random = None
        self.bound_random = None
        self.revision = 0
        self.last_error = None
        self.store_pressure = 0
        self.verified = set()
        self.values = {}
        self.lock = threading.Lock()

    def add(self, line):
        self.last_error = "invalid_secret"
        if not isinstance(line, str) or len(line) > 1024:
            return False
        parts = line.strip().split()
        if len(parts) != 3 or parts[0] not in LABELS:
            return False
        label, random, secret = parts
        if not re.fullmatch(r"[0-9a-fA-F]{64}", random) or not re.fullmatch(
            r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{96})", secret
        ):
            return False
        key = (label, random.lower())
        with self.lock:
            self.last_error = None
            if self.scoped and self.expected_random and key[1] != self.expected_random:
                self.last_error = "unrelated_session"
                return False
            if self.scoped and self.bound_random and key[1] != self.bound_random:
                self.last_error = "unrelated_session"
                return False
            value = bytes.fromhex(secret)
            if key in self.values and self.values[key] != value:
                if not self.scoped or key in self.verified:
                    self.last_error = "invalid_secret"
                    return False
            if len(self.values) >= self.maximum and key not in self.values:
                self.store_pressure += 1
                self.last_error = "key_store_full"
                if not self.scoped or self.bound_random:
                    return False
                # Only unverified groups may rotate. Reserve the observed wire
                # identifier, but allow ECH candidates to prove an inner ID.
                victim = next(
                    (
                        r
                        for _, r in self.values
                        if r != (self.expected_random or self.observed_random)
                    ),
                    None,
                )
                if victim is None:
                    return False
                for entry in tuple(self.values):
                    if entry[1] == victim:
                        del self.values[entry]
                self.revision += 1
            if self.values.get(key) != value:
                self.values[key] = value
                self.revision += 1
        return True

    def observe(self, random):
        if self.scoped:
            with self.lock:
                self.observed_random = random

    def confirm(self, label, random, secret):
        if not self.scoped:
            return
        with self.lock:
            if self.expected_random and self.expected_random != random:
                raise ValueError("authenticated key session mismatch")
            if self.bound_random is not None and self.bound_random != random:
                raise ValueError("authenticated TLS session changed")
            self.bound_random = random
            for entry in tuple(self.values):
                if entry[1] != random:
                    del self.values[entry]
                    self.revision += 1
            key = (label, random)
            if key not in self.values and len(self.values) >= self.maximum:
                raise ValueError("authenticated key budget")
            if self.values.get(key) != secret:
                self.values[key] = secret
                self.revision += 1
            self.verified.add(key)

    def reject_unverified(self, label, random, secret):
        with self.lock:
            key = (label, random)
            if not self.scoped or key in self.verified:
                return False
            if self.values.get(key) == secret:
                del self.values[key]
                self.revision += 1
            return True

    def get(self, label, random):
        with self.lock:
            return self.values.get((label, random))

    def match_record(self, label, suite, record):
        # Endpoint key logs can identify an inner ClientHello (ECH). Only a
        # successful AEAD tag, never timing or ordering, may correlate a key.
        with self.lock:
            candidates = [
                (random, secret)
                for (kind, random), secret in self.values.items()
                if kind == label
            ]
        for random, secret in candidates:
            try:
                decrypt_record(secret, suite, 0, record)
                return random, secret
            except InvalidTag:
                continue
        return None

    def clear(self):
        with self.lock:
            self.values.clear()
            self.verified.clear()
            self.observed_random = self.bound_random = None
            self.revision += 1


class HTTP2:
    PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

    def __init__(self, emit, limit=LIMIT, header_limit=16384, field_limit=64):
        self.limit, self.header_limit, self.field_limit = (
            limit,
            header_limit,
            field_limit,
        )
        self.buffer = bytearray()
        self.started = False
        self.decoder = Decoder(max_header_list_size=header_limit)
        self.headers = None
        self.stream = None
        self.emit = emit

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > self.limit:
            raise ValueError("HTTP/2 buffer limit")
        if not self.started:
            prefix = bytes(self.buffer[: len(self.PREFACE)])
            if not self.PREFACE.startswith(prefix):
                raise ValueError("application protocol is not HTTP/2")
            if len(self.buffer) < len(self.PREFACE):
                return
            del self.buffer[: len(self.PREFACE)]
            self.started = True
        while len(self.buffer) >= 9:
            length = int.from_bytes(self.buffer[:3], "big")
            if length > 65536:
                raise ValueError("HTTP/2 frame limit")
            if len(self.buffer) < length + 9:
                return
            kind, flags = self.buffer[3:5]
            stream = int.from_bytes(self.buffer[5:9], "big") & 0x7FFFFFFF
            body = bytes(self.buffer[9 : 9 + length])
            del self.buffer[: 9 + length]
            if self.headers is not None and (kind != 9 or stream != self.stream):
                raise ValueError("interleaved HTTP/2 header block")
            if kind == 1:
                if not stream:
                    raise ValueError("invalid HTTP/2 stream")
                if flags & 8:
                    if not body or body[0] >= len(body):
                        raise ValueError("invalid HTTP/2 padding")
                    body = body[1 : len(body) - body[0]]
                if flags & 32:
                    if len(body) < 5:
                        raise ValueError("invalid HTTP/2 priority")
                    body = body[5:]
                self.headers, self.stream = bytearray(body), stream
            elif kind == 9:
                if self.headers is None:
                    raise ValueError("unexpected HTTP/2 continuation")
                self.headers.extend(body)
            else:
                continue
            if len(self.headers) > self.header_limit:
                raise ValueError("HTTP/2 header block limit")
            if flags & 4:
                pairs = self.decoder.decode(bytes(self.headers))
                if len(pairs) > self.field_limit:
                    raise ValueError("HTTP/2 header field limit")
                headers = dict(pairs)
                self.headers = self.stream = None
                if ":method" in headers:
                    self.emit(
                        {
                            "type": "http_request",
                            "protocol": "h2",
                            "stream_id": stream,
                            "method": headers.get(":method"),
                            "authority": headers.get(":authority"),
                            "path": headers.get(":path"),
                            "scheme": headers.get(":scheme"),
                        }
                    )


class Direction:
    def __init__(self, session, client):
        self.session, self.client = session, client
        self.buffer, self.handshakes = bytearray(), bytearray()
        self.pending = deque()
        self.pending_bytes = 0
        self.application = False
        self.sequence = 0
        self.secret = None
        self.http = (
            HTTP2(
                session.emit, session.limit, session.header_limit, session.field_limit
            )
            if client
            else None
        )
        self.generation = 0

    def feed(self, data):
        self.buffer.extend(data)
        if len(self.buffer) > self.session.limit:
            raise ValueError("TLS input limit")
        while len(self.buffer) >= 5:
            length = int.from_bytes(self.buffer[3:5], "big")
            if length > 16640:
                raise ValueError("TLS record limit")
            if len(self.buffer) < length + 5:
                break
            record = bytes(self.buffer[: length + 5])
            del self.buffer[: length + 5]
            self.pending.append((record, time.monotonic()))
            self.pending_bytes += len(record)
            if self.pending_bytes > self.session.limit:
                raise ValueError("waiting-for-keys buffer limit")
        self.pump()

    def pump(self):
        while self.pending:
            record, received = self.pending[0]
            outer = record[0]
            if outer == 22:
                self.handshake(record[5:])
            elif outer == 20:
                pass
            elif outer == 21:
                self.session.emit({"type": "tls_alert"})
            elif outer == 23:
                if not self.session.random or not self.session.suite:
                    return
                label = ("CLIENT" if self.client else "SERVER") + (
                    "_TRAFFIC_SECRET_0"
                    if self.application
                    else "_HANDSHAKE_TRAFFIC_SECRET"
                )
                if self.secret is None:
                    self.secret = self.session.secrets.get(
                        label, self.session.key_random or self.session.random
                    )
                if self.secret is None and not self.application and self.sequence == 0:
                    match = self.session.secrets.match_record(
                        label, self.session.suite, record
                    )
                    if match:
                        self.session.key_random, self.secret = match
                        self.session.emit(
                            {"type": "key_correlation", "method": "AEAD-authenticated"}
                        )
                if self.secret is None:
                    return
                random = self.session.key_random or self.session.random
                try:
                    plain = decrypt_record(
                        self.secret, self.session.suite, self.sequence, record
                    )
                except InvalidTag:
                    if self.sequence == 0 and self.session.secrets.reject_unverified(
                        label, random, self.secret
                    ):
                        self.secret = None
                        self.session.emit({"type": "invalid_secret"})
                        return
                    raise
                self.session.secrets.confirm(label, random, self.secret)
                self.sequence += 1
                end = len(plain) - 1
                while end >= 0 and plain[end] == 0:
                    end -= 1
                if end < 0:
                    raise ValueError("invalid TLS inner plaintext")
                inner, data = plain[end], plain[:end]
                self.session.last_record_received = received
                if inner == 22:
                    self.handshake(data, authenticated=True)
                elif inner == 23:
                    if not self.application:
                        raise ValueError("application data before Finished")
                    if self.http:
                        self.http.feed(data)
                elif inner != 21:
                    raise ValueError("unsupported TLS inner content type")
            else:
                raise ValueError("unsupported TLS record type")
            self.pending.popleft()
            self.pending_bytes -= len(record)

    def handshake(self, data, authenticated=False):
        self.handshakes.extend(data)
        if len(self.handshakes) > self.session.limit:
            raise ValueError("TLS handshake limit")
        while len(self.handshakes) >= 4:
            length = int.from_bytes(self.handshakes[1:4], "big")
            if length > self.session.limit - 4:
                raise ValueError("TLS handshake message limit")
            if len(self.handshakes) < length + 4:
                return
            kind, body = self.handshakes[0], bytes(self.handshakes[4 : length + 4])
            del self.handshakes[: length + 4]
            if kind == 1 and self.client:
                if len(body) < 35:
                    raise ValueError("truncated ClientHello")
                self.session.random = body[2:34].hex()
                self.session.secrets.observe(self.session.random)
            elif kind == 2 and not self.client:
                if len(body) < 38:
                    raise ValueError("truncated ServerHello")
                if (
                    body[2:34].hex()
                    == "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
                ):
                    raise ValueError(
                        "HelloRetryRequest not supported in this prototype"
                    )
                offset = 35 + body[34]
                suite = int.from_bytes(body[offset : offset + 2], "big")
                if suite not in (0x1301, 0x1302, 0x1303):
                    raise ValueError("only TLS 1.3 is supported")
                self.session.suite = suite
                self.session.emit(
                    {
                        "type": "tls_parameters",
                        "version": "TLS 1.3",
                        "cipher_suite": hex(suite),
                    }
                )
            elif kind == 20:
                if not authenticated or len(body) != (
                    48 if self.session.suite == 0x1302 else 32
                ):
                    raise ValueError("invalid TLS Finished")
                self.application, self.sequence, self.secret = True, 0, None
            elif kind == 24:
                if (
                    not authenticated
                    or not self.application
                    or len(body) != 1
                    or body[0] > 1
                    or self.secret is None
                ):
                    raise ValueError("invalid TLS KeyUpdate")
                digest = "sha384" if self.session.suite == 0x1302 else "sha256"
                self.secret = expand_label(
                    self.secret, b"traffic upd", len(self.secret), digest
                )
                self.sequence = 0
                self.generation += 1
                self.session.emit(
                    {
                        "type": "tls_key_update",
                        "direction": "client" if self.client else "server",
                        "generation": self.generation,
                    }
                )


class Session:
    def __init__(
        self, secrets, emit, buffer_limit=LIMIT, header_limit=16384, field_limit=64
    ):
        self.limit, self.header_limit, self.field_limit = (
            buffer_limit,
            header_limit,
            field_limit,
        )
        self.secrets, self.output = secrets, emit
        self.random = self.suite = self.key_random = None
        self.last_record_received = None
        self.failed = False
        self.lock = threading.Lock()
        self.client, self.server = Direction(self, True), Direction(self, False)

    def emit(self, event):
        if event["type"] == "http_request" and self.last_record_received is not None:
            event["decode_delay_ms"] = round(
                (time.monotonic() - self.last_record_received) * 1000, 3
            )
        self.output(event)

    def feed(self, client, data):
        with self.lock:
            if self.failed:
                return
            try:
                (self.client if client else self.server).feed(data)
                self.client.pump()
                self.server.pump()
            except InvalidTag:
                self.failed = True
                self.emit(
                    {
                        "type": "analysis_unavailable",
                        "reason": "AEAD authentication failed",
                    }
                )
            except Exception as error:
                self.failed = True
                self.emit(
                    {"type": "analysis_unavailable", "reason": type(error).__name__}
                )

    def retry(self):
        self.feed(True, b"")
