"""Shared transport-signature types for Prism DPI.

Prism emits kernel matchers from typed observations. Policy remains explicit:
active app modules may drop matches, while shadow modules only count them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AppSignature:
    app: str                 # label, e.g. "whatsapp" — also the feature that activates it
    ports: tuple[int, ...]   # destination ports the signature applies to
    prefix: bytes            # first payload bytes, anchored at offset 0 (1..4 bytes)
    note: str = ""

    def __post_init__(self) -> None:
        if not 1 <= len(self.prefix) <= 4:
            raise ValueError("signature prefix must be 1..4 bytes")

    def u32_expr(self) -> str:
        """An iptables ``-m u32`` expression matching ``prefix`` at the TCP payload start.

        ``0>>22&0x3C`` = IP header length → jump to TCP header; ``12>>26&0x3C`` =
        TCP data offset → jump to the TCP payload; then compare its leading bytes.
        """
        n = len(self.prefix)
        val = int.from_bytes(self.prefix, "big")
        shift = (4 - n) * 8
        word = f"0>>{shift}" if shift else "0"
        return f"0>>22&0x3C@12>>26&0x3C@{word}=0x{val:0{n * 2}X}"


@dataclass(frozen=True)
class HttpHostSignature:
    """A cleartext HTTP request line and Host header on a fixed port."""

    app: str
    port: int
    request_line: str
    host: str
    note: str = ""

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("signature port must be 1..65535")
        for value in (self.request_line, self.host):
            if not value or any(char in value for char in ("\r", "\n", "\t", "\0")):
                raise ValueError("HTTP signature fields must be non-empty single-line strings")

    @property
    def patterns(self) -> tuple[str, str]:
        return self.request_line, f"Host: {self.host}"

    def matches(self, payload: bytes) -> bool:
        request_line, host_header = (pattern.encode("ascii") for pattern in self.patterns)
        return payload.startswith(request_line + b"\r\n") and (
            b"\r\n" + host_header + b"\r\n"
        ) in payload


@dataclass(frozen=True)
class TlsClientHelloSignature:
    """A TLS ClientHello record shape with an exact SNI allowlist."""

    app: str
    ports: tuple[int, ...]
    record_length: int
    server_names: tuple[str, ...]
    record_version: bytes = b"\x03\x01"
    note: str = ""

    def __post_init__(self) -> None:
        if not self.app:
            raise ValueError("signature app must be non-empty")
        if not self.ports or any(not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("signature ports must be 1..65535")
        if not 1 <= self.record_length <= 65535:
            raise ValueError("TLS record length must be 1..65535")
        if len(self.record_version) != 2:
            raise ValueError("TLS record version must be exactly two bytes")
        if not self.server_names:
            raise ValueError("TLS signature requires at least one server name")
        for server_name in self.server_names:
            try:
                encoded = server_name.encode("ascii")
            except UnicodeEncodeError as exc:
                raise ValueError("TLS server names must be ASCII") from exc
            if (
                not encoded
                or len(encoded) > 253
                or server_name != server_name.lower()
                or server_name.startswith(".")
                or server_name.endswith(".")
                or ".." in server_name
                or any(char not in "abcdefghijklmnopqrstuvwxyz0123456789-." for char in server_name)
            ):
                raise ValueError("TLS server names must be exact lowercase DNS names")

    def u32_expr(self) -> str:
        """Match the TLS handshake record header at the TCP payload start."""
        header = b"\x16" + self.record_version + self.record_length.to_bytes(2, "big")
        first_word = int.from_bytes(header[:4], "big")
        return (
            f"0>>22&0x3C@12>>26&0x3C@0=0x{first_word:08X}"
            f"&&0>>22&0x3C@12>>26&0x3C@4>>24=0x{header[4]:02X}"
        )

    @staticmethod
    def sni_hex_pattern(server_name: str) -> str:
        """Return an xt_string hex pattern for one complete SNI extension."""
        host = server_name.encode("ascii")
        name = b"\x00" + len(host).to_bytes(2, "big") + host
        name_list = len(name).to_bytes(2, "big") + name
        extension = b"\x00\x00" + len(name_list).to_bytes(2, "big") + name_list
        return f"|{extension.hex()}|"

    def matches(self, payload: bytes) -> bool:
        """Parse the first TLS record and match an exact SNI name."""
        if len(payload) < 9 or payload[0] != 0x16:
            return False
        if payload[1:3] != self.record_version:
            return False
        record_length = int.from_bytes(payload[3:5], "big")
        if record_length != self.record_length or len(payload) < 5 + record_length:
            return False

        record = payload[5 : 5 + record_length]
        if record[0] != 0x01:
            return False
        handshake_length = int.from_bytes(record[1:4], "big")
        if handshake_length + 4 > len(record):
            return False
        hello = record[4 : 4 + handshake_length]
        if len(hello) < 38:
            return False

        offset = 34
        session_id_length = hello[offset]
        offset += 1 + session_id_length
        if offset + 2 > len(hello):
            return False
        cipher_length = int.from_bytes(hello[offset : offset + 2], "big")
        offset += 2 + cipher_length
        if offset + 1 > len(hello):
            return False
        compression_length = hello[offset]
        offset += 1 + compression_length
        if offset + 2 > len(hello):
            return False
        extensions_length = int.from_bytes(hello[offset : offset + 2], "big")
        offset += 2
        extensions_end = offset + extensions_length
        if extensions_end > len(hello):
            return False

        expected = {server_name.encode("ascii") for server_name in self.server_names}
        while offset + 4 <= extensions_end:
            extension_type = int.from_bytes(hello[offset : offset + 2], "big")
            extension_length = int.from_bytes(hello[offset + 2 : offset + 4], "big")
            offset += 4
            extension_end = offset + extension_length
            if extension_end > extensions_end:
                return False
            if extension_type == 0:
                return self._sni_extension_matches(hello[offset:extension_end], expected)
            offset = extension_end
        return False

    @staticmethod
    def _sni_extension_matches(extension: bytes, expected: set[bytes]) -> bool:
        if len(extension) < 2:
            return False
        list_length = int.from_bytes(extension[:2], "big")
        if list_length + 2 != len(extension):
            return False
        offset = 2
        while offset + 3 <= len(extension):
            name_type = extension[offset]
            name_length = int.from_bytes(extension[offset + 1 : offset + 3], "big")
            offset += 3
            name_end = offset + name_length
            if name_end > len(extension):
                return False
            if name_type == 0 and extension[offset:name_end].lower() in expected:
                return True
            offset = name_end
        return False
