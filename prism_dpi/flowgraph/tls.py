"""Strict TLS metadata parsing without payload decryption or retention."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .events import TlsClientHello


TLS_CONTENT_TYPES = frozenset((20, 21, 22, 23))
MAX_TLS_RECORD_LENGTH = 18_432
GREASE_VALUES = frozenset(0x0A0A + (0x1010 * index) for index in range(16))


@dataclass(frozen=True)
class TlsRecord:
    content_type: int
    legacy_version: bytes
    payload: bytes

    @property
    def length(self) -> int:
        return len(self.payload)


class TlsRecordDecoder:
    """Incrementally decode a bounded TLS byte stream."""

    def __init__(self, *, max_buffer: int = 65_536) -> None:
        self._buffer = bytearray()
        self._max_buffer = max_buffer
        self._invalid = False

    @property
    def invalid(self) -> bool:
        return self._invalid

    def feed(self, data: bytes) -> list[TlsRecord]:
        if self._invalid or not data:
            return []
        if len(self._buffer) + len(data) > self._max_buffer:
            self._invalid = True
            self._buffer.clear()
            return []
        self._buffer.extend(data)
        records: list[TlsRecord] = []
        while len(self._buffer) >= 5:
            content_type = self._buffer[0]
            legacy_version = bytes(self._buffer[1:3])
            length = int.from_bytes(self._buffer[3:5], "big")
            if (
                content_type not in TLS_CONTENT_TYPES
                or legacy_version[0] != 3
                or length > MAX_TLS_RECORD_LENGTH
            ):
                self._invalid = True
                self._buffer.clear()
                break
            record_end = 5 + length
            if len(self._buffer) < record_end:
                break
            payload = bytes(self._buffer[5:record_end])
            del self._buffer[:record_end]
            records.append(TlsRecord(content_type, legacy_version, payload))
        return records


def parse_client_hello(record: TlsRecord) -> TlsClientHello | None:
    if record.content_type != 22 or len(record.payload) < 4 or record.payload[0] != 1:
        return None
    handshake_length = int.from_bytes(record.payload[1:4], "big")
    if handshake_length + 4 > len(record.payload):
        return None
    hello = record.payload[4 : 4 + handshake_length]
    if len(hello) < 38:
        return None

    offset = 34
    session_id_length = hello[offset]
    offset += 1 + session_id_length
    if offset + 2 > len(hello):
        return None
    cipher_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2
    if cipher_length % 2 or offset + cipher_length > len(hello):
        return None
    ciphers = tuple(
        int.from_bytes(hello[index : index + 2], "big")
        for index in range(offset, offset + cipher_length, 2)
    )
    offset += cipher_length
    if offset >= len(hello):
        return None
    compression_length = hello[offset]
    offset += 1 + compression_length
    if offset + 2 > len(hello):
        return None
    extensions_length = int.from_bytes(hello[offset : offset + 2], "big")
    offset += 2
    extensions_end = offset + extensions_length
    if extensions_end > len(hello):
        return None

    server_name = ""
    alpn: tuple[str, ...] = ()
    extension_ids: list[int] = []
    psk_identity_lengths: tuple[int, ...] = ()
    psk_binder_lengths: tuple[int, ...] = ()
    key_share_groups: tuple[int, ...] = ()
    supported_versions: tuple[int, ...] = ()
    while offset + 4 <= extensions_end:
        extension_type = int.from_bytes(hello[offset : offset + 2], "big")
        extension_length = int.from_bytes(hello[offset + 2 : offset + 4], "big")
        offset += 4
        extension_end = offset + extension_length
        if extension_end > extensions_end:
            return None
        extension = hello[offset:extension_end]
        extension_ids.append(extension_type)
        if extension_type == 0:
            server_name = _parse_sni(extension)
        elif extension_type == 16:
            alpn = _parse_alpn(extension)
        elif extension_type == 41:
            parsed_psk = _parse_pre_shared_key(extension)
            if parsed_psk is None:
                return None
            psk_identity_lengths, psk_binder_lengths = parsed_psk
        elif extension_type == 43:
            supported_versions = _parse_u16_vector(extension, one_byte_length=True)
        elif extension_type == 51:
            key_share_groups = _parse_key_share_groups(extension)
        offset = extension_end

    if not server_name:
        return None
    normalized_ciphers = tuple(value for value in ciphers if value not in GREASE_VALUES)
    normalized_extensions = tuple(
        value for value in extension_ids if value not in GREASE_VALUES
    )
    material = (
        ",".join(map(str, normalized_ciphers))
        + "|"
        + ",".join(map(str, normalized_extensions))
        + "|"
        + ",".join(alpn)
    ).encode("ascii")
    fingerprint = hashlib.sha256(material).hexdigest()[:16]
    lineage_material = (
        material
        + b"|sid="
        + str(session_id_length).encode("ascii")
        + b"|psk="
        + ",".join(map(str, psk_identity_lengths)).encode("ascii")
        + b"|binders="
        + ",".join(map(str, psk_binder_lengths)).encode("ascii")
        + b"|shares="
        + ",".join(map(str, key_share_groups)).encode("ascii")
        + b"|versions="
        + ",".join(map(str, supported_versions)).encode("ascii")
    )
    lineage_fingerprint = hashlib.sha256(lineage_material).hexdigest()[:16]
    return TlsClientHello(
        server_name=server_name,
        record_length=record.length,
        fingerprint=fingerprint,
        alpn=alpn,
        extension_ids=normalized_extensions,
        session_id_length=session_id_length,
        psk_identity_lengths=psk_identity_lengths,
        psk_binder_lengths=psk_binder_lengths,
        key_share_groups=key_share_groups,
        supported_versions=supported_versions,
        lineage_fingerprint=lineage_fingerprint,
    )


def _parse_sni(extension: bytes) -> str:
    if len(extension) < 5:
        return ""
    list_length = int.from_bytes(extension[:2], "big")
    if list_length + 2 != len(extension):
        return ""
    offset = 2
    while offset + 3 <= len(extension):
        name_type = extension[offset]
        name_length = int.from_bytes(extension[offset + 1 : offset + 3], "big")
        offset += 3
        name_end = offset + name_length
        if name_end > len(extension):
            return ""
        if name_type == 0:
            try:
                name = extension[offset:name_end].decode("ascii").lower().rstrip(".")
            except UnicodeDecodeError:
                return ""
            if name and len(name) <= 253:
                return name
        offset = name_end
    return ""


def _parse_alpn(extension: bytes) -> tuple[str, ...]:
    if len(extension) < 2:
        return ()
    list_length = int.from_bytes(extension[:2], "big")
    if list_length + 2 != len(extension):
        return ()
    values: list[str] = []
    offset = 2
    while offset < len(extension):
        length = extension[offset]
        offset += 1
        end = offset + length
        if end > len(extension):
            return ()
        try:
            values.append(extension[offset:end].decode("ascii"))
        except UnicodeDecodeError:
            return ()
        offset = end
    return tuple(values)


def _parse_pre_shared_key(
    extension: bytes,
) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    if len(extension) < 4:
        return None
    identities_length = int.from_bytes(extension[:2], "big")
    identities_end = 2 + identities_length
    if identities_end + 2 > len(extension):
        return None
    identity_lengths: list[int] = []
    offset = 2
    while offset < identities_end:
        if offset + 2 > identities_end:
            return None
        identity_length = int.from_bytes(extension[offset : offset + 2], "big")
        offset += 2
        identity_end = offset + identity_length
        if identity_end + 4 > identities_end:
            return None
        identity_lengths.append(identity_length)
        offset = identity_end + 4
    binders_length = int.from_bytes(
        extension[identities_end : identities_end + 2], "big"
    )
    offset = identities_end + 2
    binders_end = offset + binders_length
    if binders_end != len(extension):
        return None
    binder_lengths: list[int] = []
    while offset < binders_end:
        binder_length = extension[offset]
        offset += 1
        binder_end = offset + binder_length
        if binder_end > binders_end:
            return None
        binder_lengths.append(binder_length)
        offset = binder_end
    if not identity_lengths or len(identity_lengths) != len(binder_lengths):
        return None
    return tuple(identity_lengths), tuple(binder_lengths)


def _parse_u16_vector(
    value: bytes, *, one_byte_length: bool = False
) -> tuple[int, ...]:
    prefix = 1 if one_byte_length else 2
    if len(value) < prefix:
        return ()
    length = value[0] if one_byte_length else int.from_bytes(value[:2], "big")
    if length % 2 or prefix + length != len(value):
        return ()
    return tuple(
        item
        for offset in range(prefix, len(value), 2)
        if (item := int.from_bytes(value[offset : offset + 2], "big"))
        not in GREASE_VALUES
    )


def _parse_key_share_groups(extension: bytes) -> tuple[int, ...]:
    if len(extension) < 2:
        return ()
    shares_length = int.from_bytes(extension[:2], "big")
    if shares_length + 2 != len(extension):
        return ()
    groups: list[int] = []
    offset = 2
    while offset < len(extension):
        if offset + 4 > len(extension):
            return ()
        group = int.from_bytes(extension[offset : offset + 2], "big")
        key_length = int.from_bytes(extension[offset + 2 : offset + 4], "big")
        offset += 4
        key_end = offset + key_length
        if key_end > len(extension):
            return ()
        if group not in GREASE_VALUES:
            groups.append(group)
        offset = key_end
    return tuple(groups)


__all__ = ["TlsRecord", "TlsRecordDecoder", "parse_client_hello"]
