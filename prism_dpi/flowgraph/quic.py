"""Bounded QUIC Initial decryption for metadata-only ClientHello inspection."""

from __future__ import annotations

import hmac
from dataclasses import dataclass
from hashlib import sha256

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.exceptions import InvalidTag

from .events import TlsClientHello
from .tls import TlsRecord, parse_client_hello


QUIC_V1 = 0x00000001
QUIC_V2 = 0x6B3343CF
MAX_QUIC_DATAGRAM = 65_535
MAX_CRYPTO_BYTES = 16_384


@dataclass(frozen=True)
class QuicInitialHello:
    version: int
    destination_connection_id_length: int
    packet_number: int
    hello: TlsClientHello


@dataclass(frozen=True)
class QuicInitialCrypto:
    version: int
    destination_connection_id: bytes
    packet_number: int
    fragments: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True)
class _VersionProfile:
    initial_type: int
    salt: bytes
    key_label: str
    iv_label: str
    hp_label: str


_PROFILES = {
    QUIC_V1: _VersionProfile(
        initial_type=0,
        salt=bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
        key_label="quic key",
        iv_label="quic iv",
        hp_label="quic hp",
    ),
    QUIC_V2: _VersionProfile(
        initial_type=1,
        salt=bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
        key_label="quicv2 key",
        iv_label="quicv2 iv",
        hp_label="quicv2 hp",
    ),
}


def parse_quic_initial_client_hello(datagram: bytes) -> QuicInitialHello | None:
    initial = decrypt_quic_initial(datagram)
    if initial is None:
        return None
    crypto = _contiguous_crypto(initial.fragments)
    if crypto is None:
        return None
    hello = parse_client_hello(
        TlsRecord(
            content_type=22,
            legacy_version=b"\x03\x03",
            payload=crypto,
        )
    )
    if hello is None:
        return None
    return QuicInitialHello(
        version=initial.version,
        destination_connection_id_length=len(initial.destination_connection_id),
        packet_number=initial.packet_number,
        hello=hello,
    )


def decrypt_quic_initial(datagram: bytes) -> QuicInitialCrypto | None:
    if not 21 <= len(datagram) <= MAX_QUIC_DATAGRAM:
        return None
    first = datagram[0]
    if first & 0xC0 != 0xC0:
        return None
    version = int.from_bytes(datagram[1:5], "big")
    profile = _PROFILES.get(version)
    if profile is None or (first >> 4) & 0x03 != profile.initial_type:
        return None

    offset = 5
    destination_connection_id, offset = _read_length_prefixed_bytes(datagram, offset)
    if destination_connection_id is None or not destination_connection_id:
        return None
    source_connection_id, offset = _read_length_prefixed_bytes(datagram, offset)
    if source_connection_id is None:
        return None
    token_length, offset = _read_varint(datagram, offset)
    if token_length is None or token_length > len(datagram) - offset:
        return None
    offset += token_length
    protected_length, packet_number_offset = _read_varint(datagram, offset)
    if protected_length is None or protected_length < 17:
        return None
    packet_end = packet_number_offset + protected_length
    sample_offset = packet_number_offset + 4
    if packet_end > len(datagram) or sample_offset + 16 > packet_end:
        return None

    key, iv, hp = _derive_client_keys(version, destination_connection_id)
    mask = _aes_ecb_mask(hp, datagram[sample_offset : sample_offset + 16])
    unprotected_first = first ^ (mask[0] & 0x0F)
    packet_number_length = (unprotected_first & 0x03) + 1
    packet_number_end = packet_number_offset + packet_number_length
    if packet_number_end > packet_end:
        return None
    packet_number_bytes = bytes(
        datagram[packet_number_offset + index] ^ mask[index + 1]
        for index in range(packet_number_length)
    )
    packet_number = int.from_bytes(packet_number_bytes, "big")
    header = bytearray(datagram[:packet_number_end])
    header[0] = unprotected_first
    header[packet_number_offset:packet_number_end] = packet_number_bytes
    nonce = _packet_nonce(iv, packet_number)
    try:
        plaintext = AESGCM(key).decrypt(
            nonce,
            datagram[packet_number_end:packet_end],
            bytes(header),
        )
    except InvalidTag:
        return None

    fragments = _crypto_fragments(plaintext)
    if not fragments:
        return None
    return QuicInitialCrypto(
        version=version,
        destination_connection_id=destination_connection_id,
        packet_number=packet_number,
        fragments=fragments,
    )


def _derive_client_keys(version: int, destination_connection_id: bytes) -> tuple[bytes, bytes, bytes]:
    profile = _PROFILES[version]
    initial_secret = hmac.new(profile.salt, destination_connection_id, sha256).digest()
    client_secret = _hkdf_expand_label(initial_secret, "client in", 32)
    return (
        _hkdf_expand_label(client_secret, profile.key_label, 16),
        _hkdf_expand_label(client_secret, profile.iv_label, 12),
        _hkdf_expand_label(client_secret, profile.hp_label, 16),
    )


def _hkdf_expand_label(secret: bytes, label: str, length: int) -> bytes:
    encoded_label = b"tls13 " + label.encode("ascii")
    info = (
        length.to_bytes(2, "big")
        + bytes((len(encoded_label),))
        + encoded_label
        + b"\x00"
    )
    return HKDFExpand(
        algorithm=hashes.SHA256(),
        length=length,
        info=info,
    ).derive(secret)


def _aes_ecb_mask(key: bytes, sample: bytes) -> bytes:
    # QUIC v1 header protection applies AES-ECB to exactly one sample block.
    # It is a protocol-defined mask primitive, never payload encryption.
    encryptor = Cipher(
        algorithms.AES(key),
        modes.ECB(),  # nosec B305
    ).encryptor()
    return encryptor.update(sample) + encryptor.finalize()


def _packet_nonce(iv: bytes, packet_number: int) -> bytes:
    encoded = packet_number.to_bytes(len(iv), "big")
    return bytes(left ^ right for left, right in zip(iv, encoded, strict=True))


def _read_length_prefixed_bytes(data: bytes, offset: int) -> tuple[bytes | None, int]:
    if offset >= len(data):
        return None, offset
    length = data[offset]
    offset += 1
    end = offset + length
    if end > len(data):
        return None, offset
    return data[offset:end], end


def _read_varint(data: bytes, offset: int) -> tuple[int | None, int]:
    if offset >= len(data):
        return None, offset
    length = 1 << (data[offset] >> 6)
    end = offset + length
    if end > len(data):
        return None, offset
    value = data[offset] & 0x3F
    for byte in data[offset + 1 : end]:
        value = (value << 8) | byte
    return value, end


def _crypto_fragments(payload: bytes) -> tuple[tuple[int, bytes], ...]:
    fragments: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(payload):
        frame_type, offset = _read_varint(payload, offset)
        if frame_type is None:
            return ()
        if frame_type == 0x00:
            continue
        if frame_type == 0x01:
            continue
        if frame_type in (0x02, 0x03):
            parsed_offset = _skip_ack_frame(payload, offset, ecn=frame_type == 0x03)
            if parsed_offset is None:
                return ()
            offset = parsed_offset
            continue
        if frame_type != 0x06:
            break
        crypto_offset, offset = _read_varint(payload, offset)
        crypto_length, offset = _read_varint(payload, offset)
        if crypto_offset is None or crypto_length is None:
            return ()
        end = offset + crypto_length
        if crypto_length > MAX_CRYPTO_BYTES or end > len(payload):
            return ()
        fragments.append((crypto_offset, payload[offset:end]))
        offset = end

    return tuple(fragments)


def _contiguous_crypto(fragments: tuple[tuple[int, bytes], ...]) -> bytes | None:
    by_offset = dict(fragments)
    output = bytearray()
    while len(output) in by_offset:
        output.extend(by_offset[len(output)])
        if len(output) > MAX_CRYPTO_BYTES:
            return None
    return bytes(output) if output else None


def _skip_ack_frame(payload: bytes, offset: int, *, ecn: bool) -> int | None:
    values: list[int] = []
    for _ in range(4):
        value, offset = _read_varint(payload, offset)
        if value is None:
            return None
        values.append(value)
    ack_range_count = values[2]
    if ack_range_count > 256:
        return None
    for _ in range(ack_range_count * 2 + (3 if ecn else 0)):
        value, offset = _read_varint(payload, offset)
        if value is None:
            return None
    return offset


__all__ = [
    "QUIC_V1",
    "QUIC_V2",
    "QuicInitialCrypto",
    "QuicInitialHello",
    "decrypt_quic_initial",
    "parse_quic_initial_client_hello",
]
