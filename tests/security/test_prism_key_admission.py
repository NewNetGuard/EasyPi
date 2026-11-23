"""Generated TLS traffic verifies bounded, authenticated key admission."""

import datetime
import os
import ssl
from dataclasses import replace
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from hpack import Encoder
from prism_tls_bridge.bridge import Bridge
from prism_tls_bridge.models import Endpoint, Limits, Provenance
from prism_tls_bridge.tls import HTTP2, LABELS, Secrets

P = Provenance(
    "managed-client", "generated-capture", "authorized-source", "endpoint-origin", True
)


def trace(directory):
    directory.mkdir()
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
        .sign(key, hashes.SHA256())
    )
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.minimum_version = server.maximum_version = ssl.TLSVersion.TLSv1_3
    server.load_cert_chain(directory / "cert.pem", directory / "key.pem")
    server.set_alpn_protocols(["h2"])
    client = ssl.create_default_context(cafile=str(directory / "cert.pem"))
    client.minimum_version = client.maximum_version = ssl.TLSVersion.TLSv1_3
    client.set_alpn_protocols(["h2"])
    client.keylog_filename = str(directory / "keys.log")
    ci, co, si, so = [ssl.MemoryBIO() for _ in range(4)]
    c = client.wrap_bio(ci, co, server_hostname="localhost")
    s = server.wrap_bio(si, so, server_side=True)
    finished = [False, False]
    records = []
    for _ in range(20):
        for i, end in enumerate((c, s)):
            try:
                end.do_handshake()
                finished[i] = True
            except ssl.SSLWantReadError:
                pass
        for source, dest, direction in ((co, si, True), (so, ci, False)):
            data = source.read()
            if data:
                records.append((direction, data))
                dest.write(data)
        if all(finished):
            break
    assert all(finished) and c.selected_alpn_protocol() == "h2"
    data = HTTP2.PREFACE
    encoder = Encoder()
    for stream in (1, 3):
        block = encoder.encode(
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":authority", "localhost"),
                (":path", "/managed-probe"),
            ]
        )
        data += (
            len(block).to_bytes(3, "big")
            + bytes([1, 4])
            + stream.to_bytes(4, "big")
            + block
        )
    c.write(data)
    records.append((True, co.read()))
    lines = [
        line
        for line in (directory / "keys.log").read_text().splitlines()
        if line.split() and line.split()[0] in LABELS
    ]
    return records, lines


def opened(limits=None):
    b = Bridge(limits)
    assert b.open_flow(
        "flow", "tcp", P, Endpoint("192.0.2.10", 50000), Endpoint("198.51.100.20", 443)
    )
    for client, seq in ((True, 100), (False, 200)):
        b.feed_tcp("flow", client, seq, b"", P.capture_point, syn=True)
    return b


def deliver(b, records, positions=None):
    positions = positions or {True: 101, False: 201}
    for client, data in records:
        b.feed_tcp("flow", client, positions[client], data, P.capture_point)
        positions[client] += len(data)
    return positions


def add(b, lines):
    return [b.add_key("flow", line, P) for line in lines]


def test_correct_late_group_survives_full_unverified_store(tmp_path):
    records, keys = trace(tmp_path / "actual")
    others = [trace(tmp_path / str(i))[1] for i in range(3)]
    b = opened()
    try:
        for lines in others:
            add(b, lines)
        assert all(add(b, keys))
        deliver(b, records)
        events = b.drain_events()
        assert len(events) == 2 and {e["request"]["stream_id"] for e in events} == {
            1,
            3,
        }
        assert b.metrics()["retained_keys"] <= 8
        assert b.metrics()["key_store_full"] > 0
    finally:
        b.close()


def test_wire_session_reserved_then_authenticated_keys_pinned(tmp_path):
    records, keys = trace(tmp_path / "actual")
    foreign = trace(tmp_path / "foreign")[1]
    b = opened()
    try:
        positions = deliver(b, records[:1])
        add(b, keys)
        for _ in range(5):
            add(b, foreign)
        deliver(b, records[1:], positions)
        assert len(b.drain_events()) == 2
        assert not any(add(b, foreign))
        assert b.status("flow").state.value == "Decrypted"
        assert b.metrics()["retained_keys"] == 4
    finally:
        b.close()


def test_invalid_value_can_be_replaced_without_poisoning_session(tmp_path):
    records, keys = trace(tmp_path / "actual")
    b = opened()
    try:
        deliver(b, records)
        wrong = []
        for line in keys:
            fields = line.split()
            fields[2] = os.urandom(len(fields[2]) // 2).hex()
            wrong.append(" ".join(fields))
        add(b, wrong)
        assert b.drain_events() == []
        assert b.status("flow").diagnostic == "invalid_secret"
        add(b, keys)
        assert len(b.drain_events()) == 2
        assert b.status("flow").diagnostic == "none"
    finally:
        b.close()


def test_aead_binding_preserves_ech_identifier_fallback(tmp_path):
    records, keys = trace(tmp_path / "actual")
    inner = os.urandom(32).hex()
    changed = []
    for line in keys:
        f = line.split()
        f[1] = inner
        changed.append(" ".join(f))
    b = opened()
    try:
        deliver(b, records)
        add(b, changed)
        assert len(b.drain_events()) == 2
        assert b.flows["flow"].secrets.bound_random == inner
    finally:
        b.close()


def test_source_and_capture_loss_diagnostics_remain_distinct(tmp_path):
    _, keys = trace(tmp_path / "actual")
    b = opened()
    wrong = Provenance(
        "different-client", P.capture_point, P.key_source, P.tls_leg, True
    )
    try:
        assert not b.add_key("flow", keys[0], wrong)
        assert b.metrics()["retained_keys"] == 0
        assert b.status("flow").diagnostic == "missing_key"
        b.report_loss("flow", P.capture_point)
        assert b.status("flow").diagnostic == "capture_loss"
    finally:
        b.close()


def test_explicit_insufficient_key_budget_is_visible(tmp_path):
    _, keys = trace(tmp_path / "actual")
    b = opened(replace(Limits(), max_keys=1))
    try:
        b.flows["flow"].secrets.observe(keys[0].split()[1])
        assert b.add_key("flow", keys[0], P)
        assert not b.add_key("flow", keys[1], P)
        assert b.status("flow").diagnostic == "key_store_full"
        assert b.metrics()["retained_keys"] == 1
    finally:
        b.close()


def test_quic_candidate_rotation_retries_at_unchanged_count():
    pytest.importorskip("aioquic")
    from aioquic.buffer import Buffer
    from aioquic.quic.crypto import CryptoContext
    from aioquic.quic.packet import QuicProtocolVersion
    from aioquic.tls import CipherSuite
    import pylsqpack
    from prism_tls_bridge.quic import AdaptiveQUICSession

    def integer(v):
        b = Buffer(capacity=8)
        b.push_uint_var(v)
        return b.data

    secret = os.urandom(32)
    _, block = pylsqpack.Encoder().encode(
        0,
        [
            (b":method", b"GET"),
            (b":scheme", b"https"),
            (b":authority", b"example.test"),
            (b":path", b"/managed-probe"),
        ],
    )
    data = integer(1) + integer(len(block)) + block
    plain = integer(11) + integer(0) + integer(len(data)) + data
    plain += bytes(max(0, 24 - len(plain)))
    crypto = CryptoContext()
    crypto.setup(
        cipher_suite=CipherSuite.AES_128_GCM_SHA256,
        secret=secret,
        version=QuicProtocolVersion.VERSION_1,
    )
    packet = crypto.encrypt_packet(b"\x43" + bytes(range(20)) + bytes(4), plain, 0)
    store = Secrets(1, scoped=True)
    events = []
    decoder = AdaptiveQUICSession(store, events.append)
    store.add(
        "CLIENT_TRAFFIC_SECRET_0 " + os.urandom(32).hex() + " " + os.urandom(32).hex()
    )
    decoder.feed(packet)
    assert decoder.crypto is None
    store.add("CLIENT_TRAFFIC_SECRET_0 " + os.urandom(32).hex() + " " + secret.hex())
    decoder.retry()
    assert len([e for e in events if e["type"] == "http_request"]) == 1
    assert store.bound_random is not None


def test_authenticated_source_session_filters_noise_before_capture(tmp_path):
    records, keys = trace(tmp_path / "actual")
    foreign = trace(tmp_path / "foreign")[1]
    b = Bridge()
    try:
        assert b.open_flow(
            "flow",
            "tcp",
            P,
            Endpoint("192.0.2.10", 50000),
            Endpoint("198.51.100.20", 443),
            key_session_id=keys[0].split()[1],
        )
        assert all(add(b, keys))
        for _ in range(8):
            assert not any(add(b, foreign))
        assert b.metrics()["retained_keys"] == 4
        assert b.metrics()["unrelated_session"] == 32
        assert b.flows["flow"].secrets.bound_random is None
        for client, sequence in ((True, 100), (False, 200)):
            b.feed_tcp("flow", client, sequence, b"", P.capture_point, syn=True)
        deliver(b, records)
        assert len(b.drain_events()) == 2
    finally:
        b.close()
