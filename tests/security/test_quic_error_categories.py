"""Generated AEAD-protected fixtures only. No captured browsing or key files."""
import json
import os
from dataclasses import replace

import pytest
import pylsqpack
from aioquic.buffer import Buffer
from aioquic.quic.crypto import CryptoContext, CryptoError
from aioquic.quic.packet import QuicProtocolVersion
from aioquic.tls import CipherSuite

from prism_tls_bridge.decode_errors import DecodeError, safe_error_code
from prism_tls_bridge.models import Limits
from prism_tls_bridge.quic import AdaptiveQUICSession
from prism_tls_bridge.tls import Secrets
from prism_tls_bridge.bridge import Bridge
from prism_tls_bridge.models import Endpoint, Provenance, InspectionState


def integer(value):
    b = Buffer(capacity=16)
    b.push_uint_var(value)
    return b.data


def stream(number, data, offset=0):
    return integer(14) + integer(number) + integer(offset) + integer(len(data)) + data


def protected(secret, data, number=0):
    context = CryptoContext()
    context.setup(cipher_suite=CipherSuite.AES_128_GCM_SHA256, secret=secret, version=QuicProtocolVersion.VERSION_1)
    try:
        header = b"\x43" + bytes(range(20)) + number.to_bytes(4, "big")
        return context.encrypt_packet(header, data + bytes(max(0, 24-len(data))), number)
    finally:
        context.teardown()


def decoder(limits=None, keys=True):
    secret = os.urandom(32)
    store = Secrets()
    if keys:
        store.add("CLIENT_TRAFFIC_SECRET_0 " + os.urandom(32).hex() + " " + secret.hex())
    output = []
    value = AdaptiveQUICSession(store, output.append, limits=limits or Limits())
    return value, secret, output


@pytest.mark.parametrize("plain,code", [
    (integer(31), "frame.unsupported"),
    (integer(10)+integer(0)+integer(100)+b"x", "frame.truncated"),
    (stream(0,b"\x01\x02\x00\x80"), "qpack.invalid_field"),
    (stream(0,b"\x01\x01\x00"), "qpack.truncated"),
    (stream(0,b"x",16384), "limits.stream_bytes"),
    (integer(2)+integer(0)+integer(0)+integer(257)+integer(0), "limits.ack_ranges"),
])
def test_authenticated_packets_fail_with_fixed_codes(plain, code):
    value, secret, output = decoder()
    value.feed(protected(secret, plain))
    assert value.authenticated_packets == 1
    assert value.failed
    event = output[-1]
    assert event["error_code"] == code
    assert event["error_category"] == code.split(".")[0]
    assert secret.hex() not in json.dumps(output)
    assert not any(e["type"] == "http_request" for e in output)


def test_stream_reassembly_conflict_is_not_aead_failure():
    value, secret, output = decoder()
    value.feed(protected(secret,stream(2,b"\x21"),0))
    value.feed(protected(secret,stream(2,b"\x22"),1))
    assert value.authenticated_packets == 2
    assert output[-1]["error_code"] == "stream.conflicting_retransmission"


def test_stream_and_packet_limits_remain_enforced():
    value, secret, output = decoder()
    for i in range(9):
        value.feed(protected(secret,stream(2+4*i,b"\x21"),i))
    assert output[-1]["error_code"] == "limits.stream_count"
    value, secret, output = decoder(replace(Limits(),max_packets=2))
    for i in range(3):
        value.feed(protected(secret,b"\x01",i))
    assert output[-1]["error_code"] == "limits.packet_count"


def test_pending_limit_and_malformed_packet_have_distinct_codes():
    value, _, output = decoder(replace(Limits(),decoder_buffer_bytes=16),keys=False)
    value.feed(b"x"*17)
    assert output[-1]["error_code"] == "limits.pending_bytes"
    value, _, output = decoder()
    value.feed(b"\xc0")
    assert output[-1]["error_code"] == "reassembly.malformed_header"


def test_established_crypto_authentication_error_is_sanitized():
    value, secret, output = decoder()
    value.feed(protected(secret,b"\x01",0))
    assert value.authenticated_packets == 1
    damaged = bytearray(protected(secret,b"\x01",1));damaged[-1] ^= 1
    value.feed(bytes(damaged))
    assert output[-1]["error_code"] == "aead.authentication_failed"
    assert secret.hex() not in json.dumps(output)


def test_wrong_unverified_candidate_is_not_declared_a_bad_key():
    value, _, output = decoder()
    value.feed(protected(os.urandom(32),b"\x01"))
    assert not value.failed and not value.authenticated_packets
    assert value.timeout_code() == "timeouts.no_authenticated_packet"
    assert not any(e["type"] == "http_request" for e in output)


def test_timeout_stages_are_evidence_based():
    value, secret, _ = decoder(keys=False)
    assert value.timeout_code() == "timeouts.missing_key"
    value, secret, _ = decoder()
    value.feed(protected(secret,b"\x01"))
    assert value.timeout_code() == "timeouts.headers"
    value.guard.buffer.extend(b"\xff")
    assert value.timeout_code() == "timeouts.qpack"
    value.guard.buffer.clear()
    value.stream(2,1,b"\x21")
    assert value.timeout_code() == "timeouts.stream_gap"


def test_exception_text_is_never_serialized():
    private = "private-key-cookie-url-token"
    value, _, output = decoder()
    value.decode_stage = "qpack"
    value.fail(ValueError(private))
    assert private not in json.dumps(output)
    assert output[-1]["error_code"] == "qpack.invalid_field"
    assert safe_error_code(DecodeError(private),"packet") == "frame.internal"
    assert safe_error_code(CryptoError(private),"packet") == "aead.authentication_failed"


def test_correct_qpack_still_recovers_authenticated_headers():
    value, secret, output = decoder()
    encoder = pylsqpack.Encoder()
    _, block = encoder.encode(0, [(b":method",b"GET"),(b":scheme",b"https"),
        (b":authority",b"example.test"),(b":path",b"/owned-test")])
    h3 = integer(1)+integer(len(block))+block
    value.feed(protected(secret,stream(0,h3)))
    assert not value.failed and value.authenticated_packets == 1
    assert sum(e["type"] == "http_request" for e in output) == 1


@pytest.mark.parametrize("mode,code", [
    ("frame", "frame.unsupported"),
    ("qpack", "qpack.invalid_field"),
    ("missing", "timeouts.missing_key"),
    ("wrong_candidate", "timeouts.no_authenticated_packet"),
    ("no_headers", "timeouts.headers"),
    ("qpack_wait", "timeouts.qpack"),
    ("stream_gap", "timeouts.stream_gap"),
    ("table_capacity", "limits.qpack_table_capacity"),
])
def test_bridge_preserves_typed_failure_and_timeout_evidence(mode, code):
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    now = [0.0]
    bridge = Bridge(clock=lambda: now[0])
    provenance = Provenance("test-device", "test-capture", "test-source", "endpoint", True)
    random, secret = os.urandom(32).hex(), os.urandom(32)
    try:
        bridge.open_flow("test", "quic", provenance, Endpoint("192.0.2.1",50000),
                         Endpoint("192.0.2.2",443), key_session_id=random)
        client = QuicConnection(configuration=QuicConfiguration(is_client=True, server_name="example.test"))
        client.connect(("192.0.2.2",443), now=0)
        initial = client.datagrams_to_send(now=0)[0][0]
        bridge.feed_udp("test",True,initial,provenance.capture_point)
        if mode != "missing":
            candidate = os.urandom(32) if mode == "wrong_candidate" else secret
            bridge.add_key("test","CLIENT_TRAFFIC_SECRET_0 "+random+" "+candidate.hex(),provenance)
        plain = {
            "frame": integer(31),
            "qpack": stream(0,b"\x01\x02\x00\x80"),
            "qpack_wait": stream(0,b"\x01\x02\x02\x00"),
            "stream_gap": stream(2,b"\x21",1),
            "table_capacity": stream(2,b"\x02\x3f\xe2\xff\x03"),
        }.get(mode,b"\x01")
        bridge.feed_udp("test",True,protected(secret,plain),provenance.capture_point)
        now[0] = 6
        bridge.poll()
        state = bridge.status("test")
        assert state.transport_closed and state.decoder_code == code
        assert not state.request_headers_complete
        assert state.state != InspectionState.DECRYPTED
        assert state.quic_authenticated_packets == (0 if mode in ("missing","wrong_candidate") else 1)
        if mode == "table_capacity":
            assert state.decoder_requested_bytes == 65537
            assert state.decoder_limit_bytes == 65536
        assert secret.hex() not in json.dumps(bridge.metrics())
        assert bridge.metrics()["retained_keys"] == 0
    finally:
        bridge.close()


@pytest.mark.parametrize("length", [0, 9999])
def test_invalid_coalesced_packet_length_is_bounded(monkeypatch, length):
    from types import SimpleNamespace
    import prism_tls_bridge.quic as module
    from aioquic.quic.packet import QuicPacketType
    monkeypatch.setattr(module,"pull_quic_header",lambda *a,**k: SimpleNamespace(
        packet_length=length,packet_type=QuicPacketType.INITIAL,version=QuicProtocolVersion.VERSION_1))
    value, _, output = decoder()
    value.feed(b"\xc0"+b"x"*25)
    assert value.failed and output[-1]["error_code"] == "reassembly.invalid_length"
