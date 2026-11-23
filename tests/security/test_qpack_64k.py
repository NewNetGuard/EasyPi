"""Generated compression/AEAD fixtures; no captured browsing data."""
from dataclasses import replace
import sys
import os

import pylsqpack
import pytest

from prism_tls_bridge.models import Limits
from prism_tls_bridge.qpack_budget import TABLE_CAPACITY, QPACK_RESERVED_BYTES, quic_envelope
from prism_tls_bridge.qpack_guard import Guard
from prism_tls_bridge.decode_errors import DecodeError
from test_qpack_capacity import capacity, prefixed
from test_quic_error_categories import decoder, protected, stream, integer
from prism_tls_bridge.bridge import Bridge
from prism_tls_bridge.models import Endpoint, Provenance


def test_exact_capacity_and_one_byte_over():
    guard = Guard(capacity=TABLE_CAPACITY)
    native = pylsqpack.Decoder(TABLE_CAPACITY, 0)
    native.feed_encoder(guard.feed_encoder(capacity(TABLE_CAPACITY)))
    with pytest.raises(DecodeError) as error:
        guard.feed_encoder(capacity(TABLE_CAPACITY+1))
    assert error.value.measurements == {'requested_bytes':65537,'limit_bytes':65536}
    for size in (65537, 1 << 30):
        with pytest.raises(ValueError):
            Guard(capacity=size)


def test_fixed_metadata_ring_rotation_and_stale_reference():
    guard = Guard(capacity=TABLE_CAPACITY)
    for _ in range(8192):
        guard.insert(0, 0)
    assert len(guard.entries) == 2048
    assert guard.entry(8191) == (0,0)
    assert guard.entry(6144) == (0,0)
    with pytest.raises(DecodeError, match='qpack.invalid_reference'):
        guard.entry(6143)
    assert len(guard.entries.data)*guard.entries.data.itemsize == 16384
    assert sys.getsizeof(guard.entries.data) < 17000


def test_native_table_fill_and_rotation_after_64k_instruction():
    guard = Guard(capacity=TABLE_CAPACITY)
    native = pylsqpack.Decoder(TABLE_CAPACITY,0)
    native.feed_encoder(guard.feed_encoder(capacity(TABLE_CAPACITY)))
    # 2048 zero-length entries fill the protocol table exactly; continue to
    # exercise eviction. Batches stay below the unchanged encoder input limit.
    for _ in range(4):
        native.feed_encoder(guard.feed_encoder(b'\x40\x00'*2048))
    assert len(guard.entries) == 2048
    # Required Insert Count wraps at twice MaxEntries (4096).
    block = b'\x01\x00\x80'
    assert guard.check(block)
    assert native.feed_header(0,block)[1] == [(b'',b'')]


def h3_exchange(value, secret):
    path = b'/bounded'
    insert = b'\xc1' + bytes([len(path)]) + path
    value.feed(protected(secret,stream(2,b'\x02'+capacity(TABLE_CAPACITY)+insert),0))
    # GET from static table, :path from the new dynamic table.
    block = b'\x02\x00\xd1\x80'
    value.feed(protected(secret,stream(0,b'\x01'+integer(len(block))+block),1))


def test_sixteen_independent_authenticated_connections_and_negative_controls():
    sessions = [decoder() for _ in range(16)]
    for value, secret, events in sessions:
        h3_exchange(value,secret)
        assert not value.failed
        requests = [e for e in events if e['type']=='http_request']
        assert len(requests)==1 and requests[0]['path']=='/bounded'
        assert value.authenticated_packets==2
        assert value.guard.capacity==65536
    assert len({id(v.qpack) for v,_,_ in sessions})==16
    for keys in (False, True):
        value, _, events = decoder(keys=keys)
        h3_exchange(value,b'\x01'*32)
        assert not any(e['type']=='http_request' for e in events)
        assert value.authenticated_packets==0


def test_budget_fits_unchanged_admission_and_preserves_header_limits():
    limits = Limits()
    assert quic_envelope(limits)==999424 <= limits.per_connection_bytes==1048576
    assert limits.fixed_bytes+16*limits.per_connection_bytes==17367040
    assert limits.global_bytes==33554432
    assert QPACK_RESERVED_BYTES==524288
    assert limits.header_bytes==16384 and limits.max_header_fields==64
    with pytest.raises(ValueError,match='QPACK'):
        replace(limits,per_connection_bytes=quic_envelope(limits)-1)
    guard=Guard(capacity=TABLE_CAPACITY)
    with pytest.raises(DecodeError,match='limits.qpack_decoded'):
        guard.check(b'\0\0'+prefixed(17,6,0xc0)*65)
    guard.insert(10,1000)
    # A larger table must not permit a 17 KiB expanded field section.
    with pytest.raises(DecodeError,match='limits.qpack_decoded'):
        guard.check(b'\x02\x00'+b'\x80'*17)


def test_second_encoder_stream_cannot_expand_native_input_budget():
    value,secret,events=decoder()
    value.feed(protected(secret,stream(2,b'\x02'+capacity(TABLE_CAPACITY)),0))
    value.feed(protected(secret,stream(6,b'\x02'+capacity(TABLE_CAPACITY)),1))
    assert value.failed and events[-1]['error_code']=='qpack.encoder'


def test_bridge_sixteen_live_quic_flows_are_accounted_and_isolated():
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    bridge=Bridge()
    provenance=Provenance('test-device','test-capture','test-source','endpoint',True)
    sessions=[]
    try:
        for i in range(16):
            random, secret=os.urandom(32).hex(),os.urandom(32)
            flow=str(i)
            assert bridge.open_flow(flow,'quic',provenance,Endpoint('192.0.2.1',50000+i),
                                    Endpoint('192.0.2.2',443),key_session_id=random)
            client=QuicConnection(configuration=QuicConfiguration(is_client=True,server_name='example.test'))
            client.connect(('192.0.2.2',443),now=0)
            bridge.feed_udp(flow,True,client.datagrams_to_send(now=0)[0][0],provenance.capture_point)
            bridge.add_key(flow,'CLIENT_TRAFFIC_SECRET_0 '+random+' '+secret.hex(),provenance)
            sessions.append((flow,secret))
        for number, payload in enumerate((stream(2,b'\x02'+capacity(TABLE_CAPACITY)+b'\xc1\x08/bounded'),
                                           stream(0,b'\x01\x04\x02\x00\xd1\x80'))):
            for flow,secret in sessions:
                bridge.feed_udp(flow,True,protected(secret,payload,number),provenance.capture_point)
        for flow,_ in sessions:
            assert bridge.status(flow).request_headers_complete
            assert bridge._resident(bridge.flows[flow]) >= QPACK_RESERVED_BYTES
        assert bridge.metrics()['active']==16 and bridge.metrics()['headers']==16
        assert bridge.metrics()['reserved_bytes']==17367040
        assert not bridge.open_flow('overflow','quic',provenance,Endpoint('192.0.2.1',51000),Endpoint('192.0.2.2',443))
    finally:
        bridge.close()
    assert bridge.metrics()['active']==0 and bridge.metrics()['retained_keys']==0
