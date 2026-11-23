"""Generated, ephemeral TLS material only; no captured user traffic in tests."""
import json
import os
import socket
import struct
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hpack import Encoder

from prism_tls_bridge.chrome import ChromeObserver, Rejected
from prism_tls_bridge.tls import expand_label, LABELS


@pytest.fixture
def observer():
    now = [0.0]
    value = ChromeObserver("paired-test", "192.0.2.1", ["192.0.2.2"], clock=lambda: now[0])
    value.lease_for(value.device)
    yield value, now
    value.bridge.close()


def line(random=None, label="CLIENT_TRAFFIC_SECRET_0"):
    return f"{label} {random or os.urandom(32).hex()} {os.urandom(32).hex()}"


def packet(client, seq, data=b"", syn=False):
    source, dest = ("192.0.2.1", "192.0.2.2") if client else ("192.0.2.2", "192.0.2.1")
    ports = (50000, 443) if client else (443, 50000)
    tcp = struct.pack("!HHIIBBHHH", *ports, seq, 0, 0x50, 2 if syn else 0x18, 65535, 0, 0)+data
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(tcp), 0, 0, 64, 6, 0, socket.inet_aton(source), socket.inet_aton(dest))
    return ip+tcp


def trace():
    random = os.urandom(32)
    values = {label: os.urandom(32) for label in LABELS}
    def handshake(kind, data):
        return bytes([kind])+len(data).to_bytes(3, "big")+data
    def record(kind, data):
        return bytes([kind])+b"\x03\x03"+len(data).to_bytes(2, "big")+data
    def encrypted(label, inner, data):
        secret = values[label]
        plain = data+bytes([inner])
        header = b"\x17\x03\x03"+(len(plain)+16).to_bytes(2, "big")
        return header+AESGCM(expand_label(secret, b"key", 16)).encrypt(expand_label(secret, b"iv", 12), plain, header)
    client_hello = record(22, handshake(1, b"\x03\x03"+random+b"\0"+b"\0\x02\x13\x01\x01\0\0\0"))
    server_hello = record(22, handshake(2, b"\x03\x03"+os.urandom(32)+b"\0\x13\x01\0\0\0"))
    cf = encrypted("CLIENT_HANDSHAKE_TRAFFIC_SECRET", 22, handshake(20, os.urandom(32)))
    sf = encrypted("SERVER_HANDSHAKE_TRAFFIC_SECRET", 22, handshake(20, os.urandom(32)))
    block = Encoder().encode([(":method", "GET"), (":scheme", "https"), (":authority", "example.test"), (":path", "/owned-test")])
    h2 = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"+len(block).to_bytes(3,"big")+b"\x01\x05\0\0\0\x01"+block
    request = encrypted("CLIENT_TRAFFIC_SECRET_0", 23, h2)
    rows = [(True, client_hello), (False, server_hello+sf), (True, cf+request)]
    packets = [packet(True, 100, syn=True), packet(False, 200, syn=True)]
    seq = {True:101, False:201}
    for client, data in rows:
        packets.append(packet(client, seq[client], data)); seq[client] += len(data)
    keys = [f"{label} {random.hex()} {value.hex()}" for label,value in values.items()]
    return packets, keys


@pytest.mark.parametrize("when", ["before", "after"])
def test_automatic_tls13_h2_matching_and_recovery(observer, when):
    value, now = observer
    packets, keys = trace()
    if when == "before": value.upload(value.device,value.lease,0,keys)
    for raw in packets: value.packet(raw)
    if when == "after": value.upload(value.device,value.lease,0,keys)
    assert value.counts["headers_h2"] == 1
    assert keys[0].split()[2] not in json.dumps(value.status(value.device))


def test_quic_fragment_conflict_preserves_unrelated_h2_and_device_lease(observer, monkeypatch):
    from types import SimpleNamespace
    import prism_tls_bridge.chrome as module
    import prism_dpi.flowgraph.quic as quic
    from prism_tls_bridge.models import Endpoint
    value, _ = observer
    packets, keys = trace()
    value.upload(value.device, value.lease, 0, keys)
    original_lease = value.lease
    for raw in packets[:3]:
        value.packet(raw)
    with monkeypatch.context() as patch:
        patch.setattr(module, "parse_ip_packet", lambda _: SimpleNamespace(
            source=Endpoint("192.0.2.1", 50001), destination=Endpoint("192.0.2.2", 443),
            protocol="quic", payload=b"\xc0"))
        patch.setattr(quic, "decrypt_quic_initial", lambda _: SimpleNamespace(fragments=[(0,b"\x01"),(0,b"\x02")]))
        value.packet(b"conflicting-initial")
    assert value.lease == original_lease
    assert len(value.keys) == len(keys)
    assert value.counts["quic_initial_fragment_conflict"] == 1
    assert value.counts["capture_loss"] == 0
    for raw in packets[3:]:
        value.packet(raw)
    assert value.counts["headers_h2"] == 1


@pytest.mark.parametrize("mode", ["missing", "wrong", "unrelated"])
def test_negative_controls(observer, mode):
    value, _ = observer
    packets, keys = trace()
    if mode != "missing":
        rows = [f"{row.split()[0]} {row.split()[1] if mode=='wrong' else os.urandom(32).hex()} {os.urandom(32).hex()}" for row in keys]
        value.upload(value.device,value.lease,0,rows)
    for raw in packets:value.packet(raw)
    assert value.counts["headers_h2"] == 0


def test_batch_atomic_on_malformed_and_conflict(observer):
    value,_ = observer
    good = line()
    with pytest.raises(Rejected):value.upload(value.device,value.lease,0,[good,"invalid"])
    assert not value.keys and value.sequence == -1
    value.upload(value.device,value.lease,0,[good])
    with pytest.raises(Rejected):value.upload(value.device,value.lease,1,[line(),good[:-64]+os.urandom(32).hex()])
    assert len(value.keys)==1 and value.sequence==0


def test_conflicting_duplicates_in_one_batch_are_atomic(observer):
    value,_=observer
    good=line()
    with pytest.raises(Rejected):value.upload(value.device,value.lease,0,[good,good[:-64]+os.urandom(32).hex()])
    assert not value.keys and value.sequence==-1


def test_replay_is_idempotent_but_modified_sequence_denied(observer):
    value,_ = observer
    rows=[line()]
    assert not value.upload(value.device,value.lease,0,rows)["duplicate"]
    assert value.upload(value.device,value.lease,0,rows)["duplicate"]
    with pytest.raises(Rejected):value.upload(value.device,value.lease,0,[line()])


def test_device_scope_and_expiry_clear_flows_and_keys(observer):
    value,now=observer
    with pytest.raises(Rejected):value.lease_for("other-device")
    packets,keys=trace()
    value.upload(value.device,value.lease,0,keys)
    for raw in packets:value.packet(raw)
    old=value.lease;now[0]=61;value.tick()
    assert not value.keys and not value.flows
    with pytest.raises(Rejected):value.upload(value.device,old,1,keys)
    assert value.lease_for(value.device)["lease"] != old


def test_continuous_authenticated_renewal_does_not_reset_flow(observer):
    value,now=observer
    old=value.lease;now[0]=40
    assert value.lease_for(value.device)["lease"]==old
    now[0]=70;value.tick()
    assert value.lease==old


def test_capacity_is_bounded_and_loss_revokes_generation(observer):
    value,_=observer
    for seq in range(12):value.upload(value.device,value.lease,seq,[line() for _ in range(32)])
    assert len(value.keys)==value.MAX_KEYS
    value.loss(1)
    assert not value.keys and value.lease is None


def test_out_of_scope_packets_never_open_flow(observer):
    value,_=observer
    raw=bytearray(packet(True,1,syn=True));raw[16:20]=socket.inet_aton("192.0.2.3")
    value.packet(bytes(raw))
    assert not value.flows


@pytest.mark.parametrize("mode", ["missing", "unrelated", "wrong", "correct"])
def test_flow_stage_diagnostics_distinguish_session_match_from_authentication(mode):
    now = [0.0]
    value = ChromeObserver("paired-test", "192.0.2.1", ["192.0.2.2"], clock=lambda: now[0], diagnostics=True)
    try:
        value.lease_for(value.device)
        packets, keys = trace()
        if mode != "missing":
            rows = keys if mode == "correct" else [
                f"{row.split()[0]} {row.split()[1] if mode == 'wrong' else os.urandom(32).hex()} {os.urandom(32).hex()}"
                for row in keys]
            value.upload(value.device, value.lease, 0, rows)
        for raw in packets:
            value.packet(raw)
        now[0] = 6
        value.tick()
        for fid in list(value.bridge.flows):
            value.bridge.close_flow(fid)
        status = value.status(value.device)
        closed = status["flow_diagnostics"]["recent_closed"]
        assert closed
        row = closed[-1]
        assert row["hello_seen"]
        assert row["session_key_available"] == (mode in ("wrong", "correct"))
        assert row["other_session_keys_seen"] == (mode == "unrelated")
        assert row["authenticated_headers"] == (mode == "correct")
        if mode in ("missing", "unrelated"):
            assert row["reason"] == "matching_keys_timeout"
            assert row["key_submissions"] == 0
        if mode == "wrong":
            # A decoder can keep an unverified candidate pending until timeout;
            # retain the independently observed cryptographic diagnostic.
            assert row["diagnostic"] == "invalid_secret"
            assert row["key_submissions"] > 0
            # Subsequent labels must not be submitted to the already closed flow.
            assert status["bridge"]["key_rejected"] == 0
        output = json.dumps(status)
        for key in keys:
            for field in key.split()[1:]:
                assert field not in output
    finally:
        value.bridge.close()


def test_diagnostic_capture_scope_is_explicitly_incomplete(observer):
    value, _ = observer
    raw = bytearray(packet(True, 1, syn=True));raw[16:20] = socket.inet_aton("192.0.2.3")
    value.packet(bytes(raw))
    assert value.counts["packets_outside_scope"] == 1
    assert not value.flows


def test_ipv6_is_outside_current_chrome_observer_scope(observer):
    value, _ = observer
    payload = b"\xc0" + b"\0"*24
    udp = struct.pack("!HHHH",50000,443,len(payload)+8,0)+payload
    raw = struct.pack("!IHBB16s16s",6<<28,len(udp),17,64,
        socket.inet_pton(socket.AF_INET6,"2001:db8::1"),socket.inet_pton(socket.AF_INET6,"2001:db8::2"))+udp
    value.packet(raw)
    assert value.counts["packets_outside_scope"] == 1
    assert not value.flows
    with pytest.raises(ValueError):
        ChromeObserver("test-device","192.0.2.1",["2001:db8::2"])


def test_same_session_keys_are_not_resubmitted_on_each_packet(observer):
    value, _ = observer
    packets, keys = trace()
    value.upload(value.device, value.lease, 0, keys)
    for raw in packets:
        value.packet(raw)
    flow = next(iter(value.bridge.flows.values()))
    revision = flow.secrets.revision
    for fid in value.flows.values():
        for _ in range(10):
            value._apply(fid)
    assert flow.secrets.revision == revision


def test_remaining_keys_not_submitted_after_retry_closes_flow(observer, monkeypatch):
    value, _ = observer
    packets, keys = trace()
    for raw in packets[:3]:
        value.packet(raw)
    original = value.bridge.add_key
    calls = []

    def close_on_first(fid, line, provenance):
        calls.append(fid)
        result = original(fid, line, provenance)
        value.bridge.close_flow(fid)
        return result

    monkeypatch.setattr(value.bridge, "add_key", close_on_first)
    value.upload(value.device, value.lease, 0, keys)
    assert len(calls) == 1
    assert value.bridge.metrics()["key_rejected"] == 0


def test_secret_diagnostics_do_not_reflect_input(observer):
    value,_=observer
    private=os.urandom(32).hex()
    with pytest.raises(Rejected) as error:value.upload(value.device,value.lease,0,[private])
    assert private not in str(error.value)


def quic_trace():
    import datetime
    import io
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from aioquic.buffer import Buffer
    from aioquic.quic.packet import pull_quic_header
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.h3.connection import H3Connection
    key=ec.generate_private_key(ec.SECP256R1())
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"example.test")])
    now=datetime.datetime.now(datetime.timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
          .not_valid_after(now+datetime.timedelta(hours=1))
          .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]),False)
          .add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
    log=io.StringIO()
    cfg=QuicConfiguration(is_client=True,server_name="example.test",alpn_protocols=["h3"],secrets_log_file=log)
    cfg.cadata=cert.public_bytes(serialization.Encoding.PEM)
    client=QuicConnection(configuration=cfg); hc=H3Connection(client)
    client.connect(("192.0.2.2",443),now=0)
    first=client.datagrams_to_send(now=0)
    header=pull_quic_header(Buffer(data=first[0][0]),host_cid_length=8)
    sc=QuicConfiguration(is_client=False,alpn_protocols=["h3"]);sc.certificate,sc.private_key=cert,key
    server=QuicConnection(configuration=sc,original_destination_connection_id=header.destination_cid)
    hs=H3Connection(server);wire=[];queue=[(True,data) for data,_ in first];tick=[0.]
    def exchange():
        for _ in range(200):
            tick[0]+=.01
            for endpoint,outgoing in ((client,True),(server,False)):
                if endpoint is server and not wire:continue
                timer=endpoint.get_timer()
                if timer is not None and timer<=tick[0]:endpoint.handle_timer(now=tick[0])
                queue.extend((outgoing,data) for data,_ in endpoint.datagrams_to_send(now=tick[0]))
            if not queue:continue
            outgoing,data=queue.pop(0);wire.append((outgoing,data))
            receiver=server if outgoing else client;h3=hs if outgoing else hc
            receiver.receive_datagram(data,("192.0.2.1",50000) if outgoing else ("192.0.2.2",443),now=tick[0])
            while (event:=receiver.next_event()) is not None:h3.handle_event(event)
    exchange()
    hc.send_headers(0,[(b":method",b"GET"),(b":scheme",b"https"),(b":authority",b"example.test"),(b":path",b"/owned-test")],end_stream=True)
    exchange()
    frames=[]
    for outgoing,data in wire:
        src,dst=("192.0.2.1","192.0.2.2") if outgoing else ("192.0.2.2","192.0.2.1")
        ports=(50000,443) if outgoing else (443,50000)
        udp=struct.pack("!HHHH",*ports,8+len(data),0)+data
        frames.append(struct.pack("!BBHHHBBH4s4s",0x45,0,20+len(udp),0,0,64,17,0,socket.inet_aton(src),socket.inet_aton(dst))+udp)
    return frames,[line for line in log.getvalue().splitlines() if line.split()[0] in LABELS]


@pytest.mark.parametrize("mode",["before","after","missing","wrong"])
def test_real_quic_handshake_and_h3_in_automatic_observer(observer,mode):
    value,_=observer
    packets,keys=quic_trace()
    if mode=="wrong":keys=[row[:-64]+os.urandom(32).hex() for row in keys]
    if mode not in ("missing","after"):value.upload(value.device,value.lease,0,keys)
    for raw in packets:value.packet(raw)
    if mode=="after":value.upload(value.device,value.lease,0,keys)
    assert value.counts["headers_h3"]==(1 if mode in ("before","after") else 0)
