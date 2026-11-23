"""Request categorization cannot be used as a content/ad verdict."""
import json
from prism_tls_bridge.chrome import ChromeObserver
from prism_tls_bridge.chrome_diagnostics import request_category


def test_categories_discard_identifiers_and_credentials():
    request = {"authority": "rr1.googlevideo.com", "path": "/videoplayback?id=private-video&token=private-token",
               "protocol": "h3", "cookie": "private-cookie"}
    value = request_category(request)
    assert value == dict(host_group="video_cdn", route="media_request", protocol="h3")
    assert "private" not in json.dumps(value)
    assert "ad" not in value  # No content verdict is produced.


def test_host_boundaries_and_unknown_paths_are_not_reflected():
    assert request_category({"authority": "youtube.com.evil.test", "path": "/private-value", "protocol": "private-protocol"}) == dict(host_group="other", route="other", protocol="unknown")
    assert request_category({"authority": "www.youtube.com", "path": "/api/stats/ads"})["route"] == "ad_telemetry"
    assert request_category({"authority": "[broken"})["host_group"] == "other"


def test_diagnostics_opt_in_bounded_and_reset_clears_session_data():
    now = [10.0]
    value = ChromeObserver("test-device", "192.0.2.1", ["192.0.2.2"], clock=lambda: now[0], diagnostics=True)
    try:
        value.lease_for(value.device)
        events = [{"type": "request_headers", "flow_id": "test-flow", "request": {
            "authority": "www.youtube.com", "path": "/youtubei/v1/player?token=private", "protocol": "h2"}} for _ in range(140)]
        value.bridge.drain_events = lambda: events
        value._events()
        value.bridge.drain_events = lambda: []
        status = value.status(value.device)
        assert len(status["request_categories"]) == 24
        assert len(json.dumps(status).encode()) < 8192
        assert not status["ad_content_classified"]
        assert "private" not in json.dumps(status)
        value.reset("test_reset")
        assert not value.status(value.device)["request_categories"]
    finally:
        value.bridge.close()
    normal = ChromeObserver("test-device", "192.0.2.1", ["192.0.2.2"])
    try:
        assert "request_categories" not in normal.status(normal.device)
    finally:
        normal.bridge.close()


def test_conflicting_quic_initial_is_not_reported_as_capture_loss(monkeypatch):
    from types import SimpleNamespace
    import prism_tls_bridge.chrome as module
    import prism_dpi.flowgraph.quic as quic
    from prism_tls_bridge.models import Endpoint
    value = ChromeObserver("test-device", "192.0.2.1", ["192.0.2.2"])
    try:
        value.lease_for(value.device)
        packet = SimpleNamespace(source=Endpoint("192.0.2.1", 50000), destination=Endpoint("192.0.2.2", 443), protocol="quic", payload=b"\xc0")
        monkeypatch.setattr(module, "parse_ip_packet", lambda _: packet)
        monkeypatch.setattr(quic, "decrypt_quic_initial", lambda _: SimpleNamespace(fragments=[(0,b"\x01"),(0,b"\x02")]))
        value.packet(b"test")
        assert value.counts["quic_initial_fragment_conflict"] == 1
        assert value.counts["capture_loss"] == 0
        assert value.lease and not value.flows
    finally:
        value.bridge.close()


def test_terminal_reason_never_reflects_unrecognized_input_and_ring_is_bounded():
    from types import SimpleNamespace
    from prism_tls_bridge.chrome_diagnostics import FlowDiagnostics
    from prism_tls_bridge.models import InspectionState
    diag = FlowDiagnostics()
    bridge = SimpleNamespace(flows={}, closed={})
    for i in range(30):
        fid = str(i)
        diag.opened(fid, "quic")
        bridge.closed[fid] = SimpleNamespace(reason="private-input", diagnostic="private-input",
            state=InspectionState.UNKNOWN, request_headers_complete=False)
        diag.retire(bridge)
    result = diag.status()
    assert len(result["recent_closed"]) == 6
    assert "private-input" not in json.dumps(result)
    diag.clear()
    assert not diag.status()["recent_closed"]


def test_maximum_diagnostic_status_fits_existing_private_ipc_response_limit():
    from types import SimpleNamespace
    from prism_tls_bridge.models import InspectionState
    value = ChromeObserver("test-device", "192.0.2.1", ["192.0.2.2"], diagnostics=True)
    try:
        value.lease_for(value.device)
        value.bridge.drain_events = lambda: []
        for i in range(24):
            value.observations.append(dict(host_group="ad_network", route="playback_telemetry", protocol="h3",
                flow_id=f"{i:032x}", elapsed_ms=99999999))
        # Fill closed history without allowing arbitrary reason text into it.
        fake = SimpleNamespace(flows={}, closed={})
        for i in range(6):
            fid = str(i)
            value.flow_diagnostics.opened(fid, "quic")
            fake.closed[fid] = SimpleNamespace(reason="quic_or_qpack_gap_timeout", diagnostic="matching_keys_timeout",
                state=InspectionState.UNKNOWN, request_headers_complete=False,
                decoder_code="limits.qpack_table_capacity", quic_authenticated_packets=4096,
                decoder_requested_bytes=(1<<62)-1, decoder_limit_bytes=(1<<62)-1)
            value.flow_diagnostics.retire(fake)
        for i in range(16):
            fid = "active-"+str(i)
            value.flow_diagnostics.opened(fid, "quic")
        # Use the actual serializer shape; no active model objects needed here.
        payload = value.status(value.device)
        payload["flow_diagnostics"]["active_stages"] = [dict(transport="quic", hello_seen=True,
            session_key_available=True, other_session_keys_seen=True, key_submissions=4) for _ in range(16)]
        assert len(json.dumps(dict(ok=True, result=payload)).encode()) < 8192
    finally:
        value.bridge.close()
