from __future__ import annotations

import asyncio
import hashlib
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from starlette import status

from app.api.v1.endpoints import camera_recordings
from app.api.websocket import cameras as camera_websocket
from app.api.websocket import ws_auth
from app.services.ptz.adapters import onvif_soap
from app.services.ptz.adapters.thingino import MAX_RESPONSE_BYTES as THINGINO_MAX_RESPONSE_BYTES
from app.services.ptz.adapters.thingino import ThinginoPTZAdapter
from app.services.ptz.errors import PTZError
from app.services.recording_service import RecordingService


ROOT = Path(__file__).resolve().parents[2]


class _CountingStream(httpx.SyncByteStream):
    def __init__(self, total: int, chunk_size: int = 64 * 1024) -> None:
        self.total = total
        self.chunk_size = chunk_size
        self.bytes_read = 0

    def __iter__(self):
        while self.bytes_read < self.total:
            size = min(self.chunk_size, self.total - self.bytes_read)
            self.bytes_read += size
            yield b"x" * size


def test_onvif_rejects_oversized_chunked_response_before_reading_it_all() -> None:
    stream = _CountingStream(8 * 1024 * 1024)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request, stream=stream)
        )
    )
    try:
        with pytest.raises(PTZError, match="too large"):
            onvif_soap.call(
                "http://192.168.1.20/onvif/device_service",
                "test-action",
                "<tds:GetDeviceInformation/>",
                client=client,
            )
    finally:
        client.close()

    assert stream.bytes_read <= onvif_soap.MAX_RESPONSE_BYTES + stream.chunk_size
    assert stream.bytes_read < stream.total


def test_thingino_rejects_oversized_chunked_response_before_reading_it_all() -> None:
    stream = _CountingStream(8 * 1024 * 1024)
    client = httpx.Client(
        base_url="http://192.168.1.20",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, request=request, stream=stream)
        ),
    )
    adapter = ThinginoPTZAdapter(
        SimpleNamespace(ip="192.168.1.20", username="root", secret="secret")
    )
    adapter._client = client
    adapter._logged_in = True
    try:
        with pytest.raises(PTZError, match="too large"):
            adapter._api_get("/x/json-motor-params.cgi")
    finally:
        client.close()

    assert stream.bytes_read <= THINGINO_MAX_RESPONSE_BYTES + stream.chunk_size
    assert stream.bytes_read < stream.total


def test_camera_ws_rejects_revoked_session_before_database_or_go2rtc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        client = "security-test"

        def __init__(self) -> None:
            self.closed: list[int] = []

        async def close(self, code: int) -> None:
            self.closed.append(code)

    socket = Socket()
    monkeypatch.setattr(
        camera_websocket,
        "verify_ws_token",
        lambda _token: SimpleNamespace(user_id=7, session_jti="revoked-jti"),
    )
    monkeypatch.setattr(
        camera_websocket,
        "websocket_session_is_valid",
        lambda **_kwargs: False,
    )
    monkeypatch.setattr(
        camera_websocket,
        "get_db",
        lambda: pytest.fail("camera lookup ran for a revoked session"),
    )

    asyncio.run(
        camera_websocket.camera_live_websocket(
            socket,
            "camera-id",
            ws_token="issued-before-revocation",
        )
    )

    assert socket.closed == [status.WS_1008_POLICY_VIOLATION]


def test_revocation_closes_the_server_side_media_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        client = "security-test"
        client_state = SimpleNamespace(name="CONNECTED")

        def __init__(self) -> None:
            self.accepted = False
            self.closed = False
            self.receives = 0

        async def accept(self) -> None:
            self.accepted = True

        async def receive(self):
            self.receives += 1
            if self.receives == 1:
                return {
                    "type": "websocket.receive",
                    "text": '{"type":"mse","value":"avc1.640029,mp4a.40.2"}',
                }
            await asyncio.Future()

        async def send_bytes(self, _message: bytes) -> None:
            pass

        async def send_text(self, _message: str) -> None:
            pass

        async def close(self, **_kwargs) -> None:
            self.closed = True
            self.client_state.name = "DISCONNECTED"

    class Upstream:
        def __init__(self) -> None:
            self.closed = False
            self.sent: list[str] = []

        def __aiter__(self):
            return self

        async def __anext__(self):
            await asyncio.Future()

        async def send(self, message: str) -> None:
            self.sent.append(message)

        async def close(self) -> None:
            self.closed = True

    class DB:
        def get(self, *_args):
            return SimpleNamespace(id="camera-id", name="Hall")

        def close(self) -> None:
            pass

    async def connect(*_args, **_kwargs):
        return upstream

    async def revoke(*_args, **_kwargs) -> None:
        while not upstream.sent:
            await asyncio.sleep(0)

    socket = Socket()
    upstream = Upstream()
    monkeypatch.setattr(
        camera_websocket,
        "verify_ws_token",
        lambda _token: SimpleNamespace(user_id=7, session_jti="active-jti"),
    )
    monkeypatch.setattr(camera_websocket, "websocket_session_is_valid", lambda **_kwargs: True)
    monkeypatch.setattr(camera_websocket, "get_db", lambda: iter([DB()]))
    monkeypatch.setattr(camera_websocket, "go2rtc_authorization_header", lambda: "Basic test")
    monkeypatch.setattr(camera_websocket.websockets, "connect", connect)
    monkeypatch.setattr(camera_websocket, "revalidate_session_periodically", revoke)

    asyncio.run(
        camera_websocket.camera_live_websocket(
            socket,
            "camera-id",
            ws_token="valid-token",
        )
    )

    assert socket.accepted is True
    assert socket.closed is True
    assert upstream.closed is True
    assert upstream.sent == [
        '{"type":"mse","value":"avc1.640029,mp4a.40.2"}'
    ]


@pytest.mark.parametrize(
    "message",
    [
        '{"type":"webrtc/offer","value":"offer"}',
        '{"type":"mjpeg"}',
        '{"type":"mse","value":"ok","extra":true}',
        '{"type":"mse","value":"bad codec value"}',
        "not-json",
    ],
)
def test_camera_media_socket_accepts_only_mse_subscription(message: str) -> None:
    with pytest.raises(ValueError):
        camera_websocket._validated_mse_request(message)

    assert camera_websocket._validated_mse_request(
        '{"type":"mse","value":"avc1.640029,mp4a.40.2"}'
    ) == '{"type":"mse","value":"avc1.640029,mp4a.40.2"}'


def test_camera_ws_periodic_check_closes_a_revoked_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Socket:
        client_state = SimpleNamespace(name="CONNECTED")
        application_state = SimpleNamespace(name="CONNECTED")

        def __init__(self) -> None:
            self.closed: list[int] = []

        async def close(self, code: int) -> None:
            self.closed.append(code)

    socket = Socket()
    monkeypatch.setattr(ws_auth, "websocket_session_is_valid", lambda **_kwargs: False)

    asyncio.run(
        ws_auth.revalidate_session_periodically(
            socket,
            user_id=7,
            session_jti="revoked-jti",
            interval_sec=0,
        )
    )

    assert socket.closed == [status.WS_1008_POLICY_VIOLATION]


def test_camera_frontend_streams_media_through_the_revocable_websocket() -> None:
    frontend = (ROOT / "frontend/src/components/cameras/LiveViewModal.tsx").read_text(
        encoding="utf-8"
    )
    nginx = (ROOT / "templates/nginx/easypi.conf").read_text(encoding="utf-8")

    assert "/auth/ws-token" in frontend
    assert "/go2rtc/stream.html" not in frontend
    assert "new RTCPeerConnection()" not in frontend
    assert "new MediaSource()" in frontend
    assert "Browser media goes through /ws/cameras/<id>/live" in nginx
    assert "location /go2rtc/" in nginx
    assert "return 404;" in nginx
    assert "interval_sec=5.0" in (
        ROOT / "backend/app/api/websocket/cameras.py"
    ).read_text(encoding="utf-8")


def test_legacy_http_webrtc_offer_and_internal_go2rtc_api_are_disabled() -> None:
    camera_live = (ROOT / "backend/app/api/v1/endpoints/camera_live.py").read_text(
        encoding="utf-8"
    )
    installer = (ROOT / "scripts/setup/install_go2rtc.sh").read_text(encoding="utf-8")
    generator = (ROOT / "scripts/utils/go2rtc_config.py").read_text(encoding="utf-8")
    updater = (ROOT / "scripts/settings/go2rtc_config.sh").read_text(encoding="utf-8")

    assert '/{camera_id}/webrtc/offer' not in camera_live
    assert '/{camera_id}/mjpeg' not in camera_live
    assert "/api/webrtc" not in installer
    assert "/api/webrtc" not in generator
    assert "modules: [api, ws, rtsp, mp4]" in installer
    assert "modules: [api, ws, rtsp, mp4]" in generator
    assert "webrtc:" not in installer
    assert "webrtc:" not in generator
    assert "8555" not in installer
    assert "8555" not in generator
    assert "GO2RTC_WEBRTC_CANDIDATE" not in updater
    assert "sport = :1984" in updater
    assert "sport = :8554" in updater
    assert "go2rtc did not open its API and RTSP listeners" in updater


@pytest.mark.skipif(sys.platform == "win32", reason="openat regression requires Linux")
def test_recording_parent_swap_cannot_read_or_delete_outside_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "recordings"
    service = RecordingService(str(root))
    camera_dir = root / "camera" / "date"
    camera_dir.mkdir(parents=True)
    recording = camera_dir / "clip.mp4"
    recording.write_bytes(b"inside")
    monkeypatch.setattr(camera_recordings, "recording_service", service)
    recording_id = hashlib.sha256(str(recording.resolve()).encode()).hexdigest()[:16]
    validated = camera_recordings._find_recording_path(recording_id)
    assert validated == recording.resolve()

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "clip.mp4"
    outside_file.write_bytes(b"outside")
    moved = root / "camera-real"
    (root / "camera").rename(moved)
    (root / "camera").symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        camera_recordings._open_recording(validated)
    with pytest.raises(OSError):
        camera_recordings._delete_recording_file(validated)
    assert outside_file.read_bytes() == b"outside"


@pytest.mark.skipif(sys.platform == "win32", reason="openat regression requires Linux")
def test_snapshot_root_swap_cannot_read_or_delete_outside_storage(tmp_path: Path) -> None:
    root = tmp_path / "recordings"
    service = RecordingService(str(root))
    snapshots = service.get_snapshots_dir()
    snapshots.mkdir()
    (snapshots / "frame.jpg").write_bytes(b"\xff\xd8inside")

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "frame.jpg"
    outside_file.write_bytes(b"\xff\xd8outside")
    moved = root / "snapshots-real"
    snapshots.rename(moved)
    snapshots.symlink_to(outside, target_is_directory=True)

    assert service.open_snapshot_by_filename("frame.jpg") is None
    assert service.delete_snapshot("frame.jpg")["success"] is False
    assert outside_file.read_bytes() == b"\xff\xd8outside"
