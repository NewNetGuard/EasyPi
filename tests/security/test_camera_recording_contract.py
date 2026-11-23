from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import camera_recordings
from app.api.v1.endpoints import camera_discovery
from app.core.go2rtc_client import go2rtc_authorization_header, go2rtc_http_auth
from app.services import recording_service as recording_service_module
from app.services.recording_service import RecordingService
from app.services.ptz.errors import PTZSecurityError
from app.services.snapshot_service import snapshot_service
from fastapi import HTTPException


ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("header", "file_size", "expected"),
    [
        ("bytes=2-5", 10, (2, 5)),
        ("bytes=7-", 10, (7, 9)),
        ("bytes=-3", 10, (7, 9)),
        ("bytes=-30", 10, (0, 9)),
        ("BYTES=0-99", 10, (0, 9)),
    ],
)
def test_recording_range_parser_supports_single_and_suffix_ranges(
    header: str,
    file_size: int,
    expected: tuple[int, int],
) -> None:
    assert camera_recordings._parse_byte_range(header, file_size) == expected


@pytest.mark.parametrize(
    "header",
    [
        "bytes=",
        "bytes=3-2",
        "bytes=10-",
        "bytes=-0",
        "bytes=0-1,4-5",
        "items=0-2",
        "bytes=a-b",
    ],
)
def test_recording_range_parser_returns_416_for_invalid_ranges(header: str) -> None:
    with pytest.raises(HTTPException) as error:
        camera_recordings._parse_byte_range(header, 10)

    assert error.value.status_code == 416
    assert error.value.headers == {"Content-Range": "bytes */10"}


def test_camera_router_has_no_stub_and_cleanup_precedes_dynamic_delete() -> None:
    routes = list(camera_recordings.router.routes)
    paths = [route.path for route in routes]

    assert "/recordings/export" not in paths
    assert "/recordings/list" not in paths

    cleanup_index = next(
        index
        for index, route in enumerate(routes)
        if route.path == "/recordings/cleanup" and "DELETE" in route.methods
    )
    delete_index = next(
        index
        for index, route in enumerate(routes)
        if route.path == "/recordings/{recording_id}" and "DELETE" in route.methods
    )
    assert cleanup_index < delete_index


def test_recording_stream_serves_a_suffix_range_from_an_open_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RecordingService(str(tmp_path))
    recording_dir = tmp_path / "front_door_abcd1234" / "2026-09-03"
    recording_dir.mkdir(parents=True)
    recording = recording_dir / "front_door_20260903_120000.mp4"
    recording.write_bytes(b"0123456789")
    recording_id = hashlib.sha256(str(recording.resolve()).encode()).hexdigest()[:16]
    monkeypatch.setattr(camera_recordings, "recording_service", service)

    async def exercise() -> tuple[object, bytes]:
        response = await camera_recordings.stream_recording(
            recording_id,
            SimpleNamespace(headers={"range": "bytes=-4"}),
            SimpleNamespace(),
        )
        body = bytearray()
        async for chunk in response.body_iterator:
            body.extend(chunk)
        return response, bytes(body)

    response, body = asyncio.run(exercise())

    assert response.status_code == 206
    assert response.headers["content-range"] == "bytes 6-9/10"
    assert response.headers["content-length"] == "4"
    assert body == b"6789"


def test_protect_rejects_unknown_recording_without_persisting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RecordingService(str(tmp_path))
    calls: list[tuple[str, bool]] = []
    monkeypatch.setattr(camera_recordings, "recording_service", service)
    monkeypatch.setattr(
        service,
        "set_protected",
        lambda recording_id, protected: calls.append((recording_id, protected)) or True,
    )

    with pytest.raises(HTTPException) as error:
        camera_recordings.protect_recording("0" * 16, SimpleNamespace())

    assert error.value.status_code == 404
    assert calls == []


def test_ffmpeg_install_runs_only_through_the_approved_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RecordingService(str(tmp_path))
    availability = iter([None, "/usr/bin/ffmpeg"])
    calls: list[tuple[object, ...]] = []

    class _Process:
        def __init__(self, stdout: bytes) -> None:
            self.stdout = stdout
            self.returncode: int | None = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return self.stdout, b""

    async def create_process(*args: object, **_kwargs: object) -> _Process:
        calls.append(args)
        if args[0] == "ffmpeg":
            return _Process(b"ffmpeg version release-test\n")
        return _Process(b"FFmpeg installed successfully\n")

    monkeypatch.setattr(
        recording_service_module.shutil,
        "which",
        lambda _name: next(availability),
    )
    monkeypatch.setattr(
        recording_service_module.asyncio,
        "create_subprocess_exec",
        create_process,
    )

    result = asyncio.run(service.ensure_ffmpeg_installed())

    assert result["success"] is True
    assert calls[0] == (
        "sudo",
        "-n",
        recording_service_module.RUNNER_PATH,
        "setup/install_ffmpeg.sh",
    )
    assert calls[1][:2] == ("ffmpeg", "-version")


def test_long_running_ffmpeg_does_not_use_pipes_or_expose_rtsp_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = RecordingService(str(tmp_path))
    monkeypatch.setattr(
        RecordingService,
        "ffmpeg_available",
        property(lambda _self: True),
    )
    captured: dict[str, object] = {}

    class _FailedProcess:
        returncode = 1
        pid = 123

        @staticmethod
        def poll() -> int:
            return 1

    def fake_popen(_cmd: list[str], **kwargs: object) -> _FailedProcess:
        captured["cmd"] = _cmd
        captured.update(kwargs)
        return _FailedProcess()

    monkeypatch.setattr(recording_service_module.subprocess, "Popen", fake_popen)
    secret_url = "rtsp://camera-user:very-secret@192.0.2.10/stream"
    result = asyncio.run(service.start_recording("camera-1", "Front door", secret_url))

    assert captured["stdout"] is recording_service_module.subprocess.DEVNULL
    assert captured["stderr"] is recording_service_module.subprocess.DEVNULL
    assert "very-secret" not in " ".join(captured["cmd"])
    assert "rtsp://127.0.0.1:8554/" in " ".join(captured["cmd"])
    assert result["success"] is False
    assert "very-secret" not in str(result)
    assert secret_url not in str(result)


def test_go2rtc_control_api_is_authenticated_even_on_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GO2RTC_API_USERNAME", "internal-user")
    monkeypatch.setenv("GO2RTC_API_PASSWORD", "internal-password")

    assert go2rtc_http_auth() == ("internal-user", "internal-password")
    assert go2rtc_authorization_header() == "Basic aW50ZXJuYWwtdXNlcjppbnRlcm5hbC1wYXNzd29yZA=="

    installer = (ROOT / "scripts/setup/install_go2rtc.sh").read_text(encoding="utf-8")
    generator = (ROOT / "scripts/utils/go2rtc_config.py").read_text(encoding="utf-8")
    nginx = (ROOT / "templates/nginx/easypi.conf").read_text(encoding="utf-8")
    service = (ROOT / "templates/systemd/easypi-backend.service").read_text(encoding="utf-8")

    assert "local_auth: true" in installer
    assert "secrets.token_urlsafe(48)" in installer
    assert "GO2RTC_API_PASSWORD" in generator
    assert 'curl --config "$CURL_CONFIG_TMP"' in installer
    assert 'EnvironmentFile=/opt/go2rtc/api.env' in installer
    assert 'sudo rm -f "$GO2RTC_DIR/nginx-auth.conf"' in installer
    assert "location /go2rtc/" in nginx
    assert "Browser media goes through /ws/cameras/<id>/live" in nginx
    assert "return 404;" in nginx
    assert "EnvironmentFile=-/opt/go2rtc/api.env" in service


def test_incomplete_go2rtc_credentials_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GO2RTC_API_USERNAME", "internal-user")
    monkeypatch.delenv("GO2RTC_API_PASSWORD", raising=False)

    with pytest.raises(RuntimeError, match="Incomplete go2rtc API credentials"):
        go2rtc_http_auth()


def test_camera_discovery_preserves_special_password_characters_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ffmpeg_inputs: list[str] = []
    go2rtc_sources: list[str] = []

    async def capture(url: str):
        ffmpeg_inputs.append(url)
        return True, b"jpeg", ""

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def patch(self, _url: str, *, params: dict[str, str]):
            go2rtc_sources.append(params["src"])
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(
        camera_discovery,
        "resolve_and_pin",
        lambda _ip, _port: ("192.168.1.20", 554),
    )
    monkeypatch.setattr(
        camera_discovery,
        "check_camera_online",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(snapshot_service, "capture_snapshot", capture)
    monkeypatch.setattr(camera_discovery.httpx, "AsyncClient", lambda **_kwargs: Client())

    result = asyncio.run(
        camera_discovery.detect_camera_stream(
            ip="192.168.1.20",
            port=554,
            username="camera@example",
            password="p@ss&word$[]",
            brand="generic",
            logger=camera_discovery.logging.getLogger("test"),
        )
    )

    assert result["success"] is True
    assert go2rtc_sources[0].startswith(
        "rtsp://camera%40example:p%40ss%26word%24%5B%5D@192.168.1.20:554/"
    )
    assert ffmpeg_inputs == ["rtsp://127.0.0.1:8554/easypi_discovery"]
    assert "p%40ss" not in ffmpeg_inputs[0]
    assert go2rtc_sources[-1] == camera_discovery.GO2RTC_DISABLED_SOURCE


def test_camera_discovery_tries_explicit_path_before_generic_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    go2rtc_sources: list[str] = []

    async def capture(_url: str):
        return True, b"jpeg", ""

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def patch(self, _url: str, *, params: dict[str, str]):
            go2rtc_sources.append(params["src"])
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(camera_discovery, "resolve_and_pin", lambda _ip, _port: ("192.168.1.20", 554))
    monkeypatch.setattr(camera_discovery, "check_camera_online", lambda *_args, **_kwargs: True)
    monkeypatch.setattr(snapshot_service, "capture_snapshot", capture)
    monkeypatch.setattr(camera_discovery.httpx, "AsyncClient", lambda **_kwargs: Client())

    result = asyncio.run(
        camera_discovery.detect_camera_stream(
            ip="192.168.1.20",
            port=554,
            username="admin",
            password="secret",
            brand="generic",
            preferred_path="/ch0",
            logger=camera_discovery.logging.getLogger("test"),
        )
    )

    assert result["success"] is True
    assert result["rtspPath"] == "/ch0"
    assert result["attempts"] == 1
    assert go2rtc_sources[0].endswith("/ch0#transport=tcp")
    assert go2rtc_sources[-1] == camera_discovery.GO2RTC_DISABLED_SOURCE


def test_generic_camera_discovery_prefers_ch0_when_path_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    go2rtc_sources: list[str] = []

    async def capture(_url: str):
        return True, b"jpeg", ""

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def patch(self, _url: str, *, params: dict[str, str]):
            go2rtc_sources.append(params["src"])
            return SimpleNamespace(status_code=200)

    monkeypatch.setattr(
        camera_discovery,
        "resolve_and_pin",
        lambda _ip, _port: ("192.168.1.20", 554),
    )
    monkeypatch.setattr(
        camera_discovery,
        "check_camera_online",
        lambda *_args, **_kwargs: True,
    )
    monkeypatch.setattr(snapshot_service, "capture_snapshot", capture)
    monkeypatch.setattr(camera_discovery.httpx, "AsyncClient", lambda **_kwargs: Client())

    result = asyncio.run(
        camera_discovery.detect_camera_stream(
            ip="192.168.1.20",
            port=554,
            username="root",
            password="secret",
            brand="generic",
            logger=camera_discovery.logging.getLogger("test"),
        )
    )

    assert result["success"] is True
    assert result["rtspPath"] == "/ch0"
    assert result["attempts"] == 1
    assert go2rtc_sources[0].endswith("/ch0#transport=tcp")
    assert go2rtc_sources[-1] == camera_discovery.GO2RTC_DISABLED_SOURCE


def test_camera_discovery_rejects_blocked_target_before_connecting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        camera_discovery,
        "resolve_and_pin",
        lambda _ip, _port: (_ for _ in ()).throw(PTZSecurityError("loopback")),
    )
    monkeypatch.setattr(
        camera_discovery,
        "check_camera_online",
        lambda *_args, **_kwargs: pytest.fail("blocked target was contacted"),
    )

    result = asyncio.run(
        camera_discovery.detect_camera_stream(
            ip="127.0.0.1",
            port=8000,
            username="admin",
            password="secret",
            brand=None,
            logger=camera_discovery.logging.getLogger("test"),
        )
    )

    assert result == {
        "success": False,
        "error": "Only allowed local-network camera targets are supported",
    }
