from __future__ import annotations

from pathlib import Path
from io import BytesIO

import pytest
from app.api.deps import require_admin
from app.api.v1.endpoints import files, picloud
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def picloud_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    app = FastAPI()
    app.include_router(picloud.router, prefix="/picloud")
    app.dependency_overrides[require_admin] = lambda: object()
    app.dependency_overrides[picloud._authorize_video] = lambda: None
    monkeypatch.setattr(picloud, "check_rate_limit", lambda *_args, **_kwargs: None)
    return TestClient(app)


@pytest.mark.parametrize(
    ("method", "url", "json_body"),
    [
        ("get", "/picloud/share/public-token", None),
        ("post", "/picloud/share-access/protected-token", {"password": "password123"}),
        ("get", "/picloud/file/Documents/attack.html/download", None),
    ],
)
@pytest.mark.parametrize("filename", ["attack.html", "attack.js", "attack.svg"])
def test_picloud_active_files_are_forced_to_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    picloud_client: TestClient,
    method: str,
    url: str,
    json_body: dict[str, str] | None,
    filename: str,
) -> None:
    payload = b"<script>window.top.pwned=true</script>"
    active_file = tmp_path / filename
    active_file.write_bytes(payload)
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "open_share",
        lambda _token, _password: (
            BytesIO(payload),
            active_file,
            len(payload),
        ),
    )
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "resolve_file",
        lambda _file_id: active_file,
    )

    response = picloud_client.request(method, url, json=json_body)

    assert response.status_code == 200
    assert response.content == payload
    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "private, no-store"


def test_picloud_never_falls_back_to_inline_source_svg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    picloud_client: TestClient,
) -> None:
    source = tmp_path / "active.svg"
    source.write_text("<svg onload='window.top.pwned=true'/>", encoding="utf-8")
    monkeypatch.setattr(picloud.pi_cloud_service, "resolve_file", lambda _file_id: source)
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "_get_file_category",
        lambda _mime, _name: "photo",
    )
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "_find_thumbnail_path",
        lambda _file_id, _name: None,
    )
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "_generate_thumbnail",
        lambda _path, _file_id: None,
    )

    response = picloud_client.get("/picloud/thumbnail/active.svg")

    assert response.status_code == 404
    assert b"onload" not in response.content


def test_public_share_streams_the_already_opened_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    picloud_client: TestClient,
) -> None:
    path = tmp_path / "shared.txt"
    path.write_bytes(b"new private contents")

    def open_then_replace(_token: str, _password: str | None):
        return BytesIO(b"original shared data"), path, len(b"original shared data")

    monkeypatch.setattr(picloud.pi_cloud_service, "open_share", open_then_replace)

    response = picloud_client.get("/picloud/share/public-token")

    assert response.status_code == 200
    assert response.content == b"original shared data"
    assert b"new private contents" not in response.content


def test_picloud_generated_thumbnail_is_jpeg_with_nosniff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    picloud_client: TestClient,
) -> None:
    source = tmp_path / "source.svg"
    source.write_text("<svg/>", encoding="utf-8")
    thumbnail = tmp_path / "thumbnail.jpg"
    thumbnail.write_bytes(b"jpeg-thumbnail")
    monkeypatch.setattr(picloud.pi_cloud_service, "resolve_file", lambda _file_id: source)
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "_get_file_category",
        lambda _mime, _name: "photo",
    )
    monkeypatch.setattr(
        picloud.pi_cloud_service,
        "_find_thumbnail_path",
        lambda _file_id, _name: thumbnail,
    )

    response = picloud_client.get("/picloud/thumbnail/source.svg")

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "sandbox" in response.headers["content-security-policy"]


def test_files_image_route_rejects_active_svg(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "active.svg"
    source.write_text("<svg onload='window.top.pwned=true'/>", encoding="utf-8")
    monkeypatch.setattr(
        files.files_service,
        "open_binary_file",
        lambda _path: (source.open("rb"), source.stat(), str(source)),
    )
    app = FastAPI()
    app.include_router(files.router)
    app.dependency_overrides[require_admin] = lambda: object()

    response = TestClient(app).get("/files/image", params={"path": str(source)})

    assert response.status_code == 400
    assert b"onload" not in response.content

def test_picloud_video_supports_byte_ranges(tmp_path, monkeypatch, picloud_client):
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"0123456789")
    monkeypatch.setattr(picloud.pi_cloud_service, "resolve_file", lambda _file_id: video)

    response = picloud_client.get("/picloud/video/clip.mp4", headers={"Range": "bytes=2-5"})

    assert response.status_code == 206
    assert response.content == b"2345"
    assert response.headers["content-type"] == "video/mp4"
    assert response.headers["content-range"] == "bytes 2-5/10"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_picloud_video_requires_admin_and_rejects_active_file(tmp_path, monkeypatch, picloud_client):
    source = tmp_path / "page.html"
    source.write_text("<script></script>", encoding="utf-8")
    monkeypatch.setattr(picloud.pi_cloud_service, "resolve_file", lambda _file_id: source)
    assert picloud_client.get("/picloud/video/page.html").status_code == 404

    del picloud_client.app.dependency_overrides[picloud._authorize_video]
    assert picloud_client.get("/picloud/video/page.html").status_code == 401


def test_video_releases_database_before_streaming(tmp_path, monkeypatch, picloud_client):
    video = tmp_path / "clip.mp4"
    video.write_bytes(b"0123456789")
    state = {"closed": False}

    def get_db():
        yield object()
        state["closed"] = True

    class CheckedFileResponse(picloud.FileResponse):
        async def __call__(self, scope, receive, send):
            assert state["closed"]
            await super().__call__(scope, receive, send)

    del picloud_client.app.dependency_overrides[picloud._authorize_video]
    picloud_client.app.dependency_overrides[picloud.get_db] = get_db
    monkeypatch.setattr(picloud, "require_admin", lambda *_args: None)
    monkeypatch.setattr(picloud, "FileResponse", CheckedFileResponse)
    monkeypatch.setattr(picloud.pi_cloud_service, "resolve_file", lambda _file_id: video)
    assert picloud_client.get("/picloud/video/clip.mp4").status_code == 200
