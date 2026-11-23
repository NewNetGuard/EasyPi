"""Regressions for the browser-to-go2rtc authorization boundary."""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.v1.endpoints.auth_components import profile
from app.api.v1.endpoints.camera_helpers import normalize_stream_name
from app.core.go2rtc_proxy import validate_go2rtc_proxy_request


@pytest.mark.parametrize("uri,method", [
    ("/go2rtc/api/streams?name=Hall&src=rtsp://127.0.0.1/test", "PATCH"),
    ("/go2rtc/api/streams?src=Hall", "DELETE"),
    ("/go2rtc/api/streams", "GET"),
    ("/go2rtc/api/config", "GET"),
    ("/go2rtc/api/restart", "POST"),
    ("/go2rtc/api/webrtc?src=Hall", "POST"),
    ("/go2rtc/api/ws?src=rtsp%3A%2F%2F127.0.0.1%2Ftest", "GET"),
    ("/go2rtc/api/ws?src=exec%3Acommand", "GET"),
    ("/go2rtc/api/ws?src=Hall&name=changed", "GET"),
    ("/go2rtc/api/ws?src=Hall&dst=outside", "GET"),
    ("/go2rtc/api/ws?src=Hall&src=other", "GET"),
    ("/go2rtc/api/ws?src=Hall&%73rc=other", "GET"),
    ("/go2rtc/api/ws?src=Hall&x=1&y=2", "GET"),
    ("/go2rtc/api/ws?src=Hall", "POST"),
    ("/go2rtc/api/ws?src=missing", "GET"),
    ("/go2rtc/api/ws", "GET"),
    ("/go2rtc/stream.html", "POST"),
    ("/go2rtc/api%2Fws?src=Hall", "GET"),
    ("/go2rtc/api/ws?src=Hall#fragment", "GET"),
    ("https://other/go2rtc/api/ws?src=Hall", "GET"),
    ("", ""),
])
def test_go2rtc_proxy_rejects_management_and_unapproved_sources(uri, method):
    with pytest.raises(ValueError):
        validate_go2rtc_proxy_request(uri, method, {"Hall"})


@pytest.mark.parametrize("uri,method", [
    ("/go2rtc/stream.html?src=Hall&mode=mse&background=false", "GET"),
    ("/go2rtc/video-stream.js", "GET"),
    ("/go2rtc/video-rtc.js", "HEAD"),
    ("/go2rtc/api/ws?src=Hall", "GET"),
    ("/go2rtc/api/ws?src=%48all", "GET"),
])
def test_go2rtc_proxy_rejects_former_direct_playback(uri, method):
    with pytest.raises(ValueError, match="Direct go2rtc access is disabled"):
        validate_go2rtc_proxy_request(uri, method, {"Hall"})


def test_legacy_go2rtc_auth_endpoint_fails_closed():
    class DB:
        def query(self, *_columns):
            return self

        def all(self):
            return [("Front Door", "55f28a37-9f0b-421d-a731-013388d92ef1")]

    app = FastAPI()
    app.include_router(profile.router)
    app.dependency_overrides[profile.get_db] = DB
    app.dependency_overrides[profile.get_authenticated_user] = lambda: SimpleNamespace(id=7, role="user")
    with TestClient(app) as client:
        stream_name = normalize_stream_name(
            "Front Door", "55f28a37-9f0b-421d-a731-013388d92ef1"
        )
        headers = {
            "X-Original-URI": f"/go2rtc/api/ws?src={stream_name}",
            "X-Original-Method": "GET",
        }
        assert client.get("/auth/go2rtc-check", headers=headers).status_code == 403
        headers["X-Original-URI"] = "/go2rtc/api/ws?src=other_camera"
        assert client.get("/auth/go2rtc-check", headers=headers).status_code == 403
        headers["X-Original-URI"] = f"/go2rtc/api/streams?src={stream_name}"
        headers["X-Original-Method"] = "DELETE"
        assert client.get("/auth/go2rtc-check", headers=headers).status_code == 403

        app.dependency_overrides.pop(profile.get_authenticated_user)
        assert client.get("/auth/go2rtc-check", headers=headers).status_code == 401


def test_camera_stream_keys_do_not_collide_after_name_normalization():
    first = normalize_stream_name("Front Door", "aaaaaaaa-0000-0000-0000-000000000001")
    second = normalize_stream_name("Front/Door", "bbbbbbbb-0000-0000-0000-000000000002")

    assert first != second
    assert len(first) <= 64
    assert len(second) <= 64
