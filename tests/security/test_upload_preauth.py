from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest
from fastapi import HTTPException, Request, Response

from app.core.csrf import CSRFMiddleware, generate_csrf_token, get_csrf_secret, verify_csrf_token


@pytest.mark.parametrize("content_type", ["multipart/form-data; boundary=test", "application/x-www-form-urlencoded"])
@pytest.mark.parametrize("submitted", [None, "invalid"])
def test_csrf_rejects_before_reading_body(content_type, submitted):
    secret = get_csrf_secret()
    token = generate_csrf_token(secret)
    headers = [(b"content-type", content_type.encode()), (b"cookie", f"csrf_token={token}".encode())]
    if submitted:
        headers.append((b"x-csrf-token", submitted.encode()))

    async def receive():
        pytest.fail("CSRF rejection must not consume any request body")

    async def downstream(_request):
        pytest.fail("Rejected request reached the endpoint")

    request = Request({"type": "http", "method": "POST", "path": "/api/v1/files/upload", "headers": headers}, receive)
    response = asyncio.run(CSRFMiddleware(None, secret=secret).dispatch(request, downstream))
    assert response.status_code == 403
    with pytest.raises(HTTPException) as error:
        asyncio.run(verify_csrf_token(request))
    assert error.value.status_code == 403


def test_csrf_header_allows_form_without_preconsuming_it():
    secret = get_csrf_secret()
    token = generate_csrf_token(secret)
    headers = [(b"content-type", b"multipart/form-data; boundary=test"),
               (b"cookie", f"csrf_token={token}".encode()), (b"x-csrf-token", token.encode())]

    async def receive():
        pytest.fail("Middleware must leave the upload stream to the endpoint")

    async def downstream(_request):
        return Response(status_code=204)

    request = Request({"type": "http", "method": "POST", "path": "/api/v1/files/upload", "headers": headers}, receive)
    assert asyncio.run(CSRFMiddleware(None, secret=secret).dispatch(request, downstream)).status_code == 204
    assert asyncio.run(verify_csrf_token(request)) is True


@pytest.mark.parametrize("template", ["easypi.conf", "easypi-mobile-link.conf"])
def test_every_mobile_upload_listener_has_a_bodyless_token_gate(template):
    text = (Path(__file__).resolve().parents[2] / "templates/nginx" / template).read_text()
    upload = re.search(r"location = /api/v1/mobile/upload \{([^}]+)}", text).group(1)
    assert "auth_request /_easypi_mobile_auth;" in upload
    assert "proxy_request_buffering off;" in upload
    gate = re.search(r"location = /_easypi_mobile_auth \{([^}]+)}", text).group(1)
    for directive in ("internal;", "proxy_method GET;", "proxy_pass_request_body off;",
                      'proxy_set_header Content-Length "";', 'proxy_set_header Transfer-Encoding "";',
                      "proxy_set_header Authorization $http_authorization;", 'proxy_set_header Cookie "";',
                      "client_max_body_size 5G;", "proxy_pass http://127.0.0.1:8000/api/v1/mobile/auth-check;"):
        assert directive in gate
