"""Minimal, hardened ONVIF SOAP client (httpx + defusedxml -- no zeep/lxml).

Only what the PTZ adapter needs: build a SOAP 1.2 request with an optional
WS-Security UsernameToken (password digest -- the password is never sent in the
clear), POST it to a camera service URL that has passed the SSRF guard, and parse
the reply with a defused XML parser (no DTD / external entities / entity
expansion). Responses are size-capped. Nothing here is ever logged with secrets.
"""
from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx

try:  # defused parser: blocks XXE / entity-expansion. Required for untrusted XML.
    from defusedxml.ElementTree import fromstring as _safe_fromstring
except Exception:  # pragma: no cover - defusedxml is a dependency; fail closed if absent
    _safe_fromstring = None

from app.services.ptz.errors import PTZAuthError, PTZError, PTZUnreachable, scrub
from app.services.ptz.ssrf import validate_ip, validate_port

MAX_RESPONSE_BYTES = 512 * 1024

SOAP_ENV = "http://www.w3.org/2003/05/soap-envelope"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
PW_DIGEST = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
)
B64 = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-soap-message-security-1.0#Base64Binary"
)

NS = {
    "s": SOAP_ENV,
    "tds": "http://www.onvif.org/ver10/device/wsdl",
    "trt": "http://www.onvif.org/ver10/media/wsdl",
    "tptz": "http://www.onvif.org/ver20/ptz/wsdl",
    "tt": "http://www.onvif.org/ver10/schema",
    "wsse": WSSE,
    "wsu": WSU,
}


def _esc(text: str) -> str:
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _security_header(username: str, password: str) -> str:
    nonce = secrets.token_bytes(16)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # ONVIF's WS-Security UsernameToken PasswordDigest formula mandates SHA-1.
    # This is protocol interoperability, not a locally selected password hash;
    # the nonce is generated afresh for every request and the password is never sent.
    digest = base64.b64encode(
        hashlib.sha1(  # nosec B324
            nonce + created.encode("utf-8") + password.encode("utf-8")
        ).digest()
    ).decode()
    return (
        f'<s:Header><wsse:Security s:mustUnderstand="1" xmlns:wsse="{WSSE}" xmlns:wsu="{WSU}">'
        "<wsse:UsernameToken>"
        f"<wsse:Username>{_esc(username)}</wsse:Username>"
        f'<wsse:Password Type="{PW_DIGEST}">{digest}</wsse:Password>'
        f'<wsse:Nonce EncodingType="{B64}">{base64.b64encode(nonce).decode()}</wsse:Nonce>'
        f"<wsu:Created>{created}</wsu:Created>"
        "</wsse:UsernameToken></wsse:Security></s:Header>"
    )


def build_envelope(body_inner: str, username: Optional[str], password: Optional[str]) -> bytes:
    header = _security_header(username, password) if (username and password) else ""
    env = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<s:Envelope xmlns:s="{SOAP_ENV}" '
        f'xmlns:tds="{NS["tds"]}" xmlns:trt="{NS["trt"]}" '
        f'xmlns:tptz="{NS["tptz"]}" xmlns:tt="{NS["tt"]}">'
        f"{header}<s:Body>{body_inner}</s:Body></s:Envelope>"
    )
    return env.encode("utf-8")


def _make_client(timeout: float) -> httpx.Client:
    """Module-level so tests can substitute a MockTransport-backed client."""
    return httpx.Client(timeout=timeout, follow_redirects=False)


def _command_timeout() -> float:
    try:
        from config import get_settings

        return float(get_settings().PTZ_COMMAND_TIMEOUT_S)
    except Exception:
        return 4.0


def _validate_service_url(url: str) -> None:
    parts = urlsplit(url)
    host = (parts.hostname or "").strip()
    validate_ip(host)  # SSRF: LAN-only, never EasyPi itself; host must be an IP
    validate_port(parts.port or 80)


def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    """Read at most limit decoded bytes without buffering an oversized reply."""
    length = response.headers.get("content-length")
    if length:
        try:
            if int(length) > limit:
                raise PTZError("camera response is too large")
        except ValueError:
            pass
    content = bytearray()
    for chunk in response.iter_bytes(chunk_size=64 * 1024):
        if len(content) + len(chunk) > limit:
            raise PTZError("camera response is too large")
        content.extend(chunk)
    return bytes(content)


def call(
    service_url: str,
    action: str,
    body_inner: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    client: Optional[httpx.Client] = None,
):
    """POST a SOAP request and return the parsed (defused) root Element.

    Raises PTZAuthError on 401/403 or a SOAP auth fault, PTZUnreachable on a
    transport error, PTZError on other faults. The camera address must already
    resolve to an allowed LAN IP (see :func:`_validate_service_url`).
    """
    if _safe_fromstring is None:
        raise PTZError("secure XML parser unavailable")
    _validate_service_url(service_url)
    envelope = build_envelope(body_inner, username, password)
    own_client = client is None
    cli = client or _make_client(_command_timeout())
    try:
        try:
            request = cli.build_request(
                "POST",
                service_url,
                content=envelope,
                headers={"Content-Type": 'application/soap+xml; charset=utf-8; action="%s"' % action},
            )
            resp = cli.send(request, stream=True)
        except httpx.HTTPError as e:
            raise PTZUnreachable("camera unreachable: %s" % scrub(str(e)))
        try:
            if resp.status_code in (401, 403):
                raise PTZAuthError("camera rejected ONVIF credentials")
            try:
                content = _read_bounded(resp, MAX_RESPONSE_BYTES)
            except httpx.HTTPError as e:
                raise PTZUnreachable("camera response failed: %s" % scrub(str(e)))
            try:
                root = _safe_fromstring(content)
            except Exception:
                raise PTZError("invalid XML from camera")
            fault = root.find(".//{%s}Fault" % SOAP_ENV)
            if fault is not None:
                text_el = fault.find(".//{%s}Text" % SOAP_ENV)
                reason = (text_el.text if text_el is not None else "") or "SOAP fault"
                low = reason.lower()
                if "auth" in low or "not authorized" in low or "sender not authorized" in low:
                    raise PTZAuthError("camera authorization failed")
                raise PTZError("camera fault: %s" % scrub(reason)[:120])
            if resp.status_code >= 400:
                raise PTZError("camera HTTP error (%d)" % resp.status_code)
            return root
        finally:
            resp.close()
    finally:
        if own_client:
            cli.close()


__all__ = ["call", "build_envelope", "NS", "MAX_RESPONSE_BYTES"]
