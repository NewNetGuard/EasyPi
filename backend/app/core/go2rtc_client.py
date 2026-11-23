"""Credentials for EasyPi's loopback-only go2rtc control boundary."""
from __future__ import annotations

import base64
import os


def go2rtc_http_auth() -> tuple[str, str] | None:
    """Return internal Basic-auth credentials when provisioned by installer."""
    username = os.getenv("GO2RTC_API_USERNAME", "")
    password = os.getenv("GO2RTC_API_PASSWORD", "")
    if not username and not password:
        return None
    if not username or not password:
        raise RuntimeError("Incomplete go2rtc API credentials")
    return username, password


def go2rtc_authorization_header() -> str | None:
    """Build the Authorization header for non-httpx clients."""
    credentials = go2rtc_http_auth()
    if credentials is None:
        return None
    raw = f"{credentials[0]}:{credentials[1]}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")
