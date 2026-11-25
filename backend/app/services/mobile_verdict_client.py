"""Ask NetProtection for a full-policy decision on behalf of a linked phone.

NetProtection serves the question on a Unix socket in its data directory
(`easypi_netprotection.mobile_verdict`), reachable only by the EasyPi service
account. The phone's identity is its enrolled home-tunnel address; NetProtection
refuses any other address.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

import httpx

from app.core.paths import get_netprotection_data_dir

logger = logging.getLogger(__name__)

SOCKET_NAME = "verdict.sock"
VERDICT_URL = "http://netprotection/v1/mobile-verdict"
TIMEOUT_SECONDS = 3.0
# How long a phone may reuse one decision. Policy edits do not wait for it:
# the phone drops its cache when the policy version below changes. It still
# bounds time-driven changes such as a schedule starting.
MOBILE_DECISION_TTL_SECONDS = 60
# Files whose content decides a phone's domains: profiles and their device
# bindings, managed clients, global settings, schedules, the allowlist and
# the effective blocklist.
POLICY_FILES = (
    "profiles.json",
    "bindings.json",
    "clients.json",
    "settings.json",
    "schedules.json",
    "allowlist.txt",
    "effective_blocklist.txt",
)


@dataclass(frozen=True)
class MobileVerdict:
    blocked: bool
    status: str


def policy_version() -> str:
    """Short fingerprint of the policy files; changes whenever one changes.

    Only file metadata is read, so it is cheap enough for every phone check.
    A missing file contributes its absence, so creating or removing one also
    changes the version.
    """
    data_dir = get_netprotection_data_dir()
    digest = hashlib.sha256()
    for name in POLICY_FILES:
        try:
            info = (data_dir / name).stat()
            digest.update(f"{name}:{info.st_mtime_ns}:{info.st_size};".encode())
        except OSError:
            digest.update(f"{name}:-;".encode())
    return digest.hexdigest()[:16]


def full_policy_verdict(domain: str, client_ip: str) -> MobileVerdict | None:
    """Return NetProtection's decision, or None when it is unavailable."""
    socket_path = get_netprotection_data_dir() / SOCKET_NAME
    if not socket_path.exists():
        return None
    try:
        with httpx.Client(
            transport=httpx.HTTPTransport(uds=str(socket_path)),
            timeout=TIMEOUT_SECONDS,
        ) as client:
            response = client.post(
                VERDICT_URL, json={"domain": domain, "client_ip": client_ip}
            )
    except httpx.HTTPError as exc:
        logger.warning("NetProtection mobile verdict unavailable: %s", exc)
        return None
    if response.status_code != 200:
        logger.warning(
            "NetProtection refused a mobile verdict (HTTP %s)", response.status_code
        )
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    blocked = payload.get("blocked") if isinstance(payload, dict) else None
    status = payload.get("status") if isinstance(payload, dict) else None
    if not isinstance(blocked, bool) or not isinstance(status, str):
        return None
    return MobileVerdict(blocked=blocked, status=status)
