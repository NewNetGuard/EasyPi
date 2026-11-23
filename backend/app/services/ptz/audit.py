"""Structured PTZ audit log — records who did what, without secrets.

High-frequency PTZ commands would spam the operations-event feed, so they go to
a dedicated structured logger instead. Each entry carries user id, camera id,
adapter, command, result and request id — never a password, SOAP body or camera
URL. Any free-text detail is scrubbed before it is written.
"""
from __future__ import annotations

import logging

from app.services.ptz.errors import scrub

logger = logging.getLogger("easypi.ptz.audit")


def audit(
    *,
    user_id,
    camera_id,
    adapter: str,
    command: str,
    result: str,
    request_id: str,
    detail: str = "",
) -> None:
    """Emit one audit line for a PTZ command (secret-free)."""
    suffix = f" detail={scrub(detail)}" if detail else ""
    logger.info(
        "ptz user=%s camera=%s adapter=%s command=%s result=%s request_id=%s%s",
        user_id,
        camera_id,
        adapter,
        command,
        result,
        request_id,
        suffix,
    )


__all__ = ["audit"]
