"""Fail-closed validator retained for upgrades from the former go2rtc proxy."""
from __future__ import annotations

from collections.abc import Iterable


def validate_go2rtc_proxy_request(
    original_uri: str, original_method: str, stream_names: Iterable[str]
) -> None:
    """Reject every direct browser request; playback uses the revocable WS proxy."""
    del original_uri, original_method, stream_names
    raise ValueError("Direct go2rtc access is disabled")
