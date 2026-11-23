"""Policy-gated Apple Music TLS and QUIC flow classification.

The active boundary is deliberately limited to Apple Music's dedicated zone.
Shared Apple zones such as itunes.apple.com and mzstatic.com are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


APPLE_MUSIC_SERVER_SUFFIXES = ("music.apple.com",)
APPLE_MUSIC_POLICY_NAMES = frozenset({"apple_music"})


class AppleMusicFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh Apple Music TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="apple_music",
            policy_names=APPLE_MUSIC_POLICY_NAMES,
            server_suffixes=APPLE_MUSIC_SERVER_SUFFIXES,
            address_resolver=address_resolver,
        )


__all__ = ["APPLE_MUSIC_SERVER_SUFFIXES", "AppleMusicFlowPolicy"]
