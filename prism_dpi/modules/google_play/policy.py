"""Policy-gated Google Play TLS and QUIC flow classification.

Only Play Store control-plane and media names are actionable. Shared Android,
Firebase, Google API, download CDN, and connectivity services are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


GOOGLE_PLAY_SERVER_SUFFIXES = ("play.google.com",)
GOOGLE_PLAY_SERVER_NAMES = frozenset(
    {
        "play.googleapis.com",
        "play-fe.googleapis.com",
        "play-lh.googleusercontent.com",
        "prod-lt-playstoregatewayadapter-pa.googleapis.com",
    }
)
GOOGLE_PLAY_POLICY_NAMES = frozenset({"google_play"})


class GooglePlayFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh Google Play flows against the current device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="google_play",
            policy_names=GOOGLE_PLAY_POLICY_NAMES,
            server_suffixes=GOOGLE_PLAY_SERVER_SUFFIXES,
            server_names=GOOGLE_PLAY_SERVER_NAMES,
            address_resolver=address_resolver,
        )


__all__ = [
    "GOOGLE_PLAY_SERVER_NAMES",
    "GOOGLE_PLAY_SERVER_SUFFIXES",
    "GooglePlayFlowPolicy",
]
