"""Policy-gated SoundCloud TLS and QUIC flow classification.

Only SoundCloud-owned application and content-delivery zones are actionable.
Third-party consent, analytics, feature-flag, and generic CDN zones are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


SOUNDCLOUD_SERVER_SUFFIXES = (
    "soundcloud.com",
    "sndcdn.com",
)
SOUNDCLOUD_POLICY_NAMES = frozenset({"soundcloud"})


class SoundCloudFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh SoundCloud TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="soundcloud",
            policy_names=SOUNDCLOUD_POLICY_NAMES,
            server_suffixes=SOUNDCLOUD_SERVER_SUFFIXES,
            address_resolver=address_resolver,
        )


__all__ = ["SOUNDCLOUD_SERVER_SUFFIXES", "SoundCloudFlowPolicy"]
