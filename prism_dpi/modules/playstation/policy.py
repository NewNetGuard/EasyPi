"""Policy-gated PlayStation TLS and QUIC flow classification.

Only dedicated PlayStation Network zones are actionable. Shared Sony,
generic CDN, cloud, telemetry, and corporate zones are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


PLAYSTATION_SERVER_SUFFIXES = (
    "playstation.com",
    "playstation.net",
    "playstationnetwork.com",
    "sonyentertainmentnetwork.com",
)
PLAYSTATION_POLICY_NAMES = frozenset({"playstation"})


class PlayStationFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh PlayStation TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="playstation",
            policy_names=PLAYSTATION_POLICY_NAMES,
            server_suffixes=PLAYSTATION_SERVER_SUFFIXES,
            address_resolver=address_resolver,
        )


__all__ = ["PLAYSTATION_SERVER_SUFFIXES", "PlayStationFlowPolicy"]
