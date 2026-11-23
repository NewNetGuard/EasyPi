"""Policy-gated Deezer TLS and QUIC flow classification.

Only Deezer-owned application and content-delivery zones are actionable.
Generic cloud, CDN, consent-provider, and analytics zones are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


DEEZER_SERVER_SUFFIXES = (
    "deezer.com",
    "dzcdn.net",
)
DEEZER_POLICY_NAMES = frozenset({"deezer"})


class DeezerFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh Deezer TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="deezer",
            policy_names=DEEZER_POLICY_NAMES,
            server_suffixes=DEEZER_SERVER_SUFFIXES,
            address_resolver=address_resolver,
        )


__all__ = ["DEEZER_SERVER_SUFFIXES", "DeezerFlowPolicy"]
