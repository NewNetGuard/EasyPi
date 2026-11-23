"""Policy-gated Xbox Live TLS and QUIC flow classification.

Only dedicated Xbox and Game Pass zones are actionable. Shared Microsoft,
Azure, telemetry, identity, and content-delivery zones are excluded.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from prism_dpi.service_flow_policy import ExactServiceFlowPolicy


XBOX_SERVER_SUFFIXES = (
    "xbox.com",
    "xboxlive.com",
    "xboxservices.com",
    "gamepass.com",
)
XBOX_POLICY_NAMES = frozenset({"xbox"})


class XboxFlowPolicy(ExactServiceFlowPolicy):
    """Validate fresh Xbox Live TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        super().__init__(
            devices_path,
            policy="xbox",
            policy_names=XBOX_POLICY_NAMES,
            server_suffixes=XBOX_SERVER_SUFFIXES,
            address_resolver=address_resolver,
        )


__all__ = ["XBOX_SERVER_SUFFIXES", "XboxFlowPolicy"]
