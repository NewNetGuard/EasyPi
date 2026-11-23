"""Temporal operators for Google Mobile Ads mediation traffic.

The detector models a complete advertising cycle rather than treating one SNI,
IP address, or TLS shape as an ad verdict. Transport signatures learned from
captures assign observations to stages; this module verifies their causal order.

No function in this module authorizes packet blocking. A caller must still apply
device policy and validate every candidate flow before enforcement.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Iterable


AD_CYCLE_WINDOW_SECONDS = 20.0
ADAPTER_FANOUT_WINDOW_SECONDS = 3.0
TRACKING_BURST_WINDOW_SECONDS = 8.0
MIN_TRACKING_EVENTS = 2
MIN_DISTINCT_SOURCE_FAMILIES = 2


class FlowStage(str, Enum):
    """Role of one flow inside a learned mobile-advertising cycle."""

    ADAPTER = "adapter"
    CREATIVE = "creative"
    MEDIA = "media"
    TRACKER = "tracker"
    WEBVIEW = "webview"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class GoogleAdsFlowObservation:
    """One transport observation classified by a learned module signature."""

    timestamp: float
    flow_id: str
    source_family: str
    stage: FlowStage
    server_name: str = ""
    tls_fingerprint: str = ""
    client_payload_bytes: int = 0
    server_payload_bytes: int = 0

    def __post_init__(self) -> None:
        if not math.isfinite(self.timestamp) or self.timestamp < 0:
            raise ValueError("timestamp must be a finite non-negative value")
        if not self.flow_id or not self.flow_id.isascii():
            raise ValueError("flow_id must be a non-empty ASCII value")
        if not _valid_family(self.source_family):
            raise ValueError("source_family must be a normalized ASCII label")
        if not isinstance(self.stage, FlowStage):
            raise ValueError("stage must be a FlowStage")
        if self.server_name and not _valid_server_name(self.server_name):
            raise ValueError("server_name must be an exact lowercase DNS name")
        if self.tls_fingerprint and not _valid_fingerprint(self.tls_fingerprint):
            raise ValueError("tls_fingerprint must be 16 lowercase hex characters")
        if self.client_payload_bytes < 0 or self.server_payload_bytes < 0:
            raise ValueError("payload byte counters must be non-negative")


@dataclass(frozen=True)
class AdCycleMatch:
    """Evidence that several classified flows form one advertising cycle."""

    started_at: float
    ended_at: float
    confidence: float
    evidence: tuple[str, ...]
    flow_ids: tuple[str, ...]
    source_families: tuple[str, ...]


def detect_ad_cycle(
    observations: Iterable[GoogleAdsFlowObservation],
    *,
    window_seconds: float = AD_CYCLE_WINDOW_SECONDS,
) -> AdCycleMatch | None:
    """Return a match when classified flows form a complete ad-delivery cycle.

    A complete cycle requires an entry stage (mediation adapter or WebView ad
    event), creative/media delivery, and a post-delivery tracking burst. Extra
    evidence distinguishes bidding-style fan-out from sequential waterfall use.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    ordered = _deduplicated_observations(observations)
    if not ordered:
        return None

    for index, first in enumerate(ordered):
        window = tuple(
            observation
            for observation in ordered[index:]
            if observation.timestamp - first.timestamp <= window_seconds
        )
        match = _match_window(window)
        if match is not None:
            return match
    return None


def find_ad_cycles(
    observations: Iterable[GoogleAdsFlowObservation],
    *,
    window_seconds: float = AD_CYCLE_WINDOW_SECONDS,
) -> tuple[AdCycleMatch, ...]:
    """Return non-overlapping advertising cycles in timestamp order."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")

    remaining = list(_deduplicated_observations(observations))
    matches: list[AdCycleMatch] = []
    while remaining:
        match = detect_ad_cycle(remaining, window_seconds=window_seconds)
        if match is None:
            break
        matches.append(match)
        matched = set(match.flow_ids)
        remaining = [item for item in remaining if item.flow_id not in matched]
    return tuple(matches)


def _match_window(
    window: tuple[GoogleAdsFlowObservation, ...],
) -> AdCycleMatch | None:
    entry = tuple(
        item for item in window if item.stage in {FlowStage.ADAPTER, FlowStage.WEBVIEW}
    )
    if not entry:
        return None

    first_entry = entry[0]
    content = tuple(
        item
        for item in window
        if item.timestamp >= first_entry.timestamp
        and item.stage in {FlowStage.CREATIVE, FlowStage.MEDIA}
    )
    if not content:
        return None

    first_content = content[0]
    trackers = tuple(
        item
        for item in window
        if item.stage is FlowStage.TRACKER
        and first_content.timestamp <= item.timestamp
        and item.timestamp - first_content.timestamp <= TRACKING_BURST_WINDOW_SECONDS
    )
    if len(trackers) < MIN_TRACKING_EVENTS:
        return None

    chain = tuple(
        item
        for item in window
        if first_entry.timestamp <= item.timestamp <= trackers[-1].timestamp
        and item.stage is not FlowStage.UNKNOWN
    )
    source_families = tuple(sorted({item.source_family for item in chain}))
    if len(source_families) < MIN_DISTINCT_SOURCE_FAMILIES:
        return None

    adapters = tuple(item for item in entry if item.stage is FlowStage.ADAPTER)
    webview = any(item.stage is FlowStage.WEBVIEW for item in entry)
    evidence: list[str] = []
    confidence = 0.0

    if adapters:
        evidence.append("mediation_adapter_entry")
        confidence += 0.15
    if webview:
        evidence.append("webview_ad_event")
        confidence += 0.20

    adapter_sources = {item.source_family for item in adapters}
    if (
        len(adapter_sources) >= 2
        and adapters[-1].timestamp - adapters[0].timestamp
        <= ADAPTER_FANOUT_WINDOW_SECONDS
    ):
        evidence.append("adapter_fanout")
        confidence += 0.15

    if len(adapters) >= 3 and adapters[-1].timestamp - adapters[0].timestamp > 0.20:
        evidence.append("waterfall_transition")
        confidence += 0.10

    evidence.append("creative_delivery")
    confidence += 0.25
    if any(item.stage is FlowStage.MEDIA for item in content):
        evidence.append("media_delivery")
        confidence += 0.05

    evidence.append("post_delivery_tracking_burst")
    confidence += 0.25
    if len(source_families) >= 3:
        evidence.append("cross_source_chain")
        confidence += 0.10

    confidence = min(confidence, 1.0)
    if confidence < 0.70:
        return None

    return AdCycleMatch(
        started_at=chain[0].timestamp,
        ended_at=chain[-1].timestamp,
        confidence=confidence,
        evidence=tuple(evidence),
        flow_ids=tuple(item.flow_id for item in chain),
        source_families=source_families,
    )


def _deduplicated_observations(
    observations: Iterable[GoogleAdsFlowObservation],
) -> tuple[GoogleAdsFlowObservation, ...]:
    by_flow: dict[str, GoogleAdsFlowObservation] = {}
    for observation in observations:
        if not isinstance(observation, GoogleAdsFlowObservation):
            raise TypeError("observations must contain GoogleAdsFlowObservation values")
        previous = by_flow.get(observation.flow_id)
        if previous is None or (
            observation.client_payload_bytes + observation.server_payload_bytes
            >= previous.client_payload_bytes + previous.server_payload_bytes
        ):
            by_flow[observation.flow_id] = observation
    return tuple(
        sorted(by_flow.values(), key=lambda item: (item.timestamp, item.flow_id))
    )


def _valid_family(value: str) -> bool:
    return (
        bool(value)
        and len(value) <= 64
        and value.isascii()
        and all(char.isalnum() or char in {"_", "-"} for char in value)
    )


def _valid_server_name(value: str) -> bool:
    if value != value.lower() or len(value) > 253 or not value.isascii():
        return False
    labels = value.split(".")
    return not any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    )


def _valid_fingerprint(value: str) -> bool:
    if len(value) != 16 or value != value.lower():
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


__all__ = [
    "AD_CYCLE_WINDOW_SECONDS",
    "TRACKING_BURST_WINDOW_SECONDS",
    "AdCycleMatch",
    "FlowStage",
    "GoogleAdsFlowObservation",
    "detect_ad_cycle",
    "find_ad_cycles",
]
