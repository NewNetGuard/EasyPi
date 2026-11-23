"""Learned transport signatures for Google Mobile Ads traffic stages.

The control-plane hostname below is an observation anchor, not an advertising
verdict. Exact adapter, creative, media, and tracker fingerprints are added only
after positive and negative PCAP validation.
"""

from __future__ import annotations

from dataclasses import dataclass

from ....signatures import TlsClientHelloSignature
from .behavior import FlowStage


APP_ID = "mobile_ads_google"


@dataclass(frozen=True)
class LearnedTransportSignature:
    """Exact selectors that assign a captured flow to an ad-cycle stage."""

    name: str
    source_family: str
    stage: FlowStage
    ports: tuple[int, ...] = (443,)
    server_names: tuple[str, ...] = ()
    tls_fingerprints: tuple[str, ...] = ()
    tls_lineage_fingerprints: tuple[str, ...] = ()
    record_lengths: tuple[int, ...] = ()
    note: str = ""

    def __post_init__(self) -> None:
        if not self.name or not self.name.isascii():
            raise ValueError("signature name must be non-empty ASCII")
        if not self.source_family or not self.source_family.isascii():
            raise ValueError("source_family must be non-empty ASCII")
        if not isinstance(self.stage, FlowStage):
            raise ValueError("stage must be a FlowStage")
        if not self.ports or any(not 1 <= port <= 65_535 for port in self.ports):
            raise ValueError("signature ports must be 1..65535")
        if not (
            self.server_names
            or self.tls_fingerprints
            or self.tls_lineage_fingerprints
            or self.record_lengths
        ):
            raise ValueError("a learned signature requires at least one selector")
        if any(not _valid_server_name(value) for value in self.server_names):
            raise ValueError("server names must be exact lowercase DNS names")
        if any(not _valid_fingerprint(value) for value in self.tls_fingerprints):
            raise ValueError("invalid TLS fingerprint")
        if any(
            not _valid_fingerprint(value) for value in self.tls_lineage_fingerprints
        ):
            raise ValueError("invalid TLS lineage fingerprint")
        if any(not 1 <= value <= 65_535 for value in self.record_lengths):
            raise ValueError("TLS record lengths must be 1..65535")

    def matches(
        self,
        *,
        server_name: str,
        port: int,
        tls_fingerprint: str = "",
        tls_lineage_fingerprint: str = "",
        record_length: int = 0,
    ) -> bool:
        """Match every selector populated by the learned signature."""
        if port not in self.ports:
            return False
        normalized_name = server_name.rstrip(".").lower()
        if self.server_names and normalized_name not in self.server_names:
            return False
        if self.tls_fingerprints and tls_fingerprint not in self.tls_fingerprints:
            return False
        if (
            self.tls_lineage_fingerprints
            and tls_lineage_fingerprint not in self.tls_lineage_fingerprints
        ):
            return False
        if self.record_lengths and record_length not in self.record_lengths:
            return False
        return True


def _valid_server_name(value: str) -> bool:
    if not value or value != value.lower() or len(value) > 253 or not value.isascii():
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


GOOGLE_GMA_CONTROL = LearnedTransportSignature(
    name="google_gma_control",
    source_family="google_gma",
    stage=FlowStage.ADAPTER,
    server_names=("googleads.g.doubleclick.net",),
    note="control-plane anchor only; never sufficient for an ad verdict",
)

VRMADS_ADAPTER_DELIVERY = LearnedTransportSignature(
    name="vrmads_adapter_delivery",
    source_family="vrmads",
    stage=FlowStage.CREATIVE,
    server_names=("allcountries.xinshijueys.com",),
    tls_fingerprints=("30e20a114003bebd",),
    tls_lineage_fingerprints=("c84dbff0c45904b6",),
    record_lengths=(512,),
    note="MAO positive ad window 2026-08-24; follows vrmads control API",
)

VRMADS_MEDIA_DELIVERY = LearnedTransportSignature(
    name="vrmads_media_delivery",
    source_family="vrmads",
    stage=FlowStage.MEDIA,
    server_names=("down.xinshijueys.com",),
    tls_fingerprints=("30e20a114003bebd",),
    tls_lineage_fingerprints=("c84dbff0c45904b6",),
    record_lengths=(512,),
    note="MAO positive ad window 2026-08-24; 57 KB media response",
)

TRANSPORT_SIGNATURES = (
    GOOGLE_GMA_CONTROL,
    VRMADS_ADAPTER_DELIVERY,
    VRMADS_MEDIA_DELIVERY,
)

# The kernel can verify the exact ClientHello record shape and exact SNI. The
# richer fingerprint and lineage selectors above remain available to FlowGraph.
VRMADS_TLS_SIGNATURE = TlsClientHelloSignature(
    app=APP_ID,
    ports=(443,),
    record_length=512,
    server_names=(
        "allcountries.xinshijueys.com",
        "down.xinshijueys.com",
    ),
    note="validated MAO ad-delivery pair; exact SNI and compact ClientHello",
)

SIGNATURES: tuple[TlsClientHelloSignature, ...] = (VRMADS_TLS_SIGNATURE,)


__all__ = [
    "APP_ID",
    "GOOGLE_GMA_CONTROL",
    "SIGNATURES",
    "TRANSPORT_SIGNATURES",
    "VRMADS_ADAPTER_DELIVERY",
    "VRMADS_MEDIA_DELIVERY",
    "VRMADS_TLS_SIGNATURE",
    "LearnedTransportSignature",
]
