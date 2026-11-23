"""Google Mobile Ads mediation and creative-delivery DPI detector."""

from .behavior import (
    AD_CYCLE_WINDOW_SECONDS,
    TRACKING_BURST_WINDOW_SECONDS,
    AdCycleMatch,
    FlowStage,
    GoogleAdsFlowObservation,
    detect_ad_cycle,
    find_ad_cycles,
)
from .signatures import (
    APP_ID,
    GOOGLE_GMA_CONTROL,
    SIGNATURES,
    TRANSPORT_SIGNATURES,
    VRMADS_ADAPTER_DELIVERY,
    VRMADS_MEDIA_DELIVERY,
    VRMADS_TLS_SIGNATURE,
    LearnedTransportSignature,
)

__all__ = [
    "AD_CYCLE_WINDOW_SECONDS",
    "APP_ID",
    "GOOGLE_GMA_CONTROL",
    "SIGNATURES",
    "TRACKING_BURST_WINDOW_SECONDS",
    "TRANSPORT_SIGNATURES",
    "VRMADS_ADAPTER_DELIVERY",
    "VRMADS_MEDIA_DELIVERY",
    "VRMADS_TLS_SIGNATURE",
    "AdCycleMatch",
    "FlowStage",
    "GoogleAdsFlowObservation",
    "LearnedTransportSignature",
    "detect_ad_cycle",
    "find_ad_cycles",
]
