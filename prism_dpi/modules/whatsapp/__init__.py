"""WhatsApp detection module for Prism DPI."""

from .signatures import (
    CHATD_SIGNATURE,
    HTTP_FALLBACK_SIGNATURE,
    SIGNATURE,
    SIGNATURES,
)

__all__ = [
    "CHATD_SIGNATURE",
    "HTTP_FALLBACK_SIGNATURE",
    "SIGNATURE",
    "SIGNATURES",
]
