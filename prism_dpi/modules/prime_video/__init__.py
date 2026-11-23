"""Modular Prime Video flow policy for PRISM DPI."""

from .policy import (
    PRIME_VIDEO_SERVER_NAMES,
    PRIME_VIDEO_SERVER_SUFFIXES,
    PrimeVideoFlowPolicy,
)

__all__ = [
    "PRIME_VIDEO_SERVER_NAMES",
    "PRIME_VIDEO_SERVER_SUFFIXES",
    "PrimeVideoFlowPolicy",
]
