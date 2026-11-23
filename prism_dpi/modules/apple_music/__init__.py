"""Apple Music encrypted-flow enforcement module for PRISM DPI."""

from .policy import APPLE_MUSIC_SERVER_SUFFIXES, AppleMusicFlowPolicy

__all__ = ["APPLE_MUSIC_SERVER_SUFFIXES", "AppleMusicFlowPolicy"]
