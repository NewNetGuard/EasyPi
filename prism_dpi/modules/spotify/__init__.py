"""Spotify encrypted-flow enforcement module for PRISM DPI."""

from .policy import SPOTIFY_SERVER_SUFFIXES, SpotifyFlowPolicy

__all__ = ["SPOTIFY_SERVER_SUFFIXES", "SpotifyFlowPolicy"]
