"""Deezer encrypted-flow enforcement module for PRISM DPI."""

from .policy import DEEZER_SERVER_SUFFIXES, DeezerFlowPolicy

__all__ = ["DEEZER_SERVER_SUFFIXES", "DeezerFlowPolicy"]
