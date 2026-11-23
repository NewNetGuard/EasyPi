"""Snapchat encrypted-flow enforcement module for PRISM DPI."""

from .policy import SNAPCHAT_SERVER_SUFFIXES, SnapchatFlowPolicy

__all__ = ["SNAPCHAT_SERVER_SUFFIXES", "SnapchatFlowPolicy"]
