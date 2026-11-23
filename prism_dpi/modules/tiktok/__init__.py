"""TikTok encrypted-flow enforcement module for PRISM DPI."""

from .policy import TIKTOK_SERVER_SUFFIXES, TikTokFlowPolicy

__all__ = ["TIKTOK_SERVER_SUFFIXES", "TikTokFlowPolicy"]
