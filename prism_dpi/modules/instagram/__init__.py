"""Instagram encrypted-flow enforcement module for PRISM DPI."""

from .policy import INSTAGRAM_SERVER_SUFFIXES, InstagramFlowPolicy

__all__ = ["INSTAGRAM_SERVER_SUFFIXES", "InstagramFlowPolicy"]
