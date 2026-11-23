"""Pinterest encrypted-flow enforcement module for PRISM DPI."""

from .policy import PINTEREST_SERVER_SUFFIXES, PinterestFlowPolicy

__all__ = ["PINTEREST_SERVER_SUFFIXES", "PinterestFlowPolicy"]
