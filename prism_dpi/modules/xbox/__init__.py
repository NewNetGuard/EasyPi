"""Xbox Live encrypted-flow enforcement module for PRISM DPI."""

from .policy import XBOX_SERVER_SUFFIXES, XboxFlowPolicy

__all__ = ["XBOX_SERVER_SUFFIXES", "XboxFlowPolicy"]
