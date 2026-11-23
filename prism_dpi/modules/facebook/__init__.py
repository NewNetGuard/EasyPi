"""Facebook encrypted-flow enforcement module for PRISM DPI."""

from .policy import FACEBOOK_SERVER_SUFFIXES, FacebookFlowPolicy

__all__ = ["FACEBOOK_SERVER_SUFFIXES", "FacebookFlowPolicy"]
