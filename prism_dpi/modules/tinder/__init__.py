"""Tinder encrypted-flow enforcement module for PRISM DPI."""

from .policy import TINDER_SERVER_SUFFIXES, TinderFlowPolicy

__all__ = ["TINDER_SERVER_SUFFIXES", "TinderFlowPolicy"]
