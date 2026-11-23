"""PlayStation encrypted-flow enforcement module for PRISM DPI."""

from .policy import PLAYSTATION_SERVER_SUFFIXES, PlayStationFlowPolicy

__all__ = ["PLAYSTATION_SERVER_SUFFIXES", "PlayStationFlowPolicy"]
