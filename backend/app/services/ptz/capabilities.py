"""PTZ capability model + canonical command names.

``PTZCapabilities`` is what a camera advertises after detection; it is persisted
(as JSON, never with secrets) and returned to the client so the frontend can
show only the controls a camera actually supports. The backend re-checks every
command against these capabilities server-side (a hidden button is not security).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# Canonical command identifiers used across the layer (policy, audit, gating).
CMD_MOVE = "move"
CMD_STOP = "stop"
CMD_GO_HOME = "go_home"
CMD_SET_HOME = "set_home"
CMD_GOTO_PRESET = "goto_preset"
CMD_CREATE_PRESET = "create_preset"
CMD_DELETE_PRESET = "delete_preset"
CMD_GET_PRESETS = "get_presets"
CMD_GET_POSITION = "get_position"
CMD_DETECT = "detect"
CMD_CAPABILITIES = "capabilities"


class PTZCapabilities(BaseModel):
    """What a camera's PTZ actually supports. Booleans only -- no secrets."""

    model_config = ConfigDict(extra="ignore")

    available: bool = False
    adapter: str = "null"
    pan: bool = False
    tilt: bool = False
    optical_zoom: bool = False
    continuous_move: bool = False
    relative_move: bool = False
    absolute_move: bool = False
    stop: bool = False
    home: bool = False
    presets: bool = False
    position_feedback: bool = False

    def supports(self, command: str) -> bool:
        """Coarse capability gate for a command (fail-closed on unavailable)."""
        if not self.available:
            return False
        return {
            CMD_MOVE: self.continuous_move or self.relative_move or self.absolute_move,
            CMD_STOP: self.stop,
            CMD_GO_HOME: self.home,
            CMD_SET_HOME: self.home,
            CMD_GOTO_PRESET: self.presets,
            CMD_CREATE_PRESET: self.presets,
            CMD_DELETE_PRESET: self.presets,
            CMD_GET_PRESETS: self.presets,
            CMD_GET_POSITION: self.position_feedback,
            CMD_CAPABILITIES: True,
        }.get(command, False)

    def supports_mode(self, mode: str) -> bool:
        """Whether a move ``mode`` (continuous/relative/absolute) is supported."""
        return {
            "continuous": self.continuous_move,
            "relative": self.relative_move,
            "absolute": self.absolute_move,
        }.get(mode, False)


# Shared immutable "no PTZ" capabilities for the Null adapter / fail-closed paths.
NULL_CAPABILITIES = PTZCapabilities(available=False, adapter="null")


__all__ = [
    "PTZCapabilities",
    "NULL_CAPABILITIES",
    "CMD_MOVE",
    "CMD_STOP",
    "CMD_GO_HOME",
    "CMD_SET_HOME",
    "CMD_GOTO_PRESET",
    "CMD_CREATE_PRESET",
    "CMD_DELETE_PRESET",
    "CMD_GET_PRESETS",
    "CMD_GET_POSITION",
    "CMD_DETECT",
    "CMD_CAPABILITIES",
]
