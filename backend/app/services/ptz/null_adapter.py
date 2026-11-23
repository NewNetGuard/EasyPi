"""Fail-closed adapter for cameras with no supported PTZ control.

Selected whenever a camera has no adapter, an unknown adapter, or a reserved
adapter that is not implemented yet. It reports ``available=False`` (so the
frontend hides the controls) and refuses every movement command. ``stop`` is a
safe no-op -- Stop must never error, and there is nothing to stop.
"""
from __future__ import annotations

from app.services.ptz.base import CameraPTZAdapter, PTZPosition, PTZPreset
from app.services.ptz.capabilities import NULL_CAPABILITIES, PTZCapabilities
from app.services.ptz.errors import PTZUnavailable


class NullPTZAdapter(CameraPTZAdapter):
    adapter_name = "null"

    def probe(self) -> PTZCapabilities:
        return NULL_CAPABILITIES

    def get_capabilities(self) -> PTZCapabilities:
        return NULL_CAPABILITIES

    def _refuse(self) -> None:
        raise PTZUnavailable("PTZ control is not available for this camera")

    def continuous_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        self._refuse()

    def relative_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        self._refuse()

    def absolute_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        self._refuse()

    def stop(self) -> None:
        # No motion is possible, so Stop is a safe no-op (never raises).
        return None

    def go_home(self) -> None:
        self._refuse()

    def set_home(self) -> None:
        self._refuse()

    def get_presets(self) -> list[PTZPreset]:
        return []

    def goto_preset(self, token: str) -> None:
        self._refuse()

    def create_preset(self, name: str) -> PTZPreset:
        self._refuse()

    def delete_preset(self, token: str) -> None:
        self._refuse()

    def get_position(self) -> PTZPosition:
        return PTZPosition()


__all__ = ["NullPTZAdapter"]
