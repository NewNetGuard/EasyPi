"""Universal PTZ (pan/tilt/zoom) camera-control layer for EasyPi.

Adapter-based: every supported control protocol (ONVIF, Thingino, ...) is a
separate :class:`CameraPTZAdapter` behind a single uniform API, so the frontend
and the HTTP API never contain vendor-specific logic. All PTZ coordinates are
normalised to the EasyPi unit range ``[-1.0, +1.0]``; each adapter maps that to
the concrete device ranges internally.

Stage 2 ships the foundation only: the adapter interface, the fail-closed Null
adapter, the registry, capability model, coordinate normalisation, command
schemas, session safety, an SSRF guard and the authorization policy. Real
adapters (Thingino, ONVIF) are added later as separate files under
``adapters/`` plus one registry line -- without changing this shared API.
"""
from __future__ import annotations

from app.services.ptz.base import (
    CameraPTZAdapter,
    CameraSnapshot,
    MoveRequest,
    PTZPosition,
    PTZPreset,
)
from app.services.ptz.capabilities import PTZCapabilities
from app.services.ptz.registry import build_adapter, get_adapter_class, register_adapter

__all__ = [
    "CameraPTZAdapter",
    "CameraSnapshot",
    "MoveRequest",
    "PTZPosition",
    "PTZPreset",
    "PTZCapabilities",
    "build_adapter",
    "get_adapter_class",
    "register_adapter",
]
