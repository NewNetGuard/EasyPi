"""Adapter registry — maps a stored adapter name to its class, fail-closed.

Stage 2 registers only ``null``. Stage 3/4 add ``thingino`` / ``onvif`` by
importing their module and calling :func:`register_adapter` (one line each) --
no change to the shared API. Selecting an unknown, reserved-but-unimplemented,
or missing adapter returns the Null adapter, so PTZ is denied fail-closed rather
than crashing.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Type

from app.services.ptz.base import CameraPTZAdapter
from app.services.ptz.null_adapter import NullPTZAdapter

if TYPE_CHECKING:
    from app.services.ptz.base import CameraSnapshot

# adapter name -> class
_ADAPTERS: dict[str, Type[CameraPTZAdapter]] = {
    "null": NullPTZAdapter,
}

# Reserved adapter names that may not yet be registered. Both onvif and thingino
# are implemented now, so this is empty; selecting an *unknown* name still
# resolves to Null (fail-closed). Kept as an extension point for future adapters.
RESERVED_ADAPTERS: frozenset = frozenset()

_adapters_loaded = False


def _ensure_adapters_loaded() -> None:
    """Import the real-adapter package once so it can self-register.

    Done lazily (not at import time) to avoid an import cycle between the registry
    and the adapter modules that depend on it.
    """
    global _adapters_loaded
    if _adapters_loaded:
        return
    _adapters_loaded = True
    try:
        from app.services.ptz import adapters  # noqa: F401 -- registers real adapters
    except Exception:
        pass


def register_adapter(name: str, cls: Type[CameraPTZAdapter]) -> None:
    """Register an adapter class under ``name`` (called by adapter modules)."""
    if not name or not isinstance(name, str):
        raise ValueError("adapter name must be a non-empty string")
    _ADAPTERS[name] = cls


def get_adapter_class(name: str | None) -> Type[CameraPTZAdapter]:
    """Resolve an adapter name to a class, fail-closed to Null."""
    if not name:
        return NullPTZAdapter
    _ensure_adapters_loaded()
    return _ADAPTERS.get(name, NullPTZAdapter)


def is_implemented(name: str | None) -> bool:
    """Whether ``name`` maps to a real (non-Null fallback) adapter."""
    _ensure_adapters_loaded()
    return bool(name) and name in _ADAPTERS


def build_adapter(snapshot: "CameraSnapshot") -> CameraPTZAdapter:
    """Instantiate the adapter selected by ``snapshot.adapter_name`` (fail-closed).

    The adapter holds the immutable snapshot (never a live ORM camera / open
    session), so it is safe to keep and call from the auto-stop timer or from
    shutdown after the request's DB session has closed.
    """
    return get_adapter_class(snapshot.adapter_name)(snapshot)


def available_adapters() -> list[str]:
    """Names of registered (implemented) adapters, for admin selection UIs."""
    _ensure_adapters_loaded()
    return sorted(_ADAPTERS.keys())


__all__ = [
    "register_adapter",
    "get_adapter_class",
    "is_implemented",
    "build_adapter",
    "available_adapters",
    "RESERVED_ADAPTERS",
]
