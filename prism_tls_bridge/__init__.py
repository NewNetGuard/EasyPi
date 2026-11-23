"""Prism TLS Endpoint Bridge: opt-in, observation-only component."""

__version__ = "0.1.0"


def __getattr__(name):
    if name == "Bridge":
        from .bridge import Bridge

        return Bridge
    if name in {"Limits", "Provenance", "Endpoint", "InspectionState"}:
        from . import models

        return getattr(models, name)
    raise AttributeError(name)
