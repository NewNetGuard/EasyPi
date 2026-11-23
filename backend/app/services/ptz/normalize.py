"""Coordinate normalisation between EasyPi's unit range and device ranges.

EasyPi speaks a single normalised range to the frontend and across the API:
pan/tilt/zoom in ``[-1.0, +1.0]`` and speed in ``[0.0, 1.0]``. Adapters convert
to/from the concrete range a given camera reports (ONVIF spaces differ per
device; Thingino uses step counts). NaN/Infinity are rejected so a crafted
payload can never reach an adapter as a non-finite number.
"""
from __future__ import annotations

import math

from app.services.ptz.errors import PTZValidationError


def _finite(value: float) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise PTZValidationError("value must be a number")
    if math.isnan(f) or math.isinf(f):
        raise PTZValidationError("value must be a finite number")
    return f


def clamp(value: float, lo: float, hi: float) -> float:
    """Clamp a finite ``value`` into ``[lo, hi]`` (rejects NaN/Inf)."""
    f = _finite(value)
    return max(lo, min(hi, f))


def clamp_unit(value: float) -> float:
    """Clamp a pan/tilt/zoom value into ``[-1.0, +1.0]``."""
    return clamp(value, -1.0, 1.0)


def clamp_speed(value: float) -> float:
    """Clamp a speed value into ``[0.0, 1.0]``."""
    return clamp(value, 0.0, 1.0)


def to_device_range(unit: float, dev_min: float, dev_max: float) -> float:
    """Map a unit value in ``[-1, 1]`` linearly onto ``[dev_min, dev_max]``."""
    u = clamp_unit(unit)
    return dev_min + (u + 1.0) * 0.5 * (float(dev_max) - float(dev_min))


def from_device_range(value: float, dev_min: float, dev_max: float) -> float:
    """Map a device value on ``[dev_min, dev_max]`` back onto ``[-1, 1]``."""
    lo, hi = float(dev_min), float(dev_max)
    if hi == lo:
        return 0.0
    u = (_finite(value) - lo) / (hi - lo) * 2.0 - 1.0
    return max(-1.0, min(1.0, u))


__all__ = [
    "clamp",
    "clamp_unit",
    "clamp_speed",
    "to_device_range",
    "from_device_range",
]
