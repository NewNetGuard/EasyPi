"""Confidence utilities for the EasyPi agent."""

from __future__ import annotations

from app.agent.core.contracts import ConfidenceLevel

_CONFIDENCE_ORDER: tuple[ConfidenceLevel, ...] = ("low", "medium", "high")


def normalize_confidence(value: str | ConfidenceLevel | None) -> ConfidenceLevel:
    """Clamp an arbitrary confidence string into a supported confidence level."""

    candidate = str(value or "").strip().lower()
    if candidate in _CONFIDENCE_ORDER:
        return candidate  # type: ignore[return-value]
    return "low"


def lower_confidence(value: str | ConfidenceLevel | None, *, steps: int = 1) -> ConfidenceLevel:
    """Lower confidence by a bounded number of steps."""

    current = normalize_confidence(value)
    index = max(0, _CONFIDENCE_ORDER.index(current) - max(0, int(steps)))
    return _CONFIDENCE_ORDER[index]


def combine_confidence(*values: str | ConfidenceLevel | None) -> ConfidenceLevel:
    """Return the most conservative confidence from multiple signals."""

    normalized = [normalize_confidence(value) for value in values if value is not None]
    if not normalized:
        return "low"
    return min(normalized, key=_CONFIDENCE_ORDER.index)
