"""Time helpers that preserve NetProtection's naive-UTC storage contract."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return naive UTC without using the deprecated ``datetime.utcnow`` API."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
