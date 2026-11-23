"""Stealth (anti-censorship tunnel) fact adapter."""

from __future__ import annotations

from typing import Any

from app.services.stealth_service import get_stealth_service


class StealthAdapter:
    """Expose read-only Stealth tunnel status (Privacy -> Stealth)."""

    async def get_status(self) -> dict[str, Any]:
        try:
            return await get_stealth_service().status()
        except Exception:
            return {}
