"""Outbound VPN (Internet Encryption) fact adapter."""

from __future__ import annotations

from typing import Any

from app.services.vpn_client_service import get_vpn_client_service


class OutboundVpnAdapter:
    """Expose read-only outbound VPN client status (Privacy -> Internet Encryption)."""

    async def get_status(self) -> dict[str, Any]:
        try:
            return await get_vpn_client_service().status()
        except Exception:
            return {}
