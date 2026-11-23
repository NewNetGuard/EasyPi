"""Network activity fact adapter."""

from __future__ import annotations

from typing import Any

from app.api.v1.endpoints.network_activity import (
    get_device_traffic,
    get_live_queries,
    get_network_devices,
    get_network_stats,
    get_network_status,
)


class NetworkActivityAdapter:
    """Expose read-only network activity state."""

    async def get_status(self) -> dict[str, Any]:
        status = await get_network_status()
        return status if isinstance(status, dict) else {}

    async def get_devices(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        result = await get_network_devices(active_only=active_only)
        devices = result.get("devices", []) if isinstance(result, dict) else []
        return [device for device in devices if isinstance(device, dict)]

    async def get_stats(self) -> dict[str, Any]:
        stats = await get_network_stats()
        return stats if isinstance(stats, dict) else {}

    async def get_live_queries(self, *, limit: int = 20) -> list[dict[str, Any]]:
        result = await get_live_queries(limit=limit)
        queries = result.get("queries", []) if isinstance(result, dict) else []
        return [query for query in queries if isinstance(query, dict)]

    async def get_device_traffic(self, device_ip: str, *, limit: int = 50) -> dict[str, Any]:
        result = await get_device_traffic(device_ip=device_ip, limit=limit)
        return result if isinstance(result, dict) else {}
