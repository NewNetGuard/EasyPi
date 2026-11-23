"""Network toolkit fact adapter."""

from __future__ import annotations

from typing import Any

from app.schemas.network_toolkit import SpeedTestConfig
from app.services.network_toolkit import NetworkToolkitService


class NetworkToolkitAdapter:
    """Expose read-only network toolkit state."""

    def __init__(self, service: Any | None = None) -> None:
        self.service = service or NetworkToolkitService()

    async def get_network_info(self) -> dict[str, Any]:
        result = await self.service.get_network_info()
        return self._payload(result)

    async def get_traffic_stats(self) -> dict[str, Any]:
        result = await self.service.traffic_stats()
        return self._payload(result)

    async def get_connections(self) -> list[dict[str, Any]]:
        result = await self.service.active_connections()
        payload = self._payload(result)
        return payload if isinstance(payload, list) else []

    async def get_arp_entries(self) -> list[dict[str, Any]]:
        result = await self.service.arp_scan()
        payload = self._payload(result)
        if hasattr(payload, "model_dump"):
            payload = payload.model_dump(mode="json")
        entries = payload.get("entries", []) if isinstance(payload, dict) else []
        return [entry for entry in entries if isinstance(entry, dict)]

    async def get_port_alerts(self) -> list[dict[str, Any]]:
        result = await self.service.port_alerts()
        payload = self._payload(result)
        return payload if isinstance(payload, list) else []

    async def get_cached_devices(self) -> dict[str, Any]:
        result = await self.service.get_cached_devices()
        return result if isinstance(result, dict) else {}

    async def get_traffic_samples(self, duration: int = 30) -> list[dict[str, Any]]:
        result = await self.service.traffic_samples(duration=duration)
        payload = self._payload(result)
        return payload if isinstance(payload, list) else []

    async def run_speed_test(self) -> dict[str, Any]:
        result = await self.service.speed_test(SpeedTestConfig())
        payload = self._payload(result)
        return payload if isinstance(payload, dict) else {}

    async def get_gateway_mode_status(self) -> dict[str, Any]:
        status = await self.service.get_gateway_mode_status()
        return status if isinstance(status, dict) else {}

    async def fix_gateway_mode(self) -> dict[str, Any]:
        result = await self.service.fix_gateway_mode()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected gateway fix result"}

    def _payload(self, result: Any) -> Any:
        if hasattr(result, "model_dump"):
            data = result.model_dump(mode="json")
        elif isinstance(result, dict):
            data = dict(result)
        else:
            return None
        return data.get("data")
