"""Service status adapter for agent modules."""

from __future__ import annotations

from typing import Any


class ServiceStatusAdapter:
    """Expose read-only status calls for system-facing modules."""

    def __init__(
        self,
        *,
        netprotection: Any | None = None,
        tailscale: Any | None = None,
        threat_monitor: Any | None = None,
    ) -> None:
        if netprotection is None:
            from app.services.netprotection_service import netprotection_service

            netprotection = netprotection_service
        if tailscale is None:
            from app.services.remote_access.tailscale_service import get_tailscale_service

            tailscale = get_tailscale_service()
        if threat_monitor is None:
            from app.services.threat_service import threat_service

            threat_monitor = threat_service
        self.netprotection = netprotection
        self.tailscale = tailscale
        self.threat_monitor = threat_monitor

    async def get_tailscale_status(self) -> Any:
        detailed_status = getattr(self.tailscale, "get_detailed_status", None)
        if detailed_status is not None:
            return await detailed_status()
        return await self.tailscale.get_status()

    async def get_netprotection_status(self) -> dict[str, Any]:
        status = await self.netprotection.get_status()
        return status if isinstance(status, dict) else {}

    async def get_threat_monitor_status(self) -> dict[str, Any]:
        status = await self.threat_monitor.get_status()
        return status if isinstance(status, dict) else {}

    async def start_tailscale(self) -> dict[str, Any]:
        success, message = await self.tailscale.start()
        return {"success": success, "message": message}

    async def stop_tailscale(self) -> dict[str, Any]:
        success, message = await self.tailscale.stop()
        return {"success": success, "message": message}

    async def logout_tailscale(self) -> dict[str, Any]:
        success, message = await self.tailscale.logout()
        return {"success": success, "message": message}

    async def start_threat_monitoring(self) -> dict[str, Any]:
        result = await self.threat_monitor.start_monitoring()
        return result if isinstance(result, dict) else {"success": False, "message": "Threat monitoring returned no start evidence."}

    async def stop_threat_monitoring(self) -> dict[str, Any]:
        result = await self.threat_monitor.stop_monitoring()
        return result if isinstance(result, dict) else {"success": False, "message": "Threat monitoring returned no stop evidence."}
