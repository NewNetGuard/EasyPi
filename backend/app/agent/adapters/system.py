"""System adapter aliases for agent modules."""

from __future__ import annotations

from typing import Any

from app.agent.adapters.service_status import ServiceStatusAdapter
from app.agent.adapters.setup import SetupAdapter


class SystemAdapter:
    """Expose a combined system-facing view over setup and service state."""

    def __init__(
        self,
        *,
        setup: SetupAdapter | None = None,
        service_status: ServiceStatusAdapter | None = None,
    ) -> None:
        self.setup = setup or SetupAdapter()
        self.service_status = service_status or ServiceStatusAdapter()

    async def get_permissions_status(self) -> dict[str, Any]:
        return await self.setup.get_permissions_status()

    async def get_system_info(self) -> dict[str, Any]:
        return await self.setup.get_system_info()

    async def get_timezone(self) -> dict[str, Any]:
        return await self.setup.get_timezone()

    async def get_dns_status(self) -> dict[str, Any]:
        return await self.setup.get_dns_status()

    async def get_tailscale_status(self) -> Any:
        return await self.service_status.get_tailscale_status()

    async def get_netprotection_status(self) -> dict[str, Any]:
        return await self.service_status.get_netprotection_status()

    async def get_threat_monitor_status(self) -> dict[str, Any]:
        return await self.service_status.get_threat_monitor_status()
