"""Remote Access adapter for agent modules."""

from __future__ import annotations

from typing import Any

from app.agent.adapters.tailscale import TailscaleAdapter


class RemoteAccessAdapter(TailscaleAdapter):
    """Expose remote-access operations over the Tailscale backend."""

    async def get_tailscale_status(self) -> Any:
        return await self.get_status()

    async def get_local_networks_state(self) -> list[Any]:
        return await self.get_local_networks()

    async def start_tailscale(self) -> dict[str, Any]:
        return await self.start()

    async def stop_tailscale(self) -> dict[str, Any]:
        return await self.stop()

    async def logout_tailscale(self) -> dict[str, Any]:
        return await self.logout()

    async def get_remote_access_state(self) -> dict[str, Any]:
        status = await self.get_status()
        networks = await self.get_local_networks()
        return {
            "status": status,
            "local_networks": list(networks or []),
        }
