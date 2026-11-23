"""Tailscale-specific adapter for agent modules."""

from __future__ import annotations

from typing import Any


class TailscaleAdapter:
    """Expose Tailscale runtime and control operations."""

    def __init__(self, *, tailscale: Any | None = None) -> None:
        if tailscale is None:
            from app.services.remote_access.tailscale_service import get_tailscale_service

            tailscale = get_tailscale_service()
        self.tailscale = tailscale

    async def get_status(self) -> Any:
        detailed_status = getattr(self.tailscale, "get_detailed_status", None)
        if detailed_status is not None:
            return await detailed_status()
        return await self.tailscale.get_status()

    async def get_local_networks(self) -> list[Any]:
        return await self.tailscale.get_local_networks()

    async def login(self, auth_key: str | None = None) -> dict[str, Any]:
        success, message, login_url = await self.tailscale.login(auth_key)
        return {"success": success, "message": message, "login_url": login_url}

    async def setup_subnet_router(self) -> dict[str, Any]:
        success, message, login_url = await self.tailscale.setup_subnet_router()
        return {"success": success, "message": message, "login_url": login_url}

    async def start(self) -> dict[str, Any]:
        success, message = await self.tailscale.start()
        return {"success": success, "message": message}

    async def stop(self) -> dict[str, Any]:
        success, message = await self.tailscale.stop()
        return {"success": success, "message": message}

    async def logout(self) -> dict[str, Any]:
        success, message = await self.tailscale.logout()
        return {"success": success, "message": message}

    async def enable_funnel(self, port: int = 443) -> dict[str, Any]:
        success, message, url = await self.tailscale.setup_funnel(port)
        return {"success": success, "message": message, "url": url}

    async def disable_funnel(self) -> dict[str, Any]:
        success, message = await self.tailscale.disable_funnel()
        return {"success": success, "message": message}

    async def uninstall(self) -> dict[str, Any]:
        success, message = await self.tailscale.uninstall()
        return {"success": success, "message": message}
