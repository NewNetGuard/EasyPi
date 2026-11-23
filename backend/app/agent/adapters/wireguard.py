"""WireGuard fact adapter."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.api.v1.endpoints.wireguard import CLIENTS_DIR
from app.api.v1.endpoints.wireguard import get_status as get_wireguard_status
from app.api.v1.endpoints.wireguard import restart_service as restart_wireguard_service


class WireGuardAdapter:
    """Expose read-only WireGuard status."""

    async def get_status(self) -> dict[str, Any]:
        status = await get_wireguard_status()
        if hasattr(status, "model_dump"):
            return status.model_dump(mode="json")
        return dict(status)

    async def restart_service(self) -> dict[str, Any]:
        result = await restart_wireguard_service()
        if hasattr(result, "model_dump"):
            return result.model_dump(mode="json")
        return dict(result) if isinstance(result, dict) else {"success": False, "message": "WireGuard restart returned no completion evidence."}

    def get_peer_artifacts(self, name: str) -> dict[str, Any]:
        normalized = str(name or "").strip()
        if not normalized:
            return {"config_exists": False, "qr_exists": False}
        config_path = Path(CLIENTS_DIR) / f"{normalized}.conf"
        qr_path = Path(CLIENTS_DIR) / f"{normalized}.png"
        return {
            "config_exists": config_path.exists(),
            "qr_exists": qr_path.exists(),
            "config_path": str(config_path),
            "qr_path": str(qr_path),
        }
