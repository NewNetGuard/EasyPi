"""Setup and settings fact adapter for agent modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.api.endpoints.system import (
    get_dns_status as get_pi_dns_status,
    get_permissions_status as get_permissions_state,
    get_system_info as get_system_state,
    get_timezone as get_timezone_state,
    restart_easypi_services,
    setup_permissions as run_setup_permissions,
    SetupPermissionsRequest,
)


class SetupAdapter:
    """Expose read-only setup and settings state."""

    _HTTPS_CERT_PATH = Path("/etc/ssl/certs/easypi-selfsigned.crt")
    _HTTPS_KEY_PATH = Path("/etc/ssl/private/easypi-selfsigned.key")

    async def get_permissions_status(self) -> dict[str, Any]:
        status = await get_permissions_state()
        if hasattr(status, "model_dump"):
            return status.model_dump(mode="json")
        return dict(status)

    async def get_system_info(self) -> dict[str, Any]:
        info = await get_system_state()
        return info if isinstance(info, dict) else {}

    async def get_dns_status(self) -> dict[str, Any]:
        status = await get_pi_dns_status()
        if hasattr(status, "model_dump"):
            return status.model_dump(mode="json")
        return dict(status)

    async def get_timezone(self) -> dict[str, Any]:
        timezone_info = await get_timezone_state()
        return timezone_info if isinstance(timezone_info, dict) else {}

    async def setup_permissions(self, username: str | None = None) -> dict[str, Any]:
        result = await run_setup_permissions(SetupPermissionsRequest(username=username or None))
        if hasattr(result, "model_dump"):
            return result.model_dump(mode="json")
        return dict(result)

    async def restart_services(self) -> dict[str, Any]:
        result = await restart_easypi_services()
        return result if isinstance(result, dict) else {"success": False, "message": "EasyPi service restart returned no completion evidence."}

    async def get_https_certificate_state(self) -> dict[str, Any]:
        cert_exists = self._HTTPS_CERT_PATH.exists()
        key_exists = self._HTTPS_KEY_PATH.exists()
        return {
            "cert_path": str(self._HTTPS_CERT_PATH),
            "key_path": str(self._HTTPS_KEY_PATH),
            "cert_exists": cert_exists,
            "key_exists": key_exists,
            "cert_size": self._HTTPS_CERT_PATH.stat().st_size if cert_exists else 0,
            "key_size": self._HTTPS_KEY_PATH.stat().st_size if key_exists else 0,
            "certificate_kind": "self-signed" if cert_exists and key_exists else "missing",
        }
