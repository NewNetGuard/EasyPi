from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException

from app.api.deps import require_admin
from app.models.user import User
from app.schemas.network_toolkit import (
    ConnectionFilters,
    LANScanConfig,
    NetworkApiResponse,
    NetworkMapConfig,
    PortAlertConfig,
    PortScanConfig,
    SpeedTestConfig,
)
from app.services.operation_event_service import OperationEventService
from app.services.network_toolkit import NetworkToolkitService

router = APIRouter(prefix="/api/network-toolkit", tags=["network-toolkit"])
service = NetworkToolkitService()
operation_event_service = OperationEventService()

# Simple in-memory rate limiter for scan operations
# Prevents abuse by limiting scan frequency per user
_scan_timestamps: dict[str, float] = defaultdict(float)
SCAN_COOLDOWN_SECONDS = 5  # Minimum seconds between scans


def _record_network_toolkit_event(
    *,
    action_id: str,
    title: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            title=title,
            subtitle="Network Toolkit · Admin action",
            route="/network-toolkit",
            status=status,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        return


def _extract_result_status(result) -> tuple[str, str]:
    if isinstance(result, dict):
        success = bool(result.get("success", True))
        message = result.get("error") or result.get("message") or ("Operation completed" if success else "Operation failed")
        return ("success" if success else "failed", str(message))

    success = getattr(result, "success", True)
    message = getattr(result, "error", None) or getattr(result, "message", None) or ("Operation completed" if success else "Operation failed")
    return ("success" if success else "failed", str(message))


def _check_rate_limit(user_id: str, operation: str) -> None:
    """Check if user can perform scan operation (rate limit)."""
    key = f"{user_id}:{operation}"
    last_scan = _scan_timestamps.get(key, 0)
    now = time.time()
    
    if now - last_scan < SCAN_COOLDOWN_SECONDS:
        remaining = int(SCAN_COOLDOWN_SECONDS - (now - last_scan))
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Please wait {remaining} seconds before scanning again."
        )
    
    _scan_timestamps[key] = now


# All scanning operations require admin authentication
@router.post("/lan-scan", response_model=NetworkApiResponse)
async def lan_scan(config: LANScanConfig, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    _check_rate_limit(str(admin.id), "lan-scan")
    result = await service.scan_lan(config)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.lan-scan",
        title="Run LAN scan",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.post("/port-scan", response_model=NetworkApiResponse)
async def port_scan(config: PortScanConfig, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    _check_rate_limit(str(admin.id), "port-scan")
    result = await service.scan_ports(config)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.port-scan",
        title="Run port scan",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.post("/speed-test", response_model=NetworkApiResponse)
async def speed_test(config: SpeedTestConfig, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    _check_rate_limit(str(admin.id), "speed-test")
    result = await service.speed_test(config)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.speed-test",
        title="Run speed test",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.post("/network-map", response_model=NetworkApiResponse)
async def network_map(config: NetworkMapConfig, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    _check_rate_limit(str(admin.id), "network-map")
    result = await service.network_map(config)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.network-map",
        title="Generate network map",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.get("/traffic", response_model=NetworkApiResponse)
async def traffic(duration: int = 60, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = await service.traffic_samples(duration=duration)
    return result


@router.get("/traffic/stats", response_model=NetworkApiResponse)
async def traffic_stats(admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = await service.traffic_stats()
    return result


@router.post("/connections", response_model=NetworkApiResponse)
async def connections(filters: ConnectionFilters | None = None, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    started_at = datetime.now(timezone.utc).isoformat()
    result = await service.active_connections(filters)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.connections",
        title="Inspect active connections",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.get("/arp-scan", response_model=NetworkApiResponse)
async def arp_scan(admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = await service.arp_scan()
    return result


@router.get("/network-info", response_model=NetworkApiResponse)
async def network_info(admin: User = Depends(require_admin)) -> NetworkApiResponse:
    """Get local network information (IP, gateway, network range)"""
    result = await service.get_network_info()
    return result


@router.get("/cached-devices")
async def get_cached_devices(admin: User = Depends(require_admin)) -> dict:
    """Get the shared approved/discovered inventory for device policy pickers."""
    return await service.get_cached_devices()


@router.delete("/cached-devices")
async def clear_cached_devices(admin: User = Depends(require_admin)) -> dict:
    """Clear the cached devices list."""
    result = service.clear_cached_devices()
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.cached-devices.clear",
        title="Clear cached devices",
        status=status_text,
        message=message,
    )
    return result


@router.get("/port-alerts", response_model=NetworkApiResponse)
async def port_alerts(admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = await service.port_alerts()
    return result


@router.post("/port-alerts/config", response_model=NetworkApiResponse)
async def update_port_alert_config(config: PortAlertConfig, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = service.update_port_alert_config(config)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.port-alerts.config",
        title="Update port alert settings",
        status=status_text,
        message=message,
    )
    return result


@router.delete("/port-alerts/{alert_id}", response_model=NetworkApiResponse)
async def dismiss_port_alert(alert_id: str, admin: User = Depends(require_admin)) -> NetworkApiResponse:
    result = service.dismiss_port_alert(alert_id)
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.port-alerts.dismiss",
        title="Dismiss port alert",
        status=status_text,
        message=message,
    )
    return result


@router.get("/gateway-mode/status")
async def gateway_mode_status(admin: User = Depends(require_admin)) -> dict:
    """Get current gateway mode status"""
    return await service.get_gateway_mode_status()


@router.post("/gateway-mode/enable")
async def enable_gateway_mode(admin: User = Depends(require_admin)) -> dict:
    """Enable full gateway mode - configures static IP and NAT"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await service.enable_gateway_mode()
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.gateway-mode.enable",
        title="Enable gateway mode",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.post("/gateway-mode/disable")
async def disable_gateway_mode(admin: User = Depends(require_admin)) -> dict:
    """Disable full gateway mode - reverts to DHCP"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await service.disable_gateway_mode()
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.gateway-mode.disable",
        title="Disable gateway mode",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result

@router.post("/gateway-mode/fix")
async def fix_gateway_mode(admin: User = Depends(require_admin)) -> dict:
    """Attempt to repair gateway mode (routing/NAT) without requiring terminal access."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await service.fix_gateway_mode()
    status_text, message = _extract_result_status(result)
    _record_network_toolkit_event(
        action_id="network-toolkit.gateway-mode.fix",
        title="Repair gateway mode",
        status=status_text,
        message=message,
        started_at=started_at,
    )
    return result


@router.get("/gateway-mode/verify")
async def verify_gateway_mode(admin: User = Depends(require_admin)) -> dict:
    """Check whether devices are actually routing through EasyPi (effectiveness),
    not just whether gateway mode is enabled on the Pi."""
    return await service.verify_gateway_effective()


__all__ = ["router"]
