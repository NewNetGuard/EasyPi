from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from app.api.deps import require_admin
from app.core.service_manager import ServiceManager
from app.core.system_monitor import SystemMonitor
from app.schemas.monitoring import ServiceRuntime, SystemStats

router = APIRouter(prefix="/monitoring", tags=["monitoring"])
monitor = SystemMonitor()
service_manager = ServiceManager()


@router.get("/stats", response_model=SystemStats)
async def get_system_stats(admin: dict = Depends(require_admin)) -> SystemStats:
    # Run off the event loop: snapshot() touches psutil/sysfs and must never
    # block the asyncio loop (see SystemMonitor for the rate-sampling fix).
    snapshot = await asyncio.to_thread(monitor.snapshot)
    return SystemStats(**snapshot)


@router.get("/services", response_model=list[ServiceRuntime])
async def get_service_metrics(admin: dict = Depends(require_admin)) -> list[ServiceRuntime]:
    services = service_manager.get_available_services()
    metrics: list[ServiceRuntime] = []

    for service in services:
        try:
            status = service_manager.get_service_status(service.name)
        except FileNotFoundError:
            continue
        except RuntimeError:
            continue

        metrics.append(
            ServiceRuntime(
                name=service.name,
                running=status.running,
                uptime=status.uptime,
                cpu=status.cpu,
                ram=status.ram,
            )
        )

    metrics.sort(key=lambda item: (not item.running, item.name))
    return metrics


__all__ = ["router"]
