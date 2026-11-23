from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

import psutil
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_admin
from app.db.session import get_db
from app.models.device import Device
from app.models.user import User
from app.schemas.device import (
    DeviceCreate,
    DeviceResponse,
    DeviceStats,
)
from app.services.operation_event_service import OperationEventService

router = APIRouter(prefix="/devices", tags=["devices"])
operation_event_service = OperationEventService()


def _record_device_event(
    *,
    action_id: str,
    title: str,
    status: str,
    message: str,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            title=title,
            subtitle="Devices · Inventory",
            route="/devices",
            status=status,
            message=message,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        return


def _get_device_or_404(db: Session, device_id: UUID) -> Device:
    device = db.get(Device, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )
    return device


def _collect_local_stats() -> DeviceStats:
    cpu_percent = psutil.cpu_percent(interval=0.1)
    ram_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage("/")
    net_info = psutil.net_io_counters()

    temperature: float | None = None
    try:
        temps: dict[str, Any] = psutil.sensors_temperatures()  # type: ignore[assignment]
    except (AttributeError, NotImplementedError):
        temps = {}

    if temps:
        readings: list[float] = [
            sensor.current
            for sensor_list in temps.values()
            for sensor in sensor_list
            if sensor.current is not None
        ]
        if readings:
            temperature = sum(readings) / len(readings)

    return DeviceStats(
        cpu=cpu_percent,
        ram=ram_info.percent,
        temp=temperature,
        disk_used=disk_info.used,
        disk_total=disk_info.total,
        rx=net_info.bytes_recv,
        tx=net_info.bytes_sent,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/", response_model=list[DeviceResponse])
def list_devices(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> list[Device]:
    offset = (page - 1) * size
    stmt = select(Device).offset(offset).limit(size)
    result = db.execute(stmt)
    devices = result.scalars().all()
    return devices


@router.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> Device:
    device = Device(**payload.model_dump())
    db.add(device)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        _record_device_event(
            action_id="devices.create",
            title="Create device",
            status="failed",
            message=f"Device {payload.name} already exists",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Device with this name already exists",
        ) from exc
    db.refresh(device)
    _record_device_event(
        action_id="devices.create",
        title="Create device",
        status="success",
        message=f"Created device {device.name}",
    )
    return device


@router.get("/{device_id}", response_model=DeviceResponse)
def get_device(
    device_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> Device:
    device = _get_device_or_404(db, device_id)
    return device


@router.delete("/{device_id}")
def delete_device(
    device_id: UUID,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> dict[str, str]:
    device = _get_device_or_404(db, device_id)
    device_name = device.name
    db.delete(device)
    db.commit()
    _record_device_event(
        action_id="devices.delete",
        title="Delete device",
        status="success",
        message=f"Deleted device {device_name}",
    )
    return {"status": "ok"}


@router.get("/{device_id}/stats", response_model=DeviceStats)
def device_stats(
    device_id: UUID,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
) -> DeviceStats:
    _get_device_or_404(db, device_id)
    return _collect_local_stats()
