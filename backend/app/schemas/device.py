from __future__ import annotations

from datetime import datetime
from ipaddress import ip_address
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validate_ip(value: str) -> str:
    try:
        ip_address(value)
    except ValueError as exc:
        raise ValueError("Invalid IP address format") from exc
    return value


class DeviceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=64)
    ip: str
    ssh_port: int = Field(default=22, ge=1, le=65535)

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return _validate_ip(value)


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=64)
    ip: Optional[str] = None
    ssh_port: Optional[int] = Field(default=None, ge=1, le=65535)

    model_config = ConfigDict(str_strip_whitespace=True)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return _validate_ip(value)


class DeviceResponse(DeviceBase):
    id: UUID
    status: str
    last_seen: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class DeviceStats(BaseModel):
    cpu: float
    ram: float
    temp: Optional[float] = None
    disk_used: int
    disk_total: int
    rx: int
    tx: int
    timestamp: datetime


__all__ = [
    "DeviceBase",
    "DeviceCreate",
    "DeviceUpdate",
    "DeviceResponse",
    "DeviceStats",
]
