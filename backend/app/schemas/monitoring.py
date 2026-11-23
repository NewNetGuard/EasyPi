from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class CpuStat(BaseModel):
    usage: float = Field(ge=0.0, le=100.0)


class RamStat(BaseModel):
    used: int = Field(ge=0)
    total: int = Field(ge=0)


class DiskStat(BaseModel):
    used: int = Field(ge=0)
    total: int = Field(ge=0)
    mount: str = Field(min_length=1)


class NetStat(BaseModel):
    rx: int = Field(ge=0)
    tx: int = Field(ge=0)


class TempStat(BaseModel):
    celsius: float | None = Field(default=None)


class ServiceRuntime(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    running: bool
    uptime: int | None = Field(default=None, ge=0)
    cpu: float | None = Field(default=None, ge=0.0)
    ram: float | None = Field(default=None, ge=0.0)


class SystemStats(BaseModel):
    cpu: CpuStat
    ram: RamStat
    temp: TempStat
    disk: list[DiskStat]
    net: NetStat
    timestamp: datetime

    model_config = ConfigDict(str_strip_whitespace=True)


__all__ = [
    "CpuStat",
    "RamStat",
    "DiskStat",
    "NetStat",
    "TempStat",
    "ServiceRuntime",
    "SystemStats",
]
