"""Strict request/response schemas for the PTZ API.

All request bodies forbid unknown fields, reject NaN/Infinity, and hard-bound
pan/tilt/zoom to ``[-1, 1]`` and speed to ``[0, 1]``. The camera id is NEVER
taken from the body — it comes only from the route + the database row.
"""
from __future__ import annotations

import math
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _reject_non_finite(value: float) -> float:
    if value is None or math.isnan(value) or math.isinf(value):
        raise ValueError("must be a finite number")
    return value


class PTZMoveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    pan: float = Field(0.0, ge=-1.0, le=1.0)
    tilt: float = Field(0.0, ge=-1.0, le=1.0)
    zoom: float = Field(0.0, ge=-1.0, le=1.0)
    speed: float = Field(0.5, ge=0.0, le=1.0)
    mode: Literal["continuous", "relative", "absolute"] = "continuous"

    @field_validator("pan", "tilt", "zoom", "speed")
    @classmethod
    def _finite(cls, v: float) -> float:
        return _reject_non_finite(v)


class PTZPresetCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=64)

    @field_validator("name")
    @classmethod
    def _clean(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("preset name must not be empty")
        return v


class PTZAdapterSelectRequest(BaseModel):
    """Admin: manually force which adapter a camera uses."""

    model_config = ConfigDict(extra="forbid")

    adapter: str = Field(..., min_length=1, max_length=32)


class PTZDiscoverRequest(BaseModel):
    """Admin: WS-Discovery. Optional ``ip`` adds a directed unicast probe (for a
    camera on another subnet / a network that drops multicast)."""

    model_config = ConfigDict(extra="forbid")

    ip: Optional[str] = Field(default=None, max_length=45)

    @field_validator("ip")
    @classmethod
    def _valid_ip(cls, v: Optional[str]) -> Optional[str]:
        if v is None or not str(v).strip():
            return None
        from ipaddress import ip_address

        try:
            return str(ip_address(str(v).strip()))
        except ValueError:
            raise ValueError("ip must be a valid IPv4 or IPv6 address")


# -- responses ----------------------------------------------------------
class PTZCapabilitiesResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    available: bool = False
    adapter: str = "null"
    detected: bool = False
    pan: bool = False
    tilt: bool = False
    optical_zoom: bool = False
    continuous_move: bool = False
    relative_move: bool = False
    absolute_move: bool = False
    stop: bool = False
    home: bool = False
    presets: bool = False
    position_feedback: bool = False
    last_probe_at: Optional[str] = None
    probe_error: Optional[str] = None


class PTZPresetResponse(BaseModel):
    token: str
    name: str


class PTZPresetsResponse(BaseModel):
    presets: List[PTZPresetResponse] = Field(default_factory=list)


class PTZPositionResponse(BaseModel):
    pan: Optional[float] = None
    tilt: Optional[float] = None
    zoom: Optional[float] = None


class PTZCommandResult(BaseModel):
    ok: bool = True
    request_id: str
    command: str


__all__ = [
    "PTZMoveRequest",
    "PTZPresetCreateRequest",
    "PTZAdapterSelectRequest",
    "PTZCapabilitiesResponse",
    "PTZPresetResponse",
    "PTZPresetsResponse",
    "PTZPositionResponse",
    "PTZCommandResult",
]
