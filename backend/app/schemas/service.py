from __future__ import annotations

from typing import Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class ServiceBase(BaseModel):
    slug: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=50)
    description: Optional[str] = Field(default=None, max_length=280)
    category: Optional[str] = Field(default=None, max_length=50)

    model_config = ConfigDict(str_strip_whitespace=True)


class ServiceLinks(BaseModel):
    website: Optional[str] = None
    documentation: Optional[str] = None
    github: Optional[str] = None


class ServiceRequirements(BaseModel):
    ram: Optional[str] = None
    disk: Optional[str] = None
    ports: Optional[list[str]] = None


class ServiceResponse(ServiceBase):
    icon: Optional[str] = Field(default=None, max_length=4)
    version: Optional[str] = Field(default=None, max_length=100)
    features: list[str] = Field(default_factory=list)
    requirements: Optional[ServiceRequirements] = None
    links: Optional[ServiceLinks] = None
    installed: bool = False
    running: bool = False
    status: Optional[str] = Field(default=None, max_length=50)
    ports: Optional[list[str]] = None
    metrics: Optional["ServiceStatus"] = None


class ServiceInstallRequest(BaseModel):
    options: Optional[dict[str, Union[str, int, bool]]] = None


class ServiceStatus(BaseModel):
    running: bool
    installed: bool = True
    state: Optional[str] = Field(default=None, max_length=50)
    uptime: Optional[int] = None
    cpu: Optional[float] = None
    ram: Optional[Union[int, float]] = None
    ports: Optional[list[str]] = None
    raw_output: Optional[str] = None


__all__ = [
    "ServiceBase",
    "ServiceLinks",
    "ServiceRequirements",
    "ServiceResponse",
    "ServiceInstallRequest",
    "ServiceStatus",
]
