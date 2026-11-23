"""Administrator API for deploying a Tailscale Peer Relay to a VPS."""

from __future__ import annotations

import asyncio
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.api.deps import require_admin
from app.core.rate_limit import check_rate_limit
from app.services.remote_access.tailscale_relay_service import (
    RelayBusyError,
    RelayOperationError,
    tailscale_relay_service,
)
from app.utils.network_security import require_public_ipv4
from app.utils.ssh_host_trust import (
    SSHHostKeyChanged,
    SSHHostKeyScanError,
    SSHHostTrustStoreError,
)


router = APIRouter(prefix="/remote/tailscale/relay", tags=["Remote Access - Fast Mobile Relay"])
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_AUTH_KEY_RE = re.compile(r"^tskey-auth-[A-Za-z0-9_-]{20,480}$")


class RelayHostRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    host: str = Field(min_length=7, max_length=15)
    ssh_port: int = Field(default=22, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return require_public_ipv4(value, label="Fast Mobile Relay VPS")


class RelayTrustRequest(RelayHostRequest):
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$", max_length=50)


class RelayCredentials(RelayHostRequest):
    ssh_user: str = Field(default="root", min_length=1, max_length=32)
    auth_method: Literal["password", "key"] = "password"
    ssh_password: str | None = Field(default=None, max_length=1024)
    ssh_key: str | None = Field(default=None, max_length=65536)

    @field_validator("ssh_user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not _USER_RE.fullmatch(value):
            raise ValueError("Invalid SSH username")
        return value

    @field_validator("ssh_password", "ssh_key")
    @classmethod
    def reject_nul(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("SSH credentials cannot contain NUL")
        return value

    @model_validator(mode="after")
    def validate_authentication(self) -> "RelayCredentials":
        if self.ssh_password and self.ssh_key:
            raise ValueError("Provide only one SSH credential")
        if self.ssh_password and self.auth_method != "password":
            raise ValueError("Select password authentication for the SSH password")
        if self.ssh_key and self.auth_method != "key":
            raise ValueError("Select private-key authentication for the SSH key")
        return self

    def service_credentials(self) -> dict[str, object]:
        return {
            "host": self.host,
            "port": self.ssh_port,
            "user": self.ssh_user,
            "password": self.ssh_password,
            "private_key": self.ssh_key,
        }


class RelayDeployRequest(RelayCredentials):
    relay_name: str = Field(default="easypi-fast-relay", min_length=1, max_length=63)
    relay_port: int = Field(default=40000, ge=1, le=65535)
    public_endpoint: str | None = Field(default=None, max_length=64)
    auth_key: str | None = Field(default=None, max_length=512)

    @field_validator("relay_name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = value.lower()
        if not _NAME_RE.fullmatch(value):
            raise ValueError("Relay name must contain lowercase letters, numbers, and hyphens")
        return value

    @field_validator("relay_port")
    @classmethod
    def validate_relay_port(cls, value: int) -> int:
        if value != 443 and value < 1024:
            raise ValueError("Relay UDP port must be 443 or between 1024 and 65535")
        return value

    @field_validator("public_endpoint")
    @classmethod
    def validate_endpoint(cls, value: str | None) -> str | None:
        if not value:
            return None
        host, separator, port_text = value.rpartition(":")
        if not separator or not port_text.isdigit():
            raise ValueError("Public endpoint must be a public IPv4 address and UDP port")
        canonical = require_public_ipv4(host, label="Relay public endpoint")
        port = int(port_text)
        if port != 443 and not 1024 <= port <= 65535:
            raise ValueError("Public endpoint UDP port must be 443 or between 1024 and 65535")
        return f"{canonical}:{port}"

    @field_validator("auth_key")
    @classmethod
    def validate_auth_key(cls, value: str | None) -> str | None:
        if not value:
            return None
        if not _AUTH_KEY_RE.fullmatch(value):
            raise ValueError("Use a Tailscale one-time auth key beginning with tskey-auth-")
        return value

    @model_validator(mode="after")
    def default_endpoint(self) -> "RelayDeployRequest":
        if self.public_endpoint is None:
            self.public_endpoint = f"{self.host}:{self.relay_port}"
        return self

    def operation_args(self) -> dict[str, object]:
        return {
            **self.service_credentials(),
            "relay_name": self.relay_name,
            "relay_port": self.relay_port,
            "public_endpoint": self.public_endpoint,
            "auth_key": self.auth_key,
        }


def _raise_operation_error(exc: Exception) -> None:
    if isinstance(exc, RelayBusyError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, RelayOperationError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise exc


@router.get("/status")
async def relay_status(_admin=Depends(require_admin)):
    return tailscale_relay_service.public_status()


@router.post("/host-key")
async def inspect_relay_host_key(
    body: RelayHostRequest, request: Request, _admin=Depends(require_admin)
):
    check_rate_limit(request, "ssh_host_key")
    try:
        return await asyncio.to_thread(
            tailscale_relay_service.trust_store.inspect, body.host, body.ssh_port
        )
    except SSHHostKeyScanError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SSHHostTrustStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure SSH trust storage is unavailable",
        ) from exc


@router.post("/trust-host-key")
async def trust_relay_host_key(
    body: RelayTrustRequest, request: Request, _admin=Depends(require_admin)
):
    check_rate_limit(request, "ssh_host_key")
    try:
        return await asyncio.to_thread(
            tailscale_relay_service.trust_store.trust,
            body.host,
            body.ssh_port,
            body.fingerprint,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except SSHHostKeyChanged as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except SSHHostKeyScanError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SSHHostTrustStoreError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure SSH trust storage is unavailable",
        ) from exc


@router.post("/check")
async def check_relay_connection(
    body: RelayCredentials, request: Request, _admin=Depends(require_admin)
):
    check_rate_limit(request, "ssh_auth_check")
    try:
        return await asyncio.to_thread(
            tailscale_relay_service.check_connection, **body.service_credentials()
        )
    except Exception as exc:
        _raise_operation_error(exc)


@router.post("/deploy")
async def deploy_relay(
    body: RelayDeployRequest, request: Request, _admin=Depends(require_admin)
):
    check_rate_limit(request, "relay_operation")
    try:
        return await tailscale_relay_service.operate("deploy", **body.operation_args())
    except Exception as exc:
        _raise_operation_error(exc)


@router.post("/{action}")
async def manage_relay(
    action: Literal["check-status", "restart", "disable", "uninstall"],
    body: RelayCredentials,
    request: Request,
    _admin=Depends(require_admin),
):
    check_rate_limit(request, "relay_operation")
    remote_action = "status" if action == "check-status" else action
    try:
        return await tailscale_relay_service.operate(
            remote_action,
            **body.service_credentials(),
        )
    except Exception as exc:
        _raise_operation_error(exc)

