from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Literal
from urllib.parse import urlsplit
from weakref import WeakValueDictionary

import anyio
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Request, Response, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.api.cloud_file_responses import cloud_download_response, cloud_thumbnail_response
from app.core.paths import get_easypi_root
from app.models.mobile_device import MobileDevice, MobilePairingChallenge
from app.models.camera import Camera
from app.schemas.picloud import FileListResponse, UploadResponse
from app.services.picloud_service import pi_cloud_service
from app.services.netprotection_service import netprotection_service
from app.api.v1.endpoints.camera_helpers import get_camera_or_404
from app.api.v1.endpoints.camera_snapshots import capture_camera_snapshot
from app.services.stealth_service import get_stealth_service
from app.services.remote_access.tailscale_service import get_tailscale_service
from app.services.mobile_prism_broker import mobile_prism_broker
from app.services.mobile_verdict_client import (
    MOBILE_DECISION_TTL_SECONDS,
    full_policy_verdict,
    policy_version,
)
from app.services.mobile_link_config import (
    MobileLinkConfig,
    load_mobile_link_config,
    save_mobile_link_config,
)
from app.services.mobile_link_agent_service import MobileLinkAgentError, mobile_link_agent_service
from app.services.mobile_link_relay_service import mobile_link_relay_service
from app.services.mobile_home_tunnel_registry import (
    MobileHomeTunnelRegistryError,
    sync_mobile_home_tunnel_registry,
)
from app.services.remote_access.tailscale_relay_service import RelayBusyError, RelayOperationError
from app.core.rate_limit import check_rate_limit
from app.utils.network_security import require_public_ipv4
from app.utils.file_security import unique_upload_path
from app.utils.ssh_host_trust import SSHHostKeyChanged, SSHHostKeyScanError, SSHHostTrustStoreError
from app.utils.time import utc_now
from app.utils.sanitize import sanitize_mac
from app.services.unknown_device_admission_service import UnknownDeviceAdmissionService
from easypi_netprotection.verdict.blocklist_filter import get_blocklist_filter, normalize_domain
from easypi_netprotection.profiles.manager import get_profile_manager

router = APIRouter()


PAIRING_LIFETIME = timedelta(minutes=5)
PAIRING_EXIT_NODE_TIMEOUT_SECONDS = 2.0
MOBILE_LINK_READY_TIMEOUT_SECONDS = 12.0
MOBILE_LAST_SEEN_WRITE_INTERVAL = timedelta(minutes=1)
MOBILE_TUNNEL_NETWORK = ipaddress.ip_network("10.77.0.0/24")
# Initial access profile of a QR-paired phone; the administrator can change it
# afterwards like any other managed device.
MOBILE_TUNNEL_ACCESS_PROFILE = "balanced"
logger = logging.getLogger(__name__)
_photo_upload_locks: WeakValueDictionary[str, asyncio.Lock] = WeakValueDictionary()


class PairingStartResponse(BaseModel):
    pairing_code: str
    expires_at: datetime
    tailscale_exit_node: str | None
    certificate_sha256: str | None
    server_url: str | None = None

    @field_serializer("expires_at")
    def serialize_expires_at(self, value: datetime) -> str:
        return _utc_timestamp(value)


class PairingCompleteRequest(BaseModel):
    pairing_code: str = Field(min_length=32, max_length=128)
    device_name: str = Field(min_length=1, max_length=100)
    provision_tailscale: bool = False

    @field_validator("device_name")
    @classmethod
    def validate_device_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Device name is required")
        return cleaned


class PairingCompleteResponse(BaseModel):
    device_id: str
    device_name: str
    mobile_token: str
    tailscale_auth_key: str | None
    tailscale_exit_node: str | None


class MobileConfigResponse(BaseModel):
    device_id: str
    device_name: str
    easypi_name: str = "EasyPi"
    tailscale_exit_node: str | None
    photo_folder: str | None = None
    connection_path: Literal["direct", "mobile_link"]
    file_upload_enabled: bool = True
    prism_dns_enabled: bool = True


class MobilePingResponse(BaseModel):
    status: str = "ok"
    device_id: str
    device_name: str
    server_time: datetime

    @field_serializer("server_time")
    def serialize_server_time(self, value: datetime) -> str:
        return _utc_timestamp(value)


class MobileChameleonProfileResponse(BaseModel):
    address: str
    server_address: str
    server_dial_address: str
    # The VPS's public IPv6 endpoint; empty when it has none. Tried first.
    server_dial_address6: str = ""
    psk_key: str
    transport_key: str
    protocol: Literal["http2"] = "http2"
    reality_server_public_key: str
    verify_server_certificate: bool = True
    doh_domain: str = ""
    buffer_size: int
    reconnect_interval: int
    fingerprint_mode: Literal["mobile"] = "mobile"
    mtu: int


class MobileHomeTunnelEnrollRequest(BaseModel):
    public_key: str = Field(min_length=80, max_length=512)
    signature: str = Field(min_length=8, max_length=256)

    @field_validator("public_key", "signature")
    @classmethod
    def validate_base64(cls, value: str) -> str:
        try:
            base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Invalid tunnel identity encoding") from exc
        return value


class MobileHomeTunnelEnrollmentResponse(BaseModel):
    address: str
    state: Literal["active"]
    credential_epoch: int
    server_address: str
    server_dial_address: str
    psk_key: str
    transport_key: str
    reality_server_public_key: str
    certificate_sha256: str
    buffer_size: int = 1000
    reconnect_interval: int = 5
    mtu: int = 1200
    prism_link_relay_address: str
    prism_link_relay_installation_id: str
    prism_link_relay_route_key: str
    prism_link_direct_address: str = ""


class MobileLinkSettings(BaseModel):
    enabled: bool = False
    public_url: str | None = Field(default=None, max_length=512)


class MobileLinkAgentConfigure(BaseModel):
    relay_address: str = Field(min_length=3, max_length=320, pattern=r"^[^\s]+:\d{1,5}$")
    server_name: str = Field(min_length=1, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")


class MobileLinkAgentStatus(BaseModel):
    configured: bool = False
    enabled: bool = False
    active: bool = False
    installation_id: str | None = None
    relay_address: str | None = None
    server_name: str | None = None


class MobileLinkRelayHost(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    host: str = Field(min_length=7, max_length=15)
    ssh_port: int = Field(default=22, ge=1, le=65535)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        return require_public_ipv4(value, label="Mobile Link VPS")


class MobileLinkRelayTrust(MobileLinkRelayHost):
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$", max_length=50)


class MobileLinkRelayCredentials(MobileLinkRelayHost):
    ssh_user: str = Field(default="root", min_length=1, max_length=32, pattern=r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
    auth_method: Literal["password", "key"] = "password"
    ssh_password: str | None = Field(default=None, max_length=4096)
    ssh_key: str | None = Field(default=None, max_length=65536)

    @field_validator("ssh_password", "ssh_key")
    @classmethod
    def validate_credential(cls, value: str | None) -> str | None:
        if value is not None and "\x00" in value:
            raise ValueError("SSH credentials cannot contain NUL")
        return value

    def arguments(self) -> dict[str, object]:
        if self.ssh_password and self.ssh_key:
            raise ValueError("Provide only one SSH credential")
        if self.ssh_password and self.auth_method != "password":
            raise ValueError("Select password authentication")
        if self.ssh_key and self.auth_method != "key":
            raise ValueError("Select private-key authentication")
        return {
            "host": self.host,
            "port": self.ssh_port,
            "user": self.ssh_user,
            "password": self.ssh_password,
            "private_key": self.ssh_key,
        }


class MobileLinkRelayDeploy(MobileLinkRelayCredentials):
    domain: str = Field(min_length=4, max_length=253, pattern=r"^[A-Za-z0-9.-]+$")
    agent_port: int = Field(default=9443, ge=1024, le=65535)
    mobile_port: int = Field(default=9444, ge=1024, le=65535)

    @field_validator("domain")
    @classmethod
    def normalize_domain(cls, value: str) -> str:
        labels = value.lower().rstrip(".").split(".")
        if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
            raise ValueError("Enter a valid Mobile Link domain")
        return ".".join(labels)

    def deployment_arguments(self) -> dict[str, object]:
        if self.agent_port == self.mobile_port:
            raise ValueError("Agent and mobile ports must be different")
        return {
            **self.arguments(),
            "domain": self.domain,
            "agent_port": self.agent_port,
            "mobile_port": self.mobile_port,
        }


@router.get("/link/settings", response_model=MobileLinkSettings)
def get_mobile_link_settings(admin=Depends(require_admin)) -> MobileLinkSettings:
    config = load_mobile_link_config()
    return MobileLinkSettings(enabled=config.enabled, public_url=config.public_url)


@router.put("/link/settings", response_model=MobileLinkSettings)
def update_mobile_link_settings(
    payload: MobileLinkSettings,
    admin=Depends(require_admin),
) -> MobileLinkSettings:
    try:
        config = save_mobile_link_config(
            MobileLinkConfig(enabled=payload.enabled, public_url=payload.public_url)
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return MobileLinkSettings(enabled=config.enabled, public_url=config.public_url)


def _run_mobile_link_agent(action: str, *arguments: str) -> MobileLinkAgentStatus:
    try:
        return MobileLinkAgentStatus.model_validate(mobile_link_agent_service.run(action, *arguments))
    except MobileLinkAgentError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@router.get("/link/agent", response_model=MobileLinkAgentStatus)
def get_mobile_link_agent_status(admin=Depends(require_admin)) -> MobileLinkAgentStatus:
    return _run_mobile_link_agent("status")


@router.put("/link/agent", response_model=MobileLinkAgentStatus)
def configure_mobile_link_agent(
    payload: MobileLinkAgentConfigure,
    admin=Depends(require_admin),
) -> MobileLinkAgentStatus:
    return _run_mobile_link_agent("configure", payload.relay_address, payload.server_name)


@router.post("/link/agent/{action}", response_model=MobileLinkAgentStatus)
def manage_mobile_link_agent(
    action: str,
    admin=Depends(require_admin),
) -> MobileLinkAgentStatus:
    if action not in {"enable", "disable", "rotate-secret"}:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown Mobile Link action")
    return _run_mobile_link_agent(action)


def _relay_error(exc: Exception) -> None:
    if isinstance(exc, RelayBusyError):
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    if isinstance(exc, (RelayOperationError, ValueError)):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    raise exc


@router.get("/link/relay/status")
def get_mobile_link_relay_status(admin=Depends(require_admin)):
    return mobile_link_relay_service.public_status()


@router.post("/link/relay/host-key")
async def inspect_mobile_link_relay_host_key(
    payload: MobileLinkRelayHost,
    request: Request,
    admin=Depends(require_admin),
):
    check_rate_limit(request, "ssh_host_key")
    try:
        return await asyncio.to_thread(
            mobile_link_relay_service.trust_store.inspect, payload.host, payload.ssh_port
        )
    except SSHHostKeyScanError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SSHHostTrustStoreError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Secure SSH trust storage is unavailable") from exc


@router.post("/link/relay/trust-host-key")
async def trust_mobile_link_relay_host_key(
    payload: MobileLinkRelayTrust,
    request: Request,
    admin=Depends(require_admin),
):
    check_rate_limit(request, "ssh_host_key")
    try:
        return await asyncio.to_thread(
            mobile_link_relay_service.trust_store.trust,
            payload.host,
            payload.ssh_port,
            payload.fingerprint,
        )
    except (ValueError, SSHHostKeyChanged) as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except SSHHostKeyScanError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc
    except SSHHostTrustStoreError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Secure SSH trust storage is unavailable") from exc


@router.post("/link/relay/check")
async def check_mobile_link_relay_connection(
    payload: MobileLinkRelayCredentials,
    request: Request,
    admin=Depends(require_admin),
):
    check_rate_limit(request, "ssh_auth_check")
    try:
        return await asyncio.to_thread(
            mobile_link_relay_service.check_connection, **payload.arguments()
        )
    except Exception as exc:
        _relay_error(exc)


@router.post("/link/relay/deploy")
async def deploy_mobile_link_relay(
    payload: MobileLinkRelayDeploy,
    request: Request,
    admin=Depends(require_admin),
):
    check_rate_limit(request, "relay_operation")
    try:
        relay_address = f"{payload.domain}:{payload.agent_port}"
        _run_mobile_link_agent("configure", relay_address, payload.domain)
        result = await mobile_link_relay_service.operate(
            "deploy", **payload.deployment_arguments()
        )
        _run_mobile_link_agent("enable")
        save_mobile_link_config(MobileLinkConfig(
            enabled=True,
            public_url=f"https://{payload.domain}:{payload.mobile_port}",
        ))
        return result
    except Exception as exc:
        _relay_error(exc)


@router.post("/link/relay/{action}")
async def manage_mobile_link_relay(
    action: Literal["check-status", "restart", "disable", "uninstall"],
    payload: MobileLinkRelayCredentials,
    request: Request,
    admin=Depends(require_admin),
):
    check_rate_limit(request, "relay_operation")
    try:
        result = await mobile_link_relay_service.operate(
            "status" if action == "check-status" else action,
            **payload.arguments(),
        )
        if action in {"disable", "uninstall"}:
            _run_mobile_link_agent("disable")
            current = load_mobile_link_config()
            save_mobile_link_config(MobileLinkConfig(enabled=False, public_url=current.public_url))
        elif action == "restart":
            _run_mobile_link_agent("enable")
        return result
    except Exception as exc:
        _relay_error(exc)


class TailscaleEnrollmentResponse(BaseModel):
    tailscale_auth_key: str
    tailscale_exit_node: str


class PrismDnsCheckRequest(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    package_name: str | None = Field(default=None, max_length=255)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        normalized = normalize_domain(value)
        if normalized is None or "." not in normalized:
            raise ValueError("A valid DNS domain is required")
        return normalized

    @field_validator("package_name")
    @classmethod
    def validate_package_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            return None
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", cleaned):
            raise ValueError("Invalid Android package name")
        return cleaned


class PrismDnsCheckResponse(BaseModel):
    domain: str
    blocked: bool
    reason: str
    cache_ttl_seconds: int
    # Changes whenever EasyPi's policy files change; empty if unknown.
    policy_version: str = ""


class PrismPresenceRequest(BaseModel):
    addresses: list[str] = Field(min_length=1, max_length=8)

    @field_validator("addresses")
    @classmethod
    def validate_addresses(cls, value: list[str]) -> list[str]:
        normalized = mobile_prism_broker.normalize_addresses(value)
        if not normalized:
            raise ValueError("At least one usable device address is required")
        return sorted(normalized)


class PrismFlowCommandResponse(BaseModel):
    id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str
    policy: str
    confidence: float
    expires_at: float


class PrismFlowAckRequest(BaseModel):
    command_id: str = Field(min_length=36, max_length=36)
    result: str = Field(pattern=r"^(blocked|matched|not_found|expired|unsupported)$")
    package_name: str | None = Field(default=None, max_length=255)

    @field_validator("package_name")
    @classmethod
    def validate_ack_package_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+", cleaned):
            raise ValueError("Invalid Android package name")
        return cleaned


class MobileDeviceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    photo_folder: str | None
    is_active: bool
    created_at: datetime
    last_seen_at: datetime
    revoked_at: datetime | None
    home_tunnel_address: str | None
    home_tunnel_state: str
    home_tunnel_last_handshake_at: datetime | None

    @field_serializer(
        "created_at", "last_seen_at", "revoked_at", "home_tunnel_last_handshake_at"
    )
    def serialize_timestamp(self, value: datetime | None) -> str | None:
        return _utc_timestamp(value) if value is not None else None


class MobilePhotoFolderUpdate(BaseModel):
    photo_folder: str = Field(min_length=1, max_length=100)
    backup_videos: bool = False

    @field_validator("photo_folder")
    @classmethod
    def validate_photo_folder(cls, value: str) -> str:
        cleaned = value.strip()
        if (
            not cleaned
            or cleaned.startswith(".")
            or cleaned in {".", ".."}
            or cleaned.endswith(".")
            or any(character in cleaned for character in ("/", "\\", ":"))
            or any(ord(character) < 32 for character in cleaned)
        ):
            raise ValueError("Enter a valid visible folder name")
        reserved = {"photos", "videos", "documents", "music", "encrypted", "files", "telegram", "taildrop"}
        if cleaned.casefold() in reserved:
            raise ValueError("This folder name is reserved by EasyPi Cloud")
        return cleaned


class MobilePhotoFolderResponse(BaseModel):
    photo_folder: str
    backup_videos: bool = False


class MobileCameraResponse(BaseModel):
    id: str
    name: str
    location: str | None
    status: str


class MobileProtectionHour(BaseModel):
    hour: int = Field(ge=0, le=23)
    total: int = Field(ge=0)
    blocked: int = Field(ge=0)


class MobileBlockedDomain(BaseModel):
    domain: str = Field(min_length=1, max_length=253)
    hits: int = Field(ge=1)


class MobileProtectionStatsResponse(BaseModel):
    total_queries: int = Field(ge=0)
    blocked_queries: int = Field(ge=0)
    block_percentage: float = Field(ge=0, le=100)
    hourly: list[MobileProtectionHour]
    top_blocked: list[MobileBlockedDomain]


def _utc_timestamp(value: datetime) -> str:
    """Serialize the database's naive-UTC values as unambiguous RFC 3339 UTC."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.isoformat().replace("+00:00", "Z")


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _protection_client_id(client_ip: str) -> str:
    """Match the anonymized client identifier stored in the PRISM flow log."""
    return hashlib.sha256(client_ip.encode("utf-8")).hexdigest()[:16]


def _observed_client_ip(request: Request) -> str:
    peer_text = request.client.host if request.client is not None else ""
    forwarded = request.headers.get("x-real-ip", "").strip()
    # The packaged backend can expose no ASGI peer for its loopback-only
    # listener. Both EasyPi nginx endpoints overwrite X-Real-IP, so it remains
    # the trusted observed address in that deployment shape.
    if not peer_text and forwarded:
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid forwarded client address") from exc
    try:
        peer = ipaddress.ip_address(peer_text)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Client address is unavailable") from exc
    # Production nginx terminates HTTPS locally and overwrites X-Real-IP. Never
    # trust forwarding headers from a directly connected network client.
    if peer.is_loopback:
        if forwarded:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError as exc:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid forwarded client address") from exc
    return str(peer)


def _mobile_connection_path(request: Request) -> Literal["direct", "mobile_link"]:
    """Distinguish local nginx from the private Mobile Link nginx endpoint."""
    forwarded = request.headers.get("x-real-ip", "").strip()
    if not forwarded:
        return "direct"
    try:
        forwarded_ip = ipaddress.ip_address(forwarded)
    except ValueError:
        return "direct"
    peer_text = request.client.host if request.client is not None else ""
    if not peer_text:
        return "mobile_link" if forwarded_ip.is_loopback else "direct"
    try:
        peer_is_loopback = ipaddress.ip_address(peer_text).is_loopback
    except ValueError:
        # Starlette's in-process TestClient uses the non-IP peer "testclient".
        peer_is_loopback = peer_text == "testclient"
    if not peer_is_loopback:
        return "direct"
    return "mobile_link" if forwarded_ip.is_loopback else "direct"


def _tls_certificate_fingerprint() -> str | None:
    cert_path = os.getenv("EASYPI_TLS_CERT_PATH")
    path = get_easypi_root() / "certs" / "cert.pem" if not cert_path else get_easypi_root() / cert_path
    if cert_path and os.path.isabs(cert_path):
        path = Path(cert_path)
    try:
        pem = path.read_text(encoding="ascii")
        match = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.DOTALL)
        if match is None:
            return None
        der = ssl.PEM_cert_to_DER_cert(match.group(0))
        return hashlib.sha256(der).hexdigest()
    except (OSError, UnicodeError, ValueError):
        logger.warning("Could not read EasyPi TLS certificate fingerprint from %s", path)
        return None


async def _current_exit_node() -> str | None:
    try:
        info = await get_tailscale_service().get_detailed_status()
    except Exception as exc:
        logger.warning("Could not read Tailscale status while pairing mobile device: %s", exc)
        return None
    if not info.is_exit_node:
        return None
    return info.dns_name or info.hostname or info.tailscale_ip


async def _current_exit_node_without_blocking_pairing() -> str | None:
    """Best-effort exit-node lookup that never holds up QR-code creation."""
    try:
        return await asyncio.wait_for(
            _current_exit_node(),
            timeout=PAIRING_EXIT_NODE_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        logger.warning(
            "Tailscale status lookup exceeded %.1f seconds; continuing mobile pairing without it",
            PAIRING_EXIT_NODE_TIMEOUT_SECONDS,
        )
        return None


def _probe_pinned_mobile_link(public_url: str, certificate_sha256: str) -> bool:
    """Probe one TLS connection while pinning the exact EasyPi certificate."""
    parsed = urlsplit(public_url)
    host = parsed.hostname
    if parsed.scheme != "https" or host is None:
        return False
    try:
        port = parsed.port or 443
        expected = bytes.fromhex(certificate_sha256)
    except ValueError:
        return False
    if len(expected) != hashlib.sha256().digest_size:
        return False

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    # Mobile Link forwards the installation certificate end to end. It can be
    # locally issued and need not contain the public relay hostname, so verify
    # its exact QR-pinned fingerprint instead of trusting an unrelated CA.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=3.0) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                peer = tls.getpeercert(binary_form=True)
                if not peer or not hmac.compare_digest(hashlib.sha256(peer).digest(), expected):
                    return False
                tls.settimeout(3.0)
                request = (
                    "GET /api/v1/mobile/ping HTTP/1.1\r\n"
                    f"Host: {parsed.netloc}\r\n"
                    "Connection: close\r\n"
                    "User-Agent: EasyPi-Mobile-Link-Probe/1\r\n\r\n"
                )
                tls.sendall(request.encode("ascii"))
                header = bytearray()
                while b"\r\n" not in header and len(header) < 4096:
                    chunk = tls.recv(1024)
                    if not chunk:
                        break
                    header.extend(chunk)
    except (OSError, ssl.SSLError, UnicodeError):
        return False
    try:
        status_code = int(bytes(header).split(b"\r\n", 1)[0].split(b" ", 2)[1])
    except (IndexError, ValueError):
        return False
    return status_code == status.HTTP_401_UNAUTHORIZED


async def _mobile_link_transport_ready(public_url: str, certificate_sha256: str) -> bool:
    """Verify the complete public HTTPS -> relay -> local Mobile API path."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + MOBILE_LINK_READY_TIMEOUT_SECONDS
    while True:
        # An unauthenticated ping must reach EasyPi and return its deliberate
        # auth challenge. No mobile token is created or exposed by this probe.
        if await asyncio.to_thread(
            _probe_pinned_mobile_link, public_url, certificate_sha256
        ):
            return True
        if loop.time() >= deadline:
            return False
        await asyncio.sleep(0.5)


def require_mobile_device(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_db),
) -> MobileDevice:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Mobile authentication required")
    device = db.execute(
        select(MobileDevice).where(
            MobileDevice.token_hash == _digest(token),
            MobileDevice.is_active.is_(True),
        )
    ).scalar_one_or_none()
    if device is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked mobile token")
    now = utc_now()
    if device.last_seen_at is None or now - device.last_seen_at >= MOBILE_LAST_SEEN_WRITE_INTERVAL:
        device.last_seen_at = now
        db.commit()
    return device


@router.get("/auth-check", status_code=status.HTTP_204_NO_CONTENT)
def mobile_auth_check(device: MobileDevice = Depends(require_mobile_device)) -> Response:
    """Bodyless nginx auth_request gate, using the same revocable device token."""
    return Response(status_code=status.HTTP_204_NO_CONTENT, headers={"Cache-Control": "no-store"})


@router.post("/prism/chrome/{operation}")
async def chrome_bridge_operation(
    operation: str,
    request: Request,
    device: MobileDevice = Depends(require_mobile_device),
):
    from app.services.chrome_bridge_service import call
    if operation not in {"lease", "keys", "status", "disable"}:
        raise HTTPException(status_code=404, detail="Unknown Chrome operation")
    # Do not use a Pydantic secret-bearing body: validation responses can echo it.
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > 11000:
            raise HTTPException(status_code=413, detail="Chrome request too large")
        raw.extend(chunk)
    try:
        payload = json.loads(raw) if raw else {}
        if not isinstance(payload, dict):
            raise ValueError()
        result = await asyncio.to_thread(call, device.id, operation, payload)
    except Exception:
        raise HTTPException(status_code=409, detail="Chrome bridge unavailable or request rejected") from None
    return Response(content=json.dumps(result), media_type="application/json", headers={"Cache-Control": "no-store"})


@router.post("/pairing/start", response_model=PairingStartResponse)
async def start_pairing(
    admin=Depends(require_admin),
    db: Session = Depends(get_db),
) -> PairingStartResponse:
    mobile_link = load_mobile_link_config()
    certificate_sha256 = _tls_certificate_fingerprint()
    if mobile_link.enabled:
        # Clean installs, signed updates and pairing all use the same
        # idempotent installer for the private nginx listener.
        _run_mobile_link_agent("ensure-endpoint")
        # Pairing must never advertise a public address whose transport is
        # stopped. A configured Mobile Link is an implementation detail: heal
        # it here so adding a phone remains a single, user-facing operation.
        agent = _run_mobile_link_agent("status")
        if not agent.configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Remote Mobile Link is enabled but not configured",
            )
        if not agent.active:
            agent = _run_mobile_link_agent("enable")
        if not agent.active:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Remote Mobile Link could not be started",
            )
        if (
            mobile_link.public_url is None
            or certificate_sha256 is None
            or not await _mobile_link_transport_ready(
                mobile_link.public_url, certificate_sha256
            )
        ):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Remote Mobile Link is still starting or unavailable",
            )

    now = utc_now()
    db.execute(delete(MobilePairingChallenge).where(MobilePairingChallenge.expires_at <= now))
    pairing_code = secrets.token_urlsafe(32)
    expires_at = now + PAIRING_LIFETIME
    exit_node = await _current_exit_node_without_blocking_pairing()
    db.add(MobilePairingChallenge(
        created_by=admin.id,
        code_hash=_digest(pairing_code),
        tailscale_exit_node=exit_node,
        expires_at=expires_at,
    ))
    db.commit()
    return PairingStartResponse(
        pairing_code=pairing_code,
        expires_at=expires_at,
        tailscale_exit_node=exit_node,
        certificate_sha256=certificate_sha256,
        server_url=mobile_link.public_url if mobile_link.enabled else None,
    )


async def _create_mobile_tailscale_auth_key() -> str:
    raise ValueError("Untracked legacy mobile Tailscale enrollment is retired")


@router.post("/pairing/complete", response_model=PairingCompleteResponse)
async def complete_pairing(
    payload: PairingCompleteRequest,
    response: Response,
    db: Session = Depends(get_db),
) -> PairingCompleteResponse:
    now = utc_now()
    code_hash = _digest(payload.pairing_code)
    challenge = db.execute(
        select(MobilePairingChallenge).where(MobilePairingChallenge.code_hash == code_hash)
    ).scalar_one_or_none()
    if challenge is None or challenge.used_at is not None or challenge.expires_at <= now:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pairing code is invalid or expired")

    claimed = db.execute(
        update(MobilePairingChallenge)
        .where(
            MobilePairingChallenge.id == challenge.id,
            MobilePairingChallenge.used_at.is_(None),
            MobilePairingChallenge.expires_at > now,
        )
        .values(used_at=now)
    )
    if claimed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Pairing code is invalid or expired")

    # Retired mobile enrollment had no durable per-device node revocation.
    # Pairing still works for old callers, but never issues an untracked VPN key.
    tailscale_auth_key: str | None = None

    mobile_token = secrets.token_urlsafe(48)
    device = MobileDevice(
        owner_user_id=challenge.created_by,
        name=payload.device_name,
        token_hash=_digest(mobile_token),
        tailscale_exit_node=challenge.tailscale_exit_node,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return PairingCompleteResponse(
        device_id=device.id,
        device_name=device.name,
        mobile_token=mobile_token,
        tailscale_auth_key=tailscale_auth_key,
        tailscale_exit_node=device.tailscale_exit_node,
    )


@router.get("/ping", response_model=MobilePingResponse)
def mobile_ping(
    response: Response,
    device: MobileDevice = Depends(require_mobile_device),
) -> MobilePingResponse:
    """Minimal authenticated endpoint used to verify the Mobile Link path."""
    response.headers["Cache-Control"] = "no-store"
    return MobilePingResponse(
        device_id=device.id,
        device_name=device.name,
        server_time=utc_now(),
    )


@router.post("/tailscale/enrollment", response_model=TailscaleEnrollmentResponse)
async def create_tailscale_enrollment(
    response: Response,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> TailscaleEnrollmentResponse:
    """The untracked legacy VPN enrollment is retired; use scoped Chameleon."""
    raise HTTPException(status_code=status.HTTP_410_GONE, detail="Legacy mobile Tailscale enrollment is retired. Use Chameleon device enrollment.")


@router.get("/config", response_model=MobileConfigResponse)
def mobile_config(
    request: Request,
    device: MobileDevice = Depends(require_mobile_device),
) -> MobileConfigResponse:
    return MobileConfigResponse(
        device_id=device.id,
        device_name=device.name,
        tailscale_exit_node=device.tailscale_exit_node,
        photo_folder=device.photo_folder,
        connection_path=_mobile_connection_path(request),
    )


def _mobile_chameleon_address(device: MobileDevice, db: Session) -> str:
    used: set[str] = set()
    for value in db.execute(
        select(MobileDevice.chameleon_address).where(
            MobileDevice.chameleon_address.is_not(None),
            MobileDevice.id != device.id,
        )
    ).scalars():
        try:
            used.add(str(ipaddress.ip_interface(str(value)).ip))
        except ValueError:
            continue
    if device.chameleon_address:
        try:
            current = ipaddress.ip_interface(device.chameleon_address)
            if (current.version == 4 and current.network.prefixlen == 32
                    and current.ip in ipaddress.ip_network("10.10.0.0/24")
                    and 3 <= int(str(current.ip).rsplit(".", 1)[1]) <= 254
                    and str(current.ip) not in used):
                return str(current)
        except ValueError:
            pass
        device.chameleon_address = None
    for suffix in range(3, 255):
        candidate = f"10.10.0.{suffix}"
        if candidate not in used:
            return f"{candidate}/32"
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="No Chameleon mobile addresses are available",
    )


def _mobile_home_tunnel_address(
    device: MobileDevice, db: Session, reserved: frozenset[str] = frozenset()
) -> str:
    """Allocate a stable routed identity; never represent it as a LAN MAC.

    ``reserved`` holds addresses still claimed by managed devices of another
    identity. They are not handed to a new phone until that policy is removed,
    so a former phone's approval can never be inherited by a new one.
    """
    network = MOBILE_TUNNEL_NETWORK
    used: set[str] = set()
    for value in db.execute(
        select(MobileDevice.home_tunnel_address).where(
            MobileDevice.home_tunnel_address.is_not(None),
            MobileDevice.id != device.id,
        )
    ).scalars():
        try:
            used.add(str(ipaddress.ip_interface(str(value)).ip))
        except ValueError:
            continue
    if device.home_tunnel_address:
        try:
            current = ipaddress.ip_interface(device.home_tunnel_address)
            if (
                current.version == 4
                and current.network.prefixlen == 32
                and current.ip in network
                # .2 is reserved for the server's legacy installation
                # credential. Routed per-phone identities begin at .3.
                and 3 <= int(str(current.ip).rsplit(".", 1)[1]) <= 254
                and str(current.ip) not in used
            ):
                return str(current)
        except ValueError:
            pass
        device.home_tunnel_address = None
    for suffix in range(3, 255):
        candidate = f"10.77.0.{suffix}"
        if candidate not in used and candidate not in reserved:
            return f"{candidate}/32"
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="No mobile home-tunnel addresses are available",
    )


def _active_home_tunnel_devices(db: Session) -> list[MobileDevice]:
    return list(
        db.execute(
            select(MobileDevice).where(
                MobileDevice.is_active.is_(True),
                MobileDevice.revoked_at.is_(None),
                MobileDevice.home_tunnel_public_key.is_not(None),
                MobileDevice.home_tunnel_address.is_not(None),
                MobileDevice.home_tunnel_state == "active",
            )
        ).scalars()
    )


def _mobile_tunnel_mac(device_id: str) -> str:
    return sanitize_mac(UnknownDeviceAdmissionService.mobile_tunnel_mac(device_id))


def _client_ipv4_addresses(client: dict) -> set[str]:
    values = [client.get("ip")]
    if isinstance(client.get("ids"), list):
        values.extend(client["ids"])
    addresses: set[str] = set()
    for value in values:
        try:
            addresses.add(str(ipaddress.IPv4Address(str(value or "").strip())))
        except ValueError:
            continue
    return addresses


async def _managed_clients() -> list[dict]:
    payload = await netprotection_service.get_clients()
    clients = payload.get("clients") if isinstance(payload, dict) else None
    if not isinstance(clients, list):
        return []
    return [item for item in clients if isinstance(item, dict)]


def _claimed_tunnel_addresses(
    clients: list[dict], owned_macs: set[str]
) -> frozenset[str]:
    """Return tunnel addresses held by managed devices of another identity."""
    claimed: set[str] = set()
    for client in clients:
        if sanitize_mac(client.get("mac")) in owned_macs:
            continue
        claimed.update(
            address
            for address in _client_ipv4_addresses(client)
            if ipaddress.IPv4Address(address) in MOBILE_TUNNEL_NETWORK
        )
    return frozenset(claimed)


async def _ensure_mobile_tunnel_client(
    device_id: str, device_name: str, address: str, predecessor_id: str | None
) -> None:
    """Publish the managed device and profile of a QR-paired phone.

    Scanning an administrator-issued pairing QR code is the explicit admission
    decision, so the phone does not wait for a second banner approval. The
    shared transactional approval keeps the firewall fail-closed until the
    complete policy is active.
    """
    mac = _mobile_tunnel_mac(device_id)
    clients = await _managed_clients()
    by_mac = {sanitize_mac(client.get("mac")): client for client in clients}
    identity = {"ip": address, "ids": [address], "mac": mac}
    current = by_mac.get(mac)
    if current is not None:
        if str(current.get("ip") or "") != address:
            await netprotection_service.approve_client_transactional(
                identity, require_existing=True
            )
        return
    previous = (
        by_mac.get(_mobile_tunnel_mac(predecessor_id)) if predecessor_id else None
    )
    if previous is not None:
        # The same phone was paired again: move its existing device ID and
        # individual restrictions instead of creating a second identity.
        await netprotection_service.approve_client_transactional(
            identity, existing_client_id=str(previous.get("id") or "")
        )
        return
    names = {str(client.get("name") or "") for client in clients}
    base = f"{device_name} (mobile)"[:64]
    name, suffix = base, 2
    while name in names:
        name = f"{base[:60]} {suffix}"
        suffix += 1
    await netprotection_service.approve_client_transactional(
        netprotection_service.managed_client_record(
            name, address, mac, MOBILE_TUNNEL_ACCESS_PROFILE
        )
    )


async def _remove_mobile_tunnel_client(device_id: str) -> None:
    """Delete a revoked phone's managed device; its profile follows it."""
    mac = _mobile_tunnel_mac(device_id)
    for client in await _managed_clients():
        if sanitize_mac(client.get("mac")) == mac:
            await netprotection_service.delete_client(str(client.get("name") or ""))


def _retire_mobile_device(
    device: MobileDevice, db: Session, *, remove_policy: bool
) -> None:
    """Revoke a phone everywhere, then delete its row; safe to retry."""
    device_id = device.id
    if device.home_tunnel_address:
        device.is_active = False
        device.revoked_at = utc_now()
        db.commit()
        try:
            sync_mobile_home_tunnel_registry(_active_home_tunnel_devices(db))
        except MobileHomeTunnelRegistryError:
            raise HTTPException(
                status_code=503,
                detail="Mobile API access is revoked; home tunnel revocation could not be confirmed. Retry deletion.",
            ) from None
    if remove_policy:
        try:
            anyio.from_thread.run(_remove_mobile_tunnel_client, device_id)
        except (ValueError, RuntimeError):
            device.is_active = False
            device.revoked_at = device.revoked_at or utc_now()
            db.commit()
            raise HTTPException(
                status_code=503,
                detail="Mobile API access is revoked; its device policy could not be removed. Retry deletion.",
            ) from None
    if device.chameleon_address:
        service = get_stealth_service()
        try:
            with service.mobile_credentials_update():
                db.refresh(device)
                device.is_active = False
                device.revoked_at = utc_now()
                db.commit()
                # Keep the revoked row if remote synchronization fails: the
                # admin can retry, and API access is already closed.
                service.sync_mobile_clients(_active_chameleon_devices(db))
                db.delete(device)
                db.commit()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=503, detail="Mobile API access is revoked; VPS revocation could not be confirmed. Retry deletion.") from None
    else:
        db.delete(device)
        db.commit()


@router.post(
    "/home-tunnel/enroll", response_model=MobileHomeTunnelEnrollmentResponse
)
def enroll_mobile_home_tunnel(
    payload: MobileHomeTunnelEnrollRequest,
    response: Response,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> MobileHomeTunnelEnrollmentResponse:
    """Bind one authenticated phone identity to one routed Prism address."""
    db.refresh(device)
    if not device.is_active or device.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Mobile device revoked")
    try:
        public_der = base64.b64decode(payload.public_key, validate=True)
        public_key = serialization.load_der_public_key(public_der)
        if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(
            public_key.curve, ec.SECP256R1
        ):
            raise ValueError("unsupported key")
        proof = base64.b64decode(payload.signature, validate=True)
        statement = (
            f"easypi/home-tunnel/enroll/v1\n{device.id}\n{payload.public_key}"
        ).encode("ascii")
        public_key.verify(proof, statement, ec.ECDSA(hashes.SHA256()))
    except (ValueError, TypeError, InvalidSignature):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid home-tunnel identity proof",
        ) from None
    if (
        device.home_tunnel_public_key is not None
        and not hmac.compare_digest(device.home_tunnel_public_key, payload.public_key)
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This phone already has a different home-tunnel identity",
        )
    predecessor_id: str | None = None
    if device.home_tunnel_public_key is None:
        holder = db.execute(
            select(MobileDevice).where(
                MobileDevice.home_tunnel_public_key == payload.public_key,
                MobileDevice.id != device.id,
            )
        ).scalar_one_or_none()
        if holder is not None:
            # The signature above proves possession of the same non-exportable
            # Android keystore key: this is the same phone, paired again with a
            # new administrator-issued QR code. Retire the old record and keep
            # the phone's routed address and policy instead of creating a
            # second identity for one phone.
            predecessor_id = holder.id
            inherited_address = holder.home_tunnel_address
            inherited_folder = holder.photo_folder
            _retire_mobile_device(holder, db, remove_policy=False)
            db.refresh(device)
            if inherited_address and not device.home_tunnel_address:
                device.home_tunnel_address = inherited_address
            if inherited_folder and not device.photo_folder:
                device.photo_folder = inherited_folder
        device.home_tunnel_public_key = payload.public_key
        device.home_tunnel_credential_epoch += 1
    owned_macs = {_mobile_tunnel_mac(device.id)}
    if predecessor_id:
        owned_macs.add(_mobile_tunnel_mac(predecessor_id))
    reserved = _claimed_tunnel_addresses(
        anyio.from_thread.run(_managed_clients), owned_macs
    )
    device.home_tunnel_address = _mobile_home_tunnel_address(device, db, reserved)
    device.home_tunnel_state = "active"
    device.protection_client_id = _protection_client_id(
        device.home_tunnel_address.split("/", 1)[0]
    )
    try:
        db.flush()
        sync_mobile_home_tunnel_registry(_active_home_tunnel_devices(db))
        db.commit()
    except MobileHomeTunnelRegistryError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Mobile home-tunnel registry is unavailable",
        ) from exc
    try:
        anyio.from_thread.run(
            _ensure_mobile_tunnel_client,
            device.id,
            device.name,
            str(ipaddress.ip_interface(device.home_tunnel_address).ip),
            predecessor_id,
        )
    except (ValueError, RuntimeError) as exc:
        # Fail closed: the address stays outside the admission allow-list and
        # the peer remains visible for an explicit administrator decision.
        logger.warning("Mobile tunnel device policy was not activated: %s", exc)
    relay = mobile_link_relay_service.public_status()
    domain = str(relay.get("domain") or "").strip()
    mobile_port = int(relay.get("mobile_port") or 0) + 2
    certificate_sha256 = _tls_certificate_fingerprint()
    if not domain or mobile_port <= 2 or not certificate_sha256:
        raise HTTPException(status_code=503, detail="Mobile home tunnel endpoint is unavailable")
    try:
        profile = mobile_link_agent_service.home_profile(
            device.id, device.home_tunnel_address, domain, mobile_port
        )
    except MobileLinkAgentError as exc:
        raise HTTPException(status_code=503, detail="Mobile home tunnel endpoint is unavailable") from exc
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return MobileHomeTunnelEnrollmentResponse(
        address=device.home_tunnel_address,
        state="active",
        credential_epoch=device.home_tunnel_credential_epoch,
        server_address=profile["server_address"],
        server_dial_address=profile["server_dial_address"],
        psk_key=profile["psk_key"],
        transport_key=profile["transport_key"],
        reality_server_public_key=profile["reality_server_public_key"],
        # The VPS forwards TLS bytes unchanged. The Pi terminates TLS.
        certificate_sha256=certificate_sha256,
        buffer_size=int(profile.get("buffer_size") or 1000),
        reconnect_interval=int(profile.get("reconnect_interval") or 5),
        mtu=int(profile.get("mtu") or 1200),
        prism_link_relay_address=profile["prism_link_relay_address"],
        prism_link_relay_installation_id=profile["prism_link_relay_installation_id"],
        prism_link_relay_route_key=profile["prism_link_relay_route_key"],
        prism_link_direct_address=str(profile.get("prism_link_direct_address") or ""),
    )


@router.post("/chameleon/enroll", response_model=MobileChameleonProfileResponse)
def enroll_mobile_chameleon(
    response: Response,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> MobileChameleonProfileResponse:
    """Provision this phone on the same Chameleon VPS used by home EasyPi."""
    try:
        service = get_stealth_service()
        with service.mobile_credentials_update():
            db.refresh(device)
            if not device.is_active or device.revoked_at is not None:
                raise HTTPException(status_code=401, detail="Mobile device revoked")
            address = _mobile_chameleon_address(device, db)
            profile = service.mobile_client_profile(address, device.id)
            device.chameleon_address = address
            device.protection_client_id = _protection_client_id(address.split("/", 1)[0])
            db.commit()
            service.sync_mobile_clients(_active_chameleon_devices(db))
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_412_PRECONDITION_FAILED,
            detail=str(exc),
        ) from exc
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=503, detail="Could not synchronize device credentials with the VPN server") from None
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return MobileChameleonProfileResponse(**profile)


def _active_chameleon_devices(db: Session) -> list[dict[str, str]]:
    return [{"id": item.id, "address": item.chameleon_address} for item in db.execute(
        select(MobileDevice).where(MobileDevice.is_active.is_(True), MobileDevice.revoked_at.is_(None), MobileDevice.chameleon_address.is_not(None))
    ).scalars()]


@router.put("/config/photo-folder", response_model=MobilePhotoFolderResponse)
def update_mobile_photo_folder(
    payload: MobilePhotoFolderUpdate,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> MobilePhotoFolderResponse:
    """Bind this phone's automatic photo backups to one visible Cloud root folder."""
    other_folders = db.execute(
        select(MobileDevice.photo_folder).where(
            MobileDevice.id != device.id,
            MobileDevice.photo_folder.is_not(None),
        )
    ).scalars()
    if any(folder and folder.casefold() == payload.photo_folder.casefold() for folder in other_folders):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This photo folder is already assigned to another phone",
        )
    try:
        folder = _mobile_photo_root(payload.photo_folder)
        pi_cloud_service.create_folder(
            payload.photo_folder, exist_ok=device.photo_folder == payload.photo_folder
        )
        if payload.backup_videos:
            _prepare_mobile_video_folder(folder)
    except FileExistsError as exc:
        raise HTTPException(
            status_code=409, detail="This Cloud folder already exists. Choose a new name."
        ) from exc
    except (OSError, ValueError, RuntimeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not create this Cloud folder",
        ) from exc
    device.photo_folder = payload.photo_folder
    db.commit()
    return MobilePhotoFolderResponse(photo_folder=device.photo_folder, backup_videos=payload.backup_videos)


@router.post("/prism/dns/check", response_model=PrismDnsCheckResponse)
def prism_dns_check(
    payload: PrismDnsCheckRequest,
    device: MobileDevice = Depends(require_mobile_device),
) -> PrismDnsCheckResponse:
    """Apply EasyPi's current DNS policy to a query observed on a linked phone."""
    # The phone forgets every cached decision as soon as this changes, so a
    # policy edit reaches it with its next check instead of after the TTL.
    version = policy_version()

    def decision(blocked: bool, reason: str) -> PrismDnsCheckResponse:
        return PrismDnsCheckResponse(
            domain=payload.domain,
            blocked=blocked,
            reason=reason,
            cache_ttl_seconds=MOBILE_DECISION_TTL_SECONDS,
            policy_version=version,
        )

    # Use the address assigned to this authenticated phone, never one supplied
    # by the caller. The HTTPS control channel can arrive outside the tunnel.
    if device.home_tunnel_state == "active" and device.home_tunnel_address:
        address = str(ipaddress.ip_interface(device.home_tunnel_address).ip)
        # The complete NetProtection policy for this phone, exactly as its DNS
        # queries get it inside the home tunnel: schedules, parental
        # categories, streaming rules, learned blocks, heuristics.
        verdict = full_policy_verdict(payload.domain, address)
        if verdict is not None:
            return decision(verdict.blocked, "easypi_policy" if verdict.blocked else "allowed")
        # NetProtection unreachable: fall back to the reduced check below.
        profile = get_profile_manager().lookup_profile(address)
        if (
            profile and profile.enabled and profile.parental_enabled
            and profile.is_active_now()
            and not profile.is_whitelisted(payload.domain)
            and profile.is_blacklisted(payload.domain)
        ):
            return decision(True, "parental_profile")
    blocklist = get_blocklist_filter()
    blocklist.reload_if_changed()
    blocked = blocklist.is_blocked(payload.domain, check_allowlist=True)
    return decision(blocked, "easypi_blocklist" if blocked else "allowed")


@router.get("/cameras", response_model=list[MobileCameraResponse])
def mobile_cameras(
    _device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> list[MobileCameraResponse]:
    """Return only display-safe camera fields to a linked phone."""
    cameras = db.execute(select(Camera).order_by(Camera.name.asc())).scalars()
    return [
        MobileCameraResponse(
            id=camera.id,
            name=camera.name,
            location=camera.location,
            status=camera.status or "offline",
        )
        for camera in cameras
    ]


@router.get("/protection/stats", response_model=MobileProtectionStatsResponse)
async def mobile_protection_stats(
    request: Request,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> MobileProtectionStatsResponse:
    """Return today's protection summary for this linked phone only."""
    if _mobile_connection_path(request) == "mobile_link":
        client_id = device.protection_client_id
        if client_id is None:
            addresses = mobile_prism_broker.addresses_for(device.id)
            if len(addresses) == 1:
                client_id = _protection_client_id(next(iter(addresses)))
                device.protection_client_id = client_id
                db.commit()
    else:
        client_ip = _observed_client_ip(request)
        client_id = _protection_client_id(client_ip)
        if device.protection_client_id != client_id:
            device.protection_client_id = client_id
            db.commit()

    if client_id is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This phone has not reported protection activity yet",
        )

    stats = await netprotection_service.get_mobile_client_stats_by_id(client_id)
    queries = stats.get("dns_queries") or []
    blocked = stats.get("blocked_filtering") or []
    hourly = [
        MobileProtectionHour(
            hour=hour,
            total=max(0, int(queries[hour] if hour < len(queries) else 0)),
            blocked=max(0, int(blocked[hour] if hour < len(blocked) else 0)),
        )
        for hour in range(24)
    ]
    total_queries = max(0, int(stats.get("num_dns_queries") or sum(item.total for item in hourly)))
    blocked_queries = min(
        total_queries,
        max(0, int(stats.get("num_blocked_filtering") or sum(item.blocked for item in hourly))),
    )

    top_blocked = [
        MobileBlockedDomain(domain=domain, hits=int(hits))
        for domain, hits in (stats.get("top_blocked_domains") or {}).items()
        if domain and len(domain) <= 253 and int(hits) > 0
    ]
    percentage = round((blocked_queries / total_queries * 100) if total_queries else 0.0, 1)
    return MobileProtectionStatsResponse(
        total_queries=total_queries,
        blocked_queries=blocked_queries,
        block_percentage=percentage,
        hourly=hourly,
        top_blocked=top_blocked,
    )


@router.get("/cameras/{camera_id}/snapshot")
async def mobile_camera_snapshot(
    camera_id: str,
    _device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> Response:
    """Return a fresh camera frame using mobile-device authentication."""
    camera = get_camera_or_404(db, camera_id)
    return await capture_camera_snapshot(camera)


@router.post("/prism/presence", status_code=status.HTTP_204_NO_CONTENT)
def prism_presence(
    payload: PrismPresenceRequest,
    request: Request,
    device: MobileDevice = Depends(require_mobile_device),
    db: Session = Depends(get_db),
) -> None:
    observed = _observed_client_ip(request)
    chameleon_address = (device.chameleon_address or "").split("/", 1)[0]
    home_tunnel_address = (device.home_tunnel_address or "").split("/", 1)[0]
    if observed in payload.addresses:
        registered = [observed]
    elif home_tunnel_address and home_tunnel_address in payload.addresses:
        registered = [home_tunnel_address]
    elif chameleon_address and chameleon_address in payload.addresses:
        registered = [chameleon_address]
    else:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Reported address does not match this connection")
    mobile_prism_broker.register(device.id, registered)
    client_id = _protection_client_id(registered[0])
    if device.protection_client_id != client_id:
        device.protection_client_id = client_id
        db.commit()


@router.get("/prism/commands", response_model=list[PrismFlowCommandResponse])
def prism_commands(
    device: MobileDevice = Depends(require_mobile_device),
) -> list[PrismFlowCommandResponse]:
    return [PrismFlowCommandResponse(**command.__dict__) for command in mobile_prism_broker.claim(device.id)]


@router.post("/prism/commands/ack", status_code=status.HTTP_204_NO_CONTENT)
def prism_command_ack(
    payload: PrismFlowAckRequest,
    device: MobileDevice = Depends(require_mobile_device),
) -> None:
    if not mobile_prism_broker.acknowledge(
        device.id,
        payload.command_id,
        result=payload.result,
        package_name=payload.package_name,
    ):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="PRISM command is unknown or expired")


@router.post("/upload", response_model=UploadResponse)
async def mobile_upload(
    file: UploadFile = File(...),
    photo_backup: bool = Form(default=False),
    video_backup: bool = Form(default=False),
    captured_at_ms: int | None = Form(default=None, gt=0, le=4102444800000),
    device: MobileDevice = Depends(require_mobile_device),
) -> UploadResponse:
    """Store phone media in its gallery folder and sort other shared files."""
    content_type = (file.content_type or "").lower()
    if photo_backup and not content_type.startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only photos can use the photo backup flag",
        )
    media_type, _ = mimetypes.guess_type(file.filename or "")
    if video_backup and (photo_backup or not content_type.startswith("video/") or not (media_type or "").startswith("video/")):
        raise HTTPException(status_code=400, detail="Video backup accepts only videos")
    media_prefixes = ("image/", "video/")
    if content_type.startswith(media_prefixes) or (media_type or "").startswith(media_prefixes):
        try:
            folder = _mobile_photo_root(device.photo_folder)
        except (ValueError, OSError, RuntimeError) as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Configure this phone's photo folder before uploading media",
            ) from exc
        if photo_backup or video_backup:
            target = folder.name
            if video_backup:
                try:
                    if not _mobile_video_folder(folder).is_dir():
                        raise ValueError("Video folder missing")
                except (OSError, ValueError, RuntimeError) as exc:
                    raise HTTPException(status_code=409, detail="Enable video backup in the phone folder settings") from exc
                target = f"{folder.name}/Videos"
            lock = _photo_upload_locks.setdefault(target, asyncio.Lock())
            async with lock:
                return await pi_cloud_service.upload_files(
                    [file], target, auto_sort=False,
                    require_target=True, deduplicate=True, generate_preview=False,
                    source_modified=captured_at_ms / 1000 if captured_at_ms is not None else None,
                )
        return await pi_cloud_service.upload_files(
            [file],
            folder.name,
            auto_sort=False,
            require_target=True,
        )
    return await pi_cloud_service.upload_files(
        [file],
        "/",
        auto_sort=True,
    )


@router.get("/cloud/files", response_model=FileListResponse)
def mobile_cloud_files(
    response: Response,
    category: Literal["photos", "videos"] = Query(default="photos"),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=300, ge=1, le=500),
    device: MobileDevice = Depends(require_mobile_device),
) -> FileListResponse:
    """List only media within this phone's assigned Cloud folder."""
    response.headers["Cache-Control"] = "no-store"
    try:
        folder = _mobile_photo_root(device.photo_folder)
        return pi_cloud_service.list_files(
            folder.name,
            category=category,
            sort_by="modified",
            sort_order="desc",
            offset=offset,
            limit=limit,
            restrict_to_path=True,
        )
    except (ValueError, OSError, RuntimeError):
        return FileListResponse(path="/", items=[], total_count=0, has_more=False)


@router.get("/cloud/thumbnail/{file_id:path}")
def mobile_cloud_thumbnail(
    file_id: str,
    device: MobileDevice = Depends(require_mobile_device),
) -> FileResponse:
    """Return Cloud's existing preview for a mobile gallery item."""
    path = _mobile_cloud_path(device, file_id)
    # Legacy thumbnails are keyed by basename and can belong to another phone.
    thumbnail = pi_cloud_service._thumbnail_path(file_id)
    if not thumbnail.is_symlink() and not thumbnail.exists():
        pi_cloud_service._generate_thumbnail(path, file_id)
    if thumbnail.is_symlink() or not thumbnail.is_file():
        raise HTTPException(status_code=404, detail="Thumbnail not found")
    response = cloud_thumbnail_response(thumbnail)
    response.headers["Cache-Control"] = "no-store"
    return response


def _mobile_photo_root(folder: str | None) -> Path:
    if not folder or MobilePhotoFolderUpdate.validate_photo_folder(folder) != folder:
        raise ValueError("No valid phone folder")
    root = pi_cloud_service._safe_path("", allow_root=True)
    expected = root / folder
    if pi_cloud_service._safe_path(folder, allow_root=False) != expected:
        raise ValueError("Phone folder aliases are not allowed")
    if expected.exists() and not expected.is_dir():
        raise ValueError("Phone folder is not a directory")
    return expected


def _mobile_video_folder(folder: Path) -> Path:
    path = folder / "Videos"
    if pi_cloud_service._safe_path(f"{folder.name}/Videos", allow_root=False) != path:
        raise ValueError("Video folder aliases are not allowed")
    return path


def _prepare_mobile_video_folder(folder: Path) -> Path:
    """Create the private video folder and repair legacy mixed media safely."""
    video_folder = _mobile_video_folder(folder)
    if video_folder.is_symlink():
        raise ValueError("Video folder aliases are not allowed")
    video_folder.mkdir(exist_ok=True)
    if not video_folder.is_dir():
        raise ValueError("Video folder is not a directory")

    for entry in folder.iterdir():
        if entry.is_symlink() or not entry.is_file():
            continue
        media_type, _ = mimetypes.guess_type(entry.name)
        if not (media_type or "").startswith("video/"):
            continue
        entry.rename(unique_upload_path(video_folder, entry.name, fallback="video.mp4"))
    return video_folder


def _mobile_cloud_path(device: MobileDevice, file_id: str) -> Path:
    """Authorize both the supplied file ID and its resolved target."""
    try:
        folder = _mobile_photo_root(device.photo_folder)
        normalized = pi_cloud_service._normalize_file_id(file_id)
        parts = normalized.split("/")
        if len(parts) < 2 or parts[0] != folder.name or any(
            part.startswith(".") or ":" in part for part in parts
        ):
            raise ValueError("File outside phone folder")
        path = pi_cloud_service.resolve_file(normalized)
        if path != folder.joinpath(*parts[1:]) or not path.is_file():
            raise ValueError("Invalid phone file")
        return path
    except (ValueError, OSError, RuntimeError):
        raise HTTPException(status_code=404, detail="File not found") from None


@router.get("/cloud/file/{file_id:path}")
def mobile_cloud_file(
    file_id: str,
    device: MobileDevice = Depends(require_mobile_device),
) -> FileResponse:
    """Return an original file from the existing Cloud storage."""
    path = _mobile_cloud_path(device, file_id)
    response = cloud_download_response(path)
    response.headers["Cache-Control"] = "no-store"
    return response


@router.delete("/cloud/file/{file_id:path}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mobile_cloud_file(
    file_id: str,
    device: MobileDevice = Depends(require_mobile_device),
) -> Response:
    """Move one existing Cloud file to Cloud's normal trash."""
    _mobile_cloud_path(device, file_id)
    pi_cloud_service.delete_file(file_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/devices", response_model=list[MobileDeviceResponse])
def list_mobile_devices(_admin=Depends(require_admin), db: Session = Depends(get_db)) -> list[MobileDevice]:
    return list(db.execute(select(MobileDevice).order_by(MobileDevice.created_at.desc())).scalars())


@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_mobile_device(device_id: str, _admin=Depends(require_admin), db: Session = Depends(get_db)) -> None:
    device = db.get(MobileDevice, device_id)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Mobile device not found")
    _retire_mobile_device(device, db, remove_policy=True)
