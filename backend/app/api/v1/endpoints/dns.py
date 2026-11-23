"""
Personal DNS Server deployment API endpoints
"""

import asyncio
import base64
import hashlib
import io
import ipaddress
import logging
import os
import re
import socket
import ssl
import tarfile
import textwrap
from datetime import datetime, timezone
from app.utils.time import utc_now
from pathlib import Path
from typing import Optional, List
from fastapi import APIRouter, HTTPException, status, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session
import paramiko
import httpx

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.dns_deploy import DNSDeploy
from app.models.user import User
from app.services.operation_event_service import OperationEventService
from app.core.rate_limit import check_rate_limit
from app.utils.ssh_host_trust import (
    SSHHostKeyChanged,
    SSHHostKeyScanError,
    SSHHostKeyUnknown,
    SSHHostTrustStore,
    SSHHostTrustStoreError,
)
from app.utils.network_security import require_public_ipv4
from app.api.v1.endpoints.dns_deployment_scripts import (
    CLEANUP_SCRIPT,
    SECURE_DEPLOYMENT_SCRIPT,
)

logger = logging.getLogger(__name__)

router = APIRouter()
operation_event_service = OperationEventService()
_dns_deployment_lock = asyncio.Lock()


def _dns_ssh_trust_store() -> SSHHostTrustStore:
    return SSHHostTrustStore()


# Validation patterns
IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
)
DUCKDNS_DOMAIN_PATTERN = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.duckdns\.org$"
)
DUCKDNS_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SSH_USER_PATTERN = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$")
PORT_RANGE = (1, 65535)
CONTAINER_IMAGE_PATTERN = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?::[0-9]{1,5})?"
    r"(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|@sha256:[A-Fa-f0-9]{64})?$"
)


def _validate_container_image(value: str) -> str:
    value = value.strip()
    if len(value) > 255 or not CONTAINER_IMAGE_PATTERN.fullmatch(value):
        raise ValueError("NETPROTECTION_IMAGE is not a valid container image reference")
    return value


def _build_netprotection_bundle_b64() -> str:
    """
    Package easypi_netprotection as a tar.gz and return base64 with line breaks.
    """
    from app.core.paths import get_easypi_root

    repo_root = get_easypi_root()
    src_dir = repo_root / "easypi_netprotection"
    if not src_dir.is_dir():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="NetProtection source not found on EasyPi server",
        )

    required_files = (
        "Dockerfile",
        "requirements.txt",
        "__init__.py",
        "__main__.py",
        "server.py",
        "system/__init__.py",
        "system/bootstrap.py",
    )
    missing_files = [
        rel
        for rel in required_files
        if not (src_dir / rel).is_file()
        or (src_dir / rel).is_symlink()
        or not os.access(src_dir / rel, os.R_OK)
    ]
    if missing_files:
        logger.error("NetProtection source bundle is incomplete: %s", missing_files)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="NetProtection source is incomplete on the EasyPi server",
        )

    buf = io.BytesIO()
    archived_files: set[str] = set()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for root, dirs, files in os.walk(src_dir):
            dirs[:] = [
                d
                for d in dirs
                if d != "__pycache__" and not (Path(root) / d).is_symlink()
            ]

            # Add directories explicitly.  The remote installer deliberately
            # uses umask 077; without directory entries, tar creates implicit
            # 0700 directories that the unprivileged container UID cannot
            # traverse.  Normalize metadata instead of leaking local owners.
            root_path = Path(root)
            root_rel = root_path.relative_to(src_dir)
            root_arcname = "easypi_netprotection"
            if root_rel.parts:
                root_arcname = f"{root_arcname}/{root_rel.as_posix()}"
            directory_info = tar.gettarinfo(str(root_path), arcname=root_arcname)
            directory_info.mode = 0o755
            directory_info.uid = 0
            directory_info.gid = 0
            directory_info.uname = "root"
            directory_info.gname = "root"
            tar.addfile(directory_info)

            for name in files:
                if name.endswith(".pyc"):
                    continue
                full_path = Path(root) / name
                if full_path.is_symlink() or not full_path.is_file():
                    continue
                if not os.access(full_path, os.R_OK):
                    logger.error("Unreadable NetProtection source file: %s", full_path)
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="NetProtection source contains an unreadable file",
                    )
                rel = str(full_path.relative_to(src_dir))
                arcname = f"easypi_netprotection/{rel}"
                try:
                    file_info = tar.gettarinfo(str(full_path), arcname=arcname)
                    file_info.mode = 0o644
                    file_info.uid = 0
                    file_info.gid = 0
                    file_info.uname = "root"
                    file_info.gname = "root"
                    with full_path.open("rb") as source_file:
                        tar.addfile(file_info, source_file)
                    archived_files.add(rel.replace("\\", "/"))
                except OSError as exc:
                    logger.error(
                        "Failed to package NetProtection source file %s: %s",
                        full_path,
                        exc,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                        detail="Could not package the NetProtection source",
                    ) from exc

    missing_from_archive = sorted(set(required_files) - archived_files)
    if missing_from_archive:
        logger.error(
            "NetProtection archive is missing required files: %s", missing_from_archive
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="NetProtection source archive is incomplete",
        )

    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return "\n".join(textwrap.wrap(b64, 76))


def _run_dns_deploy_ssh(
    host: str,
    user: str,
    port: int,
    password: Optional[str],
    private_key: Optional[str],
    script: str,
    timeout: int,
) -> tuple[str, str, int]:
    """
    Blocking SSH deployment runner (executes on a worker thread).
    Returns stdout, stderr, exit_code.
    """
    client = create_ssh_client(
        host=host,
        user=user,
        port=port,
        password=password,
        private_key=private_key,
    )
    try:
        stdin, stdout, stderr = client.exec_command("bash -s", timeout=timeout)
        stdin.write(script)
        stdin.channel.shutdown_write()
        exit_code = stdout.channel.recv_exit_status()
        return stdout.read().decode(), stderr.read().decode(), exit_code
    finally:
        client.close()


class DNSDeployRequest(BaseModel):
    """Request model for DNS server deployment"""

    model_config = ConfigDict(extra="forbid")

    vps_ip: str = Field(..., max_length=15, description="Public VPS IPv4 address")
    ssh_user: str = Field(default="root", max_length=32, description="SSH username")
    ssh_port: int = Field(default=22, description="SSH port")
    ssh_password: Optional[str] = Field(
        None, max_length=1024, description="SSH password"
    )
    ssh_key: Optional[str] = Field(
        None, max_length=65536, description="SSH private key"
    )
    domain: Optional[str] = Field(
        None,
        max_length=253,
        description="Domain for DoH/DoT (optional)",
    )
    duckdns_token: Optional[str] = Field(
        None,
        max_length=128,
        description="DuckDNS token used only to point a DuckDNS name to the VPS",
    )
    certificate_email: Optional[str] = Field(None, max_length=254)
    allowed_client_ips: list[str] = Field(
        default_factory=list,
        max_length=16,
        description="Public IPv4 addresses allowed to use direct TCP/UDP DNS on port 53",
    )

    @field_validator("vps_ip")
    @classmethod
    def validate_ip(cls, v):
        return require_public_ipv4(v, label="VPS target")

    @field_validator("ssh_user")
    @classmethod
    def validate_ssh_user(cls, v):
        if not SSH_USER_PATTERN.match(v):
            raise ValueError("Invalid SSH username format")
        return v

    @field_validator("ssh_port")
    @classmethod
    def validate_ssh_port(cls, v):
        if not PORT_RANGE[0] <= v <= PORT_RANGE[1]:
            raise ValueError(
                f"SSH port must be between {PORT_RANGE[0]} and {PORT_RANGE[1]}"
            )
        return v

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v):
        if not v:
            return None
        normalized = v.strip().lower().rstrip(".")
        if not DOMAIN_PATTERN.fullmatch(normalized):
            raise ValueError("Invalid domain format")
        return normalized

    @field_validator("duckdns_token")
    @classmethod
    def validate_duckdns_token(cls, value):
        if not value:
            return None
        token = value.strip()
        if not DUCKDNS_TOKEN_PATTERN.fullmatch(token):
            raise ValueError("Invalid DuckDNS token format")
        return token

    @field_validator("certificate_email")
    @classmethod
    def validate_certificate_email(cls, value):
        if not value:
            return None
        email = value.strip().lower()
        if not EMAIL_PATTERN.fullmatch(email):
            raise ValueError("Invalid certificate email address")
        return email

    @field_validator("allowed_client_ips")
    @classmethod
    def validate_allowed_client_ips(cls, values):
        return list(
            dict.fromkeys(
                require_public_ipv4(value, label="Allowed DNS client")
                for value in values
            )
        )


class DNSHostKeyInspectRequest(BaseModel):
    """Public endpoint identity to inspect without sending SSH credentials."""

    model_config = ConfigDict(extra="forbid")

    vps_ip: str = Field(..., max_length=15)
    ssh_port: int = Field(default=22)

    @field_validator("vps_ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return require_public_ipv4(value, label="VPS target")

    @field_validator("ssh_port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        if not PORT_RANGE[0] <= value <= PORT_RANGE[1]:
            raise ValueError(
                f"SSH port must be between {PORT_RANGE[0]} and {PORT_RANGE[1]}"
            )
        return value


class DNSHostKeyTrustRequest(DNSHostKeyInspectRequest):
    expected_fingerprint: str = Field(..., min_length=50, max_length=50)


class DNSSSHCredentialCheckRequest(DNSHostKeyInspectRequest):
    """Credentials to test only after the VPS host key has been trusted."""

    ssh_user: str = Field(default="root", max_length=32)
    ssh_password: Optional[str] = Field(None, max_length=1024)
    ssh_key: Optional[str] = Field(None, max_length=65536)

    @field_validator("ssh_user")
    @classmethod
    def validate_ssh_user(cls, value: str) -> str:
        if not SSH_USER_PATTERN.fullmatch(value):
            raise ValueError("Invalid SSH username format")
        return value


class DNSDeployResponse(BaseModel):
    """Response model for DNS deployment"""

    success: bool
    dns_ipv4: str
    doh_url: Optional[str] = None
    dot_url: Optional[str] = None
    admin_panel: Optional[str] = None
    message: str
    wireguard_installed: bool = False
    wireguard_config: Optional[str] = None
    vpn_dns: Optional[str] = None
    warnings: Optional[list] = None
    recommendations: Optional[list] = None
    dns_port: Optional[str] = None


class DNSDeployHistoryEntry(BaseModel):
    """Response model for saved deployment history."""

    success: bool
    message: str
    dns_ipv4: Optional[str] = None
    doh_url: Optional[str] = None
    dot_url: Optional[str] = None
    admin_panel: Optional[str] = None
    wireguard_installed: bool = False
    vpn_dns: Optional[str] = None
    warnings: Optional[list] = None
    recommendations: Optional[list] = None
    dns_port: Optional[str] = None
    ssh_user: str = "root"
    ssh_port: int = 22
    domain: Optional[str] = None


def _history_message(deploy: DNSDeploy) -> str:
    if deploy.deployment_log:
        return deploy.deployment_log
    if deploy.status == "deployed":
        return "Personal DNS server installed successfully."
    if deploy.status == "failed":
        return "Deployment failed."
    return f"Deployment status: {deploy.status}"


def _to_history_entry(deploy: DNSDeploy) -> DNSDeployHistoryEntry:
    wireguard_installed = bool(deploy.wireguard_installed)
    recommendations = (
        deploy.recommendations if isinstance(deploy.recommendations, list) else []
    )
    direct_dns_enabled = any(
        isinstance(item, dict) and item.get("id") == "direct_dns"
        for item in recommendations
    )
    return DNSDeployHistoryEntry(
        success=deploy.status == "deployed",
        message=_history_message(deploy),
        dns_ipv4=deploy.dns_ipv4 or deploy.vps_ip,
        doh_url=deploy.doh_url,
        dot_url=deploy.dot_address,
        admin_panel=deploy.admin_url,
        wireguard_installed=wireguard_installed,
        vpn_dns="10.66.66.1" if wireguard_installed else None,
        warnings=deploy.warnings,
        recommendations=recommendations or None,
        dns_port="53" if direct_dns_enabled else "WireGuard only",
        ssh_user=deploy.ssh_user or "root",
        ssh_port=deploy.ssh_port or 22,
        domain=deploy.domain,
    )


def create_ssh_client(
    host: str,
    user: str,
    port: int = 22,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
) -> paramiko.SSHClient:
    """
    Create and connect SSH client with security measures.

    SECURITY: Uses only the exact host key explicitly approved through the
    Personal DNS trust flow. Agent/key discovery is disabled.
    """
    client = paramiko.SSHClient()

    try:
        canonical_host, canonical_port = _dns_ssh_trust_store().configure_client(
            client, host, port
        )
        if private_key:
            # Parse private key - DO NOT LOG THE KEY
            pkey = None
            for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
                try:
                    pkey = key_class.from_private_key(io.StringIO(private_key))
                    break
                except (paramiko.SSHException, ValueError):
                    continue
            if pkey is None:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="SSH private key is invalid or unsupported",
                )

            client.connect(
                canonical_host,
                port=canonical_port,
                username=user,
                pkey=pkey,
                timeout=60,
                banner_timeout=30,
                auth_timeout=30,
                look_for_keys=False,
                allow_agent=False,
            )
            logger.info(
                "SSH connected to %s:%s using key authentication",
                canonical_host,
                canonical_port,
            )
        else:
            client.connect(
                canonical_host,
                port=canonical_port,
                username=user,
                password=password,
                timeout=60,
                banner_timeout=30,
                auth_timeout=30,
                look_for_keys=False,
                allow_agent=False,
            )
            logger.info(
                "SSH connected to %s:%s using password authentication",
                canonical_host,
                canonical_port,
            )

        return client
    except HTTPException:
        client.close()
        raise
    except SSHHostKeyUnknown as exc:
        client.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except SSHHostTrustStoreError as exc:
        client.close()
        logger.error("Personal DNS SSH trust store rejected access")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure SSH trust storage is unavailable",
        ) from exc
    except paramiko.BadHostKeyException as exc:
        client.close()
        logger.error("SSH host key mismatch for %s:%s", host, port)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SSH host key changed. Deployment is blocked; verify the VPS console.",
        ) from exc
    except paramiko.AuthenticationException as exc:
        client.close()
        logger.warning("SSH authentication failed for %s:%s", host, port)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSH authentication failed. Check the username and credential.",
        ) from exc
    except paramiko.ssh_exception.SSHException as exc:
        client.close()
        logger.error(
            "SSH connection failed to %s:%s: %s", host, port, type(exc).__name__
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SSH negotiation failed. Check the VPS SSH service and try again.",
        ) from exc
    except Exception as exc:
        client.close()
        logger.error(
            "SSH connection error to %s:%s: %s", host, port, type(exc).__name__
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to connect to the VPS",
        ) from exc


def run_ssh_command(
    client: paramiko.SSHClient, command: str, timeout: int = 300
) -> tuple:
    """Run command via SSH and return stdout, stderr"""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return stdout.read().decode(), stderr.read().decode(), exit_code


# This is the only deployment template used by the endpoint.  Unlike the
# historical templates above, it configures the actual EasyPi NetProtection
# Python service (DNS :53, DoH :8053 and DoT :853), never publishes a fake
# administration port. Chameleon keeps :443; Personal DNS uses :8443 for DoH.


async def _resolve_domain_ipv4(domain: str) -> set[str]:
    def _resolve() -> set[str]:
        return {
            item[4][0]
            for item in socket.getaddrinfo(
                domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
        }

    try:
        return await asyncio.to_thread(_resolve)
    except socket.gaierror:
        return set()


async def _prepare_personal_dns_domain(request: DNSDeployRequest) -> None:
    if not request.domain:
        if request.duckdns_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A DuckDNS token can only be used together with a DuckDNS domain",
            )
        return

    if request.duckdns_token:
        if not DUCKDNS_DOMAIN_PATTERN.fullmatch(request.domain):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Automatic DNS setup supports only a separate *.duckdns.org domain",
            )
        subdomain = request.domain.removesuffix(".duckdns.org")
        try:
            async with httpx.AsyncClient(
                timeout=20, trust_env=False, follow_redirects=False
            ) as client:
                response = await client.get(
                    "https://www.duckdns.org/update",
                    params={
                        "domains": subdomain,
                        "token": request.duckdns_token,
                        "ip": request.vps_ip,
                    },
                )
            if response.status_code != 200 or response.text.strip() != "OK":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="DuckDNS rejected the domain update; check the domain and token",
                )
        except HTTPException:
            raise
        except (httpx.HTTPError, OSError) as exc:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Could not update DuckDNS right now",
            ) from exc

    for _attempt in range(10):
        if request.vps_ip in await _resolve_domain_ipv4(request.domain):
            return
        await asyncio.sleep(2)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Domain {request.domain} does not resolve to VPS {request.vps_ip}",
    )


def _safe_remote_deploy_error(stdout: str, stderr: str) -> str:
    def _redact(value: str) -> list[str]:
        value = re.sub(
            r"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
            "[REDACTED KEY]",
            value,
            flags=re.S,
        )
        value = re.sub(
            r"(?im)^(PrivateKey|PresharedKey|token|password)\s*[=:].*$",
            r"\1 = [REDACTED]",
            value,
        )
        value = re.sub(r"(?i)(token=)[^&\s]+", r"\1[REDACTED]", value)
        return [line.strip() for line in value.splitlines() if line.strip()]

    stderr_lines = _redact(stderr)
    stdout_lines = _redact(stdout)

    # The remote script writes the actionable failure and its stage to stderr.
    # Docker writes a large amount of normal build progress to stdout.  Appending
    # stdout after stderr used to hide the real error behind lines such as
    # "Successfully tagged".  Prefer the explicit stage marker, then stderr,
    # and use stdout only when the command produced no stderr at all.
    stage_lines = [line for line in stderr_lines if "EASYPI_DEPLOY_ERROR" in line]
    if stage_lines:
        context = stderr_lines[-8:]
        selected_lines = context + [line for line in stage_lines if line not in context]
    elif stderr_lines:
        actionable = [
            line
            for line in stderr_lines
            if re.search(
                r"(?i)(error|failed|failure|fatal|traceback|timed? out|"
                r"did not become ready|permission denied|address already in use)",
                line,
            )
        ]
        selected_lines = actionable[-8:] if actionable else stderr_lines[-8:]
    else:
        selected_lines = stdout_lines[-8:]

    selected = " | ".join(selected_lines)
    if len(selected) > 1600:
        selected = selected[-1600:]
    return selected or "Remote installation exited without a diagnostic message"


@router.post("/ssh/host-key")
async def inspect_dns_ssh_host_key(
    body: DNSHostKeyInspectRequest,
    http_request: Request,
    _admin: User = Depends(require_admin),
):
    """Observe the VPS identity without sending an SSH password or private key."""

    check_rate_limit(http_request, "ssh_host_key")
    try:
        return await asyncio.to_thread(
            _dns_ssh_trust_store().inspect, body.vps_ip, body.ssh_port
        )
    except SSHHostKeyScanError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc
    except SSHHostTrustStoreError as exc:
        logger.error("Personal DNS SSH trust-store inspection failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure SSH trust storage is unavailable",
        ) from exc


@router.post("/ssh/trust-host-key")
async def trust_dns_ssh_host_key(
    body: DNSHostKeyTrustRequest,
    http_request: Request,
    _admin: User = Depends(require_admin),
):
    """Pin an observed host key only when the administrator confirms its fingerprint."""

    check_rate_limit(http_request, "ssh_host_key")
    try:
        result = await asyncio.to_thread(
            _dns_ssh_trust_store().trust,
            body.vps_ip,
            body.ssh_port,
            body.expected_fingerprint,
        )
        logger.info(
            "Administrator trusted the Personal DNS VPS SSH identity for %s:%s",
            body.vps_ip,
            body.ssh_port,
        )
        return result
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except SSHHostKeyChanged as exc:
        logger.warning(
            "Personal DNS VPS host-key confirmation was rejected for %s:%s",
            body.vps_ip,
            body.ssh_port,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    except SSHHostKeyScanError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)
        ) from exc
    except SSHHostTrustStoreError as exc:
        logger.error("Personal DNS SSH trust-store update failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure SSH trust storage is unavailable",
        ) from exc


@router.post("/ssh/check-credentials")
async def check_dns_ssh_credentials(
    body: DNSSSHCredentialCheckRequest,
    http_request: Request,
    _admin: User = Depends(require_admin),
):
    """Test SSH authentication against an already trusted VPS identity."""

    check_rate_limit(http_request, "ssh_auth_check")
    if bool(body.ssh_password) == bool(body.ssh_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide exactly one SSH credential: password or private key",
        )

    client = await asyncio.to_thread(
        create_ssh_client,
        body.vps_ip,
        body.ssh_user,
        body.ssh_port,
        body.ssh_password,
        body.ssh_key,
    )
    client.close()
    return {"success": True, "message": "SSH authentication succeeded"}


@router.post("/deploy", response_model=DNSDeployResponse)
async def deploy_dns_server(
    request: DNSDeployRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """
    Deploy a personal DNS server to a VPS

    This endpoint:
    1. Connects to the VPS via SSH
    2. Updates system packages
    3. Installs Docker
    4. Deploys NetProtection
    5. Configures DoH/DoT if domain provided
    6. Sets up SSL with Let's Encrypt
    7. Configures firewall rules

    Requires admin authentication.
    """
    import traceback

    # SECURITY: Do not log sensitive data
    logger.info(f"Starting DNS deployment to {request.vps_ip} by admin user")

    # Validate authentication
    if not request.ssh_password and not request.ssh_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either SSH password or SSH key is required",
        )
    check_rate_limit(http_request, "dns_deploy")
    if _dns_deployment_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another Personal DNS deployment is already running",
        )
    await _dns_deployment_lock.acquire()
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        await _prepare_personal_dns_domain(request)

        certificate_email = request.certificate_email or (
            f"admin@{request.domain}" if request.domain else ""
        )
        allowed_clients = " ".join(
            f'"{client}"' for client in request.allowed_client_ips
        )
        script = (
            SECURE_DEPLOYMENT_SCRIPT.replace("__DOMAIN__", request.domain or "")
            .replace("__CERT_EMAIL__", certificate_email)
            .replace("__ALLOWED_CLIENTS__", allowed_clients)
            .replace("__DOT_ENABLED__", "true" if request.domain else "false")
            .replace("__VPS_IP__", request.vps_ip)
        )

        bundle_b64 = await asyncio.to_thread(_build_netprotection_bundle_b64)
        bundle_sha256 = hashlib.sha256(base64.b64decode(bundle_b64)).hexdigest()
        script = script.replace("__NP_TARBALL_B64__", bundle_b64).replace(
            "__NP_SOURCE_SHA256__", bundle_sha256
        )

        np_image = os.getenv("NETPROTECTION_IMAGE")
        if np_image:
            safe_image = _validate_container_image(np_image)
            script = f'NETPROTECTION_IMAGE="{safe_image}"\n' + script

        # Upload and execute script in a worker thread (avoid blocking event loop)
        logger.debug("Uploading script via SFTP...")
        logger.debug("Script uploaded, executing...")
        stdout, stderr, exit_code = await asyncio.to_thread(
            _run_dns_deploy_ssh,
            request.vps_ip,
            request.ssh_user,
            request.ssh_port,
            request.ssh_password,
            request.ssh_key,
            script,
            1800,  # 30 minutes for bundled build + WireGuard
        )

        logger.info(f"Script finished with exit code: {exit_code}")
        # Sanitize output - hide private keys in logs
        safe_stdout = stdout
        if "PrivateKey" in stdout:
            safe_stdout = re.sub(
                r"PrivateKey\s*=\s*[A-Za-z0-9+/=]+", "PrivateKey = [HIDDEN]", stdout
            )
        logger.debug(f"STDOUT: {safe_stdout[:500] if safe_stdout else 'empty'}")
        if stderr:
            logger.warning("DNS deployment emitted %d stderr bytes", len(stderr))

        if exit_code != 0:
            diagnostic = _safe_remote_deploy_error(stdout, stderr)
            logger.warning("Personal DNS remote deployment failed: %s", diagnostic)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Remote deployment failed: {diagnostic}",
            )

        if request.domain:
            probe_error: Exception | None = None
            for _attempt in range(5):
                try:
                    await asyncio.to_thread(
                        _probe_dot, request.vps_ip, request.domain
                    )
                    probe_error = None
                    break
                except (OSError, ssl.SSLError, ValueError, ConnectionError) as exc:
                    probe_error = exc
                    await asyncio.sleep(1)
            if probe_error is not None:
                logger.warning(
                    "Personal DNS post-deploy DoT verification failed: %s",
                    type(probe_error).__name__,
                )
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail=(
                        "Personal DNS was installed, but its DoT endpoint did not "
                        "return a usable public DNS answer"
                    ),
                )

        # Parse WireGuard config from output
        wireguard_config = None
        wireguard_installed = False
        if "=== WIREGUARD_CLIENT_CONFIG_START ===" in stdout:
            start = stdout.find("=== WIREGUARD_CLIENT_CONFIG_START ===") + len(
                "=== WIREGUARD_CLIENT_CONFIG_START ==="
            )
            end = stdout.find("=== WIREGUARD_CLIENT_CONFIG_END ===")
            if end > start:
                wireguard_config = stdout[start:end].strip()

        if "WG_INSTALLED=true" in stdout:
            wireguard_installed = True

        # Build warnings and recommendations
        warnings = []
        recommendations = []

        if not wireguard_installed:
            recommendations.append(
                {
                    "id": "setup_wireguard",
                    "title": "Set up WireGuard VPN",
                    "description": "For encrypted DNS, install WireGuard on this server",
                    "priority": "high",
                }
            )

        if not request.domain:
            recommendations.append(
                {
                    "id": "add_domain",
                    "title": "Add a domain for DoH/DoT",
                    "description": "With a domain, you can use encrypted DNS (DoH/DoT) from anywhere",
                    "priority": "medium",
                }
            )

        if request.allowed_client_ips:
            recommendations.append(
                {
                    "id": "direct_dns",
                    "title": "Direct DNS for approved computers",
                    "description": f"Set DNS to {request.vps_ip}; only the approved public IP addresses can connect",
                    "priority": "info",
                }
            )
        # Build message
        message = "Personal DNS server installed successfully."
        message += (
            " Chameleon remains on port 443; DNS administration is handled from EasyPi."
        )

        # Build response
        response = DNSDeployResponse(
            success=True,
            dns_ipv4=request.vps_ip,
            message=message,
            wireguard_installed=wireguard_installed,
            wireguard_config=wireguard_config,
            vpn_dns="10.66.66.1" if wireguard_installed else None,
            warnings=warnings if warnings else None,
            recommendations=recommendations if recommendations else None,
            dns_port="53" if request.allowed_client_ips else "WireGuard only",
        )

        if request.domain:
            response.doh_url = f"https://{request.domain}:8443/dns-query"
            response.dot_url = f"tls://{request.domain}"
        response.admin_panel = None

        try:
            deploy_record = DNSDeploy(
                user_id=_admin.id,
                vps_ip=request.vps_ip,
                ssh_user=request.ssh_user,
                ssh_port=request.ssh_port,
                domain=request.domain,
                dns_ipv4=response.dns_ipv4,
                admin_url=response.admin_panel,
                doh_url=response.doh_url,
                dot_address=response.dot_url,
                wireguard_installed=wireguard_installed,
                status="deployed",
                warnings=warnings if warnings else None,
                recommendations=recommendations if recommendations else None,
                deployment_log=message,
            )
            db.add(deploy_record)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Failed to persist DNS deployment history")

        try:
            operation_event_service.record_event(
                action_id="dns.deploy",
                status="success",
                title=f"Deploy Personal DNS to {request.vps_ip}",
                subtitle="Personal DNS · VPS deployment",
                route="/dns",
                message=message,
                started_at=started_at,
            )
        except Exception:
            logger.exception("Failed to record DNS deployment event")

        return response

    except HTTPException:
        try:
            operation_event_service.record_event(
                action_id="dns.deploy",
                status="failed",
                title=f"Deploy Personal DNS to {request.vps_ip}",
                subtitle="Personal DNS · VPS deployment",
                route="/dns",
                message="Personal DNS deployment failed",
                started_at=started_at,
            )
        except Exception:
            logger.exception("Failed to record DNS deployment failure event")
        raise
    except Exception as e:
        logger.error(f"Deployment error: {str(e)}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        try:
            operation_event_service.record_event(
                action_id="dns.deploy",
                status="failed",
                title=f"Deploy Personal DNS to {request.vps_ip}",
                subtitle="Personal DNS · VPS deployment",
                route="/dns",
                message=f"Deployment error: {str(e)}",
                started_at=started_at,
            )
        except Exception:
            logger.exception("Failed to record DNS deployment failure event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Deployment error: {str(e)}",
        )
    finally:
        _dns_deployment_lock.release()


@router.get("/deploys", response_model=List[DNSDeployHistoryEntry])
async def list_dns_deploys(
    db: Session = Depends(get_db), _admin: User = Depends(require_admin)
):
    """Return deployment history for the current admin user."""
    deploys = (
        db.query(DNSDeploy)
        .filter(
            DNSDeploy.user_id == _admin.id,
            DNSDeploy.status == "deployed",
        )
        .order_by(DNSDeploy.deployment_date.desc())
        .all()
    )
    return [_to_history_entry(deploy) for deploy in deploys]


def _dns_status_query() -> bytes:
    """Return a small A query used only for an authenticated health probe."""
    transaction_id = os.urandom(2)
    return (
        transaction_id
        + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + b"\x07example\x03com\x00\x00\x01\x00\x01"
    )


def _recv_exact(sock: ssl.SSLSocket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("encrypted DNS connection closed early")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _skip_dns_name(payload: bytes, offset: int) -> int:
    """Return the first byte after one validated DNS name."""
    while True:
        if offset >= len(payload):
            raise ValueError("truncated DNS name")
        length = payload[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("truncated DNS compression pointer")
            return offset + 2
        if length & 0xC0 or length > 63:
            raise ValueError("invalid DNS label")
        offset += length + 1


def _validate_dns_status_response(query: bytes, response: bytes) -> None:
    """Require a successful, non-sinkhole A answer for the health query."""
    if len(response) < 12 or response[:2] != query[:2]:
        raise ValueError("invalid DNS response")
    flags = int.from_bytes(response[2:4], "big")
    if not flags & 0x8000 or flags & 0x000F:
        raise ValueError("DNS query failed")
    question_count = int.from_bytes(response[4:6], "big")
    answer_count = int.from_bytes(response[6:8], "big")
    if question_count != 1 or answer_count < 1:
        raise ValueError("DNS response has no answers")

    offset = 12
    for _ in range(question_count):
        offset = _skip_dns_name(response, offset)
        if offset + 4 > len(response):
            raise ValueError("truncated DNS question")
        offset += 4

    for _ in range(answer_count):
        offset = _skip_dns_name(response, offset)
        if offset + 10 > len(response):
            raise ValueError("truncated DNS answer")
        record_type = int.from_bytes(response[offset : offset + 2], "big")
        record_class = int.from_bytes(response[offset + 2 : offset + 4], "big")
        data_size = int.from_bytes(response[offset + 8 : offset + 10], "big")
        offset += 10
        if offset + data_size > len(response):
            raise ValueError("truncated DNS record data")
        record_data = response[offset : offset + data_size]
        offset += data_size
        if record_type == 1 and record_class == 1 and data_size == 4:
            if ipaddress.ip_address(record_data).is_global:
                return
    raise ValueError("DNS response contains only blocked or non-public answers")


def _probe_dot(vps_ip: str, domain: str) -> None:
    """Query DoT at the fixed VPS IP while validating the domain certificate."""
    query = _dns_status_query()
    context = ssl.create_default_context()
    with socket.create_connection((vps_ip, 853), timeout=6) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            tls.settimeout(6)
            tls.sendall(len(query).to_bytes(2, "big") + query)
            response_size = int.from_bytes(_recv_exact(tls, 2), "big")
            if response_size < 12 or response_size > 65535:
                raise ValueError("invalid DoT response length")
            response = _recv_exact(tls, response_size)
            _validate_dns_status_response(query, response)


def _probe_doh(vps_ip: str, domain: str) -> None:
    """Query DoH at the fixed VPS IP without allowing DNS-based SSRF."""
    query = _dns_status_query()
    request_head = (
        f"POST /dns-query HTTP/1.1\r\n"
        f"Host: {domain}\r\n"
        "Content-Type: application/dns-message\r\n"
        "Accept: application/dns-message\r\n"
        f"Content-Length: {len(query)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")
    context = ssl.create_default_context()
    with socket.create_connection((vps_ip, 8443), timeout=6) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            tls.settimeout(6)
            tls.sendall(request_head + query)
            received = b""
            while b"\r\n\r\n" not in received and len(received) < 16384:
                chunk = tls.recv(512)
                if not chunk:
                    break
                received += chunk
            header, separator, body = received.partition(b"\r\n\r\n")
            if not separator:
                raise ConnectionError("incomplete DoH response headers")
            status_line = header.split(b"\r\n", 1)[0]
            if not status_line.startswith(b"HTTP/1.1 200"):
                raise ConnectionError("DoH endpoint did not return HTTP 200")
            headers: dict[bytes, bytes] = {}
            for line in header.split(b"\r\n")[1:]:
                name, marker, value = line.partition(b":")
                if marker:
                    headers[name.strip().lower()] = value.strip().lower()
            content_length = headers.get(b"content-length")
            if content_length is not None:
                try:
                    expected = int(content_length)
                except ValueError as exc:
                    raise ConnectionError("invalid DoH content length") from exc
                if expected < 12 or expected > 65535:
                    raise ConnectionError("invalid DoH response size")
                if len(body) < expected:
                    body += _recv_exact(tls, expected - len(body))
                body = body[:expected]
            else:
                while len(body) <= 65535:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    body += chunk
                if len(body) > 65535:
                    raise ConnectionError("DoH response is too large")
            _validate_dns_status_response(query, body)


@router.get("/status/{vps_ip}")
async def get_dns_status(
    vps_ip: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Check the deployed encrypted DNS service without relying on public port 53."""
    try:
        vps_ip = require_public_ipv4(vps_ip, label="VPS target")
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    deployment = (
        db.query(DNSDeploy)
        .filter(
            DNSDeploy.user_id == _admin.id,
            DNSDeploy.vps_ip == vps_ip,
            DNSDeploy.status == "deployed",
        )
        .order_by(DNSDeploy.deployment_date.desc())
        .first()
    )
    domain = (deployment.domain or "").strip().lower().rstrip(".") if deployment else ""
    details: list[str] = []
    state = "restricted"

    if domain and DOMAIN_PATTERN.fullmatch(domain):
        try:
            await asyncio.to_thread(_probe_dot, vps_ip, domain)
            state = "online"
            details.append("DoT answered with a valid TLS certificate and DNS response")
        except (OSError, ssl.SSLError, ValueError, ConnectionError) as dot_error:
            details.append(f"DoT probe failed ({type(dot_error).__name__})")
            try:
                await asyncio.to_thread(_probe_doh, vps_ip, domain)
                state = "online"
                details.append("DoH answered with a valid TLS certificate and HTTP 200")
            except (OSError, ssl.SSLError, ValueError, ConnectionError) as doh_error:
                state = "offline"
                details.append(f"DoH probe failed ({type(doh_error).__name__})")
    else:
        try:
            with socket.create_connection((vps_ip, 53), timeout=5):
                state = "online"
                details.append("Direct TCP DNS port 53 is reachable from EasyPi")
        except OSError:
            details.append(
                "Public DNS is restricted; status cannot be verified without a domain or VPS SSH credentials"
            )

    if deployment:
        deployment.last_check = utc_now()
        deployment.is_online = state == "online" if state != "restricted" else None
        db.commit()

    return {
        "state": state,
        "reachable": state == "online",
        "ip": vps_ip,
        "domain": domain or None,
        "details": details,
    }


class CleanupRequest(BaseModel):
    """Request model for VPS cleanup"""

    model_config = ConfigDict(extra="forbid")

    vps_ip: str = Field(..., max_length=15, description="Public VPS IPv4 address")
    ssh_user: str = Field(default="root", max_length=32, description="SSH username")
    ssh_port: int = Field(default=22, description="SSH port")
    ssh_password: Optional[str] = Field(
        None, max_length=1024, description="SSH password"
    )
    ssh_key: Optional[str] = Field(
        None, max_length=65536, description="SSH private key"
    )

    @field_validator("vps_ip")
    @classmethod
    def validate_ip(cls, v):
        return require_public_ipv4(v, label="VPS target")

    @field_validator("ssh_user")
    @classmethod
    def validate_ssh_user(cls, v):
        if not SSH_USER_PATTERN.match(v):
            raise ValueError("Invalid SSH username format")
        return v

    @field_validator("ssh_port")
    @classmethod
    def validate_ssh_port(cls, v):
        if not PORT_RANGE[0] <= v <= PORT_RANGE[1]:
            raise ValueError(
                f"SSH port must be between {PORT_RANGE[0]} and {PORT_RANGE[1]}"
            )
        return v


@router.post("/cleanup")
async def cleanup_vps(
    request: CleanupRequest,
    http_request: Request,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """
    Remove only EasyPi Personal DNS resources from the VPS.
    Requires admin authentication.
    """
    import traceback

    # SECURITY: Do not log credentials
    logger.info(f"Starting VPS cleanup on {request.vps_ip} by admin user")

    if not request.ssh_password and not request.ssh_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enter the VPS SSH password or private key again to remove Personal DNS",
        )

    check_rate_limit(http_request, "dns_deploy")
    if _dns_deployment_lock.locked():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Another Personal DNS deployment or cleanup is already running",
        )
    await _dns_deployment_lock.acquire()
    client = None
    try:
        client = create_ssh_client(
            host=request.vps_ip,
            user=request.ssh_user,
            port=request.ssh_port,
            password=request.ssh_password,
            private_key=request.ssh_key,
        )

        # Run cleanup script
        stdout, stderr, exit_code = run_ssh_command(client, CLEANUP_SCRIPT, timeout=120)
        if exit_code != 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Personal DNS cleanup failed: {_safe_remote_deploy_error(stdout, stderr)}",
            )

        # Parse results
        docker_cleaned = "Personal DNS cleanup complete" in stdout
        logs_cleaned = False
        apt_cleaned = False

        # Extract disk usage
        disk_usage = None
        for line in stdout.split("\n"):
            if "/" in line and "%" in line:
                parts = line.split()
                if len(parts) >= 5:
                    disk_usage = {
                        "total": parts[1] if len(parts) > 1 else "?",
                        "used": parts[2] if len(parts) > 2 else "?",
                        "available": parts[3] if len(parts) > 3 else "?",
                        "percent": parts[4] if len(parts) > 4 else "?",
                    }

        active_deployments = (
            db.query(DNSDeploy)
            .filter(
                DNSDeploy.user_id == _admin.id,
                DNSDeploy.vps_ip == request.vps_ip,
                DNSDeploy.status == "deployed",
            )
            .all()
        )
        for deployment in active_deployments:
            deployment.status = "removed"
            deployment.is_online = False
            deployment.last_check = utc_now()
            deployment.deployment_log = "Personal DNS resources removed from VPS."
        db.commit()

        return {
            "success": True,
            "message": "Personal DNS resources removed; other VPS services were preserved",
            "details": {
                "docker_cleaned": docker_cleaned,
                "logs_cleaned": logs_cleaned,
                "apt_cleaned": apt_cleaned,
                "disk_usage": disk_usage,
            },
            "output": stdout,
        }

    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Cleanup error: {str(e)}")
        logger.debug(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cleanup error: {str(e)}",
        )
    finally:
        if client is not None:
            client.close()
        _dns_deployment_lock.release()
