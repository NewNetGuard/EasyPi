"""
WireGuard API endpoints for installation, configuration, and peer management
"""
import os
import json
import ipaddress
import re
import subprocess
import logging
import httpx
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, HTTPException, Depends, status
from fastapi.responses import FileResponse, Response

from app.api.deps import require_admin
from app.models.user import User
from config import ROOT_DIR
from app.schemas.wireguard import (
    WireGuardInstallRequest,
    WireGuardPeerRequest,
    WireGuardStatus,
    WireGuardPeer,
    WireGuardPeerResponse,
    TaskResponse,
    validate_wireguard_endpoint,
)
from app.core.installer import create_install_job, start_install_job, read_installer_log
from app.services.operation_event_service import OperationEventService

router = APIRouter()
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()

# Paths
SCRIPTS_BASE = os.getenv("EASYPI_SCRIPTS_BASE", str(ROOT_DIR / "scripts"))
RUNNER_PATH = os.getenv("EASYPI_RUNNER", str(Path(SCRIPTS_BASE) / "runner"))
WG_SCRIPT = f"{SCRIPTS_BASE}/services/wireguard.sh"
DATA_DIR = os.getenv("EASYPI_WIRE_DATA", "/var/lib/easypi/wireguard")
CLIENTS_DIR = os.path.join(DATA_DIR, "clients")
META_FILE = os.path.join(DATA_DIR, "meta.json")
PUBLIC_IP_LOOKUP_URL = "https://api.ipify.org"


# Input validation patterns
PEER_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]{1,32}$')
PORT_RANGE = (1024, 65535)
FORBIDDEN_CHARS = re.compile(r'[;|&$`><"\']')
ALLOWED_SCRIPT_PATTERN = re.compile(r'^(services|stacks|security|backup|settings)/')


def _record_wireguard_event(
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
            status=status,
            title=title,
            subtitle="VPN - WireGuard runtime",
            route="/vpn",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception:
        logger.exception("Failed to record WireGuard event")


def _validate_peer_name(name: str) -> str:
    """Validate peer name format"""
    if not name or not PEER_NAME_PATTERN.match(name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid peer name. Use only alphanumeric characters, dots, underscores, hyphens (1-32 chars)"
        )
    return name


def _validate_install_params(request: WireGuardInstallRequest) -> None:
    """Validate installation parameters"""
    if not (PORT_RANGE[0] <= request.port <= PORT_RANGE[1]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Port must be between {PORT_RANGE[0]} and {PORT_RANGE[1]}"
        )
    
    try:
        network = ipaddress.ip_network(request.cidr, strict=True)
    except ValueError:
        network = None
    if network is None or network.version != 4 or network.prefixlen != 24:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid CIDR format. Expected: 10.0.0.0/24"
        )
    
    try:
        dns_servers = [ipaddress.ip_address(item.strip()) for item in request.dns.split(",")]
    except ValueError:
        dns_servers = []
    if not dns_servers or len(dns_servers) > 4 or any(address.version != 4 for address in dns_servers):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid DNS format. Expected: 1.1.1.1"
        )
    
    try:
        validate_wireguard_endpoint(request.endpoint)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid endpoint format. Expected host:port (e.g., 1.2.3.4:51820)"
        )


def _validate_allowed_ips(allowed: str) -> str:
    """Validate allowed IPs format"""
    items = [item.strip() for item in allowed.split(",")]
    try:
        valid = bool(items) and len(items) <= 32 and all(
            item and ipaddress.ip_network(item, strict=False) for item in items
        )
    except ValueError:
        valid = False
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid allowed IPs format. Expected: 0.0.0.0/0 or 10.0.0.0/24,192.168.1.0/24"
        )
    return allowed


def _client_artifact(name: str, suffix: str) -> Path:
    """Resolve a root-managed client artifact without following symlinks."""
    clients_root = Path(CLIENTS_DIR).resolve()
    candidate = Path(CLIENTS_DIR) / f"{name}{suffix}"
    if candidate.is_symlink():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client artifact not found")
    try:
        resolved = candidate.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client artifact not found") from None
    if resolved.parent != clients_root or not resolved.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Client artifact not found")
    return resolved


_SENSITIVE_DOWNLOAD_HEADERS = {
    "Cache-Control": "private, no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def _normalize_public_ipv4(value: object) -> str | None:
    """Return a globally routable IPv4 address or ``None`` for invalid data."""
    try:
        address = ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return None
    if address.version != 4 or not address.is_global:
        return None
    return str(address)


def _resolve_script(script_path: str) -> str:
    if FORBIDDEN_CHARS.search(script_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid characters in script path"
        )
    if not ALLOWED_SCRIPT_PATTERN.match(script_path):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Script path must start with services/, stacks/, security/, backup/, or settings/"
        )
    script_full = os.path.realpath(os.path.join(SCRIPTS_BASE, script_path))
    scripts_base = os.path.realpath(SCRIPTS_BASE)
    if not script_full.startswith(scripts_base + os.sep):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid script path"
        )
    if not os.path.exists(script_full):
        logger.error("Script not found: %s (full path: %s)", script_path, script_full)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Required script not found: {script_path}. Please ensure EasyPi scripts are properly installed."
        )
    if not os.access(script_full, os.R_OK):
        logger.error("Script not readable: %s (permissions issue, current user: %s)", script_path, os.getenv('USER', 'unknown'))
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Cannot access script: {script_path}. This is a permissions issue. Please ensure the backend user has read access to /opt/EasyPi/scripts/"
        )
    return script_full


def _run_runner(script_path: str, *args) -> subprocess.CompletedProcess:
    """
    Execute script through runner with validation
    
    Args:
        script_path: Relative path to script (e.g., "services/wireguard.sh")
        *args: Additional arguments to pass to script
        
    Returns:
        CompletedProcess with stdout/stderr
    """
    script_full = _resolve_script(script_path)
    cmd: list[str]
    if os.path.exists(RUNNER_PATH):
        if os.access(RUNNER_PATH, os.X_OK):
            cmd = ["sudo", "-n", RUNNER_PATH, script_path] + list(args)
        else:
            logger.warning("Runner not executable, using bash: %s", RUNNER_PATH)
            cmd = ["sudo", "-n", "/bin/bash", RUNNER_PATH, script_path] + list(args)
    else:
        logger.warning("Runner missing, using bash directly: %s", script_full)
        cmd = ["sudo", "-n", "/bin/bash", script_full] + list(args)
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes max
            check=False
        )
        return result
    except subprocess.TimeoutExpired:
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Script execution timed out"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to execute script: {str(e)}"
        )


@router.post("/install", response_model=TaskResponse, status_code=status.HTTP_202_ACCEPTED)
async def install_wireguard(request: WireGuardInstallRequest, _admin: User = Depends(require_admin)):
    """
    Install and configure WireGuard VPN server
    
    This endpoint starts an async task that:
    - Installs WireGuard and dependencies (wireguard, qrencode, jq)
    - Generates server keys
    - Creates wg0.conf with NAT rules
    - Enables IP forwarding
    - Starts wg-quick@wg0 service
    
    Returns task_id and websocket_url for real-time log streaming
    """
    # Validate input parameters
    _validate_install_params(request)
    started_at = datetime.now(timezone.utc).isoformat()
    
    # Run installation via installer service with parameters
    job_id = create_install_job(
        "services/wireguard.sh",
        [
            "install",
            "--port",
            str(request.port),
            "--cidr",
            request.cidr,
            "--dns",
            request.dns,
            "--endpoint",
            request.endpoint,
        ],
    )

    try:
        result = start_install_job(job_id, timeout=900)
    except subprocess.TimeoutExpired:
        _record_wireguard_event(
            action_id="wireguard.install",
            title="Install WireGuard",
            status="failed",
            message="Installation timed out",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Installation timed out"
        )

    if result.returncode != 0:
        log_tail = read_installer_log(job_id)
        error_detail = (result.stderr.strip() or result.stdout.strip() or log_tail or "Unknown error")
        logger.error(
            "WireGuard install failed (code %s). stdout=%s stderr=%s log=%s",
            result.returncode,
            (result.stdout or "").strip(),
            (result.stderr or "").strip(),
            log_tail,
        )
        _record_wireguard_event(
            action_id="wireguard.install",
            title="Install WireGuard",
            status="failed",
            message=error_detail,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Installation failed: {error_detail}"
        )
    _record_wireguard_event(
        action_id="wireguard.install",
        title="Install WireGuard",
        status="success",
        message="WireGuard installation completed",
        started_at=started_at,
    )

    # Return success response
    return TaskResponse(
        task_id="wireguard-install",
        status="success",
        websocket_url=""
    )


@router.get("/status", response_model=WireGuardStatus)
async def get_status(_admin: User = Depends(require_admin)):
    """
    Get current WireGuard server status
    
    Returns:
    - installed: Whether WireGuard is installed
    - running: Whether wg-quick@wg0 is active
    - port, cidr, dns, endpoint: Configuration
    - server_public_key: Server's public key
    - peers: List of all configured peers with stats
    """
    result = _run_runner("services/wireguard.sh", "status")
    
    if result.returncode != 0:
        # If script fails, assume WireGuard is not installed
        return WireGuardStatus(
            installed=False,
            running=False,
            port=None,
            cidr=None,
            dns=None,
            endpoint=None,
            server_public_key=None,
            peers=[]
        )
    
    try:
        status_data = json.loads(result.stdout)
        
        # Merge peer metadata with peer stats
        peers = []
        peer_stats_map = {p["public_key"]: p for p in status_data.get("peers_stats", [])}
        
        for peer in status_data.get("peers", []):
            peer_data = {
                "name": peer["name"],
                "address": peer["address"],
                "public_key": peer["public_key"],
                "created_at": peer.get("created_at"),
                "rx_bytes": 0,
                "tx_bytes": 0,
                "latest_handshake": None
            }
            
            # Add stats if available
            stats = peer_stats_map.get(peer["public_key"])
            if stats:
                peer_data["rx_bytes"] = stats.get("rx_bytes", 0)
                peer_data["tx_bytes"] = stats.get("tx_bytes", 0)
                peer_data["latest_handshake"] = stats.get("latest_handshake")
            
            peers.append(WireGuardPeer(**peer_data))
        
        return WireGuardStatus(
            installed=status_data["installed"],
            running=status_data["running"],
            port=status_data.get("port"),
            cidr=status_data.get("cidr"),
            dns=status_data.get("dns"),
            endpoint=status_data.get("endpoint"),
            server_public_key=status_data.get("server_public_key"),
            peers=peers
        )
        
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Invalid JSON response from script: {str(e)}"
        )


@router.get("/public-ip")
async def get_public_ip(_admin: User = Depends(require_admin)) -> dict[str, str | None]:
    """Best-effort public IPv4 lookup for the WireGuard endpoint form.

    The browser deliberately stays same-origin so the panel can keep its strict
    ``connect-src 'self'`` policy. Failure is represented as a successful,
    empty optional result because WireGuard status must remain usable offline.
    """
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=False) as client:
            response = await client.get(
                PUBLIC_IP_LOOKUP_URL,
                headers={"Accept": "text/plain"},
            )
            response.raise_for_status()
            public_ip = _normalize_public_ipv4(response.text)
            if public_ip:
                return {"ip": public_ip}
            logger.warning("Public IPv4 lookup returned an invalid value")
    except (httpx.HTTPError, ValueError):
        logger.warning("Public IPv4 lookup is unavailable", exc_info=True)

    return {"ip": None}


@router.post("/peers", response_model=WireGuardPeerResponse, status_code=status.HTTP_201_CREATED)
async def add_peer(request: WireGuardPeerRequest, _admin: User = Depends(require_admin)):
    """
    Add a new WireGuard peer (client)
    
    This endpoint:
    - Validates peer name
    - Generates client keys
    - Assigns next available IP
    - Creates client config file
    - Generates QR code
    - Adds peer to server
    
    Returns URLs to download config and QR code
    """
    # Validate input
    _validate_peer_name(request.name)
    _validate_allowed_ips(request.allowed)
    started_at = datetime.now(timezone.utc).isoformat()
    
    result = _run_runner(
        "services/wireguard.sh",
        "add-peer",
        "--name", request.name,
        "--allowed", request.allowed
    )
    
    if result.returncode != 0:
        # Parse error message
        error_msg = result.stderr or result.stdout or "Unknown error"
        
        if "already exists" in error_msg:
            _record_wireguard_event(
                action_id="wireguard.peer.add",
                title="Add WireGuard peer",
                status="failed",
                message=f"Peer '{request.name}' already exists",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Peer '{request.name}' already exists"
            )
        elif "not installed" in error_msg or "not running" in error_msg:
            _record_wireguard_event(
                action_id="wireguard.peer.add",
                title="Add WireGuard peer",
                status="failed",
                message="WireGuard server is not ready",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_412_PRECONDITION_FAILED,
                detail="WireGuard server must be installed and running before adding a peer."
            )
        else:
            _record_wireguard_event(
                action_id="wireguard.peer.add",
                title="Add WireGuard peer",
                status="failed",
                message=error_msg,
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=error_msg
            )
    
    # Extract assigned IP from output
    address = None
    for line in result.stdout.split('\n'):
        if "Assigned address:" in line:
            address = line.split("Assigned address:")[1].strip()
            break
    
    if not address:
        address = "Unknown"  # Fallback
    _record_wireguard_event(
        action_id="wireguard.peer.add",
        title="Add WireGuard peer",
        status="success",
        message=f"Created peer '{request.name}' with address {address}",
        started_at=started_at,
    )
    
    return WireGuardPeerResponse(
        name=request.name,
        address=address,
        download_url=f"/api/v1/wireguard/peers/{request.name}/config",
        qr_url=f"/api/v1/wireguard/peers/{request.name}/qr"
    )


@router.delete("/peers/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_peer(name: str, _admin: User = Depends(require_admin)):
    """
    Remove a WireGuard peer
    
    This endpoint:
    - Removes peer from server
    - Deletes client config and QR code files
    - Updates meta.json
    """
    # Validate name format
    _validate_peer_name(name)
    started_at = datetime.now(timezone.utc).isoformat()
    
    result = _run_runner(
        "services/wireguard.sh",
        "remove-peer",
        "--name", name
    )
    
    if result.returncode != 0:
        error_msg = result.stderr or result.stdout or "Unknown error"
        
        if "not found" in error_msg:
            _record_wireguard_event(
                action_id="wireguard.peer.remove",
                title="Remove WireGuard peer",
                status="failed",
                message=f"Peer '{name}' not found",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Peer '{name}' not found"
            )
        else:
            _record_wireguard_event(
                action_id="wireguard.peer.remove",
                title="Remove WireGuard peer",
                status="failed",
                message=error_msg,
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=error_msg
            )
    _record_wireguard_event(
        action_id="wireguard.peer.remove",
        title="Remove WireGuard peer",
        status="success",
        message=f"Removed peer '{name}'",
        started_at=started_at,
    )
    
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/peers/{name}/config")
async def download_config(name: str, _admin: User = Depends(require_admin)):
    """
    Download WireGuard client configuration file
    
    Returns .conf file with client private key, address, and server connection details.
    This file can be imported into WireGuard clients.
    """
    # Validate name
    _validate_peer_name(name)
    
    config_path = _client_artifact(name, ".conf")
    
    return FileResponse(
        path=config_path,
        media_type="application/octet-stream",
        filename=f"{name}.conf",
        headers=_SENSITIVE_DOWNLOAD_HEADERS,
    )


@router.get("/peers/{name}/qr")
async def get_qr_code(name: str, _admin: User = Depends(require_admin)):
    """
    Get QR code for WireGuard client configuration
    
    Returns PNG image of QR code that can be scanned by mobile WireGuard apps
    """
    # Validate name
    _validate_peer_name(name)
    
    qr_path = _client_artifact(name, ".png")
    
    return FileResponse(
        path=qr_path,
        media_type="image/png",
        headers={
            **_SENSITIVE_DOWNLOAD_HEADERS,
            "Content-Disposition": f'inline; filename="{name}-qr.png"',
        },
    )


@router.post("/restart", response_model=TaskResponse, status_code=status.HTTP_202_ACCEPTED)
async def restart_service(_admin: User = Depends(require_admin)):
    """
    Restart WireGuard service
    
    Restarts wg-quick@wg0 systemd service
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = _run_runner("services/wireguard.sh", "restart")
    
    if result.returncode != 0:
        error_detail = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        _record_wireguard_event(
            action_id="wireguard.restart",
            title="Restart WireGuard",
            status="failed",
            message=error_detail,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Restart failed: {result.stderr}"
        )
    _record_wireguard_event(
        action_id="wireguard.restart",
        title="Restart WireGuard",
        status="success",
        message="WireGuard service restarted",
        started_at=started_at,
    )
    
    return TaskResponse(
        task_id="wireguard-restart",
        status="success",
        websocket_url=""
    )


@router.post("/reset", response_model=TaskResponse, status_code=status.HTTP_202_ACCEPTED)
async def reset_service(_admin: User = Depends(require_admin)):
    """Reset WireGuard configuration (remove config and clients)."""
    result = _run_runner("services/wireguard.sh", "reset")

    if result.returncode != 0:
        error_detail = result.stderr.strip() or result.stdout.strip() or "Unknown error"
        logger.error(
            "WireGuard reset failed (code %s). stdout=%s stderr=%s",
            result.returncode,
            result.stdout.strip(),
            result.stderr.strip(),
        )
        try:
            operation_event_service.record_event(
                action_id="wireguard.reset",
                status="failed",
                title="Reset WireGuard",
                subtitle="VPN · WireGuard runtime",
                route="/vpn",
                message=f"Reset failed: {error_detail}",
            )
        except Exception:
            logger.exception("Failed to record WireGuard reset event")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Reset failed: {error_detail}"
        )

    try:
        operation_event_service.record_event(
            action_id="wireguard.reset",
            status="success",
            title="Reset WireGuard",
            subtitle="VPN · WireGuard runtime",
            route="/vpn",
            message="WireGuard reset completed",
        )
    except Exception:
        logger.exception("Failed to record WireGuard reset event")

    return TaskResponse(
        task_id="wireguard-reset",
        status="success",
        websocket_url=""
    )


@router.post("/uninstall", response_model=TaskResponse, status_code=status.HTTP_202_ACCEPTED)
async def uninstall_service(_admin: User = Depends(require_admin)):
    """Uninstall WireGuard (reset + remove packages where possible)."""
    started_at = datetime.now(timezone.utc).isoformat()
    job_id = create_install_job("services/wireguard.sh", ["uninstall"])

    try:
        result = start_install_job(job_id, timeout=900)
    except subprocess.TimeoutExpired:
        _record_wireguard_event(
            action_id="wireguard.uninstall",
            title="Uninstall WireGuard",
            status="failed",
            message="Uninstall timed out",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_408_REQUEST_TIMEOUT,
            detail="Uninstall timed out"
        )

    if result.returncode != 0:
        log_tail = read_installer_log(job_id)
        error_detail = (result.stderr.strip() or result.stdout.strip() or log_tail or "Unknown error")
        logger.error(
            "WireGuard uninstall failed (code %s). stdout=%s stderr=%s log=%s",
            result.returncode,
            (result.stdout or "").strip(),
            (result.stderr or "").strip(),
            log_tail,
        )
        _record_wireguard_event(
            action_id="wireguard.uninstall",
            title="Uninstall WireGuard",
            status="failed",
            message=error_detail,
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Uninstall failed: {error_detail}"
        )
    _record_wireguard_event(
        action_id="wireguard.uninstall",
        title="Uninstall WireGuard",
        status="success",
        message="WireGuard uninstall completed",
        started_at=started_at,
    )

    return TaskResponse(
        task_id="wireguard-uninstall",
        status="success",
        websocket_url=""
    )
