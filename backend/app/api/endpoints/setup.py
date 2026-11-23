"""
Pi-Guard Setup API Endpoints
Automatic installation and configuration of NetProtection

Security: All endpoints require admin authentication.
"""

import re
import ipaddress
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field, field_validator
import asyncio
import secrets
import logging
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import set_key

from app.api.deps import require_admin
from app.services.netprotection_service import netprotection_service
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/security/setup", tags=["Pi-Guard Setup"])
operation_event_service = OperationEventService()

# Command execution timeout (seconds)
COMMAND_TIMEOUT = 120

# Security patterns
USERNAME_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_]{2,31}$')


def _validate_http_url(value: str, *, loopback_only: bool = False) -> str:
    """Validate a service base URL without userinfo or control characters."""
    value = value.strip()
    if not value or any(char.isspace() or char == "\x00" for char in value):
        raise ValueError("URL contains invalid characters")

    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid URL format")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid URL port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port")

    hostname = parsed.hostname.rstrip(".").lower()
    if loopback_only:
        is_loopback = hostname == "localhost"
        if not is_loopback:
            try:
                is_loopback = ipaddress.ip_address(hostname).is_loopback
            except ValueError:
                is_loopback = False
        if not is_loopback:
            raise ValueError("Initial setup URL must use localhost")
        if parsed.path not in {"", "/"}:
            raise ValueError("Initial setup URL must not include a path")

    return value.rstrip("/")


def _validate_env_value(value: str | None) -> str | None:
    if value is not None and any(char in value for char in ("\r", "\n", "\x00")):
        raise ValueError("Value contains invalid control characters")
    return value


def _record_setup_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/setup",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record setup event %s: %s", action_id, exc)


class ConfigureRequest(BaseModel):
    username: str | None = Field(None, min_length=3, max_length=32)
    password: str | None = Field(None, min_length=8, max_length=128)
    url: str = Field(default="http://localhost:3000", max_length=500)
    skip_auth: bool = False
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not USERNAME_PATTERN.match(v):
            raise ValueError('Username must start with a letter and contain only alphanumeric characters and underscores')
        return v
    
    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        return _validate_http_url(v, loopback_only=True)

    @field_validator('password')
    @classmethod
    def validate_password(cls, v: str | None) -> str | None:
        return _validate_env_value(v)


class BackendConfigRequest(BaseModel):
    NETPROTECTION_URL: str = Field(..., max_length=500)
    NETPROTECTION_USERNAME: str | None = Field(None, max_length=64)
    NETPROTECTION_PASSWORD: str | None = Field(None, max_length=128)
    
    @field_validator('NETPROTECTION_URL')
    @classmethod
    def validate_NETPROTECTION_URL(cls, v: str) -> str:
        return _validate_http_url(v)
    
    @field_validator('NETPROTECTION_USERNAME')
    @classmethod
    def validate_NETPROTECTION_USERNAME(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not USERNAME_PATTERN.match(v):
            raise ValueError('Username must start with a letter and contain only alphanumeric characters and underscores')
        return v

    @field_validator('NETPROTECTION_PASSWORD')
    @classmethod
    def validate_NETPROTECTION_PASSWORD(cls, v: str | None) -> str | None:
        return _validate_env_value(v)


def _generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password"""
    return secrets.token_urlsafe(length)


async def run_command(command: str, timeout: int = COMMAND_TIMEOUT) -> tuple[int, str, str]:
    """Execute shell command asynchronously with timeout"""
    try:
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            logger.error(f"Command timed out after {timeout}s: {command[:50]}...")
            return 124, "", f"Command timed out after {timeout} seconds"
        
        return (
            process.returncode or 0,
            stdout.decode().strip(),
            stderr.decode().strip()
        )
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return 1, "", str(e)


async def _check_sudo_available() -> bool:
    """Check if sudo is available and configured"""
    returncode, _, _ = await run_command("sudo -n true 2>/dev/null", timeout=5)
    return returncode == 0


async def _is_NetProtection_installed() -> bool:
    """Check if NetProtection service exists"""
    returncode, stdout, _ = await run_command("systemctl list-unit-files NetProtectionHome.service 2>/dev/null", timeout=10)
    return "NetProtectionHome.service" in stdout


async def _is_NetProtection_configured() -> tuple[bool, bool]:
    """
    Check if NetProtection is responding and already configured.
    Returns: (is_responding, is_initial_setup_done)
    """
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5.0) as client:
            # Check status endpoint
            response = await client.get("http://localhost:3000/control/status")
            if response.status_code == 200:
                return True, True
            # 403 means it's running but initial setup not done
            if response.status_code == 403:
                return True, False
            return False, False
    except Exception:
        return False, False


@router.get("/check")
async def check_installation(admin: dict = Depends(require_admin)):
    """Check if NetProtection is installed and configured (admin only)"""
    try:
        installed = await _is_NetProtection_installed()
        responding, configured = await _is_NetProtection_configured() if installed else (False, False)
        
        status = "ready" if (installed and configured) else (
            "needs_configuration" if (installed and responding and not configured) else (
                "installed_not_running" if installed else "not_installed"
            )
        )
        
        return {
            "installed": installed,
            "responding": responding,
            "configured": configured,
            "status": status
        }
    except Exception as e:
        logger.error(f"Error checking installation: {e}")
        raise HTTPException(status_code=500, detail="Failed to check installation status")


@router.post("/install")
async def install_NetProtection(admin: dict = Depends(require_admin)):
    """Reject the retired remote root-installer path."""
    started_at = datetime.now(timezone.utc).isoformat()
    if await _is_NetProtection_installed():
        responding, configured = await _is_NetProtection_configured()
        if responding:
            _record_setup_event(
                action_id="setup.netprotection.install",
                title="Install NetProtection",
                subtitle="Setup - NetProtection",
                status="success",
                message="NetProtection is already installed",
                started_at=started_at,
            )
            return {
                "success": True,
                "message": "NetProtection is already installed",
                "already_installed": True,
                "configured": configured
            }

    message = (
        "Remote third-party root installation has been disabled. "
        "Install the built-in EasyPi NetProtection component with the signed "
        "EasyPi installer."
    )
    _record_setup_event(
        action_id="setup.netprotection.install",
        title="Install NetProtection",
        subtitle="Setup - NetProtection",
        status="failed",
        message=message,
        started_at=started_at,
    )
    raise HTTPException(status_code=410, detail=message)


@router.post("/configure")
async def configure_NetProtection(config: ConfigureRequest, admin: dict = Depends(require_admin)):
    """Configure NetProtection initial setup (admin only)"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        import httpx
        
        # Check current state
        responding, already_configured = await _is_NetProtection_configured()
        
        if not responding:
            _record_setup_event(
                action_id="setup.netprotection.configure",
                title="Configure NetProtection",
                subtitle="Setup - NetProtection",
                status="failed",
                message="NetProtection is not responding. Please install it first.",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=503,
                detail="NetProtection is not responding. Please install it first."
            )
        
        if already_configured:
            # Already configured - return success without changing anything
            _record_setup_event(
                action_id="setup.netprotection.configure",
                title="Configure NetProtection",
                subtitle="Setup - NetProtection",
                status="success",
                message="NetProtection is already configured",
                started_at=started_at,
            )
            return {
                "success": True,
                "message": "NetProtection is already configured",
                "already_configured": True,
                "credentials_changed": False
            }
        
        # Generate credentials
        # If skip_auth, generate random password (NetProtection requires one, but user won't need it)
        # If not skip_auth, require user to provide password
        if config.skip_auth:
            username = "admin"
            password = _generate_secure_password()
            logger.info("Generating random credentials for skip_auth mode")
        else:
            if not config.username or not config.password:
                _record_setup_event(
                    action_id="setup.netprotection.configure",
                    title="Configure NetProtection",
                    subtitle="Setup - NetProtection",
                    status="failed",
                    message="Username and password are required when skip_auth is false",
                    started_at=started_at,
                )
                raise HTTPException(
                    status_code=400,
                    detail="Username and password are required when skip_auth is false"
                )
            if len(config.password) < 8:
                _record_setup_event(
                    action_id="setup.netprotection.configure",
                    title="Configure NetProtection",
                    subtitle="Setup - NetProtection",
                    status="failed",
                    message="Password must be at least 8 characters",
                    started_at=started_at,
                )
                raise HTTPException(
                    status_code=400,
                    detail="Password must be at least 8 characters"
                )
            username = config.username
            password = config.password
        
        setup_data = {
            "web": {
                "ip": "0.0.0.0",
                "port": 3000,
                "status": "",
                "can_autofix": False
            },
            "dns": {
                "ip": "0.0.0.0",
                "port": 53,
                "status": "",
                "can_autofix": False
            },
            "username": username,
            "password": password
        }
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{config.url}/control/install/configure",
                json=setup_data
            )
            logger.info(f"NetProtection configure response: {response.status_code}")
            
            if response.status_code not in [200, 201]:
                _record_setup_event(
                    action_id="setup.netprotection.configure",
                    title="Configure NetProtection",
                    subtitle="Setup - NetProtection",
                    status="failed",
                    message=f"NetProtection configuration failed with status {response.status_code}",
                    started_at=started_at,
                )
                raise HTTPException(
                    status_code=500,
                    detail=f"NetProtection configuration failed with status {response.status_code}"
                )
        
        # Return credentials for backend to save (not exposed to logs)
        # Credentials are only returned once during initial setup
        _record_setup_event(
            action_id="setup.netprotection.configure",
            title="Configure NetProtection",
            subtitle="Setup - NetProtection",
            status="success",
            message="Configuration completed",
            started_at=started_at,
        )
        return {
            "success": True,
            "message": "Configuration completed",
            "already_configured": False,
            "credentials_changed": True,
            "url": config.url,
            "_credentials": {
                "username": username,
                "password": password
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        _record_setup_event(
            action_id="setup.netprotection.configure",
            title="Configure NetProtection",
            subtitle="Setup - NetProtection",
            status="failed",
            message="Configuration failed",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Configuration failed")


@router.post("/filters")
async def setup_default_filters(admin: dict = Depends(require_admin)):
    """Add default blocklist filters (admin only)"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        # Check if NetProtection is configured
        responding, configured = await _is_NetProtection_configured()
        if not responding or not configured:
            _record_setup_event(
                action_id="setup.netprotection.filters",
                title="Setup default filters",
                subtitle="Setup - NetProtection",
                status="failed",
                message="NetProtection is not configured. Please run /configure first.",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=503,
                detail="NetProtection is not configured. Please run /configure first."
            )
        
        # Get existing filters to avoid duplicates
        try:
            existing_filters = await netprotection_service.get_filters()
            existing_urls = {f.get("url") for f in existing_filters.get("filters", [])}
        except Exception:
            existing_urls = set()
        
        default_filters = [
            {
                "name": "NetProtection DNS filter",
                "url": "https://NetProtectionteam.github.io/NetProtectionSDNSFilter/Filters/filter.txt"
            },
            {
                "name": "AdAway Default Blocklist",
                "url": "https://adaway.org/hosts.txt"
            },
            {
                "name": "Steven Black's Unified Hosts",
                "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
            },
            {
                "name": "Peter Lowe's List",
                "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus&showintro=1&mimetype=plaintext"
            }
        ]
        
        added_count = 0
        skipped_count = 0
        
        for filter_data in default_filters:
            # Skip if already exists
            if filter_data["url"] in existing_urls:
                skipped_count += 1
                continue
                
            try:
                await netprotection_service.add_filter(
                    url=filter_data["url"],
                    name=filter_data["name"],
                    whitelist=False
                )
                added_count += 1
                await asyncio.sleep(0.5)  # Rate limiting
            except Exception as e:
                logger.warning(f"Failed to add filter {filter_data['name']}: {e}")
        
        # Apply the resulting configuration now. Retrying after a previous partial
        # failure must also refresh already-added filters instead of reporting success.
        if added_count > 0 or skipped_count > 0:
            await netprotection_service.refresh_filters()
        _record_setup_event(
            action_id="setup.netprotection.filters",
            title="Setup default filters",
            subtitle="Setup - NetProtection",
            status="success",
            message=f"Added {added_count} filters, skipped {skipped_count} existing",
            started_at=started_at,
        )
        
        return {
            "success": True,
            "message": f"Added {added_count} filters, skipped {skipped_count} existing",
            "filters_added": added_count,
            "filters_skipped": skipped_count
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Filter setup error: {e}")
        _record_setup_event(
            action_id="setup.netprotection.filters",
            title="Setup default filters",
            subtitle="Setup - NetProtection",
            status="failed",
            message="Failed to add filters. You can add them manually in NetProtection settings.",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500,
            detail="Failed to add filters. You can add them manually in NetProtection settings."
        )


@router.post("/backend")
async def update_backend_config(config: BackendConfigRequest, admin: dict = Depends(require_admin)):
    """Update backend .env configuration (admin only)"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        from app.core.config import get_settings
        
        env_path = Path(__file__).parent.parent.parent.parent / ".env"
        
        # python-dotenv quotes values before updating the file, so spaces,
        # comment characters and shell metacharacters cannot change its syntax.
        settings = {
            "NETPROTECTION_URL": config.NETPROTECTION_URL,
            "NETPROTECTION_USERNAME": config.NETPROTECTION_USERNAME or "",
            "NETPROTECTION_PASSWORD": config.NETPROTECTION_PASSWORD or ""
        }
        for key, value in settings.items():
            set_key(str(env_path), key, value, quote_mode="always")
        
        # Clear settings cache so new values are loaded
        get_settings.cache_clear()
        logger.info("Settings cache cleared, new configuration will be loaded")
        _record_setup_event(
            action_id="setup.backend.config",
            title="Update backend config",
            subtitle="Setup - Backend connection",
            status="success",
            message="Backend configuration updated",
            started_at=started_at,
        )
        
        return {
            "success": True,
            "message": "Backend configuration updated",
            "config": {
                "url": config.NETPROTECTION_URL,
                "username": config.NETPROTECTION_USERNAME or "(not set)",
                "password": "***" if config.NETPROTECTION_PASSWORD else "(not set)"
            }
        }
    except Exception as e:
        logger.error(f"Config update error: {e}")
        _record_setup_event(
            action_id="setup.backend.config",
            title="Update backend config",
            subtitle="Setup - Backend connection",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))
