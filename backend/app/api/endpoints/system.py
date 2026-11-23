"""
System Settings API Endpoints
Manages system permissions, user configuration and EasyPi setup
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, ConfigDict, Field, field_validator
import asyncio
import os
import platform
import logging
import re
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, List, Literal

from app.api.deps import require_admin
from app.core.installer import JOB_ID_RE, create_install_job, read_installer_log, start_install_job
from app.core.paths import get_data_dir, get_easypi_root
from app.models.user import User
from app.services.operation_event_service import OperationEventService

# Linux-specific imports (not available on Windows)
if platform.system() != "Windows":
    import pwd
    import grp
else:
    pwd = None  # type: ignore
    grp = None  # type: ignore

logger = logging.getLogger(__name__)
SYSTEM_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_.-]{0,31}$")
SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
RESTART_SERVICES_SCRIPT = "maintenance/restart_services.sh"
PERMISSIONS_SETUP_SCRIPT = "setup/add_user_permissions.sh"

# Check if running on Linux
IS_LINUX = platform.system() == "Linux"


router = APIRouter(prefix="/system", tags=["System"])
operation_event_service = OperationEventService()


def _record_system_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    route: str = "/setup",
    started_at: str | None = None,
    event_id: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route=route,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
            event_id=event_id,
        )
    except Exception as exc:
        logger.warning("Failed to record system event %s: %s", action_id, exc)


def _finish_update_operation_event(job_id: str, *, success: bool, message: str) -> None:
    """Persist the terminal update state after the backend has restarted."""
    try:
        operation_event_service.update_event(
            f"op-{job_id}",
            status="success" if success else "failed",
            message=message,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to finalize update operation event %s: %s", job_id, exc)


class PermissionStatus(BaseModel):
    """Current permission status"""
    current_user: str
    in_easypi_group: bool
    group_exists: bool
    sudo_configured: bool
    needs_relogin: bool
    permissions_ok: bool
    is_development: bool = False  # True when running on Windows/non-Linux


class SetupPermissionsRequest(BaseModel):
    """Request to set up permissions for a user"""
    username: Optional[str] = Field(default=None, max_length=32)  # If None, use current user

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _validate_linux_username(value)


class SetupPermissionsResponse(BaseModel):
    """Response from permissions setup"""
    success: bool
    message: str
    needs_relogin: bool
    username: str


async def run_command(command: str, shell: bool = True) -> tuple[int, str, str]:
    """Execute shell command asynchronously"""
    try:
        if shell:
            # Ensure sudo never prompts for a password in non-interactive API calls.
            command = re.sub(r"\bsudo\s+(?!-n\b)", "sudo -n ", command)
        if shell:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        else:
            args = command.split()
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
        stdout, stderr = await process.communicate()
        
        return (
            process.returncode,
            stdout.decode().strip(),
            stderr.decode().strip()
        )
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return 1, "", str(e)


async def run_command_args(args: list[str], timeout: int = 1800) -> tuple[int, str, str]:
    """Execute command arguments asynchronously (no shell)."""
    try:
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        return (
            process.returncode,
            stdout.decode(errors="ignore").strip(),
            stderr.decode(errors="ignore").strip(),
        )
    except asyncio.TimeoutError:
        return 124, "", f"Command timed out after {timeout}s"
    except Exception as e:
        logger.error(f"Command args execution failed: {e}")
        return 1, "", str(e)


async def _schedule_easypi_services_restart() -> tuple[int, str, str]:
    """Schedule the fixed EasyPi stack restart through the reviewed root runner."""
    runner = get_easypi_root() / "scripts" / "runner"
    return await run_command_args(
        ["sudo", "-n", str(runner), RESTART_SERVICES_SCRIPT, "schedule"],
        timeout=15,
    )


async def _run_permissions_setup(username: str) -> tuple[int, str, str]:
    """Run the narrow, root-owned EasyPi group setup helper."""
    runner = get_easypi_root() / "scripts" / "runner"
    return await run_command_args(
        ["sudo", "-n", str(runner), PERMISSIONS_SETUP_SCRIPT, username],
        timeout=30,
    )


def get_current_user() -> str:
    """Get the current username running the backend"""
    if not IS_LINUX:
        return os.environ.get("USERNAME", os.environ.get("USER", "developer"))
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except Exception:
        return os.environ.get("USER", "unknown")


def _validate_linux_username(value: str) -> str:
    """Validate Linux username before it is used in privileged operations."""

    username = str(value or "").strip()
    if not username:
        raise ValueError("Username is required")
    if not SYSTEM_USERNAME_RE.fullmatch(username):
        raise ValueError("Username contains unsupported characters")
    return username


def check_group_exists(group_name: str = "easypi") -> bool:
    """Check if a group exists"""
    if not IS_LINUX:
        return False  # Groups don't work the same on Windows
    try:
        grp.getgrnam(group_name)
        return True
    except KeyError:
        return False


def check_user_in_group(username: str, group_name: str = "easypi") -> bool:
    """Check if user is in the specified group.

    Linux users may belong to a group either as:
    - an explicit supplementary member in ``/etc/group``
    - or by having the group's GID as their primary group
    """
    if not IS_LINUX:
        return False
    try:
        group_info = grp.getgrnam(group_name)
        if username in group_info.gr_mem:
            return True

        try:
            user_info = pwd.getpwnam(username)
        except KeyError:
            return False

        return user_info.pw_gid == group_info.gr_gid
    except KeyError:
        return False


def check_user_in_group_current_session(group_name: str = "easypi") -> bool:
    """Check if current process has the group in its effective groups (current session)"""
    if not IS_LINUX:
        return False
    try:
        group_info = grp.getgrnam(group_name)
        current_groups = os.getgroups()
        return group_info.gr_gid in current_groups
    except KeyError:
        return False


async def check_sudo_configured() -> bool:
    """Check if sudoers file for easypi is properly configured"""
    if not IS_LINUX:
        return False  # No sudo on Windows
    sudoers_path = "/etc/sudoers.d/easypi"
    try:
        returncode, _, _ = await run_command(
            f"sudo -n test -f {sudoers_path}"
        )
        return returncode == 0
    except Exception:
        return False


@router.get("/permissions/status", response_model=PermissionStatus)
async def get_permissions_status(_admin: User = Depends(require_admin)):
    """
    Check current permission status for the system
    Returns information about user, group membership, and sudo configuration
    """
    try:
        current_user = get_current_user()
        
        # On Windows/development mode, return development status
        if not IS_LINUX:
            return PermissionStatus(
                current_user=current_user,
                in_easypi_group=False,
                group_exists=False,
                sudo_configured=False,
                needs_relogin=False,
                permissions_ok=False,
                is_development=True
            )
        
        group_exists = check_group_exists("easypi")
        
        # Check if user is in group in /etc/group file
        in_group_file = check_user_in_group(current_user, "easypi") if group_exists else False
        # Check if current process/session has the group
        in_group_session = check_user_in_group_current_session("easypi") if group_exists else False
        
        sudo_configured = await check_sudo_configured()
        
        # User needs re-login if they're in the group file but not in current session
        needs_relogin = in_group_file and not in_group_session
        
        # Permissions are OK only if user has group in current session AND sudo is configured
        permissions_ok = group_exists and in_group_session and sudo_configured
        
        return PermissionStatus(
            current_user=current_user,
            in_easypi_group=in_group_session,  # Report actual session status
            group_exists=group_exists,
            sudo_configured=sudo_configured,
            needs_relogin=needs_relogin,
            permissions_ok=permissions_ok,
            is_development=False
        )
    except Exception as e:
        logger.error(f"Error checking permissions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/permissions/setup", response_model=SetupPermissionsResponse)
async def setup_permissions(
    request: SetupPermissionsRequest = SetupPermissionsRequest(username=None),
    _admin: User = Depends(require_admin),
):
    """
    Set up system permissions for EasyPi
    Creates easypi group, adds user to it, and ensures sudoers is configured
    """
    # On Windows (development), just return success
    if not IS_LINUX:
        return SetupPermissionsResponse(
            success=True,
            message="Development mode - permissions not required on Windows",
            needs_relogin=False,
            username=get_current_user()
        )
    
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        username = _validate_linux_username(request.username or get_current_user())
        was_in_group = check_user_in_group(username, "easypi") if check_group_exists("easypi") else False
        returncode, _stdout, stderr = await _run_permissions_setup(username)
        if returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to configure permissions: {stderr}")

        current_user = get_current_user()
        needs_restart = username == current_user and not check_user_in_group_current_session("easypi")
        needs_relogin = username != current_user and not was_in_group
        
        # Step 4: Schedule an out-of-process restart so the HTTP response can be
        # delivered before the backend receives SIGTERM. The privileged helper
        # accepts only this fixed service stack; no broad systemctl grant exists.
        if needs_restart:
            logger.info("Scheduling backend restart to apply group changes...")
            returncode, _stdout, stderr = await _schedule_easypi_services_restart()
            if returncode != 0:
                raise HTTPException(
                    status_code=500,
                    detail=f"Permissions were updated, but the service restart could not be scheduled: {stderr}",
                )
        
        message = "Permissions configured successfully"
        if needs_restart:
            message += " - EasyPi services are restarting to apply changes..."
        elif needs_relogin:
            message += " - the user must log out and back in to apply changes"
        _record_system_event(
            action_id="system.permissions.setup",
            title="Configure EasyPi permissions",
            subtitle="Setup · Permissions",
            status="success",
            message=message,
            started_at=started_at,
        )
        return SetupPermissionsResponse(
            success=True,
            message=message,
            needs_relogin=needs_relogin,
            username=username
        )
        
    except HTTPException as exc:
        _record_system_event(
            action_id="system.permissions.setup",
            title="Configure EasyPi permissions",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise
    except ValueError as e:
        _record_system_event(
            action_id="system.permissions.setup",
            title="Configure EasyPi permissions",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error setting up permissions: {e}")
        _record_system_event(
            action_id="system.permissions.setup",
            title="Configure EasyPi permissions",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/users")
async def list_system_users(_admin: User = Depends(require_admin)):
    """
    List system users that can be added to easypi group
    Only shows real users (UID >= 1000, with valid shell)
    """
    # On Windows, return empty list
    if not IS_LINUX:
        return {"users": [{"username": get_current_user(), "uid": 1000, "home": os.path.expanduser("~"), "in_easypi_group": False}]}
    
    try:
        users = []
        valid_shells = ['/bin/bash', '/bin/sh', '/bin/zsh', '/usr/bin/bash', '/usr/bin/zsh']
        
        for user in pwd.getpwall():
            # Filter: UID >= 1000 (real users), valid login shell, not nobody
            if (user.pw_uid >= 1000 and 
                user.pw_shell in valid_shells and 
                user.pw_name != "nobody"):
                
                in_group = check_user_in_group(user.pw_name, "easypi")
                users.append({
                    "username": user.pw_name,
                    "uid": user.pw_uid,
                    "home": user.pw_dir,
                    "in_easypi_group": in_group
                })
        
        return {"users": users}
    except Exception as e:
        logger.error(f"Error listing users: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/users/{username}/add-to-group")
async def add_user_to_group(username: str, _admin: User = Depends(require_admin)):
    """Add a specific user to the easypi group (admin only)."""
    # On Windows, return success
    if not IS_LINUX:
        return {
            "success": True,
            "message": "Development mode - user management not available on Windows",
            "needs_relogin": False
        }
    
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        username = _validate_linux_username(username)
        # Verify user exists
        try:
            pwd.getpwnam(username)
        except KeyError:
            raise HTTPException(status_code=404, detail=f"User {username} not found")
        
        # Check if already in group
        if check_user_in_group(username, "easypi"):
            _record_system_event(
                action_id="system.user.add-to-group",
                title="Add user to EasyPi group",
                subtitle="Setup · Permissions",
                status="success",
                message=f"User {username} is already in easypi group",
                started_at=started_at,
            )
            return {
                "success": True,
                "message": f"User {username} is already in easypi group",
                "needs_relogin": False
            }
        
        returncode, _stdout, stderr = await _run_permissions_setup(username)
        if returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to add user: {stderr}")
        
        message = f"User {username} added to easypi group"
        _record_system_event(
            action_id="system.user.add-to-group",
            title="Add user to EasyPi group",
            subtitle="Setup · Permissions",
            status="success",
            message=message,
            started_at=started_at,
        )
        return {
            "success": True,
            "message": message,
            "needs_relogin": True
        }
    except HTTPException as exc:
        _record_system_event(
            action_id="system.user.add-to-group",
            title="Add user to EasyPi group",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise
    except ValueError as e:
        _record_system_event(
            action_id="system.user.add-to-group",
            title="Add user to EasyPi group",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding user to group: {e}")
        _record_system_event(
            action_id="system.user.add-to-group",
            title="Add user to EasyPi group",
            subtitle="Setup · Permissions",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/info")
async def get_system_info(_admin: User = Depends(require_admin)):
    """Get general system information"""
    try:
        from app.utils.system import get_pi_model, is_raspberry_pi
        
        if IS_LINUX:
            # Get system info on Linux
            returncode, hostname, _ = await run_command("hostname")
            _, os_info, _ = await run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d'\"' -f2")
            _, kernel, _ = await run_command("uname -r")
            _, uptime, _ = await run_command("uptime -p")
            
            # Get Pi model
            pi_model = None
            if is_raspberry_pi():
                pi_model = get_pi_model()
        else:
            # Windows development mode
            import socket
            hostname = socket.gethostname()
            os_info = f"Windows {platform.release()}"
            kernel = platform.version()
            uptime = "Development mode"
            pi_model = None
        
        return {
            "hostname": hostname,
            "os": os_info,
            "kernel": kernel,
            "uptime": uptime,
            "current_user": get_current_user(),
            "easypi_installed": IS_LINUX and os.path.exists("/opt/EasyPi"),
            "pi_model": pi_model,
            "is_raspberry_pi": IS_LINUX and is_raspberry_pi() if IS_LINUX else False
        }
    except Exception as e:
        logger.error(f"Error getting system info: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============== EasyPi Update ==============

class SystemUpdateRequest(BaseModel):
    mode: Literal["archive", "url"] = "url"
    archive_path: Optional[str] = None
    url: Optional[str] = None
    # Detached release signature: a URL (url mode) or a local file path (archive
    # mode). Required — the updater refuses anything not signed by the release key.
    signature: Optional[str] = None
    sha256: Optional[str] = None
    run_install: bool = False
    delete_obsolete: bool = False
    dry_run: bool = False
    # A normal update is health-gated. Callers must opt out explicitly; the
    # browser's recommended workflows also leave this enabled.
    restart_services: bool = True

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        value = value.strip().lower()
        if not SHA256_RE.match(value):
            raise ValueError("sha256 must be a 64-character hex string")
        return value


@router.post("/update/run")
async def run_easypi_update(request: SystemUpdateRequest, _admin: User = Depends(require_admin)):
    """Start the signed updater in a detached, root-owned installer unit."""
    if not IS_LINUX:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "success": True,
            "status": "success",
            "message": "Development mode - update command not executed",
            "command": f"apply_update.sh --mode {request.mode} [signed source]",
            "mode": request.mode,
            "job_id": None,
            "exit_code": 0,
            "started_at": now,
            "finished_at": now,
            "stdout": "",
            "stderr": "",
        }

    # Signed updater: a root-owned wrapper that verifies the release signature
    # against a baked-in public key before applying anything. easypi cannot modify
    # it and cannot forge a signature, so this is not an easypi->root path.
    update_script = Path("/opt/EasyPi/scripts/maintenance/apply_update.sh")
    if not update_script.exists():
        raise HTTPException(status_code=500, detail="Signed updater not found at /opt/EasyPi/scripts/maintenance/apply_update.sh")

    signature = str(request.signature or "").strip()
    if not signature:
        raise HTTPException(status_code=400, detail="A release signature is required (signature URL for URL mode, or signature file path for archive mode)")

    args = ["--mode", request.mode, "--sig", signature]

    if request.mode == "archive":
        archive_path = str(request.archive_path or "").strip()
        if not archive_path:
            raise HTTPException(status_code=400, detail="archive_path is required for archive mode")
        if not Path(archive_path).is_file():
            raise HTTPException(status_code=400, detail=f"Archive not found: {archive_path}")
        args.extend(["--archive", archive_path])
    else:
        update_url = str(request.url or "").strip()
        if not update_url:
            raise HTTPException(status_code=400, detail="url is required for url mode")
        if not re.match(r"^https://", update_url, flags=re.IGNORECASE):
            raise HTTPException(status_code=400, detail="Only HTTPS update URLs are supported")
        args.extend(["--url", update_url])
        if request.sha256:
            args.extend(["--sha256", request.sha256])

    if request.run_install:
        args.append("--run-install")
    if request.delete_obsolete:
        args.append("--delete-obsolete")
    if request.dry_run:
        args.append("--dry-run")
    if not request.restart_services:
        args.append("--skip-restart")

    started_at = datetime.now(timezone.utc).isoformat()
    job_id: str | None = None
    try:
        job_id = create_install_job("maintenance/apply_update.sh", args)
        _record_system_event(
            action_id="system.update",
            title="Run EasyPi update",
            subtitle="Setup · System maintenance",
            status="running",
            message="Signed update job starting",
            started_at=started_at,
            event_id=f"op-{job_id}",
        )
        start_result = await asyncio.to_thread(
            start_install_job,
            job_id,
            30,
            True,
        )
        if start_result.returncode != 0:
            error = (start_result.stderr or start_result.stdout or "Failed to start update job").strip()
            (get_data_dir() / "installer" / f"{job_id}.json").unlink(missing_ok=True)
            raise RuntimeError(error[:400])
    except Exception as exc:
        logger.error("Failed to start signed update job: %s", exc, exc_info=True)
        _record_system_event(
            action_id="system.update",
            title="Run EasyPi update",
            subtitle="Setup · System maintenance",
            status="failed",
            message="Failed to start signed update job",
            started_at=started_at,
            event_id=f"op-{job_id}" if job_id else None,
        )
        raise HTTPException(status_code=500, detail="Failed to start signed update job") from exc

    _record_system_event(
        action_id="system.update",
        title="Run EasyPi update",
        subtitle="Setup · System maintenance",
        status="running",
        message="Signed update job started",
        started_at=started_at,
        event_id=f"op-{job_id}",
    )
    return {
        "success": True,
        "status": "running",
        "message": "Signed update job started",
        "command": f"apply_update.sh --mode {request.mode} [signed source]",
        "mode": request.mode,
        "job_id": job_id,
        "exit_code": None,
        "started_at": started_at,
        "finished_at": None,
        "stdout": "",
        "stderr": "",
    }


@router.get("/update/status/{job_id}")
async def get_easypi_update_status(job_id: str, _admin: User = Depends(require_admin)):
    """Read persistent status for a signed update installer unit."""
    if not JOB_ID_RE.fullmatch(job_id):
        raise HTTPException(status_code=400, detail="Invalid update job id")

    log_tail = read_installer_log(job_id, max_bytes=18000)
    finished_matches = re.findall(r"Installer job [0-9a-f]{32} finished \(exit=(\d+)\)", log_tail)
    if finished_matches:
        exit_code = int(finished_matches[-1])
        success = exit_code == 0
        message = "Update completed successfully" if success else "Update failed"
        _finish_update_operation_event(job_id, success=success, message=message)
        return {
            "success": success,
            "status": "success" if success else "failed",
            "message": message,
            "job_id": job_id,
            "exit_code": exit_code,
            "stdout": log_tail,
            "stderr": "",
        }

    unit = f"easypi-installer@{job_id}.service"
    rc, unit_output, _unit_error = await run_command_args(
        [
            "systemctl",
            "show",
            unit,
            "--property=ActiveState",
            "--property=Result",
            "--property=ExecMainStatus",
            "--no-pager",
        ],
        timeout=5,
    )
    unit_state = {}
    if rc == 0:
        for line in unit_output.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                unit_state[key] = value

    active_state = unit_state.get("ActiveState", "")
    result = unit_state.get("Result", "")
    exit_text = unit_state.get("ExecMainStatus", "")
    if active_state == "failed" or (result not in {"", "success"} and active_state != "active"):
        exit_code = int(exit_text) if exit_text.isdigit() else 1
        _finish_update_operation_event(job_id, success=False, message="Update job failed before completion")
        return {
            "success": False,
            "status": "failed",
            "message": "Update job failed before completion",
            "job_id": job_id,
            "exit_code": exit_code,
            "stdout": log_tail,
            "stderr": "",
        }

    job_file = get_data_dir() / "installer" / f"{job_id}.json"
    if not log_tail and not job_file.exists() and active_state not in {"active", "activating"}:
        raise HTTPException(status_code=404, detail="Update job not found")

    return {
        "success": True,
        "status": "running",
        "message": "Signed update is running",
        "job_id": job_id,
        "exit_code": None,
        "stdout": log_tail,
        "stderr": "",
    }


@router.post("/update/restart-services")
async def restart_easypi_services(_admin: User = Depends(require_admin)):
    """Schedule a restart of the fixed EasyPi service stack."""
    if not IS_LINUX:
        return {"success": True, "message": "Development mode - no restart performed"}

    started_at = datetime.now(timezone.utc).isoformat()
    code, out, err = await _schedule_easypi_services_restart()
    logs = "\n".join(part for part in (out, err) if part).strip()
    if code != 0:
        message = "Failed to schedule the EasyPi service restart"
        _record_system_event(
            action_id="system.restart-services",
            title="Restart EasyPi services",
            subtitle="Setup · Service lifecycle",
            status="failed",
            message=message,
            started_at=started_at,
        )
        return {"success": False, "message": message, "logs": logs, "exit_code": code}

    _record_system_event(
        action_id="system.restart-services",
        title="Restart EasyPi services",
        subtitle="Setup · Service lifecycle",
        status="success",
        message="Scheduled the reviewed EasyPi service stack restart",
        started_at=started_at,
    )
    return {
        "success": True,
        "message": "EasyPi services restart scheduled",
        "logs": logs,
        "exit_code": 0,
    }


# ============== Timezone Settings ==============

class TimezoneRequest(BaseModel):
    """Request to set timezone"""
    timezone: str


@router.get("/timezone")
async def get_timezone(_admin: User = Depends(require_admin)):
    """Get current timezone"""
    if not IS_LINUX:
        return {"timezone": "UTC", "is_development": True}
    
    try:
        returncode, stdout, stderr = await run_command("timedatectl show --property=Timezone --value")
        if returncode == 0 and stdout.strip():
            return {"timezone": stdout.strip(), "is_development": False}
        return {"timezone": "UTC", "is_development": False}
    except Exception as e:
        logger.error(f"Error getting timezone: {e}")
        return {"timezone": "UTC", "error": str(e)}


@router.post("/timezone")
async def set_timezone(request: TimezoneRequest, _admin: User = Depends(require_admin)):
    """Set system timezone (admin only)."""
    if not IS_LINUX:
        return {"success": True, "message": "Development mode - no changes made", "timezone": request.timezone}

    started_at = datetime.now(timezone.utc).isoformat()
    tz = request.timezone.strip()
    # Keep malformed values out before invoking the privileged validator.
    if not re.fullmatch(r"[A-Za-z0-9_+./-]{1,64}", tz):
        raise HTTPException(status_code=400, detail="Invalid timezone format")
    try:
        runner = str(get_easypi_root() / "scripts" / "runner")
        returncode, stdout, stderr = await run_command_args([
            "sudo", "-n", runner, "settings/system_settings.sh",
            "set-timezone", tz,
        ])
        if returncode != 0:
            if returncode == 2:
                raise HTTPException(status_code=400, detail=f"Invalid timezone: {tz}")
            raise HTTPException(status_code=500, detail=f"Failed to set timezone: {stderr}")
        
        message = f"Timezone set to {request.timezone}"
        _record_system_event(
            action_id="system.timezone.set",
            title="Set system timezone",
            subtitle="Settings · General",
            status="success",
            message=message,
            route="/settings",
            started_at=started_at,
        )
        return {"success": True, "message": message, "timezone": request.timezone}
    except HTTPException as exc:
        _record_system_event(
            action_id="system.timezone.set",
            title="Set system timezone",
            subtitle="Settings · General",
            status="failed",
            message=str(exc.detail),
            route="/settings",
            started_at=started_at,
        )
        raise
    except Exception as e:
        logger.error(f"Error setting timezone: {e}")
        _record_system_event(
            action_id="system.timezone.set",
            title="Set system timezone",
            subtitle="Settings · General",
            status="failed",
            message=str(e),
            route="/settings",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


# ============== DNS Settings ==============

class DNSSettings(BaseModel):
    """DNS configuration for the Pi itself"""
    primary_dns: str = "8.8.8.8"
    secondary_dns: str = ""  # optional (may be empty)
    ignore_dhcp_dns: bool = True  # Don't use DNS from DHCP

    @field_validator("primary_dns", "secondary_dns")
    @classmethod
    def validate_dns_ip(cls, value: str, info) -> str:
        """Only accept real IP addresses — blocks shell-metacharacter injection.
        secondary_dns is optional and may be empty."""
        value = (value or "").strip()
        if not value:
            if info.field_name == "secondary_dns":
                return ""
            raise ValueError("Primary DNS must not be empty")
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"Invalid DNS IP address: {value}")
        return value


class DNSStatus(BaseModel):
    """Current DNS status"""
    current_dns: List[str]
    connection_name: Optional[str]
    ignore_dhcp_dns: bool
    is_development: bool
    gateway: Optional[str] = None  # default gateway / router IP (for "use router DNS")


@router.get("/dns/status", response_model=DNSStatus)
async def get_dns_status(_admin: User = Depends(require_admin)):
    """Get current DNS configuration of the Pi"""
    if not IS_LINUX:
        return DNSStatus(
            current_dns=["Development mode"],
            connection_name=None,
            ignore_dhcp_dns=False,
            is_development=True
        )
    
    try:
        # Get current DNS servers from resolv.conf
        dns_servers = []
        try:
            with open("/etc/resolv.conf", "r") as f:
                for line in f:
                    if line.strip().startswith("nameserver"):
                        dns = line.strip().split()[1]
                        if dns not in dns_servers:
                            dns_servers.append(dns)
        except Exception:
            pass
        
        # Get NetworkManager connection name
        connection_name = None
        ignore_dhcp = False
        try:
            returncode, stdout, stderr = await run_command("nmcli -t -f NAME,DEVICE con show --active")
            if returncode == 0 and stdout.strip():
                # Get first active connection
                lines = stdout.strip().split('\n')
                for line in lines:
                    parts = line.split(':')
                    if len(parts) >= 2 and parts[1]:  # Has device
                        connection_name = parts[0]
                        break
                
                if connection_name:
                    # Check if DHCP DNS is ignored
                    returncode2, stdout2, stderr2 = await run_command_args([
                        "nmcli", "-t", "-f", "ipv4.ignore-auto-dns",
                        "connection", "show", connection_name,
                    ])
                    if returncode2 == 0:
                        ignore_dhcp = "yes" in stdout2.lower()
        except Exception:
            pass
        
        # Detect the default gateway (router) so the UI can offer "use router DNS".
        gateway = None
        try:
            _rc, out_g, _err = await run_command("ip route show default")
            m = re.search(r"default via (\S+)", out_g or "")
            if m:
                gateway = m.group(1)
        except Exception:
            pass

        return DNSStatus(
            current_dns=dns_servers if dns_servers else ["Not configured"],
            connection_name=connection_name,
            ignore_dhcp_dns=ignore_dhcp,
            is_development=False,
            gateway=gateway
        )
    except Exception as e:
        logger.error(f"Error getting DNS status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns/configure")
async def configure_dns(settings: DNSSettings, _admin: User = Depends(require_admin)):
    """
    Configure DNS for the Pi itself (bypass NetProtection for system updates)
    This sets the Pi to use external DNS directly, not its own NetProtection
    """
    if not IS_LINUX:
        return {"success": True, "message": "Development mode - no changes made"}
    
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        # Get active connection name
        returncode, stdout, stderr = await run_command("nmcli -t -f NAME,DEVICE con show --active")
        if returncode != 0:
            raise HTTPException(status_code=500, detail="Failed to get network connection")
        
        connection_name = None
        lines = stdout.strip().split('\n')
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 2 and parts[1]:  # Has device
                connection_name = parts[0]
                break
        
        if not connection_name:
            raise HTTPException(status_code=500, detail="No active network connection found")
        
        # Configure DNS via arg-list (no shell) using the full nmcli verbs that the
        # sudoers grant actually allows ("connection modify"/"connection up"). DNS
        # values are validated as IPs on the model, so there is no injection surface.
        dns_string = settings.primary_dns
        if settings.secondary_dns:
            dns_string += f" {settings.secondary_dns}"

        runner = str(get_easypi_root() / "scripts" / "runner")
        returncode, _, stderr = await run_command_args([
            "sudo", "-n", runner, "settings/network_firewall.sh",
            "nmcli-dns", "set", connection_name, dns_string,
            "yes" if settings.ignore_dhcp_dns else "no",
        ])
        if returncode != 0:
            # Connection might briefly drop, that's okay
            logger.warning("DNS connection update failed: %s", stderr)
            raise HTTPException(status_code=500, detail=f"Failed to set DNS: {stderr}")
        
        message = f"DNS configured: {dns_string}. Pi will now use external DNS directly."
        _record_system_event(
            action_id="system.dns.configure",
            title="Configure system DNS",
            subtitle="Setup · Device DNS",
            status="success",
            message=message,
            started_at=started_at,
        )
        return {
            "success": True,
            "message": message,
            "connection": connection_name
        }
    except HTTPException as exc:
        _record_system_event(
            action_id="system.dns.configure",
            title="Configure system DNS",
            subtitle="Setup · Device DNS",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise
    except Exception as e:
        logger.error(f"Error configuring DNS: {e}")
        _record_system_event(
            action_id="system.dns.configure",
            title="Configure system DNS",
            subtitle="Setup · Device DNS",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns/reset")
async def reset_dns(_admin: User = Depends(require_admin)):
    """Reset DNS to use DHCP-provided DNS (default behavior)"""
    if not IS_LINUX:
        return {"success": True, "message": "Development mode - no changes made"}
    
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        # Get active connection name
        returncode, stdout, stderr = await run_command("nmcli -t -f NAME,DEVICE con show --active")
        if returncode != 0:
            raise HTTPException(status_code=500, detail="Failed to get network connection")
        
        connection_name = None
        lines = stdout.strip().split('\n')
        for line in lines:
            parts = line.split(':')
            if len(parts) >= 2 and parts[1]:
                connection_name = parts[0]
                break
        
        if not connection_name:
            raise HTTPException(status_code=500, detail="No active network connection found")
        
        runner = str(get_easypi_root() / "scripts" / "runner")
        returncode, _, stderr = await run_command_args([
            "sudo", "-n", runner, "settings/network_firewall.sh",
            "nmcli-dns-reset", connection_name,
        ])
        if returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to reset DNS: {stderr}")
        
        message = "DNS reset to DHCP defaults"
        _record_system_event(
            action_id="system.dns.reset",
            title="Reset system DNS",
            subtitle="Setup · Device DNS",
            status="success",
            message=message,
            started_at=started_at,
        )
        return {
            "success": True,
            "message": message,
            "connection": connection_name
        }
    except HTTPException as exc:
        _record_system_event(
            action_id="system.dns.reset",
            title="Reset system DNS",
            subtitle="Setup · Device DNS",
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise
    except Exception as e:
        logger.error(f"Error resetting DNS: {e}")
        _record_system_event(
            action_id="system.dns.reset",
            title="Reset system DNS",
            subtitle="Setup · Device DNS",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))
