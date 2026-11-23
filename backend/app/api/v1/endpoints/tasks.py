"""Tasks endpoint for executing service installation/management scripts."""
import asyncio
import logging
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from config import get_settings

from app.api.deps import require_admin
from app.models.user import User
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tasks", tags=["tasks"])
operation_event_service = OperationEventService()

# Configuration
_settings = get_settings()
SCRIPTS_BASE = _settings.SCRIPTS_ROOT
RUNNER_PATH = _settings.RUNNER_PATH
LOGS_DIR = _settings.TASK_LOG_DIR
ALLOWED_SCRIPT_PATTERN = re.compile(r"^(services|stacks|security|backup|settings)/[a-zA-Z0-9_\-]+\.sh$")

# In-memory task storage (in production, use Redis or DB)
active_tasks: Dict[str, Dict] = {}


def _describe_task(script_path: str, action: str) -> tuple[str, str, str]:
    normalized = str(script_path or "").lower()
    action_label = action.replace("-", " ").title()

    component = "Script task"
    subtitle = f"Jobs · {script_path}"
    route = "/jobs"

    if "tailscale" in normalized:
        component = "Tailscale"
        subtitle = "Remote Access · Script task"
        route = "/remote-access"
    elif "wireguard" in normalized:
        component = "WireGuard"
        subtitle = "VPN · Script task"
        route = "/vpn"
    elif "ai" in normalized:
        component = "AI runtime"
        subtitle = "AI Chat · Script task"
        route = "/ai"
    elif "netprotection" in normalized:
        component = "NetProtection"
        subtitle = "Guard Security · Script task"
        route = "/guard-security"
    elif normalized.startswith("backup/"):
        component = "Backup task"
        subtitle = "System Backup · Script task"
        route = "/backup"
    elif normalized.startswith("security/"):
        component = "Security task"
        subtitle = "Security · Script task"
        route = "/security"
    elif normalized.startswith("settings/"):
        component = "Settings task"
        subtitle = "Setup · Script task"
        route = "/setup"

    title = f"{action_label} {component}"
    return title, subtitle, route


def _record_task_event(
    *,
    event_id: str,
    action_id: str,
    status: str,
    title: str,
    subtitle: str,
    route: str,
    message: str,
    started_at: str,
) -> None:
    try:
        operation_event_service.record_event(
            event_id=event_id,
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route=route,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record task event %s: %s", action_id, exc)


class TaskRunRequest(BaseModel):
    """Request to run a script task."""
    script: str = Field(..., description="Script path relative to scripts base (e.g., 'services/ai.sh')")
    action: str = Field(default="install", description="Action to perform (install, start, stop, restart, uninstall)")
    args: Optional[Dict[str, str]] = Field(default=None, description="Optional environment variables")

    @field_validator("script")
    @classmethod
    def validate_script_path(cls, v):
        """Ensure script path matches allowed pattern."""
        if not ALLOWED_SCRIPT_PATTERN.match(v):
            raise ValueError(
                f"Script path must match pattern: {ALLOWED_SCRIPT_PATTERN.pattern}"
            )
        # Check for path traversal attempts
        if ".." in v or v.startswith("/"):
            raise ValueError("Invalid script path: directory traversal not allowed")
        return v

    @field_validator("action")
    @classmethod
    def validate_action(cls, v):
        """Ensure action is one of allowed values."""
        allowed = ["install", "start", "stop", "restart", "status", "uninstall"]
        if v not in allowed:
            raise ValueError(f"Action must be one of: {', '.join(allowed)}")
        return v


class TaskResponse(BaseModel):
    """Response for a started task."""
    task_id: str
    script: str
    action: str
    status: str
    created_at: str
    websocket_url: str


@router.post("/run", response_model=TaskResponse)
async def run_task(request: TaskRunRequest, _admin: User = Depends(require_admin)) -> TaskResponse:
    """Execute a service script via the secure runner.
    
    Returns a task ID and WebSocket URL for real-time log streaming.
    """
    task_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    event_id = f"task-{task_id}"
    
    # Construct full script path
    script_rel_path = request.script
    title, subtitle, route = _describe_task(script_rel_path, request.action)
    
    # Create log file
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOGS_DIR / f"{task_id}.log"
    
    # Store task metadata
    active_tasks[task_id] = {
        "id": task_id,
        "script": script_rel_path,
        "action": request.action,
        "status": "running",
        "created_at": created_at,
        "log_file": str(log_file),
        "process": None,
        "event_id": event_id,
        "event_title": title,
        "event_subtitle": subtitle,
        "event_route": route,
    }

    _record_task_event(
        event_id=event_id,
        action_id="tasks.run",
        status="running",
        title=title,
        subtitle=subtitle,
        route=route,
        message=f"Queued {script_rel_path} with action {request.action}",
        started_at=created_at,
    )
    
    # Start the task in background
    asyncio.create_task(_execute_script(task_id, script_rel_path, request.action, request.args, log_file))
    
    return TaskResponse(
        task_id=task_id,
        script=script_rel_path,
        action=request.action,
        status="running",
        created_at=created_at,
        websocket_url=f"/ws/tasks/{task_id}",
    )


async def _execute_script(
    task_id: str,
    script_path: str,
    action: str,
    env_args: Optional[Dict[str, str]],
    log_file: Path,
):
    """Execute script via runner and stream output to log file."""
    task = active_tasks.get(task_id) or {}
    event_id = str(task.get("event_id") or f"task-{task_id}")
    started_at = str(task.get("created_at") or datetime.now(timezone.utc).isoformat())
    title = str(task.get("event_title") or "Run script task")
    subtitle = str(task.get("event_subtitle") or f"Jobs · {script_path}")
    route = str(task.get("event_route") or "/jobs")
    try:
        # Build command: sudo /opt/EasyPi/scripts/runner services/ai.sh status
        cmd = ["sudo", str(RUNNER_PATH), script_path, action]
        
        # Prepare environment
        env = os.environ.copy()
        if env_args:
            for key, value in env_args.items():
                env[f"SERVICE_OPTION_{key.upper()}"] = value
        
        logger.info(f"Task {task_id}: Executing {cmd}")
        
        # Run the script off the event loop: Popen + streaming read + wait
        # block, so they must not run on the asyncio loop (freezes backend).
        def _run_and_stream() -> int:
            with open(log_file, "w") as log_f:
                log_f.write(f"Task ID: {task_id}\n")
                log_f.write(f"Script: {script_path}\n")
                log_f.write(f"Action: {action}\n")
                log_f.write(f"Started: {datetime.now(timezone.utc).isoformat()}\n")
                log_f.write("-" * 80 + "\n\n")
                log_f.flush()
            
                # Execute script
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    env=env,
                    text=True,
                    bufsize=1,
                )
            
                active_tasks[task_id]["process"] = process
            
                # Stream output
                if process.stdout:
                    for line in process.stdout:
                        log_f.write(line)
                        log_f.flush()
            
                # Wait for completion
                exit_code = process.wait()
            
                log_f.write("\n" + "-" * 80 + "\n")
                log_f.write(f"Exit code: {exit_code}\n")
                log_f.write(f"Finished: {datetime.now(timezone.utc).isoformat()}\n")
            return exit_code

        exit_code = await asyncio.to_thread(_run_and_stream)
        
        # Update task status
        if exit_code == 0:
            active_tasks[task_id]["status"] = "success"
            logger.info(f"Task {task_id} completed successfully")
            _record_task_event(
                event_id=event_id,
                action_id="tasks.run",
                status="success",
                title=title,
                subtitle=subtitle,
                route=route,
                message=f"{script_path} {action} finished successfully",
                started_at=started_at,
            )
        else:
            active_tasks[task_id]["status"] = "failed"
            logger.error(f"Task {task_id} failed with exit code {exit_code}")
            _record_task_event(
                event_id=event_id,
                action_id="tasks.run",
                status="failed",
                title=title,
                subtitle=subtitle,
                route=route,
                message=f"{script_path} {action} failed with exit code {exit_code}",
                started_at=started_at,
            )
        
        active_tasks[task_id]["exit_code"] = exit_code
        
    except Exception as e:
        logger.exception(f"Task {task_id} error: {e}")
        active_tasks[task_id]["status"] = "error"
        active_tasks[task_id]["error"] = str(e)
        _record_task_event(
            event_id=event_id,
            action_id="tasks.run",
            status="failed",
            title=title,
            subtitle=subtitle,
            route=route,
            message=str(e),
            started_at=started_at,
        )


@router.get("/")
def list_tasks(_admin: User = Depends(require_admin)) -> dict[str, str]:
    """List running tasks."""
    return {"status": "ok", "tasks": list(active_tasks.keys())}


@router.get("/{task_id}")
def get_task(task_id: str, _admin: User = Depends(require_admin)):
    """Get task status and metadata."""
    if task_id not in active_tasks:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    
    task = active_tasks[task_id].copy()
    task.pop("process", None)  # Don't serialize process object
    return task


@router.get("/{task_id}/logs")
def get_task_logs(task_id: str, _admin: User = Depends(require_admin)):
    """Get task logs."""
    if task_id not in active_tasks:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")
    
    log_file = Path(active_tasks[task_id]["log_file"])
    if not log_file.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Log file not found")
    
    return {"task_id": task_id, "logs": log_file.read_text()}


__all__ = ["router"]
