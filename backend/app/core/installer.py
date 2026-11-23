"""
Installer job helper for privileged installs.

Creates a job file under /opt/EasyPi/data/installer and triggers
the root-owned systemd unit easypi-installer@<job>.service.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from app.core.paths import get_data_dir, get_privileged_logs_dir, get_scripts_dir

logger = logging.getLogger(__name__)

ALLOWED_INSTALL_SCRIPTS = {
    "maintenance/apply_update.sh",
    "services/tailscale.sh",
    "services/wireguard.sh",
    "services/ai.sh",
    "security/update_system.sh",
}
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _installer_dir() -> Path:
    return get_data_dir() / "installer"


def create_install_job(script: str, args: Sequence[str] | None = None) -> str:
    if script not in ALLOWED_INSTALL_SCRIPTS:
        raise ValueError(f"Script not allowed for installer job: {script}")

    job_id = uuid.uuid4().hex
    created_at = datetime.now(timezone.utc)
    job_dir = _installer_dir()
    job_dir.mkdir(parents=True, exist_ok=True)

    job_path = job_dir / f"{job_id}.json"
    payload = {
        "script": script,
        "args": list(args or []),
        "created_at": created_at.isoformat(),
        "created_at_epoch": created_at.timestamp(),
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(job_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, separators=(",", ":"))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        job_path.unlink(missing_ok=True)
        raise

    return job_id


def start_install_job(job_id: str, timeout: int = 600, no_block: bool = False) -> subprocess.CompletedProcess:
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("Invalid installer job id")
    cmd = [
        "sudo",
        "-n",
        str(get_scripts_dir() / "runner"),
        "services/start_installer_job.sh",
        job_id,
    ]
    if no_block:
        cmd.append("--no-block")
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)


def get_installer_log_path(job_id: str) -> Path:
    if not JOB_ID_RE.fullmatch(job_id):
        raise ValueError("Invalid installer job id")
    return get_privileged_logs_dir() / f"installer-{job_id}.log"


def read_installer_log(job_id: str, max_bytes: int = 8192) -> str:
    log_path = get_installer_log_path(job_id)
    if not log_path.exists():
        return ""

    try:
        with log_path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            if size > max_bytes:
                handle.seek(size - max_bytes)
            else:
                handle.seek(0)
            data = handle.read()
        return data.decode("utf-8", errors="replace").strip()
    except Exception as exc:
        logger.warning("Failed to read installer log %s: %s", log_path, exc)
        return ""
