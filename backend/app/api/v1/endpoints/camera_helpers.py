from __future__ import annotations

import json
import hashlib
import logging
import os
import re
import socket
import tempfile
import time
from pathlib import Path

import psutil
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.camera import Camera
from app.schemas.camera import CameraSettings, StorageInfo
from app.core.paths import get_easypi_root
from app.services.ptz.errors import PTZSecurityError
from app.services.ptz.ssrf import resolve_and_pin

logger = logging.getLogger("easypi")

RECORDINGS_PATH = Path("/opt/EasyPi/data/recordings")
SETTINGS_FILE = Path("/opt/EasyPi/data/camera_settings.json")
GO2RTC_DISCOVERY_STREAM = "easypi_discovery"
GO2RTC_DISABLED_SOURCE = "rtsp://127.0.0.1:9/unavailable"

_camera_status_cache: dict[str, tuple[bool, float]] = {}
_CACHE_TTL = 10.0


def ensure_camera_paths() -> None:
    """Ensure camera storage paths exist."""
    RECORDINGS_PATH.mkdir(parents=True, exist_ok=True)


def normalize_stream_name(name: str, camera_id: str | None = None) -> str:
    """Build a safe, stable and collision-resistant go2rtc stream key."""
    normalized = re.sub(r"[^A-Za-z0-9_-]+", "_", (name or "").strip())
    slug = (normalized.strip("_") or "camera")[:48]
    if camera_id is None:
        return slug
    compact_id = re.sub(r"[^A-Za-z0-9]+", "", camera_id)[:32]
    if not compact_id:
        compact_id = hashlib.sha256(camera_id.encode("utf-8")).hexdigest()[:32]
    # Stored cameras use only their immutable ID. Renaming a camera therefore
    # cannot break an active recorder or leave an obsolete stream key behind.
    return f"camera_{compact_id}"


def get_go2rtc_rtsp_url(name: str, camera_id: str) -> str:
    """Return a credential-free loopback URL for a configured camera stream."""
    return f"rtsp://127.0.0.1:8554/{normalize_stream_name(name, camera_id)}"


def sync_go2rtc_config(db: Session) -> bool:
    """Sync go2rtc.yaml with cameras from database."""
    import subprocess

    try:
        cameras = db.query(Camera).all()
        new_streams: dict[str, str] = {
            GO2RTC_DISCOVERY_STREAM: GO2RTC_DISABLED_SOURCE,
        }
        for camera in cameras:
            try:
                rtsp_url = camera.get_rtsp_url()
            except PTZSecurityError as exc:
                logger.warning(
                    "Skipping unsafe stored camera target %s: %s",
                    camera.id,
                    exc,
                )
                continue
            if not rtsp_url:
                continue
            if "#transport=tcp" not in rtsp_url:
                rtsp_url = f"{rtsp_url}#transport=tcp"
            new_streams[normalize_stream_name(camera.name, camera.id)] = rtsp_url

        runner = get_easypi_root() / "scripts" / "runner"
        payload = json.dumps({"streams": new_streams}, separators=(",", ":"))
        result = subprocess.run(
            ["sudo", "-n", str(runner), "settings/go2rtc_config.sh", "apply"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "configuration helper failed").strip()
            raise RuntimeError(detail[:500])

        logger.info(f"go2rtc config synced with {len(new_streams)} camera(s)")

        return True
    except Exception as exc:
        logger.error(f"Failed to sync go2rtc config: {exc}")
        return False


def get_camera_or_404(db: Session, camera_id: str) -> Camera:
    """Get camera by ID or raise 404."""
    camera = db.get(Camera, camera_id)
    if camera is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Camera not found")
    return camera


def check_camera_online(ip: str, port: int, timeout: float = 5.0) -> bool:
    """Check if camera is reachable via socket."""
    try:
        pinned_ip, pinned_port = resolve_and_pin(ip, port)
        with socket.create_connection((pinned_ip, pinned_port), timeout=timeout):
            return True
    except Exception:
        return False


def get_camera_status_cached(camera_id: str, ip: str, port: int) -> bool:
    """Check camera status with a short TTL cache."""
    now = time.time()
    if camera_id in _camera_status_cache:
        is_online, timestamp = _camera_status_cache[camera_id]
        if now - timestamp < _CACHE_TTL:
            return is_online

    is_online = check_camera_online(ip, port)
    _camera_status_cache[camera_id] = (is_online, now)
    return is_online


def get_storage_info() -> StorageInfo:
    """Get recordings storage information."""
    try:
        ensure_camera_paths()
        usage = psutil.disk_usage(str(RECORDINGS_PATH))
        return StorageInfo(
            total=f"{usage.total / (1024**3):.1f} GB",
            used=f"{usage.used / (1024**3):.1f} GB",
            free=f"{usage.free / (1024**3):.1f} GB",
            percent=usage.percent,
        )
    except Exception as exc:
        logger.warning(f"Failed to get storage info: {exc}")
        return StorageInfo()


def load_camera_settings() -> CameraSettings:
    """Load camera settings from file."""
    if SETTINGS_FILE.exists():
        try:
            data = json.loads(SETTINGS_FILE.read_text())
            return CameraSettings(**data)
        except Exception as exc:
            logger.warning(f"Failed to load camera settings: {exc}")
    return CameraSettings()


def save_camera_settings(settings: CameraSettings) -> None:
    """Save camera settings to file."""
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".camera_settings.", dir=SETTINGS_FILE.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(settings.model_dump_json(indent=2))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, SETTINGS_FILE)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
