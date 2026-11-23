"""Pydantic schemas for IP Cameras management."""
from __future__ import annotations

from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.services.ptz.errors import PTZSecurityError
from app.services.ptz.ssrf import validate_ip as validate_camera_ip
from app.services.ptz.ssrf import validate_port as validate_camera_port


def _validated_ip(value: str) -> str:
    try:
        return str(validate_camera_ip(value))
    except PTZSecurityError as exc:
        raise ValueError(str(exc)) from exc


def _validated_port(value: int) -> int:
    try:
        return validate_camera_port(value)
    except PTZSecurityError as exc:
        raise ValueError(str(exc)) from exc


def _validated_rtsp_path(value: str) -> str:
    if not value.startswith("/"):
        raise ValueError("rtspPath must start with '/'")
    if "\r" in value or "\n" in value:
        raise ValueError("rtspPath must not contain line breaks")
    return value


def _validated_camera_name(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("name must not be blank")
    if "/" in value or "\\" in value or any(ord(char) < 32 for char in value):
        raise ValueError("name must not contain path separators or control characters")
    return value


class CameraHealthChecks(BaseModel):
    """Health check results for a camera."""
    network: Literal["ok", "error"] = "ok"
    rtspStream: Literal["ok", "error"] = "ok"
    recordingService: Literal["active", "inactive", "failed"] = "inactive"
    diskSpace: Literal["ok", "warning", "critical"] = "ok"
    lastFrame: str = ""


class CameraHealth(BaseModel):
    """Camera health status."""
    status: Literal["healthy", "degraded", "unhealthy"] = "healthy"
    checks: CameraHealthChecks = Field(default_factory=CameraHealthChecks)


class CameraStatus(BaseModel):
    """Camera recording status."""
    cameraId: str
    recording: bool = False
    since: Optional[str] = None
    fileSize: Optional[str] = None
    status: Literal["active", "inactive", "failed"] = "inactive"
    lastFrame: Optional[str] = None
    health: CameraHealth = Field(default_factory=CameraHealth)


class CameraBase(BaseModel):
    """Base camera properties."""
    name: str = Field(min_length=1, max_length=100)
    ip: str = Field(min_length=2, max_length=45)
    port: int = Field(default=554, ge=1, le=65535)
    username: str = Field(default="", max_length=100)
    rtspPath: str = Field(default="/stream1", min_length=1, max_length=255)
    brand: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    location: Optional[str] = Field(default=None, max_length=255)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _validated_camera_name(value)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        return _validated_ip(value)

    @field_validator("port")
    @classmethod
    def validate_port(cls, value: int) -> int:
        return _validated_port(value)

    @field_validator("rtspPath")
    @classmethod
    def validate_rtsp_path(cls, value: str) -> str:
        return _validated_rtsp_path(value)


class CameraCreate(CameraBase):
    """Create camera payload."""
    password: str = Field(min_length=1, max_length=127)
    # Optional, separate PTZ/ONVIF credentials (kept apart from the RTSP creds so
    # they never change the video URL). Recommended: a limited ONVIF user.
    ptzUsername: str = Field(default="", max_length=100)
    ptzPassword: str = Field(default="", max_length=127)
    # ONVIF control port (from WS-Discovery); distinct from the RTSP port.
    onvifPort: Optional[int] = Field(default=None, ge=1, le=65535)

    @field_validator("onvifPort")
    @classmethod
    def validate_onvif_port(cls, value: Optional[int]) -> Optional[int]:
        return _validated_port(value) if value is not None else value


class CameraUpdate(BaseModel):
    """Update camera payload."""
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    ip: Optional[str] = Field(default=None, min_length=2, max_length=45)
    port: Optional[int] = Field(default=None, ge=1, le=65535)
    username: Optional[str] = Field(default=None, max_length=100)
    password: Optional[str] = Field(default=None, min_length=1, max_length=127)
    rtspPath: Optional[str] = Field(default=None, min_length=1, max_length=255)
    brand: Optional[str] = Field(default=None, max_length=100)
    model: Optional[str] = Field(default=None, max_length=100)
    location: Optional[str] = Field(default=None, max_length=255)
    ptzUsername: Optional[str] = Field(default=None, max_length=100)
    ptzPassword: Optional[str] = Field(default=None, min_length=1, max_length=127)
    onvifPort: Optional[int] = Field(default=None, ge=1, le=65535)

    @model_validator(mode="before")
    @classmethod
    def reject_null_required_values(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for field in ("name", "ip", "port", "username", "password", "rtspPath"):
                if field in data and data[field] is None:
                    raise ValueError(f"{field} must not be null")
        return data

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return _validated_camera_name(value)

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: Optional[str]) -> Optional[str]:
        return _validated_ip(value) if value is not None else value

    @field_validator("port", "onvifPort")
    @classmethod
    def validate_port(cls, value: Optional[int]) -> Optional[int]:
        return _validated_port(value) if value is not None else value

    @field_validator("rtspPath")
    @classmethod
    def validate_rtsp_path(cls, value: Optional[str]) -> Optional[str]:
        return _validated_rtsp_path(value) if value is not None else value


class CameraResponse(CameraBase):
    """Camera response."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    hasAuth: bool = False
    hasPtzAuth: bool = False
    ptzUsername: str = ""
    onvifPort: Optional[int] = None
    status: Literal["online", "offline", "recording", "error"] = "offline"
    lastSeen: Optional[str] = None
    createdAt: str
    updatedAt: str


class StorageInfo(BaseModel):
    """Storage information."""
    total: str = "0 GB"
    used: str = "0 GB"
    free: str = "0 GB"
    percent: float = 0.0


class RecordingsInfo(BaseModel):
    """Recordings statistics."""
    total: int = 0
    today: int = 0
    size: str = "0 MB"


class EventsToday(BaseModel):
    """Events count for today."""
    motion: int = 0
    offline: int = 0
    online: int = 0


class CameraStats(BaseModel):
    """Camera statistics."""
    totalCameras: int = 0
    online: int = 0
    offline: int = 0
    recording: int = 0
    storage: StorageInfo = Field(default_factory=StorageInfo)
    recordings: RecordingsInfo = Field(default_factory=RecordingsInfo)
    eventsToday: EventsToday = Field(default_factory=EventsToday)


class RecordingEvent(BaseModel):
    """Recording event."""
    id: str
    type: Literal["motion", "offline", "online", "manual"] = "manual"
    timestamp: str
    metadata: Optional[dict[str, Any]] = None


class Recording(BaseModel):
    """Recording entry."""
    id: str
    cameraId: str
    cameraName: str
    startTime: str
    endTime: str
    duration: int  # seconds
    fileSize: int  # bytes
    hasMotion: bool = False
    locked: bool = False  # user "kept" it -> excluded from auto-cleanup
    thumbnail: Optional[str] = None
    events: list[RecordingEvent] = Field(default_factory=list)


class CameraEvent(BaseModel):
    """Camera event."""
    id: str
    cameraId: str
    cameraName: str
    type: Literal["motion", "offline", "online", "storage_full", "recording_started", "recording_stopped"]
    timestamp: str
    message: str
    metadata: Optional[dict[str, Any]] = None
    notified: bool = False
    snapshot: Optional[str] = None


class MotionDetectionSettings(BaseModel):
    """Motion detection settings."""
    enabled: bool = False
    sensitivity: int = Field(default=50, ge=0, le=100)
    notifyEmail: bool = False
    notifyTelegram: bool = False
    notifyBrowser: bool = True
    cooldownMinutes: int = Field(default=5, ge=1, le=1440)


class OfflineNotifySettings(BaseModel):
    """Offline notification settings."""
    enabled: bool = True
    retryAttempts: int = Field(default=3, ge=1, le=20)


class StorageFullSettings(BaseModel):
    """Storage full alert settings."""
    enabled: bool = True
    thresholdPercent: int = Field(default=90, ge=1, le=99)
    autoCleanup: bool = False


class CameraSettings(BaseModel):
    """Global camera settings."""
    storageLocation: Literal["/opt/EasyPi/data/recordings"] = "/opt/EasyPi/data/recordings"
    retentionDays: int = Field(default=30, ge=1, le=3650)
    autoCleanup: bool = True
    motionDetection: MotionDetectionSettings = Field(default_factory=MotionDetectionSettings)
    offlineNotify: OfflineNotifySettings = Field(default_factory=OfflineNotifySettings)
    storageFull: StorageFullSettings = Field(default_factory=StorageFullSettings)


class RecordingsFilter(BaseModel):
    """Filter for recordings list."""
    cameraId: Optional[str] = None
    date: Optional[str] = None
    startTime: Optional[str] = None
    endTime: Optional[str] = None
    eventsOnly: bool = False
    sort: Literal["newest", "oldest"] = "newest"
    limit: int = 50
    offset: int = 0


# ============================================================================
# Snapshots
# ============================================================================

class SnapshotInfo(BaseModel):
    """Snapshot information."""
    id: str
    camera_id: Optional[str] = None
    camera_name: str
    filename: str
    size: int
    created_at: str
    url: str


class SnapshotListResponse(BaseModel):
    """Response for snapshot list."""
    snapshots: list[SnapshotInfo]
    total_count: int
    total_size: int


class SnapshotDeleteResponse(BaseModel):
    """Response for snapshot deletion."""
    success: bool
    deleted_count: int
    freed_bytes: int
    message: str
