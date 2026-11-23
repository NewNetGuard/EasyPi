from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# Типы
FileCategory = Literal["all", "photos", "videos", "documents", "audio", "archives", "encrypted", "other"]
ColorLabel = Literal["none", "red", "orange", "yellow", "green", "blue", "purple", "gray"]
AccessLevel = Literal["private", "public", "password"]
SortField = Literal["name", "size", "modified", "type"]
SortOrder = Literal["asc", "desc"]


class PiCloudFile(BaseModel):
    id: str
    name: str
    path: str
    mime: str | None = None
    type: Literal["folder", "file"]
    size: int
    modified: datetime
    created: datetime | None = None
    extension: str | None = None
    favorite: bool = False
    tags: list[str] = Field(default_factory=list)
    color_label: ColorLabel = "none"
    thumbnail: bool = False
    thumbnail_url: str | None = None
    category: FileCategory | None = None
    # Медиа
    width: int | None = None
    height: int | None = None
    duration: float | None = None
    # Telegram
    uploaded_via_telegram: bool = False
    telegram_user_id: int | None = None


class FileListResponse(BaseModel):
    path: str
    items: list[PiCloudFile]
    total_count: int = 0
    has_more: bool = False


class StorageStats(BaseModel):
    total: int
    used: int
    free: int
    percent: float
    file_count: int = 0
    folder_count: int = 0


class UsageByType(BaseModel):
    photos: int
    videos: int
    documents: int
    audio: int
    archives: int = 0
    other: int


class ShareLink(BaseModel):
    id: str
    url: str
    file_id: str
    file_name: str
    expires_at: datetime | None = None
    password: str | None = None
    access_count: int = 0
    max_access: int | None = None
    qr_base64: str | None = None
    embed_code: str | None = None
    created_at: datetime


class UploadProgress(BaseModel):
    file_id: str
    file_name: str
    file_size: int
    progress: int = 0
    status: Literal["queued", "uploading", "processing", "completed", "error"]
    error: str | None = None
    speed: int | None = None
    eta: int | None = None


class UploadResponse(BaseModel):
    uploaded: list[PiCloudFile]
    failed: list[dict[str, str]] = []


class TrashItem(BaseModel):
    id: str
    original: str
    deleted_at: str


class GPSData(BaseModel):
    latitude: float
    longitude: float
    altitude: float | None = None


class ExifData(BaseModel):
    camera: str | None = None
    lens: str | None = None
    aperture: str | None = None
    shutter_speed: str | None = None
    iso: str | None = None
    focal_length: str | None = None
    date_taken: str | None = None
    gps: GPSData | None = None


class AudioMetadata(BaseModel):
    title: str | None = None
    artist: str | None = None
    album: str | None = None
    year: str | None = None
    genre: str | None = None
    bitrate: int | None = None
    sample_rate: int | None = None


class VideoMetadata(BaseModel):
    codec: str | None = None
    bitrate: int | None = None
    fps: float | None = None
    audio_codec: str | None = None
    audio_bitrate: int | None = None


class Metadata(BaseModel):
    name: str
    path: str
    size: int
    mime: str | None = None
    modified: datetime
    created: datetime | None = None
    width: int | None = None
    height: int | None = None
    duration: float | None = None
    exif: ExifData | None = None
    audio: AudioMetadata | None = None
    video: VideoMetadata | None = None


class Folder(BaseModel):
    id: str
    name: str
    path: str
    parent_path: str
    item_count: int = 0
    size: int = 0
    modified: datetime
    created: datetime
    color_label: ColorLabel = "none"


class FolderTreeItem(BaseModel):
    id: str
    name: str
    path: str
    children: list["FolderTreeItem"] = []
    item_count: int = 0
FolderTreeItem.model_rebuild()


class TelegramBotConfig(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    token: str = ""
    allowed_user_ids: list[int] = Field(default_factory=list, alias="allowedUserIds")
    auto_organize: bool = Field(default=True, alias="autoOrganize")
    notify_on_upload: bool = Field(default=True, alias="notifyOnUpload")
    max_file_size: int = Field(default=50 * 1024 * 1024, alias="maxFileSize")  # 50MB default
    upload_folder: str = Field(default="/", alias="uploadFolder")


class TelegramAuthorizedUser(BaseModel):
    id: int
    username: str | None = None
    first_name: str | None = None
    last_upload: datetime | None = None
    upload_count: int = 0


class TelegramBotStatus(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    enabled: bool = False
    configured: bool = False
    connected: bool = False
    is_running: bool = Field(default=False, alias="isRunning")
    bot_username: str | None = Field(default=None, alias="botUsername")
    last_activity: datetime | None = Field(default=None, alias="lastActivity")
    total_uploads: int = Field(default=0, alias="totalUploads")
    storage_used: int = Field(default=0, alias="storageUsed")
    message: str | None = None
    authorized_users: list[TelegramAuthorizedUser] = Field(default_factory=list, alias="authorizedUsers")


class TelegramUpload(BaseModel):
    id: str
    file_id: str
    file_name: str
    file_size: int
    telegram_user_id: int
    telegram_username: str | None = None
    uploaded_at: datetime
    storage_path: str


class BotConfigRequest(BaseModel):
    token: str
    allowed_ids: list[int] = []
    auto_organize: bool = True
    notify_on_upload: bool = True
    max_file_size: int = 50 * 1024 * 1024
    upload_folder: str = "/"


class BotStatus(BaseModel):
    enabled: bool
    configured: bool
    connected: bool = False
    bot_username: str | None = None
    last_uploads: list[PiCloudFile] = []
    message: str | None = None


class ActivityItem(BaseModel):
    id: str
    action: Literal["upload", "download", "delete", "move", "rename", "share", "favorite", "tag"]
    file_id: str | None = None
    file_name: str
    file_path: str | None = None
    details: str | None = None
    timestamp: datetime
    source: Literal["web", "telegram", "api"] = "web"


class BulkOperationRequest(BaseModel):
    file_ids: list[str]


class BulkOperationResult(BaseModel):
    success: list[str]
    failed: list[dict[str, str]]


class DuplicateFile(BaseModel):
    hash: str
    size: int
    files: list[PiCloudFile]


class SearchRequest(BaseModel):
    query: str
    category: FileCategory | None = None
    tags: list[str] | None = None
    favorite_only: bool = False
    date_from: datetime | None = None
    date_to: datetime | None = None
    size_min: int | None = None
    size_max: int | None = None
    sort_by: SortField = "name"
    sort_order: SortOrder = "asc"
    offset: int = 0
    limit: int = 50


__all__ = [
    "PiCloudFile",
    "FileListResponse",
    "StorageStats",
    "UsageByType",
    "ShareLink",
    "UploadProgress",
    "UploadResponse",
    "TrashItem",
    "Metadata",
    "ExifData",
    "AudioMetadata",
    "VideoMetadata",
    "GPSData",
    "Folder",
    "FolderTreeItem",
    "TelegramBotConfig",
    "TelegramBotStatus",
    "TelegramUpload",
    "TelegramAuthorizedUser",
    "BotStatus",
    "BotConfigRequest",
    "ActivityItem",
    "BulkOperationRequest",
    "BulkOperationResult",
    "DuplicateFile",
    "SearchRequest",
]
