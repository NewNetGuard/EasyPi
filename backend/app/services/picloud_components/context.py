from __future__ import annotations

import mimetypes
import os
import shutil
import uuid
import json
import asyncio
import threading
import sys
import logging
import re
import zipfile
import html
from datetime import datetime, timedelta
from app.utils.time import utc_now
from pathlib import Path

from fastapi import HTTPException, UploadFile
from PIL import Image, ExifTags, ImageFile, ImageDraw, ImageFont

from app.core.security import get_password_hash, verify_password
from app.utils.file_security import unique_upload_path
from app.services.cloud_tags import (
    load_cloud_tag_map,
    normalize_cloud_tags,
    save_cloud_tag_map,
)
from app.schemas.picloud import (
    FileListResponse,
    PiCloudFile,
    ShareLink,
    StorageStats,
    UploadResponse,
    UsageByType,
    Metadata,
    Folder,
    FolderTreeItem,
    ActivityItem,
    DuplicateFile,
    BulkOperationResult,
    TelegramBotConfig,
    TelegramBotStatus,
    TelegramUpload,
    TelegramAuthorizedUser,
    ColorLabel,
    FileCategory,
)
import hashlib

ImageFile.LOAD_TRUNCATED_IMAGES = True

from app.core.paths import get_picloud_data_dir  # noqa: E402

DEFAULT_ROOT = get_picloud_data_dir()
STORAGE_ROOT = Path(os.getenv("PICLOUD_ROOT", str(DEFAULT_ROOT))).expanduser()
THUMB_ROOT = STORAGE_ROOT / ".thumbnails"
META_ROOT = STORAGE_ROOT / ".meta"
FAV_FILE = META_ROOT / "favorites.txt"
TAG_FILE = META_ROOT / "tags.json"
SHARE_FILE = META_ROOT / "shares.json"
TRASH_ROOT = STORAGE_ROOT / ".trash"
TRASH_META = META_ROOT / "trash.json"
COLOR_LABELS_FILE = META_ROOT / "color_labels.json"
ACTIVITY_FILE = META_ROOT / "activity.json"
SHARES_DB_FILE = META_ROOT / "shares_db.json"
TELEGRAM_CONFIG_FILE = META_ROOT / "telegram_config.json"
TELEGRAM_STATE_FILE = META_ROOT / "telegram_state.json"
TELEGRAM_UPLOADS_FILE = META_ROOT / "telegram_uploads.json"
DEFAULT_MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024
DEFAULT_MAX_PHOTO_UPLOAD_BYTES = 250 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
PICLOUD_FREE_SPACE_RESERVE = 5 * 1024 * 1024 * 1024
DOCX_PREVIEW_MAX_BYTES = 2 * 1024 * 1024
logger = logging.getLogger(__name__)


class PiCloudCapacityError(HTTPException):
    """Raised before a Cloud write would consume the system disk reserve."""

    def __init__(self) -> None:
        super().__init__(
            status_code=507,
            detail=(
                "Not enough disk space. EasyPi keeps 5 GiB free "
                "for system operation."
            ),
        )


def require_picloud_capacity(path: Path, additional_bytes: int = 0) -> None:
    """Keep the shared system filesystem above the PiCloud safety reserve."""
    required_bytes = max(0, int(additional_bytes)) + PICLOUD_FREE_SPACE_RESERVE
    probe = path
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    if shutil.disk_usage(probe).free < required_bytes:
        raise PiCloudCapacityError()


def _max_upload_bytes() -> int:
    try:
        return max(
            1, int(os.getenv("EASYPI_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES))
        )
    except (TypeError, ValueError):
        return DEFAULT_MAX_UPLOAD_BYTES


def _max_photo_upload_bytes() -> int:
    try:
        return max(
            1,
            int(
                os.getenv(
                    "EASYPI_MAX_PHOTO_UPLOAD_BYTES",
                    DEFAULT_MAX_PHOTO_UPLOAD_BYTES,
                )
            ),
        )
    except (TypeError, ValueError):
        return DEFAULT_MAX_PHOTO_UPLOAD_BYTES


# Auto-sort folders by file type
AUTO_SORT_FOLDERS = {
    "photos": {
        "folder": "Photos",
        "mimes": [
            "image/jpeg",
            "image/png",
            "image/gif",
            "image/webp",
            "image/bmp",
            "image/tiff",
            "image/heic",
            "image/heif",
        ],
        "extensions": [
            ".jpg",
            ".jpeg",
            ".png",
            ".gif",
            ".webp",
            ".bmp",
            ".tiff",
            ".heic",
            ".heif",
            ".raw",
            ".cr2",
            ".nef",
            ".arw",
        ],
    },
    "videos": {
        "folder": "Videos",
        "mimes": [
            "video/mp4",
            "video/quicktime",
            "video/x-msvideo",
            "video/x-matroska",
            "video/webm",
            "video/mpeg",
        ],
        "extensions": [
            ".mp4",
            ".mov",
            ".avi",
            ".mkv",
            ".webm",
            ".mpeg",
            ".mpg",
            ".m4v",
            ".wmv",
            ".flv",
        ],
    },
    "documents": {
        "folder": "Documents",
        "mimes": [
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument",
            "text/plain",
            "application/vnd.ms-excel",
            "application/vnd.ms-powerpoint",
        ],
        "extensions": [
            ".pdf",
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".txt",
            ".rtf",
            ".odt",
            ".ods",
            ".odp",
            ".csv",
        ],
    },
    "music": {
        "folder": "Music",
        "mimes": [
            "audio/mpeg",
            "audio/wav",
            "audio/flac",
            "audio/aac",
            "audio/ogg",
            "audio/x-m4a",
        ],
        "extensions": [
            ".mp3",
            ".wav",
            ".flac",
            ".aac",
            ".ogg",
            ".m4a",
            ".wma",
            ".opus",
        ],
    },
    "encrypted": {
        "folder": "Encrypted",
        "mimes": [],
        "extensions": [
            ".enc",
            ".encrypted",
            ".epec",
        ],  # EPEC = EasyPi Encrypted Content
    },
}

PROTECTED_ROOT_FOLDERS = {
    "Videos",
    "Music",
    "Documents",
    "Encrypt",
    "Encrypted",
    "Photos",
    "Files",
    "Taildrop",
}


def _get_auto_sort_folder(filename: str, mime: str | None) -> str | None:
    """Determine the auto-sort folder based on file type."""
    ext = Path(filename).suffix.lower()

    for category, config in AUTO_SORT_FOLDERS.items():
        # Check by extension first (more reliable)
        if ext in config["extensions"]:
            return config["folder"]
        # Then check by MIME type
        if mime:
            for mime_prefix in config["mimes"]:
                if mime.startswith(mime_prefix.split("/")[0]) and mime_prefix in mime:
                    return config["folder"]

    return None  # No auto-sort, use target path as-is


def cloud_runtime():
    """Resolve facade globals so test/runtime path overrides remain effective."""
    return sys.modules.get("app.services.picloud_service", sys.modules[__name__])


__all__ = [
    "ACTIVITY_FILE",
    "AUTO_SORT_FOLDERS",
    "ActivityItem",
    "BulkOperationResult",
    "COLOR_LABELS_FILE",
    "ColorLabel",
    "DEFAULT_MAX_PHOTO_UPLOAD_BYTES",
    "DEFAULT_MAX_UPLOAD_BYTES",
    "DEFAULT_ROOT",
    "DOCX_PREVIEW_MAX_BYTES",
    "DuplicateFile",
    "ExifTags",
    "FAV_FILE",
    "FileCategory",
    "FileListResponse",
    "Folder",
    "FolderTreeItem",
    "HTTPException",
    "Image",
    "ImageDraw",
    "ImageFile",
    "ImageFont",
    "META_ROOT",
    "Metadata",
    "PICLOUD_FREE_SPACE_RESERVE",
    "PiCloudCapacityError",
    "PROTECTED_ROOT_FOLDERS",
    "Path",
    "PiCloudFile",
    "SHARES_DB_FILE",
    "SHARE_FILE",
    "STORAGE_ROOT",
    "ShareLink",
    "StorageStats",
    "TAG_FILE",
    "TELEGRAM_CONFIG_FILE",
    "TELEGRAM_STATE_FILE",
    "TELEGRAM_UPLOADS_FILE",
    "THUMB_ROOT",
    "TRASH_META",
    "TRASH_ROOT",
    "TelegramAuthorizedUser",
    "TelegramBotConfig",
    "TelegramBotStatus",
    "TelegramUpload",
    "UPLOAD_CHUNK_BYTES",
    "UploadFile",
    "UploadResponse",
    "UsageByType",
    "_get_auto_sort_folder",
    "_max_photo_upload_bytes",
    "_max_upload_bytes",
    "asyncio",
    "cloud_runtime",
    "datetime",
    "get_password_hash",
    "get_picloud_data_dir",
    "hashlib",
    "html",
    "json",
    "load_cloud_tag_map",
    "logger",
    "logging",
    "mimetypes",
    "normalize_cloud_tags",
    "os",
    "re",
    "require_picloud_capacity",
    "save_cloud_tag_map",
    "shutil",
    "sys",
    "threading",
    "timedelta",
    "unique_upload_path",
    "utc_now",
    "uuid",
    "verify_password",
    "zipfile",
]
