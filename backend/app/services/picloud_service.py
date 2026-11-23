"""Stable public facade for PiCloud storage."""

# ruff: noqa: F401

# ruff: noqa: F401

from app.services.picloud_components.context import (
    ACTIVITY_FILE,
    AUTO_SORT_FOLDERS,
    ActivityItem,
    BulkOperationResult,
    COLOR_LABELS_FILE,
    ColorLabel,
    DEFAULT_MAX_PHOTO_UPLOAD_BYTES,
    DEFAULT_MAX_UPLOAD_BYTES,
    DEFAULT_ROOT,
    DOCX_PREVIEW_MAX_BYTES,
    DuplicateFile,
    ExifTags,
    FAV_FILE,
    FileCategory,
    FileListResponse,
    Folder,
    FolderTreeItem,
    HTTPException,
    Image,
    ImageDraw,
    ImageFile,
    ImageFont,
    META_ROOT,
    Metadata,
    PROTECTED_ROOT_FOLDERS,
    Path,
    PiCloudFile,
    SHARES_DB_FILE,
    SHARE_FILE,
    STORAGE_ROOT,
    ShareLink,
    StorageStats,
    TAG_FILE,
    TELEGRAM_CONFIG_FILE,
    TELEGRAM_STATE_FILE,
    TELEGRAM_UPLOADS_FILE,
    THUMB_ROOT,
    TRASH_META,
    TRASH_ROOT,
    TelegramAuthorizedUser,
    TelegramBotConfig,
    TelegramBotStatus,
    TelegramUpload,
    UPLOAD_CHUNK_BYTES,
    UploadFile,
    UploadResponse,
    UsageByType,
    _get_auto_sort_folder,
    _max_photo_upload_bytes,
    _max_upload_bytes,
    asyncio,
    cloud_runtime,
    datetime,
    get_password_hash,
    get_picloud_data_dir,
    hashlib,
    html,
    json,
    load_cloud_tag_map,
    logger,
    logging,
    mimetypes,
    normalize_cloud_tags,
    os,
    re,
    save_cloud_tag_map,
    shutil,
    sys,
    threading,
    timedelta,
    unique_upload_path,
    utc_now,
    uuid,
    verify_password,
    zipfile,
)

from app.services.picloud_components.files import CloudFilesMixin
from app.services.picloud_components.metadata import CloudMetadataMixin
from app.services.picloud_components.previews import CloudPreviewsMixin
from app.services.picloud_components.telegram import CloudTelegramMixin


class PiCloudService(
    CloudFilesMixin, CloudPreviewsMixin, CloudMetadataMixin, CloudTelegramMixin
):
    def __init__(self) -> None:
        STORAGE_ROOT.mkdir(parents=True, exist_ok=True)
        THUMB_ROOT.mkdir(parents=True, exist_ok=True)
        META_ROOT.mkdir(parents=True, exist_ok=True)
        TRASH_ROOT.mkdir(parents=True, exist_ok=True)
        self._migrate_encrypted_folder()
        self._migrate_taildrop_folder()
        if not FAV_FILE.exists():
            FAV_FILE.write_text("", encoding="utf-8")
        if not TAG_FILE.exists():
            TAG_FILE.write_text("{}", encoding="utf-8")
        if not SHARE_FILE.exists():
            SHARE_FILE.write_text("{}", encoding="utf-8")
        if not TRASH_META.exists():
            TRASH_META.write_text("{}", encoding="utf-8")
        self._share_lock = threading.RLock()
        self.share_tokens: dict[str, dict[str, object]] = self._load_shares()
        self._tag_lock = threading.Lock()
        self._telegram_state_cache: dict[str, object] = {}
        self._telegram_fs_error: str | None = None

    def _migrate_encrypted_folder(self) -> None:
        old_dir = STORAGE_ROOT / ".encrypted"
        new_dir = STORAGE_ROOT / "Encrypted"
        if not old_dir.exists():
            return
        new_dir.mkdir(parents=True, exist_ok=True)
        for entry in old_dir.iterdir():
            target = new_dir / entry.name
            if target.exists():
                base = target.stem
                ext = target.suffix
                counter = 1
                while target.exists():
                    target = new_dir / f"{base}_{counter}{ext}"
                    counter += 1
            shutil.move(str(entry), str(target))
        try:
            if not any(old_dir.iterdir()):
                old_dir.rmdir()
        except Exception:
            pass

    def _migrate_taildrop_folder(self) -> None:
        """Move files created by the first Taildrop importer into type folders."""
        old_dir = STORAGE_ROOT / "Taildrop"
        if not old_dir.is_dir() or old_dir.is_symlink():
            return
        for entry in old_dir.iterdir():
            if entry.is_symlink() or not entry.is_file():
                logger.error("Refusing unsupported legacy Taildrop entry: %s", entry)
                continue
            try:
                mime = mimetypes.guess_type(entry.name)[0]
                folder_name = _get_auto_sort_folder(entry.name, mime) or "Files"
                destination_dir = STORAGE_ROOT / folder_name
                destination_dir.mkdir(parents=True, exist_ok=True)
                destination = unique_upload_path(destination_dir, entry.name)
                shutil.move(str(entry), str(destination))
            except Exception:
                logger.exception("Could not sort legacy Taildrop file: %s", entry)
        try:
            old_dir.rmdir()
        except OSError:
            pass


pi_cloud_service = PiCloudService()
