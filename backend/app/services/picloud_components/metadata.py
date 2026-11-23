"""CloudMetadataMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.picloud_components.context import (
    ACTIVITY_FILE,
    AUTO_SORT_FOLDERS,
    ActivityItem,
    BulkOperationResult,
    COLOR_LABELS_FILE,
    ColorLabel,
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


class CloudMetadataMixin:
    def _get_file_category(self, mime: str | None, filename: str = "") -> FileCategory:
        """Classify recognized content; keep every other format in Files."""
        ext = Path(filename).suffix.lower()
        if filename.lower().endswith(".encrypted") or ext in {".enc", ".epec"}:
            return "encrypted"
        if (mime and mime.startswith("image/")) or ext in {
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
        }:
            return "photos"
        if (mime and mime.startswith("video/")) or ext in {
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
        }:
            return "videos"
        if (mime and mime.startswith("audio/")) or ext in {
            ".mp3",
            ".wav",
            ".flac",
            ".aac",
            ".ogg",
            ".m4a",
            ".wma",
            ".opus",
        }:
            return "audio"
        document_extensions = {
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
        }
        document_mimes = {
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-excel",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-powerpoint",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            "application/rtf",
            "application/vnd.oasis.opendocument.text",
            "application/vnd.oasis.opendocument.spreadsheet",
            "application/vnd.oasis.opendocument.presentation",
        }
        if ext in document_extensions or (
            mime and (mime.startswith("text/") or mime in document_mimes)
        ):
            return "documents"
        return "other"

    def set_color_label(self, file_id: str, color: ColorLabel) -> None:
        color_data = self._load_color_labels()
        color_data[file_id] = color
        self._save_color_labels(color_data)

    def get_color_label(self, file_id: str) -> ColorLabel:
        color_data = self._load_color_labels()
        return color_data.get(file_id, "none")

    def list_folders(self, path: str) -> list[Folder]:
        try:
            base = self._safe_path(path, allow_root=True)
        except ValueError:
            base = cloud_runtime().STORAGE_ROOT
        if not base.exists():
            base = cloud_runtime().STORAGE_ROOT

        folders = []
        for entry in base.iterdir():
            if (
                entry.is_dir()
                and not entry.name.startswith(".")
                and not (
                    base == cloud_runtime().STORAGE_ROOT and entry.name == "Telegram"
                )
            ):
                stat = entry.stat()
                item_count = sum(1 for _ in entry.iterdir())
                size = sum(f.stat().st_size for f in entry.rglob("*") if f.is_file())

                folders.append(
                    Folder(
                        id=str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                        name=entry.name,
                        path="/" + str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                        parent_path="/"
                        + str(entry.parent.relative_to(cloud_runtime().STORAGE_ROOT)),
                        item_count=item_count,
                        size=size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        created=datetime.fromtimestamp(stat.st_ctime),
                        color_label=self.get_color_label(
                            str(entry.relative_to(cloud_runtime().STORAGE_ROOT))
                        ),
                    )
                )

        return sorted(folders, key=lambda x: x.name.lower())

    def get_folder_tree(self) -> list[FolderTreeItem]:
        def build_tree(path: Path) -> list[FolderTreeItem]:
            items = []
            for entry in path.iterdir():
                if (
                    entry.is_dir()
                    and not entry.name.startswith(".")
                    and not (
                        path == cloud_runtime().STORAGE_ROOT
                        and entry.name == "Telegram"
                    )
                ):
                    item_count = sum(1 for _ in entry.iterdir())
                    items.append(
                        FolderTreeItem(
                            id=str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                            name=entry.name,
                            path="/"
                            + str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                            children=build_tree(entry),
                            item_count=item_count,
                        )
                    )
            return sorted(items, key=lambda x: x.name.lower())

        return build_tree(cloud_runtime().STORAGE_ROOT)

    def get_activity(self, limit: int = 50) -> list[ActivityItem]:
        activities = self._load_activity()
        return activities[:limit]

    def _log_activity(
        self,
        action: str,
        file_name: str,
        file_id: str | None = None,
        file_path: str | None = None,
        details: str | None = None,
        source: str = "web",
    ):
        activities = self._load_activity()
        activities.insert(
            0,
            ActivityItem(
                id=str(utc_now().timestamp()),
                action=action,
                file_id=file_id,
                file_name=file_name,
                file_path=file_path,
                details=details,
                timestamp=utc_now(),
                source=source,
            ),
        )
        activities = activities[:1000]
        self._save_activity(activities)

    def find_duplicates(self) -> list[DuplicateFile]:
        hash_map = {}

        for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
            if entry.is_file() and not entry.name.startswith("."):
                file_hash = self._calculate_file_hash(entry)
                size = entry.stat().st_size

                if file_hash not in hash_map:
                    hash_map[file_hash] = {"size": size, "files": []}

                stat = entry.stat()
                mime, _ = mimetypes.guess_type(entry.name)
                hash_map[file_hash]["files"].append(
                    PiCloudFile(
                        id=str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                        name=entry.name,
                        path="/" + str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                        mime=mime,
                        type="file",
                        size=size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        extension=entry.suffix.lower(),
                    )
                )

        duplicates = []
        for file_hash, data in hash_map.items():
            if len(data["files"]) > 1:
                duplicates.append(
                    DuplicateFile(
                        hash=file_hash,
                        size=data["size"],
                        files=data["files"],
                    )
                )

        return duplicates

    def _calculate_file_hash(self, file_path: Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def bulk_delete(self, file_ids: list[str]) -> BulkOperationResult:
        success, failed = [], []
        for file_id in file_ids:
            try:
                self.delete_file(file_id)
                success.append(file_id)
            except Exception as e:
                failed.append({"id": file_id, "error": str(e)})
        return BulkOperationResult(success=success, failed=failed)

    def bulk_move(self, file_ids: list[str], target_path: str) -> BulkOperationResult:
        success, failed = [], []
        for file_id in file_ids:
            try:
                src = self._safe_path(file_id, allow_root=False)
                new_path = (
                    f"{self._normalize_file_id(target_path).rstrip('/')}/{src.name}"
                )
                self.rename_or_move(file_id, new_path)
                success.append(file_id)
            except Exception as e:
                failed.append({"id": file_id, "error": str(e)})
        return BulkOperationResult(success=success, failed=failed)

    def bulk_copy(self, file_ids: list[str], target_path: str) -> BulkOperationResult:
        success, failed = [], []
        for file_id in file_ids:
            try:
                src = self._safe_path(file_id, allow_root=False)
                new_path = (
                    f"{self._normalize_file_id(target_path).rstrip('/')}/{src.name}"
                )
                self.copy_file(file_id, new_path)
                success.append(file_id)
            except Exception as e:
                failed.append({"id": file_id, "error": str(e)})
        return BulkOperationResult(success=success, failed=failed)

    def bulk_favorite(self, file_ids: list[str], value: bool) -> BulkOperationResult:
        success, failed = [], []
        for file_id in file_ids:
            try:
                self.toggle_favorite(file_id, value)
                success.append(file_id)
            except Exception as e:
                failed.append({"id": file_id, "error": str(e)})
        return BulkOperationResult(success=success, failed=failed)

    def get_share_info(self, share_id: str) -> ShareLink | None:
        with self._share_lock:
            if share_id not in self.share_tokens:
                return None
            shares = self._load_shares_db()
            return shares.get(share_id)

    def delete_share(self, share_id: str) -> None:
        with self._share_lock:
            removed = self.share_tokens.pop(share_id, None)
            try:
                self._persist_shares()
            except Exception:
                if removed is not None:
                    self.share_tokens[share_id] = removed
                raise
            shares = self._load_shares_db()
            shares.pop(share_id, None)
            self._save_shares_db(shares)

    def list_shares(self) -> list[ShareLink]:
        with self._share_lock:
            shares = self._load_shares_db()
            return [
                share
                for share_id, share in shares.items()
                if share_id in self.share_tokens
            ]

    def delete_from_trash(self, trash_id: str) -> None:
        trash_path = cloud_runtime().TRASH_ROOT / trash_id
        if trash_path.exists():
            if trash_path.is_dir():
                shutil.rmtree(trash_path)
            else:
                trash_path.unlink()

        trash_meta = self._load_trash()
        trash_meta.pop(trash_id, None)
        cloud_runtime().TRASH_META.write_text(json.dumps(trash_meta), encoding="utf-8")

    def _load_color_labels(self) -> dict:
        if not cloud_runtime().COLOR_LABELS_FILE.exists():
            return {}
        try:
            return json.loads(
                cloud_runtime().COLOR_LABELS_FILE.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError:
            return {}

    def _save_color_labels(self, data: dict):
        cloud_runtime().COLOR_LABELS_FILE.write_text(json.dumps(data), encoding="utf-8")

    def _load_activity(self) -> list[ActivityItem]:
        if not cloud_runtime().ACTIVITY_FILE.exists():
            return []
        try:
            data = json.loads(cloud_runtime().ACTIVITY_FILE.read_text(encoding="utf-8"))
            return [
                ActivityItem(
                    id=item["id"],
                    action=item["action"],
                    file_id=item.get("file_id"),
                    file_name=item["file_name"],
                    file_path=item.get("file_path"),
                    details=item.get("details"),
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    source=item.get("source", "web"),
                )
                for item in data
            ]
        except (json.JSONDecodeError, KeyError):
            return []

    def _save_activity(self, activities: list[ActivityItem]):
        data = [
            {
                "id": a.id,
                "action": a.action,
                "file_id": a.file_id,
                "file_name": a.file_name,
                "file_path": a.file_path,
                "details": a.details,
                "timestamp": a.timestamp.isoformat(),
                "source": a.source,
            }
            for a in activities
        ]
        cloud_runtime().ACTIVITY_FILE.write_text(json.dumps(data), encoding="utf-8")

    def _load_shares_db(self) -> dict:
        if not cloud_runtime().SHARES_DB_FILE.exists():
            return {}
        try:
            data = json.loads(
                cloud_runtime().SHARES_DB_FILE.read_text(encoding="utf-8")
            )
            result = {}
            needs_scrub = False
            for share_id, share_data in data.items():
                needs_scrub = needs_scrub or bool(
                    share_data.get("password") or share_data.get("qr_base64")
                )
                result[share_id] = ShareLink(
                    id=share_id,
                    url=share_data["url"],
                    file_id=share_data["file_id"],
                    file_name=share_data["file_name"],
                    expires_at=datetime.fromisoformat(share_data["expires_at"])
                    if share_data.get("expires_at")
                    else None,
                    password=None,
                    access_count=share_data.get("access_count", 0),
                    max_access=share_data.get("max_access"),
                    qr_base64=None,
                    embed_code=share_data.get("embed_code"),
                    created_at=datetime.fromisoformat(share_data["created_at"]),
                )
            if needs_scrub:
                self._save_shares_db(result)
            return result
        except (json.JSONDecodeError, KeyError):
            return {}

    def _save_shares_db(self, shares: dict):
        data = {}
        for share_id, share in shares.items():
            data[share_id] = {
                "url": share.url,
                "file_id": share.file_id,
                "file_name": share.file_name,
                "expires_at": share.expires_at.isoformat()
                if share.expires_at
                else None,
                "password": None,
                "access_count": share.access_count,
                "max_access": share.max_access,
                "qr_base64": None,
                "embed_code": share.embed_code,
                "created_at": share.created_at.isoformat(),
            }
        cloud_runtime().SHARES_DB_FILE.write_text(json.dumps(data), encoding="utf-8")
