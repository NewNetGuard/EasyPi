"""CloudFilesMixin implementation."""

from __future__ import annotations

from typing import BinaryIO

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
    _max_photo_upload_bytes,
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
    require_picloud_capacity,
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


class CloudFilesMixin:
    def _normalize_file_id(self, file_id: str) -> str:
        normalized = file_id.lstrip("/").replace("\\", "/")
        parts: list[str] = []
        for part in normalized.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("Parent path segments are not allowed")
            parts.append(part)
        return "/".join(parts)

    def _safe_path(self, rel_path: str, allow_root: bool = True) -> Path:
        normalized = self._normalize_file_id(rel_path)
        candidate = (cloud_runtime().STORAGE_ROOT / normalized).resolve()
        root = cloud_runtime().STORAGE_ROOT.resolve()
        if candidate == root and not allow_root:
            raise ValueError("Invalid path")
        if candidate == root or root in candidate.parents:
            return candidate
        raise ValueError("Invalid path")

    def _is_protected_root_folder(self, target: Path) -> bool:
        try:
            relative = target.resolve().relative_to(
                cloud_runtime().STORAGE_ROOT.resolve()
            )
        except ValueError:
            return False
        return (
            len(relative.parts) == 1
            and relative.name in cloud_runtime().PROTECTED_ROOT_FOLDERS
        )

    def _thumbnail_key(self, file_id: str) -> str:
        normalized = self._normalize_file_id(file_id)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _thumbnail_path(self, file_id: str) -> Path:
        return cloud_runtime().THUMB_ROOT / f"{self._thumbnail_key(file_id)}.jpg"

    def _legacy_thumbnail_path(self, name: str) -> Path:
        return cloud_runtime().THUMB_ROOT / f"{name}.jpg"

    def _should_thumbnail(self, mime: str | None, name: str | None = None) -> bool:
        ext = Path(name).suffix.lower() if name else ""
        text_exts = {".txt", ".log", ".md", ".csv", ".json", ".yaml", ".yml"}
        doc_exts = {
            ".doc",
            ".docx",
            ".xls",
            ".xlsx",
            ".ppt",
            ".pptx",
            ".rtf",
            ".odt",
            ".ods",
            ".odp",
        }
        doc_mimes = {
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
        if mime:
            if mime.startswith("image/"):
                return True
            if mime.startswith("video/"):
                return shutil.which("ffmpeg") is not None
            if mime.startswith("text/"):
                return True
            if mime in doc_mimes:
                return True
        if ext in text_exts or ext in doc_exts:
            return True
        return False

    def _find_thumbnail_path(self, file_id: str, name: str) -> Path | None:
        primary = self._thumbnail_path(file_id)
        if primary.exists():
            return primary
        legacy = self._legacy_thumbnail_path(name)
        if legacy.exists():
            return legacy
        return None

    def list_files(
        self,
        path: str,
        category: FileCategory | None = None,
        favorite_only: bool = False,
        sort_by: str = "name",
        sort_order: str = "asc",
        offset: int = 0,
        limit: int = 100,
        search: str | None = None,
        restrict_to_path: bool = False,
    ) -> FileListResponse:
        try:
            base = self._safe_path(path, allow_root=True)
        except ValueError:
            if restrict_to_path:
                raise
            base = cloud_runtime().STORAGE_ROOT
        if not base.exists():
            if restrict_to_path:
                return FileListResponse(path="/" + path, items=[], total_count=0, has_more=False)
            base = cloud_runtime().STORAGE_ROOT
        if restrict_to_path:
            root = cloud_runtime().STORAGE_ROOT.resolve()
            if base == root or base != root / self._normalize_file_id(path):
                raise ValueError("A private folder is required")

        items: list[PiCloudFile] = []
        favorites = self._load_favorites()
        all_tags = self._load_tags()
        color_labels = self._load_color_labels()

        # Show virtual category folders when at root with category "all"
        if (
            base == cloud_runtime().STORAGE_ROOT
            and category == "all"
            and not search
            and not favorite_only
        ):
            # Count files by category
            category_counts = {
                "photos": 0,
                "videos": 0,
                "documents": 0,
                "audio": 0,
                "other": 0,
                "encrypted": 0,
            }

            for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
                if entry.is_dir() or entry.name.startswith("."):
                    continue
                # Skip hidden directories
                relative_parts = entry.relative_to(cloud_runtime().STORAGE_ROOT).parts
                if any(part.startswith(".") for part in relative_parts):
                    continue

                mime, _ = mimetypes.guess_type(entry.name)
                file_category = self._get_file_category(mime, entry.name)

                if file_category in category_counts:
                    category_counts[file_category] += 1

            # Create virtual category folders
            category_info = [
                ("Photos", "photos", "📷"),
                ("Videos", "videos", "🎥"),
                ("Documents", "documents", "📄"),
                ("Music", "audio", "🎵"),
                ("Files", "other", "📦"),
                ("Encrypted Files", "encrypted", "🔒"),
            ]

            now = utc_now()
            for name, cat_id, icon in category_info:
                count = category_counts.get(cat_id, 0)
                items.append(
                    PiCloudFile(
                        id=f"_category_{cat_id}",
                        name=f"{icon} {name}",
                        path=f"/_category_{cat_id}",
                        mime=None,
                        type="folder",
                        size=count,  # Use size field to store file count
                        modified=now,
                        created=now,
                        extension=None,
                        favorite=False,
                        color_label="none",
                        thumbnail=False,
                        category=None,
                    )
                )

            # Keep user-created folders visible in All Files. Managed folders
            # are represented by the virtual category cards above.
            managed_folders = {
                str(config["folder"]) for config in AUTO_SORT_FOLDERS.values()
            }
            managed_folders.update({"Telegram", "Taildrop"})
            for entry in cloud_runtime().STORAGE_ROOT.iterdir():
                if (
                    not entry.is_dir()
                    or entry.name.startswith(".")
                    or entry.name in managed_folders
                ):
                    continue

                stat = entry.stat()
                file_id = str(entry.relative_to(cloud_runtime().STORAGE_ROOT))
                items.append(
                    PiCloudFile(
                        id=file_id,
                        name=entry.name,
                        path="/" + file_id,
                        mime=None,
                        type="folder",
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        created=datetime.fromtimestamp(stat.st_ctime),
                        extension=None,
                        favorite=file_id in favorites,
                        tags=all_tags.get(self._normalize_file_id(file_id), []),
                        color_label=color_labels.get(file_id, "none"),
                        thumbnail=False,
                        category=None,
                    )
                )

        # Cloud category views are global unless the caller supplies a private scope.
        elif search or (category and category != "all"):
            search_root = base if restrict_to_path else cloud_runtime().STORAGE_ROOT
            storage_root = cloud_runtime().STORAGE_ROOT
            if restrict_to_path:
                storage_root = storage_root.resolve()
            for entry in search_root.rglob("*"):
                if restrict_to_path and (
                    entry.is_symlink() or not entry.is_file() or entry.resolve() != entry
                ):
                    continue
                if entry.is_dir() or entry.name.startswith("."):
                    continue
                # Skip hidden directories
                relative_parts = entry.relative_to(storage_root).parts
                if any(part.startswith(".") for part in relative_parts):
                    if restrict_to_path or ".encrypted" not in relative_parts:
                        continue

                # Search filter
                if search and search.lower() not in entry.name.lower():
                    continue

                mime, _ = mimetypes.guess_type(entry.name)
                file_category = self._get_file_category(mime, entry.name)

                # Category filter
                if category and category != "all" and file_category != category:
                    continue

                file_id = str(entry.relative_to(storage_root))
                is_favorite = file_id in favorites

                if favorite_only and not is_favorite:
                    continue

                stat = entry.stat()
                thumbnail_ready = file_category != "other" and (
                    self._should_thumbnail(mime, entry.name)
                    or (
                        not restrict_to_path
                        and self._find_thumbnail_path(file_id, entry.name) is not None
                    )
                )
                items.append(
                    PiCloudFile(
                        id=file_id,
                        name=entry.name,
                        path="/" + file_id,
                        mime=mime,
                        type="file",
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        created=datetime.fromtimestamp(stat.st_ctime),
                        extension=entry.suffix.lower(),
                        favorite=is_favorite,
                        tags=all_tags.get(self._normalize_file_id(file_id), []),
                        color_label=color_labels.get(file_id, "none"),
                        thumbnail=thumbnail_ready,
                        category=file_category,
                    )
                )
        else:
            # Normal directory listing
            for entry in base.iterdir():
                if entry.name.startswith(".") or (
                    base == cloud_runtime().STORAGE_ROOT and entry.name == "Telegram"
                ):
                    continue
                stat = entry.stat()
                mime, _ = mimetypes.guess_type(entry.name)
                file_id = str(entry.relative_to(cloud_runtime().STORAGE_ROOT))
                file_category = (
                    self._get_file_category(mime, entry.name)
                    if entry.is_file()
                    else None
                )

                # Favorite filter
                is_favorite = file_id in favorites
                if favorite_only and not is_favorite:
                    continue
                thumbnail_ready = (
                    entry.is_file()
                    and file_category != "other"
                    and (
                        self._should_thumbnail(mime, entry.name)
                        or self._find_thumbnail_path(file_id, entry.name) is not None
                    )
                )
                items.append(
                    PiCloudFile(
                        id=file_id,
                        name=entry.name,
                        path="/" + file_id,
                        mime=mime,
                        type="folder" if entry.is_dir() else "file",
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        created=datetime.fromtimestamp(stat.st_ctime),
                        extension=entry.suffix.lower() if entry.is_file() else None,
                        favorite=is_favorite,
                        tags=all_tags.get(self._normalize_file_id(file_id), []),
                        color_label=color_labels.get(file_id, "none"),
                        thumbnail=thumbnail_ready,
                        category=file_category,
                    )
                )

        # Sorting
        reverse = sort_order == "desc"
        if sort_by == "name":
            items.sort(key=lambda x: x.name.lower(), reverse=reverse)
        elif sort_by == "size":
            items.sort(key=lambda x: x.size, reverse=reverse)
        elif sort_by == "modified":
            items.sort(key=lambda x: x.modified, reverse=reverse)
        elif sort_by == "type":
            items.sort(key=lambda x: (x.type, x.name.lower()), reverse=reverse)

        # Keep folders visible before files, even across pages.
        items.sort(key=lambda item: item.type != "folder")

        total_count = len(items)
        items = items[offset : offset + limit]
        has_more = offset + limit < total_count

        storage_root = cloud_runtime().STORAGE_ROOT
        if restrict_to_path:
            storage_root = storage_root.resolve()
        return FileListResponse(
            path="/" + str(base.relative_to(storage_root)),
            items=items,
            total_count=total_count,
            has_more=has_more,
        )

    @staticmethod
    def _find_identical_upload(directory: Path, file: UploadFile, size: int) -> Path | None:
        digest = None
        for candidate in directory.iterdir():
            if candidate.name.startswith(".") or candidate.is_symlink() or not candidate.is_file():
                continue
            try:
                if candidate.stat().st_size != size:
                    continue
                if digest is None:
                    file.file.seek(0)
                    try:
                        digest = hashlib.file_digest(file.file, "sha256").digest()
                    finally:
                        file.file.seek(0)
                with candidate.open("rb") as existing:
                    if hashlib.file_digest(existing, "sha256").digest() == digest:
                        return candidate
            except FileNotFoundError:
                continue
        return None

    async def upload_files(
        self,
        files: list[UploadFile],
        target: str,
        auto_sort: bool = True,
        *,
        require_target: bool = False,
        deduplicate: bool = False,
        generate_preview: bool = True,
        source_modified: float | None = None,
    ) -> UploadResponse:
        """Upload files with optional auto-sorting by type.

        If auto_sort is True and target is root ("/"), files are automatically
        sorted into folders: Photos, Videos, Documents, Music, and Encrypted.
        APKs, archives, and unrecognized formats remain in the requested folder.
        """
        uploaded: list[PiCloudFile] = []

        for file in files:
            mime, _ = mimetypes.guess_type(file.filename)

            # Determine destination folder
            if auto_sort and (target == "/" or target == ""):
                # Auto-sort to appropriate folder
                auto_folder = _get_auto_sort_folder(file.filename, mime)
                if auto_folder:
                    dest_dir = self._safe_path(auto_folder, allow_root=True)
                else:
                    dest_dir = cloud_runtime().STORAGE_ROOT  # Root for unknown types
            else:
                # Use specified target path
                try:
                    dest_dir = self._safe_path(target, allow_root=True)
                except ValueError:
                    if require_target:
                        raise HTTPException(status_code=409, detail="Phone folder unavailable") from None
                    dest_dir = cloud_runtime().STORAGE_ROOT

            if require_target:
                root = cloud_runtime().STORAGE_ROOT.resolve()
                if dest_dir == root or dest_dir != root / self._normalize_file_id(target):
                    raise HTTPException(status_code=409, detail="Phone folder unavailable")
            dest_dir.mkdir(parents=True, exist_ok=True)
            is_photo = bool(mime and mime.startswith("image/"))
            max_bytes = _max_photo_upload_bytes() if is_photo else _max_upload_bytes()
            limit_label = "250 MiB photo limit" if is_photo else "4 GiB file limit"
            declared_size = getattr(file, "size", None)
            if declared_size is not None and int(declared_size) > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded file exceeds the {limit_label}",
                )
            dest_path = None
            if deduplicate and declared_size is not None:
                dest_path = await asyncio.to_thread(
                    self._find_identical_upload, dest_dir, file, int(declared_size)
                )
            if dest_path is None:
                dest_path = unique_upload_path(dest_dir, file.filename)
                total = 0
                created = False
                try:
                    require_picloud_capacity(dest_dir, int(declared_size or 0))
                    with dest_path.open("xb") as output:
                        created = True
                        while chunk := await file.read(cloud_runtime().UPLOAD_CHUNK_BYTES):
                            total += len(chunk)
                            if total > max_bytes:
                                raise HTTPException(
                                    status_code=413,
                                    detail=f"Uploaded file exceeds the {limit_label}",
                                )
                            require_picloud_capacity(dest_dir, len(chunk))
                            output.write(chunk)
                    if source_modified is not None:
                        os.utime(dest_path, (dest_path.stat().st_atime, source_modified))
                except BaseException:
                    if created:
                        try:
                            dest_path.unlink()
                        except OSError:
                            pass
                    raise
                if is_photo and generate_preview:
                    self._generate_thumbnail(
                        dest_path, str(dest_path.relative_to(cloud_runtime().STORAGE_ROOT))
                    )
            stat = dest_path.stat()

            uploaded.append(
                PiCloudFile(
                    id=str(dest_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                    name=dest_path.name,
                    path="/" + str(dest_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                    mime=mime,
                    type="file",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime),
                    extension=dest_path.suffix.lower(),
                    category=self._get_file_category(mime, dest_path.name),
                )
            )

        return UploadResponse(uploaded=uploaded)

    def delete_file(self, file_id: str) -> None:
        try:
            target = self._safe_path(file_id, allow_root=False)
        except ValueError:
            return
        if not target.exists():
            return
        if target.is_dir() and self._is_protected_root_folder(target):
            raise HTTPException(
                status_code=403, detail="System Cloud folders cannot be deleted"
            )

        # Remember parent directory
        parent_dir = target.parent

        trash_id = uuid.uuid4().hex
        trash_dest = cloud_runtime().TRASH_ROOT / trash_id
        trash_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(target), trash_dest)
        trash_meta = self._load_trash()
        trash_meta[trash_id] = {
            "original": str(target.relative_to(cloud_runtime().STORAGE_ROOT)),
            "deleted_at": utc_now().isoformat(),
        }
        cloud_runtime().TRASH_META.write_text(json.dumps(trash_meta), encoding="utf-8")

        # Remove parent directory if it's empty (and not the storage root)
        if (
            parent_dir != cloud_runtime().STORAGE_ROOT
            and parent_dir.exists()
            and not self._is_protected_root_folder(parent_dir)
        ):
            try:
                # Check if directory is empty (ignoring hidden files)
                visible_items = [
                    item
                    for item in parent_dir.iterdir()
                    if not item.name.startswith(".")
                ]
                if not visible_items:
                    parent_dir.rmdir()
            except (OSError, ValueError):
                pass  # Directory not empty or other error, ignore

    def delete_file_permanently(self, file_id: str) -> None:
        """Permanently remove one regular file after an explicit caller request.

        This deliberately refuses directories. It is used by the encryption
        workflow only after the uploaded ciphertext has been read back and
        verified, so an unencrypted source is not retained in Trash.
        """
        path_parts = file_id.replace("\\", "/").split("/")
        if any(part == ".." for part in path_parts):
            raise HTTPException(status_code=400, detail="Invalid file path")
        try:
            target = self._safe_path(file_id, allow_root=False)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid file path") from exc
        if not target.exists():
            raise HTTPException(status_code=404, detail="File not found")
        if not target.is_file():
            raise HTTPException(
                status_code=400, detail="Permanent deletion is limited to files"
            )

        normalized_id = str(target.relative_to(cloud_runtime().STORAGE_ROOT)).replace(
            "\\", "/"
        )

        # Remove cached clear-text previews before removing the source itself.
        for thumbnail in (
            self._thumbnail_path(normalized_id),
            self._legacy_thumbnail_path(target.name),
        ):
            if thumbnail.exists() and thumbnail.is_file():
                thumbnail.unlink()

        # Remove stale metadata that could retain the original path or filename.
        if cloud_runtime().FAV_FILE.exists():
            favorites = [
                item
                for item in self._load_favorites()
                if self._normalize_file_id(item) != normalized_id
            ]
            cloud_runtime().FAV_FILE.write_text("\n".join(favorites), encoding="utf-8")
        if cloud_runtime().TAG_FILE.exists():
            tags = self._load_tags()
            tags = {
                key: value
                for key, value in tags.items()
                if self._normalize_file_id(key) != normalized_id
            }
            cloud_runtime().TAG_FILE.write_text(json.dumps(tags), encoding="utf-8")
        if cloud_runtime().COLOR_LABELS_FILE.exists():
            colors = self._load_color_labels()
            colors = {
                key: value
                for key, value in colors.items()
                if self._normalize_file_id(key) != normalized_id
            }
            self._save_color_labels(colors)
        with self._share_lock:
            if cloud_runtime().SHARES_DB_FILE.exists():
                shares = self._load_shares_db()
                shares = {
                    share_id: share
                    for share_id, share in shares.items()
                    if self._normalize_file_id(share.file_id) != normalized_id
                }
                self._save_shares_db(shares)
            if hasattr(self, "share_tokens"):
                self.share_tokens = {
                    token: info
                    for token, info in self.share_tokens.items()
                    if self._normalize_file_id(str(info.get("file_id", "")))
                    != normalized_id
                }
                self._persist_shares()
        if cloud_runtime().ACTIVITY_FILE.exists():
            activities = [
                activity
                for activity in self._load_activity()
                if self._normalize_file_id(activity.file_id or "") != normalized_id
            ]
            self._save_activity(activities)

        parent_dir = target.parent
        target.unlink()
        if (
            parent_dir != cloud_runtime().STORAGE_ROOT
            and parent_dir.exists()
            and not self._is_protected_root_folder(parent_dir)
        ):
            try:
                visible_items = [
                    item
                    for item in parent_dir.iterdir()
                    if not item.name.startswith(".")
                ]
                if not visible_items:
                    parent_dir.rmdir()
            except (OSError, ValueError):
                pass

    def create_folder(self, path: str, *, exist_ok: bool = True) -> PiCloudFile:
        try:
            folder = self._safe_path(path, allow_root=False)
        except ValueError:
            raise ValueError("Invalid folder path")
        folder.mkdir(parents=True, exist_ok=exist_ok)
        stat = folder.stat()
        return PiCloudFile(
            id=str(folder.relative_to(cloud_runtime().STORAGE_ROOT)),
            name=folder.name,
            path="/" + str(folder.relative_to(cloud_runtime().STORAGE_ROOT)),
            mime=None,
            type="folder",
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime),
        )

    def rename_or_move(self, file_id: str, new_path: str) -> PiCloudFile:
        src = self._safe_path(file_id, allow_root=False)
        dst = self._safe_path(new_path, allow_root=False)
        if not src.exists():
            raise FileNotFoundError(file_id)
        if self._is_protected_root_folder(src):
            raise ValueError("System folders cannot be moved or renamed")
        if src == dst:
            raise ValueError("Source and destination paths are identical")
        if src.is_dir() and src in dst.parents:
            raise ValueError("A folder cannot be moved into itself")
        if dst.exists():
            raise FileExistsError(new_path)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        stat = dst.stat()
        mime, _ = mimetypes.guess_type(dst.name)
        relative_id = dst.relative_to(cloud_runtime().STORAGE_ROOT).as_posix()
        return PiCloudFile(
            id=relative_id,
            name=dst.name,
            path="/" + relative_id,
            mime=mime,
            type="folder" if dst.is_dir() else "file",
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime),
            extension=dst.suffix.lower() if dst.is_file() else None,
        )

    def copy_file(self, file_id: str, new_path: str) -> PiCloudFile:
        src = self._safe_path(file_id, allow_root=False)
        dst = self._safe_path(new_path, allow_root=False)
        if not src.exists():
            raise FileNotFoundError(file_id)
        if src == dst:
            raise ValueError("Source and destination paths are identical")
        if src.is_dir() and src in dst.parents:
            raise ValueError("A folder cannot be copied into itself")
        if dst.exists():
            raise FileExistsError(new_path)
        copy_size = (
            sum(
                item.stat().st_size
                for item in src.rglob("*")
                if item.is_file()
            )
            if src.is_dir()
            else src.stat().st_size
        )
        require_picloud_capacity(dst.parent, copy_size)
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            if src.is_dir():
                shutil.copytree(src, dst, copy_function=self._copy_with_capacity)
            else:
                self._copy_with_capacity(src, dst)
        except Exception:
            if dst.is_dir() and not dst.is_symlink():
                shutil.rmtree(dst)
            else:
                dst.unlink(missing_ok=True)
            raise
        stat = dst.stat()
        mime, _ = mimetypes.guess_type(dst.name)
        relative_id = dst.relative_to(cloud_runtime().STORAGE_ROOT).as_posix()
        return PiCloudFile(
            id=relative_id,
            name=dst.name,
            path="/" + relative_id,
            mime=mime,
            type="folder" if dst.is_dir() else "file",
            size=stat.st_size,
            modified=datetime.fromtimestamp(stat.st_mtime),
            extension=dst.suffix.lower() if dst.is_file() else None,
        )

    @staticmethod
    def _copy_with_capacity(source_path, destination_path):
        source = Path(source_path)
        destination = Path(destination_path)
        with source.open("rb") as source_file, destination.open("xb") as target_file:
            while chunk := source_file.read(UPLOAD_CHUNK_BYTES):
                require_picloud_capacity(destination.parent, len(chunk))
                target_file.write(chunk)
        shutil.copystat(source, destination)
        return str(destination)

    def search(
        self,
        query: str,
        category: FileCategory | None = None,
        tags: list[str] | None = None,
        favorite_only: bool = False,
        sort_by: str = "name",
        sort_order: str = "asc",
        offset: int = 0,
        limit: int = 100,
    ) -> list[PiCloudFile]:
        results: list[PiCloudFile] = []
        favorites = self._load_favorites()
        all_tags = self._load_tags()
        color_labels = self._load_color_labels()

        for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
            if entry.is_dir() or entry.name.startswith("."):
                continue

            file_id = str(entry.relative_to(cloud_runtime().STORAGE_ROOT))

            # Search filter
            if query.lower() not in entry.name.lower():
                continue

            # Category filter
            mime, _ = mimetypes.guess_type(entry.name)
            if category and category != "all":
                if self._get_file_category(mime, entry.name) != category:
                    continue

            # Tags filter
            if tags:
                file_tags = all_tags.get(self._normalize_file_id(file_id), [])
                if not any(t in file_tags for t in tags):
                    continue

            # Favorite filter
            is_favorite = file_id in favorites
            if favorite_only and not is_favorite:
                continue

            stat = entry.stat()
            results.append(
                PiCloudFile(
                    id=file_id,
                    name=entry.name,
                    path="/" + file_id,
                    mime=mime,
                    type="file",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime),
                    created=datetime.fromtimestamp(stat.st_ctime),
                    extension=entry.suffix.lower(),
                    favorite=is_favorite,
                    tags=all_tags.get(self._normalize_file_id(file_id), []),
                    color_label=color_labels.get(file_id, "none"),
                    category=self._get_file_category(mime, entry.name),
                )
            )

        # Sorting
        reverse = sort_order == "desc"
        if sort_by == "name":
            results.sort(key=lambda x: x.name.lower(), reverse=reverse)
        elif sort_by == "size":
            results.sort(key=lambda x: x.size, reverse=reverse)
        elif sort_by == "modified":
            results.sort(key=lambda x: x.modified, reverse=reverse)

        return results[offset : offset + limit]

    def storage_stats(self) -> StorageStats:
        st = os.statvfs(cloud_runtime().STORAGE_ROOT)
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bavail
        used = total - free
        percent = round((used / total) * 100, 2) if total else 0.0

        # Count files and folders
        file_count = 0
        folder_count = 0
        for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
            # Skip hidden directories (.trash, .meta, .thumbnails, etc)
            relative_parts = entry.relative_to(cloud_runtime().STORAGE_ROOT).parts
            if any(part.startswith(".") for part in relative_parts):
                continue

            if entry.is_dir():
                folder_count += 1
            else:
                file_count += 1

        return StorageStats(
            total=total,
            used=used,
            free=free,
            percent=percent,
            file_count=file_count,
            folder_count=folder_count,
        )

    def usage_by_type(self) -> UsageByType:
        totals = {"photos": 0, "videos": 0, "documents": 0, "audio": 0, "other": 0}
        for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
            if entry.is_dir():
                continue
            mime, _ = mimetypes.guess_type(entry.name)
            size = entry.stat().st_size
            if mime and mime.startswith("image/"):
                totals["photos"] += size
            elif mime and mime.startswith("video/"):
                totals["videos"] += size
            elif mime and mime.startswith("audio/"):
                totals["audio"] += size
            elif mime and mime in (
                "application/pdf",
                "application/msword",
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ):
                totals["documents"] += size
            else:
                totals["other"] += size
        return UsageByType(**totals)

    def recent_files(self, limit: int = 20) -> list[PiCloudFile]:
        items = []
        favorites = self._load_favorites()
        for entry in cloud_runtime().STORAGE_ROOT.rglob("*"):
            if entry.is_dir():
                continue
            stat = entry.stat()
            items.append(
                PiCloudFile(
                    id=str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                    name=entry.name,
                    path="/" + str(entry.relative_to(cloud_runtime().STORAGE_ROOT)),
                    mime=mimetypes.guess_type(entry.name)[0],
                    type="file",
                    size=stat.st_size,
                    modified=datetime.fromtimestamp(stat.st_mtime),
                    extension=entry.suffix.lower(),
                    favorite=str(entry.relative_to(cloud_runtime().STORAGE_ROOT))
                    in favorites,
                )
            )
        items.sort(key=lambda f: f.modified, reverse=True)
        return items[:limit]

    def favorites(self) -> list[PiCloudFile]:
        favs = self._load_favorites()
        files: list[PiCloudFile] = []
        for fav in favs:
            path = cloud_runtime().STORAGE_ROOT / fav
            if path.exists():
                stat = path.stat()
                mime, _ = mimetypes.guess_type(path.name)
                files.append(
                    PiCloudFile(
                        id=fav,
                        name=path.name,
                        path="/" + fav,
                        mime=mime,
                        type="folder" if path.is_dir() else "file",
                        size=stat.st_size,
                        modified=datetime.fromtimestamp(stat.st_mtime),
                        extension=path.suffix.lower() if path.is_file() else None,
                        favorite=True,
                    )
                )
        return files

    def toggle_favorite(self, file_id: str, value: bool) -> None:
        favs = self._load_favorites()
        if value and file_id not in favs:
            favs.append(file_id)
        elif not value and file_id in favs:
            favs.remove(file_id)
        cloud_runtime().FAV_FILE.write_text("\n".join(favs), encoding="utf-8")

    def create_share(
        self, file_id: str, hours: int | None = None, password: str | None = None
    ) -> ShareLink:
        file_id = self._normalize_file_id(file_id)
        target = self._safe_path(file_id, allow_root=False)
        if not target.is_file():
            raise FileNotFoundError(file_id)
        if password and (len(password) < 8 or len(password.encode("utf-8")) > 72):
            raise ValueError("Share password must be 8-72 bytes")
        token = uuid.uuid4().hex
        expires = utc_now() + timedelta(hours=hours) if hours else None
        password_hash = get_password_hash(password) if password else None
        token_info = {
            "file_id": file_id,
            "expires": expires,
            "password_hash": password_hash,
            "file_identity": self._share_file_identity(target),
        }
        file_name = Path(file_id).name
        share = ShareLink(
            id=token,
            url=f"/api/v1/picloud/share/{token}",
            file_id=file_id,
            file_name=file_name,
            expires_at=expires,
            password=None,
            access_count=0,
            max_access=None,
            qr_base64=None,
            embed_code=None,
            created_at=utc_now(),
        )
        with self._share_lock:
            self.share_tokens[token] = token_info
            shares = self._load_shares_db()
            shares[token] = share
            try:
                self._persist_shares()
                self._save_shares_db(shares)
            except Exception:
                self.share_tokens.pop(token, None)
                self._persist_shares()
                raise
        return share

    def resolve_share(self, token: str, password: str | None = None) -> Path | None:
        opened = self.open_share(token, password)
        if opened is None:
            return None
        file_handle, target, _size = opened
        file_handle.close()
        return target

    def open_share(
        self, token: str, password: str | None = None
    ) -> tuple[BinaryIO, Path, int] | None:
        """Open and validate the exact shared inode before releasing it."""
        with self._share_lock:
            info = self.share_tokens.get(token)
            if not info:
                return None
            expires = info.get("expires")
            if expires and utc_now() > expires:
                self.delete_share(token)
                return None
            if info.get("password_hash"):
                if not password or len(password.encode("utf-8")) > 72:
                    return None
                try:
                    password_valid = verify_password(
                        password, str(info["password_hash"])
                    )
                except (TypeError, ValueError):
                    password_valid = False
                if not password_valid:
                    return None
            try:
                target = self._safe_path(str(info["file_id"]), allow_root=False)
                descriptor = os.open(
                    target,
                    os.O_RDONLY | getattr(os, "O_BINARY", 0),
                )
            except (OSError, ValueError):
                return None
            file_handle = os.fdopen(descriptor, "rb")
            actual_identity = self._share_stat_identity(os.fstat(descriptor))
            expected_identity = info.get("file_identity")
            if (
                not isinstance(expected_identity, dict)
                or actual_identity != expected_identity
            ):
                file_handle.close()
                self.delete_share(token)
                return None
            return file_handle, target, actual_identity["size"]

    @staticmethod
    def _share_file_identity(path: Path) -> dict[str, int]:
        return CloudFilesMixin._share_stat_identity(path.stat())

    @staticmethod
    def _share_stat_identity(stat) -> dict[str, int]:
        identity = {
            "device": int(stat.st_dev),
            "inode": int(stat.st_ino),
            "size": int(stat.st_size),
            "mtime_ns": int(stat.st_mtime_ns),
        }
        birthtime_ns = getattr(stat, "st_birthtime_ns", None)
        if birthtime_ns is not None:
            identity["birthtime_ns"] = int(birthtime_ns)
        elif os.name == "posix":
            identity["ctime_ns"] = int(stat.st_ctime_ns)
        return identity

    def list_trash(self) -> list[dict[str, str]]:
        meta = self._load_trash()
        items = []
        for trash_id, info in meta.items():
            items.append({"id": trash_id, **info})
        return items

    def restore_trash(self, trash_id: str):
        meta = self._load_trash()
        if trash_id not in meta:
            return
        try:
            original = self._safe_path(meta[trash_id]["original"], allow_root=False)
        except ValueError:
            return
        trash_path = cloud_runtime().TRASH_ROOT / trash_id
        original.parent.mkdir(parents=True, exist_ok=True)
        if trash_path.exists():
            shutil.move(str(trash_path), original)
        meta.pop(trash_id, None)
        cloud_runtime().TRASH_META.write_text(json.dumps(meta), encoding="utf-8")

    def empty_trash(self):
        shutil.rmtree(cloud_runtime().TRASH_ROOT, ignore_errors=True)
        cloud_runtime().TRASH_ROOT.mkdir(parents=True, exist_ok=True)
        cloud_runtime().TRASH_META.write_text("{}", encoding="utf-8")

    def set_tags(self, file_id: str, tags: list[str]) -> list[str]:
        normalized_id = self._normalize_file_id(file_id)
        target = self._safe_path(normalized_id, allow_root=False)
        if not target.exists() or target.name.startswith("."):
            raise FileNotFoundError("Cloud file not found")
        normalized_tags = normalize_cloud_tags(tags)
        with self._tag_lock:
            data = self._load_tags()
            if normalized_tags:
                data[normalized_id] = normalized_tags
            else:
                data.pop(normalized_id, None)
            save_cloud_tag_map(cloud_runtime().TAG_FILE, data)
        return normalized_tags

    def get_tags(self, file_id: str) -> list[str]:
        normalized_id = self._normalize_file_id(file_id)
        target = self._safe_path(normalized_id, allow_root=False)
        if not target.exists() or target.name.startswith("."):
            raise FileNotFoundError("Cloud file not found")
        return self._load_tags().get(normalized_id, [])

    def _load_favorites(self) -> list[str]:
        if not cloud_runtime().FAV_FILE.exists():
            return []
        return [
            line.strip()
            for line in cloud_runtime()
            .FAV_FILE.read_text(encoding="utf-8")
            .splitlines()
            if line.strip()
        ]

    def _load_tags(self) -> dict[str, list[str]]:
        return load_cloud_tag_map(cloud_runtime().TAG_FILE)

    def resolve_file(self, file_id: str) -> Path:
        try:
            return self._safe_path(file_id, allow_root=False)
        except ValueError:
            raise FileNotFoundError

    def _load_shares(self) -> dict[str, dict[str, object]]:
        if not cloud_runtime().SHARE_FILE.exists():
            return {}
        try:
            raw = json.loads(cloud_runtime().SHARE_FILE.read_text(encoding="utf-8"))
            fixed: dict[str, dict[str, object]] = {}
            migrated = False
            for token, info in raw.items():
                file_identity = info.get("file_identity")
                if not isinstance(file_identity, dict):
                    migrated = True
                    continue
                expires = info.get("expires")
                password_hash = info.get("password_hash")
                if not password_hash and info.get("password"):
                    password_hash = get_password_hash(str(info["password"]))
                    migrated = True
                fixed[token] = {
                    "file_id": info.get("file_id"),
                    "expires": datetime.fromisoformat(expires) if expires else None,
                    "password_hash": password_hash,
                    "file_identity": file_identity,
                }
            if migrated:
                serializable = {
                    token: {
                        "file_id": info.get("file_id"),
                        "expires": (
                            info["expires"].isoformat()
                            if isinstance(info.get("expires"), datetime)
                            else None
                        ),
                        "password_hash": info.get("password_hash"),
                        "file_identity": info.get("file_identity"),
                    }
                    for token, info in fixed.items()
                }
                cloud_runtime().SHARE_FILE.write_text(
                    json.dumps(serializable), encoding="utf-8"
                )
            return fixed
        except json.JSONDecodeError:
            return {}

    def _persist_shares(self):
        with self._share_lock:
            serializable = {}
            for token, info in self.share_tokens.items():
                expires = info.get("expires")
                serializable[token] = {
                    "file_id": info.get("file_id"),
                    "expires": expires.isoformat()
                    if isinstance(expires, datetime)
                    else None,
                    "password_hash": info.get("password_hash"),
                    "file_identity": info.get("file_identity"),
                }
            destination = cloud_runtime().SHARE_FILE
            temporary = destination.with_name(
                f".{destination.name}.{uuid.uuid4().hex}.tmp"
            )
            try:
                temporary.write_text(json.dumps(serializable), encoding="utf-8")
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)

    def _load_trash(self) -> dict[str, dict[str, str]]:
        if not cloud_runtime().TRASH_META.exists():
            return {}
        try:
            return json.loads(cloud_runtime().TRASH_META.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
