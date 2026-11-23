"""CloudPreviewsMixin implementation."""

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


class CloudPreviewsMixin:
    def _generate_thumbnail(
        self, path: Path, file_id: str | None = None
    ) -> Path | None:
        """Generate thumbnail for file types that support preview."""
        if not path.exists():
            return None
        if not file_id:
            try:
                file_id = str(path.relative_to(cloud_runtime().STORAGE_ROOT))
            except ValueError:
                file_id = path.name
        file_id = self._normalize_file_id(file_id)
        thumb_path = self._thumbnail_path(file_id)
        mime, _ = mimetypes.guess_type(path.name)
        ext = path.suffix.lower()

        def sanitize(text: str) -> str:
            return "".join(ch if 32 <= ord(ch) < 127 else "?" for ch in text)

        def render_text_preview(lines: list[str], label: str) -> Path | None:
            try:
                img = Image.new("RGB", (320, 320), color=(245, 247, 250))
                draw = ImageDraw.Draw(img)
                font = ImageFont.load_default()
                draw.text((10, 8), sanitize(label), fill=(60, 60, 60), font=font)
                y = 24
                for line in lines:
                    safe_line = sanitize(line.strip())
                    if not safe_line:
                        continue
                    draw.text((10, y), safe_line[:64], fill=(40, 40, 40), font=font)
                    y += 14
                    if y > 300:
                        break
                img.save(thumb_path, "JPEG", quality=80)
                return thumb_path if thumb_path.exists() else None
            except Exception:
                return None

        def make_text_lines(text: str) -> list[str]:
            lines = [line.strip() for line in text.splitlines() if line.strip()]
            return lines[:12] if lines else ["(empty file)"]

        def extract_xml_text(names: list[str]) -> str:
            extracted: list[str] = []
            remaining = cloud_runtime().DOCX_PREVIEW_MAX_BYTES
            with zipfile.ZipFile(path) as zf:
                for name in names[:32]:
                    try:
                        info = zf.getinfo(name)
                    except KeyError:
                        continue
                    if info.file_size > remaining:
                        continue
                    with zf.open(info) as source:
                        raw_xml = source.read(min(remaining, info.file_size) + 1)
                    if len(raw_xml) > remaining:
                        break
                    remaining -= len(raw_xml)
                    xml = raw_xml.decode("utf-8", errors="ignore")
                    plain = re.sub(r"<[^>]+>", " ", xml)
                    plain = html.unescape(re.sub(r"\s+", " ", plain)).strip()
                    if plain:
                        extracted.append(plain)
                    if remaining <= 0:
                        break
            return "\n".join(extracted)

        def extract_binary_strings() -> str:
            with path.open("rb") as source:
                raw = source.read(cloud_runtime().DOCX_PREVIEW_MAX_BYTES)
            ascii_parts = [
                part.decode("latin-1", errors="ignore")
                for part in re.findall(rb"[ -~]{4,}", raw)
            ]
            utf16 = raw.decode("utf-16le", errors="ignore")
            unicode_parts = re.findall(r"[\w][\w\s.,:;!?()'\"/-]{3,}", utf16)
            return "\n".join((ascii_parts + unicode_parts)[:24])

        try:
            if mime and mime.startswith("image/"):
                # Image thumbnail
                with Image.open(path) as img:
                    img.thumbnail((320, 320))
                    img.convert("RGB").save(thumb_path, "JPEG", quality=80)
            elif mime and mime.startswith("video/"):
                # Video thumbnail using ffmpeg
                import subprocess

                try:
                    result = subprocess.run(
                        [
                            "ffmpeg",
                            "-y",
                            "-i",
                            str(path),
                            "-ss",
                            "00:00:01",  # 1 second into video
                            "-vframes",
                            "1",
                            "-vf",
                            "scale=320:-1",
                            str(thumb_path),
                        ],
                        capture_output=True,
                        timeout=30,
                    )
                    if result.returncode != 0:
                        return None
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    return None
            elif (mime and mime.startswith("text/")) or ext in {
                ".txt",
                ".log",
                ".md",
                ".csv",
                ".json",
                ".yaml",
                ".yml",
            }:
                with path.open("rb") as source:
                    raw = source.read(32768)
                text = raw.decode("utf-8", errors="replace")
                label = (ext.lstrip(".") or "TEXT").upper()
                return render_text_preview(make_text_lines(text), f"{label} PREVIEW")
            elif ext in {".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp"}:
                text = ""
                try:
                    with zipfile.ZipFile(path) as zf:
                        names = zf.namelist()
                    if ext == ".docx":
                        selected = ["word/document.xml"]
                    elif ext == ".xlsx":
                        selected = [
                            name
                            for name in names
                            if name == "xl/sharedStrings.xml"
                            or name.startswith("xl/worksheets/sheet")
                        ]
                    elif ext == ".pptx":
                        selected = [
                            name
                            for name in names
                            if name.startswith("ppt/slides/slide")
                            and name.endswith(".xml")
                        ]
                    else:
                        selected = ["content.xml"]
                    text = extract_xml_text(selected)
                except Exception:
                    text = ""
                return render_text_preview(
                    make_text_lines(text or "(no text)"),
                    f"{ext.lstrip('.').upper()} PREVIEW",
                )
            elif ext == ".rtf":
                try:
                    with path.open("rb") as source:
                        rtf = source.read(
                            cloud_runtime().DOCX_PREVIEW_MAX_BYTES
                        ).decode("latin-1", errors="ignore")
                    rtf = re.sub(r"\\'[0-9a-fA-F]{2}", " ", rtf)
                    text = re.sub(r"\\[a-zA-Z]+-?\d* ?|[{}]", " ", rtf)
                    text = re.sub(r"\s+", " ", text).strip()
                except Exception:
                    text = ""
                return render_text_preview(
                    make_text_lines(text or "(no text)"), "RTF PREVIEW"
                )
            elif ext in {".doc", ".xls", ".ppt"}:
                try:
                    text = extract_binary_strings()
                except Exception:
                    text = ""
                return render_text_preview(
                    make_text_lines(text or "(binary document)"),
                    f"{ext.lstrip('.').upper()} PREVIEW",
                )
        except Exception:
            return None
        return thumb_path if thumb_path.exists() else None

    def regenerate_all_thumbnails(self) -> dict:
        """Regenerate thumbnails for all files that don't have one."""
        generated = 0
        skipped = 0
        errors = 0

        for root, dirs, files in os.walk(cloud_runtime().STORAGE_ROOT):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith(".")]

            for fname in files:
                fpath = Path(root) / fname
                file_id = str(fpath.relative_to(cloud_runtime().STORAGE_ROOT))
                thumb_path = self._thumbnail_path(file_id)

                if thumb_path.exists():
                    skipped += 1
                    continue

                mime, _ = mimetypes.guess_type(fname)
                if self._should_thumbnail(mime, fname):
                    try:
                        self._generate_thumbnail(fpath, file_id)
                        if thumb_path.exists():
                            generated += 1
                        else:
                            errors += 1
                    except Exception:
                        errors += 1

        return {"generated": generated, "skipped": skipped, "errors": errors}

    def metadata(self, file_id: str) -> Metadata:
        target = self.resolve_file(file_id)
        if not target.exists():
            raise FileNotFoundError
        stat = target.stat()
        mime, _ = mimetypes.guess_type(target.name)
        width = height = None
        exif_data: dict[str, str] | None = None
        if mime and mime.startswith("image/"):
            try:
                img = Image.open(target)
                width, height = img.size
                raw_exif = img._getexif() or {}
                exif_data = {}
                for tag_id, value in raw_exif.items():
                    tag = ExifTags.TAGS.get(tag_id, str(tag_id))
                    exif_data[tag] = str(value)
            except Exception:
                pass
        return Metadata(
            name=target.name,
            path="/" + str(target.relative_to(cloud_runtime().STORAGE_ROOT)),
            size=stat.st_size,
            mime=mime,
            modified=datetime.fromtimestamp(stat.st_mtime),
            created=datetime.fromtimestamp(stat.st_ctime),
            width=width,
            height=height,
            exif=exif_data,
        )
