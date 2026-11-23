"""CloudTelegramMixin implementation."""

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
    PiCloudCapacityError,
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


class CloudTelegramMixin:
    def _telegram_upload_directory(
        self, filename: str, mime: str | None = None
    ) -> Path:
        """Use the same PiCloud type folders regardless of upload transport."""
        detected_mime = mime or mimetypes.guess_type(filename)[0]
        folder = _get_auto_sort_folder(filename, detected_mime) or "Files"
        target_dir = self._safe_path(folder, allow_root=True)
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _telegram_user_is_authorized(self, user_id: int | None) -> bool:
        """Read current access state so revocation does not require a bot restart."""
        if user_id is None:
            return False
        config, error = self._load_telegram_config_data()
        if error or config is None:
            return False
        return user_id in self._coerce_int_list(config.get("allowed_user_ids"))

    async def _download_telegram_file(
        self, telegram_file, target_path: Path, declared_size: int | None
    ) -> Path:
        """Download one Telegram file without consuming the system disk reserve."""
        require_picloud_capacity(target_path.parent, declared_size or 0)
        temporary = target_path.parent / f".tg-{uuid.uuid4().hex}.part"
        try:
            payload = await telegram_file.download_as_bytearray()
            require_picloud_capacity(target_path.parent, len(payload))
            with temporary.open("xb") as output:
                view = memoryview(payload)
                for offset in range(0, len(view), UPLOAD_CHUNK_BYTES):
                    chunk = view[offset : offset + UPLOAD_CHUNK_BYTES]
                    require_picloud_capacity(target_path.parent, len(chunk))
                    output.write(chunk)
                    require_picloud_capacity(target_path.parent)
            require_picloud_capacity(target_path.parent)
            return self._publish_telegram_file(temporary, target_path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _publish_telegram_file(temporary: Path, requested_path: Path) -> Path:
        """Atomically publish without replacing a file created during download."""
        candidate = requested_path
        while True:
            try:
                os.link(temporary, candidate)
            except FileExistsError:
                candidate = unique_upload_path(
                    requested_path.parent, requested_path.name
                )
                continue
            temporary.unlink()
            return candidate

    def _load_telegram_config_data(self) -> tuple[dict | None, str | None]:
        if not cloud_runtime().TELEGRAM_CONFIG_FILE.exists():
            return None, "Bot not configured"
        try:
            data = json.loads(
                cloud_runtime().TELEGRAM_CONFIG_FILE.read_text(encoding="utf-8")
            )
        except PermissionError:
            message = (
                f"Telegram config not readable: {cloud_runtime().TELEGRAM_CONFIG_FILE}"
            )
            logging.error(message)
            self._telegram_fs_error = message
            return None, message
        except OSError as exc:
            message = f"Telegram config read failed: {exc}"
            logging.error(message)
            self._telegram_fs_error = message
            return None, message
        except json.JSONDecodeError:
            logging.error("Telegram config JSON is invalid.")
            return None, "Bot configuration is invalid"
        if not isinstance(data, dict):
            logging.error("Telegram config has invalid structure.")
            return None, "Bot configuration is invalid"
        return data, None

    @staticmethod
    def _parse_iso_datetime(value: str | None) -> datetime | None:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_int_list(value: object) -> list[int]:
        if not isinstance(value, list):
            return []
        result: list[int] = []
        for item in value:
            try:
                result.append(int(item))
            except (TypeError, ValueError):
                continue
        return result

    @staticmethod
    def _coerce_int(value: object, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _update_telegram_state_cache(self, state: dict) -> None:
        self._telegram_state_cache = dict(state)

    def _write_telegram_json(self, path: Path, data: dict | list, context: str) -> bool:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
            if self._telegram_fs_error:
                self._telegram_fs_error = None
            if path == cloud_runtime().TELEGRAM_STATE_FILE:
                self._update_telegram_state_cache(
                    data if isinstance(data, dict) else {}
                )
            return True
        except PermissionError:
            message = f"{context} not writable: {path}"
            logging.error(message)
            self._telegram_fs_error = message
            if path == cloud_runtime().TELEGRAM_STATE_FILE and isinstance(data, dict):
                self._update_telegram_state_cache(data)
            return False
        except OSError as exc:
            message = f"{context} write failed: {exc}"
            logging.error(message)
            self._telegram_fs_error = message
            if path == cloud_runtime().TELEGRAM_STATE_FILE and isinstance(data, dict):
                self._update_telegram_state_cache(data)
            return False

    def get_telegram_config(self) -> TelegramBotConfig:
        """Get current Telegram bot configuration."""
        if not cloud_runtime().TELEGRAM_CONFIG_FILE.exists():
            return TelegramBotConfig(
                token="",
                allowed_user_ids=[],
                auto_organize=True,
                notify_on_upload=True,
                max_file_size=50 * 1024 * 1024,
                upload_folder="/",
            )

        try:
            config = json.loads(
                cloud_runtime().TELEGRAM_CONFIG_FILE.read_text(encoding="utf-8")
            )
            return TelegramBotConfig(
                token=config.get("token", ""),
                allowed_user_ids=config.get("allowed_user_ids", []),
                auto_organize=config.get("auto_organize", True),
                notify_on_upload=config.get("notify_on_upload", True),
                max_file_size=config.get("max_file_size", 50 * 1024 * 1024),
                upload_folder="/",
            )
        except Exception:
            return TelegramBotConfig(
                token="",
                allowed_user_ids=[],
                auto_organize=True,
                notify_on_upload=True,
                max_file_size=50 * 1024 * 1024,
                upload_folder="/",
            )

    def configure_telegram_bot(self, config: TelegramBotConfig) -> TelegramBotStatus:
        config_data = {
            "token": config.token,
            "allowed_user_ids": config.allowed_user_ids,
            "auto_organize": True,
            "notify_on_upload": config.notify_on_upload,
            "max_file_size": config.max_file_size,
            "upload_folder": "/",
        }
        if not self._write_telegram_json(
            cloud_runtime().TELEGRAM_CONFIG_FILE, config_data, "Telegram config"
        ):
            return TelegramBotStatus(
                enabled=False,
                configured=False,
                connected=False,
                message=self._telegram_fs_error or "Configuration save failed",
                authorized_users=[],
            )

        return TelegramBotStatus(
            enabled=True,
            configured=True,
            connected=False,
            message="Configuration saved",
            authorized_users=[],
        )

    def get_telegram_status(self) -> TelegramBotStatus:
        config, error = self._load_telegram_config_data()
        if error:
            return TelegramBotStatus(
                enabled=False,
                configured=False,
                message=error,
            )

        bot_state = self._sync_telegram_state(self._load_telegram_state())
        uploads = [u for u in self._load_telegram_uploads() if isinstance(u, dict)]
        allowed_ids = self._coerce_int_list(config.get("allowed_user_ids"))

        user_stats: dict[int, dict[str, object]] = {}
        for upload in uploads:
            try:
                user_id = int(upload.get("telegram_user_id"))
            except (TypeError, ValueError):
                continue
            uploaded_at = self._parse_iso_datetime(upload.get("uploaded_at"))
            if not uploaded_at:
                continue
            if user_id not in user_stats:
                user_stats[user_id] = {
                    "upload_count": 0,
                    "last_upload": None,
                    "username": upload.get("telegram_username"),
                }
            user_stats[user_id]["upload_count"] = (
                int(user_stats[user_id].get("upload_count", 0)) + 1
            )
            if (
                not user_stats[user_id]["last_upload"]
                or uploaded_at > user_stats[user_id]["last_upload"]
            ):
                user_stats[user_id]["last_upload"] = uploaded_at
                if upload.get("telegram_username"):
                    user_stats[user_id]["username"] = upload.get("telegram_username")

        authorized_users = []
        for user_id in allowed_ids:
            stats = user_stats.get(user_id, {})
            authorized_users.append(
                TelegramAuthorizedUser(
                    id=user_id,
                    username=stats.get("username"),
                    last_upload=stats.get("last_upload"),
                    upload_count=stats.get("upload_count") or 0,
                )
            )

        is_running = bot_state.get("enabled", False) and bot_state.get(
            "connected", False
        )
        storage_used = sum(self._coerce_int(u.get("file_size"), 0) for u in uploads)
        message = bot_state.get("message", "Ready")
        if self._telegram_fs_error:
            message = self._telegram_fs_error

        return TelegramBotStatus(
            enabled=bot_state.get("enabled", False),
            configured=True,
            connected=bot_state.get("connected", False),
            is_running=is_running,
            bot_username=bot_state.get("bot_username"),
            last_activity=self._parse_iso_datetime(bot_state.get("last_activity")),
            total_uploads=len(uploads),
            storage_used=storage_used,
            message=message,
            authorized_users=authorized_users,
        )

    # Bot instance variables
    _bot_thread: threading.Thread | None = None
    _bot_stop_event: threading.Event | None = None
    _bot_loop: asyncio.AbstractEventLoop | None = None

    def _is_bot_thread_alive(self) -> bool:
        return bool(self._bot_thread and self._bot_thread.is_alive())

    def _sync_telegram_state(self, state: dict) -> dict:
        if not self._is_bot_thread_alive():
            state = {
                "enabled": False,
                "connected": False,
                "message": "Stopped",
            }
            self._write_telegram_json(
                cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
            )
        return state

    def auto_start_telegram_bot(self) -> bool:
        """Restore a bot that was running before the backend restarted."""
        state = self._load_telegram_state()
        if not state.get("enabled", False):
            return False
        self.start_telegram_bot()
        return True

    def start_telegram_bot(self) -> None:
        """Start the Telegram bot in a background thread."""
        config, error = self._load_telegram_config_data()
        if error:
            state = {"enabled": False, "connected": False, "message": error}
            self._write_telegram_json(
                cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
            )
            return

        token = config.get("token", "")
        try:
            telegram_max_file_size = max(
                1,
                min(
                    int(config.get("max_file_size", 50 * 1024 * 1024)),
                    DEFAULT_MAX_UPLOAD_BYTES,
                ),
            )
        except (TypeError, ValueError):
            telegram_max_file_size = 50 * 1024 * 1024

        if not token:
            state = {"enabled": False, "connected": False, "message": "Token not set"}
            self._write_telegram_json(
                cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
            )
            return

        # Stop existing bot if running
        self.stop_telegram_bot()

        state = {
            "enabled": True,
            "connected": False,
            "message": "Connecting to Telegram...",
        }
        self._write_telegram_json(
            cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
        )

        self._bot_stop_event = threading.Event()

        def run_bot_thread():
            try:
                from types import SimpleNamespace
                from telegram import Bot

                service = self  # Reference to service for file operations

                def is_authorized(user_id: int | None) -> bool:
                    return service._telegram_user_is_authorized(user_id)

                async def cmd_start(update, context):
                    user = update.effective_user
                    user_id = user.id if user else None
                    if not is_authorized(user_id):
                        await update.message.reply_text(
                            f"⛔ Access denied.\n\nYour User ID: `{user_id}`\n\n"
                            "Send this ID to admin to get access.",
                            parse_mode="Markdown",
                        )
                        return
                    await update.message.reply_text(
                        "✅ *Welcome to PiCloud Bot!*\n\n"
                        "📤 Send me any file, photo or video to upload to your cloud.\n\n"
                        "*Commands:*\n"
                        "/status - Storage info\n"
                        "/help - Show help",
                        parse_mode="Markdown",
                    )

                async def cmd_status(update, context):
                    user_id = (
                        update.effective_user.id if update.effective_user else None
                    )
                    if not is_authorized(user_id):
                        await update.message.reply_text("⛔ Unauthorized")
                        return
                    try:
                        stats = service.storage_stats()
                        await update.message.reply_text(
                            f"📦 *PiCloud Storage*\n\n"
                            f"Used: {stats.used / 1024 / 1024:.1f} MB\n"
                            f"Free: {stats.free / 1024 / 1024:.1f} MB\n"
                            f"Total: {stats.total / 1024 / 1024:.1f} MB\n"
                            f"Usage: {stats.percent:.1f}%",
                            parse_mode="Markdown",
                        )
                    except Exception:
                        await update.message.reply_text("📦 Storage info unavailable")

                async def cmd_help(update, context):
                    if not is_authorized(
                        update.effective_user.id if update.effective_user else None
                    ):
                        return
                    await update.message.reply_text(
                        "📁 *PiCloud Bot Help*\n\n"
                        "Send any file to upload it to your cloud storage.\n\n"
                        "*Supported:*\n"
                        "• Documents (PDF, DOC, etc.)\n"
                        "• Photos\n"
                        "• Videos\n"
                        "• Audio\n"
                        "• Archives\n\n"
                        "*Commands:*\n"
                        "/start - Start bot\n"
                        "/status - Storage info\n"
                        "/help - This help",
                        parse_mode="Markdown",
                    )

                async def handle_document(update, context):
                    user = update.effective_user
                    user_id = user.id if user else None
                    if not is_authorized(user_id):
                        await update.message.reply_text("⛔ Unauthorized")
                        return

                    doc = update.message.document
                    if (doc.file_size or 0) > telegram_max_file_size:
                        await update.message.reply_text("File is too large.")
                        return
                    msg = await update.message.reply_text(
                        f"⏳ Uploading {doc.file_name}..."
                    )

                    try:
                        file = await context.bot.get_file(doc.file_id)

                        from app.utils.file_security import unique_upload_path

                        filename = doc.file_name or "document.bin"
                        target_dir = service._telegram_upload_directory(
                            filename, getattr(doc, "mime_type", None)
                        )
                        target_path = unique_upload_path(target_dir, filename)

                        # Download file
                        target_path = await service._download_telegram_file(
                            file,
                            target_path,
                            doc.file_size or telegram_max_file_size,
                        )

                        # Log upload
                        service._log_telegram_upload(
                            doc.file_id,
                            target_path.name,
                            doc.file_size or 0,
                            user_id,
                            user.username,
                            str(target_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                        )

                        await msg.edit_text(f"✅ Uploaded: {target_path.name}")
                    except PiCloudCapacityError as e:
                        logging.warning("Telegram upload deferred: %s", e.detail)
                        await msg.edit_text(e.detail)
                    except Exception as e:
                        logging.error(f"Telegram upload error: {e}")
                        await msg.edit_text("Upload failed.")

                async def handle_photo(update, context):
                    user = update.effective_user
                    user_id = user.id if user else None
                    if not is_authorized(user_id):
                        await update.message.reply_text("⛔ Unauthorized")
                        return

                    photo = update.message.photo[-1]  # Largest size
                    if (photo.file_size or 0) > telegram_max_file_size:
                        await update.message.reply_text("File is too large.")
                        return
                    msg = await update.message.reply_text("⏳ Uploading photo...")

                    try:
                        file = await context.bot.get_file(photo.file_id)
                        filename = f"photo_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{photo.file_unique_id}.jpg"

                        from app.utils.file_security import unique_upload_path

                        target_dir = service._telegram_upload_directory(
                            filename, "image/jpeg"
                        )
                        target_path = unique_upload_path(
                            target_dir, filename, fallback="photo.jpg"
                        )
                        filename = target_path.name

                        target_path = await service._download_telegram_file(
                            file,
                            target_path,
                            photo.file_size or telegram_max_file_size,
                        )
                        filename = target_path.name

                        service._log_telegram_upload(
                            photo.file_id,
                            filename,
                            photo.file_size or 0,
                            user_id,
                            user.username,
                            str(target_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                        )

                        # Generate thumbnail
                        service._generate_thumbnail(
                            target_path,
                            str(target_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                        )

                        await msg.edit_text("✅ Photo uploaded!")
                    except PiCloudCapacityError as e:
                        logging.warning("Telegram photo upload deferred: %s", e.detail)
                        await msg.edit_text(e.detail)
                    except Exception as e:
                        logging.error(f"Telegram photo upload error: {e}")
                        await msg.edit_text("Upload failed.")

                async def handle_video(update, context):
                    user = update.effective_user
                    user_id = user.id if user else None
                    if not is_authorized(user_id):
                        await update.message.reply_text("⛔ Unauthorized")
                        return

                    video = update.message.video
                    if (video.file_size or 0) > telegram_max_file_size:
                        await update.message.reply_text("File is too large.")
                        return
                    filename = (
                        video.file_name
                        or f"video_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{video.file_unique_id}.mp4"
                    )
                    msg = await update.message.reply_text("⏳ Uploading video...")

                    try:
                        file = await context.bot.get_file(video.file_id)

                        from app.utils.file_security import unique_upload_path

                        target_dir = service._telegram_upload_directory(
                            filename, getattr(video, "mime_type", None)
                        )
                        target_path = unique_upload_path(
                            target_dir, filename, fallback="video.mp4"
                        )
                        filename = target_path.name

                        target_path = await service._download_telegram_file(
                            file,
                            target_path,
                            video.file_size or telegram_max_file_size,
                        )
                        filename = target_path.name

                        service._log_telegram_upload(
                            video.file_id,
                            filename,
                            video.file_size or 0,
                            user_id,
                            user.username,
                            str(target_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                        )

                        await msg.edit_text(f"✅ Video uploaded: {filename}")
                    except PiCloudCapacityError as e:
                        logging.warning("Telegram video upload deferred: %s", e.detail)
                        await msg.edit_text(e.detail)
                    except Exception as e:
                        logging.error(f"Telegram video upload error: {e}")
                        await msg.edit_text("Upload failed.")

                async def handle_audio(update, context):
                    user = update.effective_user
                    user_id = user.id if user else None
                    if not is_authorized(user_id):
                        await update.message.reply_text("⛔ Unauthorized")
                        return

                    audio = update.message.audio or update.message.voice
                    if not audio:
                        return
                    if (audio.file_size or 0) > telegram_max_file_size:
                        await update.message.reply_text("File is too large.")
                        return

                    if hasattr(audio, "file_name") and audio.file_name:
                        filename = audio.file_name
                    else:
                        ext = ".ogg" if update.message.voice else ".mp3"
                        filename = f"audio_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{audio.file_unique_id}{ext}"

                    msg = await update.message.reply_text("⏳ Uploading audio...")

                    try:
                        file = await context.bot.get_file(audio.file_id)

                        from app.utils.file_security import unique_upload_path

                        target_dir = service._telegram_upload_directory(
                            filename, getattr(audio, "mime_type", None)
                        )
                        target_path = unique_upload_path(
                            target_dir, filename, fallback="audio.bin"
                        )
                        filename = target_path.name

                        target_path = await service._download_telegram_file(
                            file,
                            target_path,
                            audio.file_size or telegram_max_file_size,
                        )
                        filename = target_path.name

                        service._log_telegram_upload(
                            audio.file_id,
                            filename,
                            audio.file_size or 0,
                            user_id,
                            user.username,
                            str(target_path.relative_to(cloud_runtime().STORAGE_ROOT)),
                        )

                        await msg.edit_text(f"✅ Audio uploaded: {filename}")
                    except PiCloudCapacityError as e:
                        logging.warning("Telegram audio upload deferred: %s", e.detail)
                        await msg.edit_text(e.detail)
                    except Exception as e:
                        logging.error(f"Telegram audio upload error: {e}")
                        await msg.edit_text("Upload failed.")

                # Create event loop for this thread
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                self._bot_loop = loop

                async def run_bot():
                    # Verify token and get bot info
                    # Use reasonable timeouts - httpx will try IPv6 then IPv4 automatically
                    from telegram.request import HTTPXRequest

                    request = HTTPXRequest(
                        connection_pool_size=8,
                        connect_timeout=10.0,  # Enough for IPv6 fallback to IPv4
                        read_timeout=15.0,
                        write_timeout=15.0,
                        pool_timeout=15.0,
                    )
                    bot = Bot(token, request=request)
                    me = await bot.get_me()

                    # Update state with bot info
                    state = {
                        "enabled": True,
                        "connected": True,
                        "message": "Running",
                        "bot_username": me.username,
                        "last_activity": datetime.now().isoformat(),
                    }
                    self._write_telegram_json(
                        cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
                    )

                    context = SimpleNamespace(bot=bot)
                    try:
                        await bot.delete_webhook(drop_pending_updates=True)
                    except Exception as exc:
                        logger.warning("Could not clear Telegram webhook: %s", exc)

                    logging.info(f"Telegram bot @{me.username} started")

                    offset: int | None = None
                    while not self._bot_stop_event.is_set():
                        try:
                            updates = await bot.get_updates(offset=offset, timeout=30)
                            for update in updates:
                                offset = update.update_id + 1
                                message = update.message
                                if not message:
                                    continue
                                text = message.text or ""
                                if text.startswith("/start"):
                                    await cmd_start(update, context)
                                    continue
                                if text.startswith("/status"):
                                    await cmd_status(update, context)
                                    continue
                                if text.startswith("/help"):
                                    await cmd_help(update, context)
                                    continue
                                if message.document:
                                    await handle_document(update, context)
                                    continue
                                if message.photo:
                                    await handle_photo(update, context)
                                    continue
                                if message.video:
                                    await handle_video(update, context)
                                    continue
                                if message.audio or message.voice:
                                    await handle_audio(update, context)
                                    continue
                        except Exception as e:
                            logging.error(f"Telegram polling error: {e}")
                            await asyncio.sleep(1)

                    # Graceful shutdown
                    logging.info("Stopping Telegram bot...")
                    try:
                        await bot.close()
                    except Exception as exc:
                        logger.warning("Could not close Telegram bot cleanly: %s", exc)

                loop.run_until_complete(run_bot())
                loop.close()

            except Exception as e:
                logging.error(f"Telegram bot error: {e}")
                state = {
                    "enabled": False,
                    "connected": False,
                    "message": f"Error: {str(e)[:100]}",
                }
                self._write_telegram_json(
                    cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
                )

        # Start bot in background thread (non-daemon so it keeps process alive)
        self._bot_thread = threading.Thread(
            target=run_bot_thread, daemon=False, name="TelegramBot"
        )
        self._bot_thread.start()

        # Initial state
        state = {"enabled": True, "connected": False, "message": "Starting..."}
        self._write_telegram_json(
            cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
        )

    def stop_telegram_bot(self) -> None:
        """Stop the running Telegram bot."""
        if self._bot_stop_event:
            self._bot_stop_event.set()

        if self._bot_thread and self._bot_thread.is_alive():
            self._bot_thread.join(timeout=5)
            if self._bot_thread.is_alive():
                state = {
                    "enabled": True,
                    "connected": False,
                    "message": "Telegram bot stop timed out; the worker is still running",
                }
                self._write_telegram_json(
                    cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
                )
                raise RuntimeError("Telegram bot worker did not stop within 5 seconds")

        self._bot_thread = None
        self._bot_stop_event = None
        self._bot_loop = None

        state = {"enabled": False, "connected": False, "message": "Stopped"}
        self._write_telegram_json(
            cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
        )

    def test_telegram_bot(self) -> dict:
        """Test Telegram bot connection and send test message."""
        config, error = self._load_telegram_config_data()
        if error:
            return {"success": False, "message": error}

        # Check if bot is running
        state = self.get_telegram_status()
        if not state.is_running:
            return {
                "success": False,
                "message": "Bot is not running. Start the bot first.",
            }

        token = config.get("token", "")
        allowed_ids = self._coerce_int_list(config.get("allowed_user_ids"))

        if not token:
            return {"success": False, "message": "Token not set"}

        try:
            import asyncio
            from telegram import Bot
            from telegram.request import HTTPXRequest
            from datetime import datetime

            async def check_and_notify():
                # Configure request with longer timeout for first connection
                request = HTTPXRequest(
                    connection_pool_size=8,
                    connect_timeout=15.0,  # Allow time for IPv6->IPv4 fallback
                    read_timeout=20.0,
                    write_timeout=20.0,
                    pool_timeout=20.0,
                )
                bot = Bot(token, request=request)

                # Retry logic for initial connection
                me = None
                max_retries = 2
                for attempt in range(max_retries):
                    try:
                        me = await bot.get_me()
                        break
                    except Exception:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                        else:
                            raise

                sent_count = 0
                for user_id in allowed_ids:
                    try:
                        now = datetime.now().strftime("%H:%M:%S")
                        # Escape underscores in username for Markdown
                        safe_username = me.username.replace("_", "\\_")
                        msg = "✅ *EasyPi Cloud Test*\n\n"
                        msg += "Connection successful\\!\n"
                        msg += f"Bot: @{safe_username}\n"
                        msg += f"Time: {now}\n\n"
                        msg += "📤 Send files here to upload to your cloud\\."
                        await bot.send_message(
                            chat_id=user_id, text=msg, parse_mode="MarkdownV2"
                        )
                        sent_count += 1
                    except Exception as exc:
                        logger.warning(
                            "Could not send Telegram Cloud test message to user %s: %s",
                            user_id,
                            exc,
                        )

                await bot.close()

                return me.username, sent_count

            loop = asyncio.new_event_loop()
            username, sent = loop.run_until_complete(check_and_notify())
            loop.close()

            if sent > 0:
                return {
                    "success": True,
                    "message": "Connected to @" + username + ". Test message sent!",
                }
            elif allowed_ids:
                return {
                    "success": True,
                    "message": "Connected to @"
                    + username
                    + ". Could not send message.",
                }
            else:
                return {
                    "success": True,
                    "message": "Connected to @"
                    + username
                    + ". Add User ID to get messages.",
                }
        except Exception as e:
            return {"success": False, "message": str(e)}

    def _log_telegram_upload(
        self,
        file_id: str,
        file_name: str,
        file_size: int,
        user_id: int,
        username: str | None,
        storage_path: str,
    ) -> None:
        """Log a Telegram upload."""
        uploads = self._load_telegram_uploads()
        uploads.insert(
            0,
            {
                "id": str(uuid.uuid4()),
                "file_id": file_id,
                "file_name": file_name,
                "file_size": file_size,
                "telegram_user_id": user_id,
                "telegram_username": username,
                "uploaded_at": datetime.now().isoformat(),
                "storage_path": storage_path,
            },
        )
        # Keep last 1000 uploads
        uploads = uploads[:1000]
        self._write_telegram_json(
            cloud_runtime().TELEGRAM_UPLOADS_FILE, uploads, "Telegram uploads"
        )

        # Update last activity
        state = self._load_telegram_state()
        state["last_activity"] = datetime.now().isoformat()
        self._write_telegram_json(
            cloud_runtime().TELEGRAM_STATE_FILE, state, "Telegram state"
        )

    def get_telegram_uploads(self, limit: int = 20) -> list[TelegramUpload]:
        uploads = [u for u in self._load_telegram_uploads() if isinstance(u, dict)]
        result: list[TelegramUpload] = []
        for upload in uploads[:limit]:
            uploaded_at = self._parse_iso_datetime(upload.get("uploaded_at"))
            if not uploaded_at:
                continue
            try:
                user_id = int(upload.get("telegram_user_id"))
            except (TypeError, ValueError):
                continue
            result.append(
                TelegramUpload(
                    id=str(upload.get("id", "")),
                    file_id=str(upload.get("file_id", "")),
                    file_name=str(upload.get("file_name", "")),
                    file_size=self._coerce_int(upload.get("file_size"), 0),
                    telegram_user_id=user_id,
                    telegram_username=upload.get("telegram_username"),
                    uploaded_at=uploaded_at,
                    storage_path=str(upload.get("storage_path", "")),
                )
            )
        return result

    def remove_telegram_user(self, user_id: int) -> None:
        config, error = self._load_telegram_config_data()
        if error:
            return
        allowed_ids = self._coerce_int_list(config.get("allowed_user_ids"))
        if user_id in allowed_ids:
            allowed_ids.remove(user_id)
            config["allowed_user_ids"] = allowed_ids
            if not self._write_telegram_json(
                cloud_runtime().TELEGRAM_CONFIG_FILE, config, "Telegram config"
            ):
                raise OSError(self._telegram_fs_error or "Telegram config write failed")

    def _load_telegram_state(self) -> dict:
        if not cloud_runtime().TELEGRAM_STATE_FILE.exists():
            return dict(self._telegram_state_cache)
        try:
            data = json.loads(
                cloud_runtime().TELEGRAM_STATE_FILE.read_text(encoding="utf-8")
            )
            if isinstance(data, dict):
                self._telegram_state_cache = dict(data)
                return data
            return dict(self._telegram_state_cache)
        except PermissionError:
            message = (
                f"Telegram state not readable: {cloud_runtime().TELEGRAM_STATE_FILE}"
            )
            logging.error(message)
            self._telegram_fs_error = message
            return dict(self._telegram_state_cache)
        except OSError as exc:
            message = f"Telegram state read failed: {exc}"
            logging.error(message)
            self._telegram_fs_error = message
            return dict(self._telegram_state_cache)
        except json.JSONDecodeError:
            return dict(self._telegram_state_cache)

    def _load_telegram_uploads(self) -> list:
        if not cloud_runtime().TELEGRAM_UPLOADS_FILE.exists():
            return []
        try:
            return json.loads(
                cloud_runtime().TELEGRAM_UPLOADS_FILE.read_text(encoding="utf-8")
            )
        except PermissionError:
            message = f"Telegram uploads not readable: {cloud_runtime().TELEGRAM_UPLOADS_FILE}"
            logging.error(message)
            self._telegram_fs_error = message
            return []
        except OSError as exc:
            message = f"Telegram uploads read failed: {exc}"
            logging.error(message)
            self._telegram_fs_error = message
            return []
        except json.JSONDecodeError:
            return []
