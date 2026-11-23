"""AIInstallationMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.ai_components.context import (
    AIConfig,
    AIConversation,
    AIInstallStatus,
    AIModelInfo,
    AISettingsUpdate,
    AsyncGenerator,
    ChatResponse,
    List,
    Optional,
    Path,
    Session,
    asyncio,
    create_install_job,
    get_installer_log_path,
    get_settings,
    httpx,
    json,
    logger,
    logging,
    os,
    re,
    read_installer_log,
    run_in_threadpool,
    start_install_job,
    subprocess,
    text,
    utc_now,
    uuid,
)


class AIInstallationMixin:
    async def install_via_script(
        self,
        db: Session,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Install Ollama and a model via bash script (legacy method)."""
        if self.active_installation:
            yield (
                json.dumps(
                    {"type": "error", "message": "Installation already in progress"}
                )
                + "\n"
            )
            return

        # Check if install script exists
        script_ok, script_error = self._check_install_script()
        if not script_ok:
            yield json.dumps({"type": "error", "message": script_error}) + "\n"
            return

        config = self._ensure_config(db)
        selected_model = self._validate_model_name(model_name or config.model_name)
        selected_temp = self._clamp_temperature(
            temperature if temperature is not None else config.temperature
        )
        selected_prompt = (
            system_prompt or config.system_prompt or self.DEFAULT_SYSTEM_PROMPT
        ).strip() or self.DEFAULT_SYSTEM_PROMPT

        # Get model size for progress calculation
        model_info = next(
            (m for m in self.AVAILABLE_MODELS if m["name"] == selected_model), None
        )
        model_size_gb = model_info["size_gb"] if model_info else 5.0

        lock_acquired = False
        try:
            lock_ok, lock_message = await self._acquire_install_lock(selected_model)
            if not lock_ok:
                yield json.dumps({"type": "error", "message": lock_message}) + "\n"
                return
            lock_acquired = True
            self.active_installation = True

            config.status = "installing"
            config.is_installed = False
            config.model_name = selected_model
            config.temperature = selected_temp
            config.system_prompt = selected_prompt
            db.commit()

            # Stage 1: Initialization (0-5%)
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 0,
                        "message": "🚀 Starting AI installation...",
                        "stage": "init",
                    }
                )
                + "\n"
            )
            yield (
                json.dumps(
                    {
                        "type": "log",
                        "message": f"📦 Selected model: {selected_model} ({model_size_gb:.1f} GB)",
                    }
                )
                + "\n"
            )
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 5,
                        "message": "Checking system requirements...",
                        "stage": "init",
                    }
                )
                + "\n"
            )

            process = await asyncio.create_subprocess_exec(
                "sudo",
                "bash",
                self.install_script,
                selected_model,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            ollama_installed = False
            model_download_started = False
            # mutable container so helper tasks can update it
            last_model_percent = {"v": 0}

            # queue will receive decoded lines from both subprocess stdout and a logfile tailer
            progress_q: asyncio.Queue = asyncio.Queue()

            async def _read_stdout(proc: asyncio.subprocess.Process, q: asyncio.Queue):
                if not proc.stdout:
                    return
                try:
                    async for b in proc.stdout:
                        decoded = b.decode("utf-8", errors="replace").strip()
                        if decoded:
                            await q.put(decoded)
                except asyncio.CancelledError:
                    return

            async def _tail_log_file(
                path: str, q: asyncio.Queue, proc: asyncio.subprocess.Process
            ):
                # follow the installation logfile to pick up progress lines if stdout is not usable
                try:
                    if not os.path.exists(path):
                        return
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(0, os.SEEK_END)
                        while True:
                            line = f.readline()
                            if line:
                                await q.put(line.strip())
                            else:
                                # if process ended, break out after attempting once more
                                if proc.returncode is not None:
                                    line = f.readline()
                                    if line:
                                        await q.put(line.strip())
                                    break
                                await asyncio.sleep(0.5)
                except asyncio.CancelledError:
                    return
                except Exception:
                    logger.debug("tail_log_file errored", exc_info=True)

            stdout_task = asyncio.create_task(_read_stdout(process, progress_q))
            tail_task = asyncio.create_task(
                _tail_log_file(
                    str(get_settings().LOG_DIR / "ai_install.log"), progress_q, process
                )
            )

            async def _dispatch_loop():
                nonlocal ollama_installed, model_download_started
                while True:
                    try:
                        decoded_line = await asyncio.wait_for(
                            progress_q.get(), timeout=0.5
                        )
                    except asyncio.TimeoutError:
                        # stop when process done and queue drained
                        if process.returncode is not None and progress_q.empty():
                            break
                        continue

                    if not decoded_line:
                        continue

                    # Stage 2: Ollama installation (5-30%)
                    if "Installing Ollama" in decoded_line or "Ustanav" in decoded_line:
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 10,
                                    "message": "📥 Installing Ollama...",
                                    "stage": "ollama",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "ollama_progress",
                                    "percent": 20,
                                    "message": decoded_line,
                                }
                            )
                            + "\n"
                        )
                    elif "Downloading" in decoded_line and not model_download_started:
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 15,
                                    "message": "⬇️ Downloading Ollama...",
                                    "stage": "ollama",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "ollama_progress",
                                    "percent": 50,
                                    "message": decoded_line,
                                }
                            )
                            + "\n"
                        )
                    elif (
                        "Ollama installed" in decoded_line
                        or "successfully" in decoded_line.lower()
                    ):
                        ollama_installed = True
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 30,
                                    "message": "✅ Ollama installed!",
                                    "stage": "ollama",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "ollama_progress",
                                    "percent": 100,
                                    "message": decoded_line,
                                }
                            )
                            + "\n"
                        )
                    elif (
                        "Starting Ollama" in decoded_line
                        or "starting" in decoded_line.lower()
                    ):
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 25,
                                    "message": "🔄 Starting Ollama service...",
                                    "stage": "ollama",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "ollama_progress",
                                    "percent": 80,
                                    "message": decoded_line,
                                }
                            )
                            + "\n"
                        )

                    # Stage 3: Model download (30-90%)
                    elif decoded_line.startswith("MODEL_DOWNLOAD_STARTED"):
                        model_download_started = True
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 30,
                                    "message": f"📦 Starting model download {selected_model}...",
                                    "stage": "model",
                                }
                            )
                            + "\n"
                        )
                        continue  # Don't log this line
                    elif "MODEL_DOWNLOAD_PROGRESS" in decoded_line:
                        try:
                            # Format: MODEL_DOWNLOAD_PROGRESS: 45 2.1 GB 4.7 GB 15 MB/s
                            # Or: MODEL_DOWNLOAD_PROGRESS: 99 verifying
                            # Or: MODEL_DOWNLOAD_PROGRESS: 100 complete
                            line_content = decoded_line.split(
                                "MODEL_DOWNLOAD_PROGRESS:"
                            )[-1].strip()
                            parts = line_content.split()

                            logger.info(
                                "Parsing progress: %s -> parts: %s", decoded_line, parts
                            )

                            if len(parts) >= 1:
                                percent_str = parts[0]
                                if percent_str == "verifying":
                                    yield (
                                        json.dumps(
                                            {
                                                "type": "model_progress",
                                                "percent": 99,
                                                "message": "🔍 Verifying model...",
                                                "downloaded": "",
                                                "total": "",
                                                "speed": "",
                                            }
                                        )
                                        + "\n"
                                    )
                                    yield (
                                        json.dumps(
                                            {
                                                "type": "progress",
                                                "percent": 95,
                                                "message": "🔍 Verifying model...",
                                                "stage": "verify",
                                            }
                                        )
                                        + "\n"
                                    )
                                    continue
                                elif percent_str == "complete":
                                    yield (
                                        json.dumps(
                                            {
                                                "type": "model_progress",
                                                "percent": 100,
                                                "message": "✅ Download complete!",
                                                "downloaded": "",
                                                "total": "",
                                                "speed": "",
                                            }
                                        )
                                        + "\n"
                                    )
                                    yield (
                                        json.dumps(
                                            {
                                                "type": "progress",
                                                "percent": 90,
                                                "message": "✅ Model downloaded!",
                                                "stage": "model",
                                            }
                                        )
                                        + "\n"
                                    )
                                    continue

                                try:
                                    percent = int(percent_str)
                                except ValueError:
                                    logger.warning(
                                        "Cannot parse percent from: %s", percent_str
                                    )
                                    continue

                                # Parse remaining parts: "2.1 GB 4.7 GB --" or "2.1 GB 4.7 GB 15 MB/s"
                                downloaded = ""
                                total = ""
                                speed = ""

                                # Join remaining parts and try to extract info
                                remaining = (
                                    " ".join(parts[1:]) if len(parts) > 1 else ""
                                )

                                # Simple parsing: look for GB/MB patterns (with or without space)
                                import re

                                # Match patterns like "2.1 GB", "2.1GB", "350 MB", "350MB"
                                size_matches = re.findall(
                                    r"[\d.]+\s*[KMGT]?B(?![/])", remaining
                                )
                                if len(size_matches) >= 1:
                                    downloaded = size_matches[0].strip()
                                if len(size_matches) >= 2:
                                    total = size_matches[1].strip()

                                speed_match = re.search(
                                    r"[\d.]+\s*[KMGT]?B/s", remaining
                                )
                                if speed_match:
                                    speed = speed_match.group(0).strip()

                                # Fallback: calculate sizes from percent and model size if not parsed
                                if not downloaded and not total and percent > 0:
                                    total = f"{model_size_gb:.1f} GB"
                                    downloaded_gb = (percent / 100) * model_size_gb
                                    if downloaded_gb >= 1:
                                        downloaded = f"{downloaded_gb:.1f} GB"
                                    else:
                                        downloaded = f"{int(downloaded_gb * 1024)} MB"

                                # Scale model progress: 30% + (percent * 0.6) = 30-90%
                                overall_percent = 30 + int(percent * 0.6)

                                # Always send progress update
                                if percent >= last_model_percent["v"]:
                                    last_model_percent["v"] = percent

                                    message = (
                                        f"⬇️ {downloaded}"
                                        if downloaded
                                        else f"⬇️ {percent}%"
                                    )
                                    if total:
                                        message += f" / {total}"
                                    if speed and speed != "--":
                                        message += f" ({speed})"

                                    logger.info(
                                        "Sending model_progress: %d%%, downloaded=%s, total=%s, speed=%s",
                                        percent,
                                        downloaded,
                                        total,
                                        speed,
                                    )

                                    yield (
                                        json.dumps(
                                            {
                                                "type": "model_progress",
                                                "percent": percent,
                                                "message": message,
                                                "downloaded": downloaded,
                                                "total": total,
                                                "speed": speed,
                                            }
                                        )
                                        + "\n"
                                    )
                                    yield (
                                        json.dumps(
                                            {
                                                "type": "progress",
                                                "percent": overall_percent,
                                                "message": f"⬇️ Downloading: {percent}%",
                                                "stage": "model",
                                            }
                                        )
                                        + "\n"
                                    )
                            continue
                        except Exception as e:
                            logger.warning(
                                "Failed to parse progress line: %s - %s",
                                decoded_line,
                                e,
                            )
                    elif (
                        "pull" in decoded_line.lower()
                        and "success" in decoded_line.lower()
                    ):
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 90,
                                    "message": "✅ Model downloaded!",
                                    "stage": "model",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "model_progress",
                                    "percent": 100,
                                    "downloaded": "",
                                    "total": "",
                                    "speed": "",
                                    "message": "Download complete",
                                }
                            )
                            + "\n"
                        )
                        continue  # Don't log this line

                    # Stage 4: Verification (90-100%)
                    elif "success" in decoded_line.lower():
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 95,
                                    "message": "🔍 Verifying installation...",
                                    "stage": "verify",
                                }
                            )
                            + "\n"
                        )
                        continue  # Don't log this line
                    elif "ready" in decoded_line.lower():
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 98,
                                    "message": "✅ AI ready to use!",
                                    "stage": "verify",
                                }
                            )
                            + "\n"
                        )
                        continue  # Don't log this line

                    # Log other messages (skip progress-related lines)
                    if not any(
                        skip in decoded_line
                        for skip in ["MODEL_DOWNLOAD", "%", "pulling", "verifying"]
                    ):
                        yield (
                            json.dumps({"type": "log", "message": decoded_line}) + "\n"
                        )
                    logger.info("Install: %s", decoded_line)

            # actually run the dispatcher generator and yield to the caller
            try:
                async for msg in _dispatch_loop():
                    yield msg
            finally:
                try:
                    stdout_task.cancel()
                except Exception:
                    pass
                try:
                    tail_task.cancel()
                except Exception:
                    pass

            return_code = await process.wait()
            if return_code == 0:
                yield (
                    json.dumps(
                        {
                            "type": "progress",
                            "percent": 100,
                            "message": "🎉 Installation completed successfully!",
                            "stage": "complete",
                        }
                    )
                    + "\n"
                )
                config.is_installed = True
                config.status = "ready"
                config.installed_at = utc_now()
                config.last_health_check = utc_now()
                db.commit()
                logger.info("AI installation completed successfully")
            else:
                yield (
                    json.dumps(
                        {
                            "type": "error",
                            "message": f"❌ Installation failed (code {return_code})",
                        }
                    )
                    + "\n"
                )
                config.status = "error"
                db.commit()
                logger.error("AI installation failed with code %s", return_code)
        except Exception as exc:
            yield (
                json.dumps(
                    {"type": "error", "message": f"❌ Installation error: {exc}"}
                )
                + "\n"
            )
            logger.exception("AI installation error")
            config.status = "error"
            db.commit()
        finally:
            self.active_installation = False
            if lock_acquired:
                self._clear_install_lock()

    async def update_config(
        self, db: Session, payload: AISettingsUpdate
    ) -> AIInstallStatus:
        """Update stored configuration (model / prompt / temperature)."""

        def _update():
            config = self._ensure_config(db)
            if payload.model_name:
                config.model_name = self._validate_model_name(payload.model_name)
            if payload.temperature is not None:
                config.temperature = self._clamp_temperature(payload.temperature)
            if payload.system_prompt is not None:
                cleaned = payload.system_prompt.strip()
                config.system_prompt = cleaned or self.DEFAULT_SYSTEM_PROMPT
            db.commit()
            db.refresh(config)
            return self._config_to_status(config)

        return await run_in_threadpool(_update)
