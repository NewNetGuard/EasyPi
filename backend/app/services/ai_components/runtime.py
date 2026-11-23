"""AIRuntimeMixin implementation."""

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


class AIRuntimeMixin:
    def _normalize_ollama_url(self, url: str) -> str:
        return url.rstrip("/")

    def _ollama_url_candidates(self, config: AIConfig | None = None) -> list[str]:
        raw_urls: list[str] = []
        if config and config.ollama_url:
            raw_urls.append(config.ollama_url)
        if self.ollama_url:
            raw_urls.append(self.ollama_url)
        raw_urls.extend(["http://127.0.0.1:11434", "http://localhost:11434"])

        urls: list[str] = []
        for url in raw_urls:
            normalized = self._normalize_ollama_url(url)
            if normalized and normalized not in urls:
                urls.append(normalized)
        return urls

    def _ollama_timeout(self) -> httpx.Timeout:
        return httpx.Timeout(130.0, connect=5.0, read=120.0, write=30.0, pool=5.0)

    # --------------------------------------------------------------------- #
    # Helpers
    # --------------------------------------------------------------------- #
    def _check_install_script(self) -> tuple[bool, str]:
        """Check if install script exists and is executable."""
        import shutil

        if not os.path.exists(self.install_script):
            return False, f"Install script not found: {self.install_script}"

        if not os.access(self.install_script, os.R_OK):
            return False, f"No read permission for script: {self.install_script}"

        if not shutil.which("sudo"):
            return False, "sudo command not found on system"

        if not shutil.which("bash"):
            return False, "bash command not found on system"

        return True, "OK"

    def _get_ollama_binary(self) -> str | None:
        import shutil

        for path in (
            "/usr/local/bin/ollama",
            "/usr/bin/ollama",
            "/usr/local/lib/ollama/ollama",
            "/usr/lib/ollama/ollama",
        ):
            if os.path.exists(path):
                return path
        return shutil.which("ollama")

    def _ollama_binary_exists(self) -> bool:
        return self._get_ollama_binary() is not None

    def _read_install_lock(self) -> dict | None:
        try:
            payload = self._install_lock_path.read_text(encoding="utf-8").strip()
            return json.loads(payload) if payload else None
        except FileNotFoundError:
            return None
        except Exception as exc:
            logger.warning("Failed to read AI install lock: %s", exc)
            return None

    def _write_install_lock(self, payload: dict) -> bool:
        self._install_lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(
                str(self._install_lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY
            )
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(json.dumps(payload))
        return True

    def _clear_install_lock(self) -> None:
        try:
            self._install_lock_path.unlink()
        except FileNotFoundError:
            return
        except Exception as exc:
            logger.warning("Failed to remove AI install lock: %s", exc)

    def _pid_is_active(self, pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _format_pull_processes(self, pulls: list[dict]) -> str:
        parts = []
        for entry in pulls:
            pid = entry.get("pid")
            model = entry.get("model")
            label = str(pid) if pid else "unknown"
            if model:
                label += f" ({model})"
            parts.append(label)
        return ", ".join(parts)

    async def _get_ollama_pull_processes(self) -> list[dict]:
        import shutil

        if not shutil.which("pgrep"):
            return []

        proc = await asyncio.create_subprocess_exec(
            "pgrep",
            "-af",
            "ollama pull",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode not in (0, 1):
            return []

        pulls: list[dict] = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            parts = line.strip().split(maxsplit=1)
            if not parts:
                continue
            pid = int(parts[0]) if parts[0].isdigit() else None
            cmd = parts[1] if len(parts) > 1 else ""
            model = cmd.split()[-1] if cmd else None
            pulls.append({"pid": pid, "cmd": cmd, "model": model})
        return pulls

    async def _acquire_install_lock(self, model_name: str) -> tuple[bool, str]:
        pulls = await self._get_ollama_pull_processes()
        if pulls:
            return (
                False,
                f"Another model download is already running: {self._format_pull_processes(pulls)}",
            )

        payload = {
            "pid": os.getpid(),
            "model": model_name,
            "started_at": utc_now().isoformat() + "Z",
        }

        if self._write_install_lock(payload):
            return True, ""

        existing = self._read_install_lock()
        if existing:
            pid = existing.get("pid")
            if isinstance(pid, int) and self._pid_is_active(pid):
                message = "Installation already in progress"
                model = existing.get("model")
                if model:
                    message += f" for {model}"
                return False, message

        self._clear_install_lock()
        if self._write_install_lock(payload):
            return True, ""

        return False, "Installation already in progress"

    async def _sudo_available(self) -> bool:
        proc = await asyncio.create_subprocess_exec(
            "sudo",
            "-n",
            "true",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        return proc.returncode == 0

    async def _systemctl(self, *args: str, sudo: bool = False) -> tuple[int, str, str]:
        cmd = ["systemctl", *args]
        if sudo:
            cmd = ["sudo", "-n", *cmd]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode, stdout.decode().strip(), stderr.decode().strip()

    async def _ollama_unit_exists(self) -> bool:
        code, out, err = await self._systemctl("status", "ollama")
        text = f"{out}\n{err}".lower()
        if "could not be found" in text or "not found" in text:
            return False
        return code in (0, 3)

    async def _create_ollama_systemd_unit(self) -> tuple[bool, str]:
        # Create unit via installer service to avoid sudo in backend
        job_id = create_install_job("services/ai.sh", ["service"])
        try:
            result = await asyncio.to_thread(start_install_job, job_id, 600)
        except subprocess.TimeoutExpired:
            return False, "Service setup timed out"

        if result.returncode != 0:
            log_tail = read_installer_log(job_id)
            return (
                False,
                log_tail
                or result.stderr
                or result.stdout
                or "Failed to create systemd unit",
            )

        return True, "systemd unit created"

    async def _ollama_service_active(self) -> tuple[bool, str]:
        code, out, err = await self._systemctl("is-active", "ollama")
        status = out or err or "unknown"
        err_lower = err.lower()
        if "could not be found" in err_lower or "not found" in err_lower:
            status = err
        elif out.strip().lower() == "unknown" and err:
            status = err
        return code == 0, status

    async def get_ollama_status(self, db: Session) -> dict:
        installed = self._ollama_binary_exists()
        if not installed:
            return {
                "installed": False,
                "service_active": False,
                "service_status": "not-installed",
                "healthy": False,
            }

        unit_exists = await self._ollama_unit_exists()
        running = False
        service_status = "not-managed"
        if unit_exists:
            running, service_status = await self._ollama_service_active()

        healthy = await self.check_health(db)
        if not unit_exists:
            service_status = "running (manual)" if healthy else "manual-start-required"

        return {
            "installed": True,
            "service_active": running or healthy,
            "service_status": service_status,
            "healthy": healthy,
        }

    async def start_ollama(self, db: Session) -> dict:
        if not self._ollama_binary_exists():
            return {
                "success": False,
                "error": "Ollama is not installed",
                "installed": False,
                "service_active": False,
                "service_status": "not-installed",
                "healthy": False,
            }
        if not await self._ollama_unit_exists():
            ok, msg = await self._create_ollama_systemd_unit()
            if not ok:
                return {
                    "success": False,
                    "error": msg or "Failed to create Ollama service",
                    "installed": True,
                    "service_active": False,
                    "service_status": "not-found",
                    "healthy": False,
                }
            await self._systemctl("daemon-reload", sudo=True)

        code, out, err = await self._systemctl("start", "ollama")
        if code != 0:
            code, out, err = await self._systemctl("start", "ollama", sudo=True)
            if code != 0:
                error_msg = (err or out or "Failed to start Ollama service").strip()
                lowered = error_msg.lower()
                if (
                    "password" in lowered
                    or "sudo" in lowered
                    or "not allowed" in lowered
                ):
                    error_msg = "sudo is not available for starting Ollama"
                return {
                    "success": False,
                    "error": error_msg,
                    "installed": True,
                    "service_active": False,
                    "service_status": "start-failed",
                    "healthy": False,
                }
        running, status = await self._ollama_service_active()
        if not running:
            return {
                "success": False,
                "error": "Ollama service failed to start",
                "installed": True,
                "service_active": False,
                "service_status": status,
                "healthy": False,
            }

        # Wait briefly for API to become responsive
        healthy = False
        for _ in range(10):
            if await self.check_health(db):
                healthy = True
                break
            await asyncio.sleep(1.0)

        if not healthy:
            return {
                "success": False,
                "error": "Ollama service started but API is not responding",
                "installed": True,
                "service_active": running,
                "service_status": status,
                "healthy": False,
            }

        return {
            "success": True,
            "installed": True,
            "service_active": running,
            "service_status": status,
            "healthy": True,
        }

    async def stop_ollama(self, db: Session) -> dict:
        if not self._ollama_binary_exists():
            return {
                "success": False,
                "error": "Ollama is not installed",
                "installed": False,
                "service_active": False,
                "service_status": "not-installed",
                "healthy": False,
            }
        if not await self._ollama_unit_exists():
            return {
                "success": False,
                "error": "Ollama service not found. Install Ollama first.",
                "installed": False,
                "service_active": False,
                "service_status": "not-found",
                "healthy": False,
            }
        running, status = await self._ollama_service_active()
        if not running:
            return {
                "success": True,
                "installed": True,
                "service_active": False,
                "service_status": status,
                "healthy": False,
            }

        code, out, err = await self._systemctl("stop", "ollama")
        if code != 0:
            code, out, err = await self._systemctl("stop", "ollama", sudo=True)
            if code != 0:
                error_msg = (err or out or "Failed to stop Ollama service").strip()
                lowered = error_msg.lower()
                if (
                    "password" in lowered
                    or "sudo" in lowered
                    or "not allowed" in lowered
                ):
                    error_msg = "sudo is not available for stopping Ollama"
                return {
                    "success": False,
                    "error": error_msg,
                    "installed": True,
                    "service_active": True,
                    "service_status": "stop-failed",
                    "healthy": False,
                }
        running, status = await self._ollama_service_active()
        healthy = await self.check_health(db) if running else False
        return {
            "success": not running,
            "installed": True,
            "service_active": running,
            "service_status": status,
            "healthy": healthy,
        }

    async def ensure_ollama(self, db: Session) -> AsyncGenerator[str, None]:
        installed = self._ollama_binary_exists()

        if installed:
            if await self.check_health(db):
                yield (
                    json.dumps(
                        {
                            "type": "progress",
                            "percent": 100,
                            "message": "✅ Ollama already running",
                        }
                    )
                    + "\n"
                )
                return

        if not installed:
            if self.active_installation:
                yield (
                    json.dumps(
                        {
                            "type": "error",
                            "message": "Installation already in progress. Please wait.",
                        }
                    )
                    + "\n"
                )
                return
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 5,
                        "message": "📥 Installing Ollama...",
                    }
                )
                + "\n"
            )
            try:
                self.active_installation = True
                async for msg in self._install_ollama():
                    yield msg
            except Exception as exc:
                yield (
                    json.dumps(
                        {"type": "error", "message": f"❌ Ollama install failed: {exc}"}
                    )
                    + "\n"
                )
                return
            finally:
                self.active_installation = False
        else:
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 25,
                        "message": "✅ Ollama already installed",
                    }
                )
                + "\n"
            )

        if await self.check_health(db):
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 100,
                        "message": "✅ Ollama already running",
                    }
                )
                + "\n"
            )
            return

        if not await self._sudo_available():
            yield (
                json.dumps(
                    {
                        "type": "error",
                        "message": "❌ Ollama installed but not running. Start it manually or enable passwordless sudo.",
                    }
                )
                + "\n"
            )
            return

        if not await self._ollama_unit_exists():
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 45,
                        "message": "🧩 Creating Ollama service unit...",
                    }
                )
                + "\n"
            )
            ok, msg = await self._create_ollama_systemd_unit()
            if not ok:
                yield json.dumps({"type": "error", "message": f"❌ {msg}"}) + "\n"
                return
            yield (
                json.dumps({"type": "log", "message": "✅ Ollama service unit created"})
                + "\n"
            )

        yield (
            json.dumps(
                {
                    "type": "progress",
                    "percent": 65,
                    "message": "🔄 Reloading systemd...",
                }
            )
            + "\n"
        )
        await self._systemctl("daemon-reload", sudo=True)
        yield (
            json.dumps(
                {
                    "type": "progress",
                    "percent": 80,
                    "message": "▶️ Enabling Ollama service...",
                }
            )
            + "\n"
        )
        code, out, err = await self._systemctl("enable", "--now", "ollama", sudo=True)
        if code != 0:
            yield (
                json.dumps(
                    {
                        "type": "error",
                        "message": err or out or "❌ Failed to enable Ollama service",
                    }
                )
                + "\n"
            )
            return

        running, status = await self._ollama_service_active()
        if running:
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 100,
                        "message": "✅ Ollama service started",
                    }
                )
                + "\n"
            )
        else:
            yield (
                json.dumps(
                    {
                        "type": "error",
                        "message": f"❌ Failed to start Ollama service: {status}",
                    }
                )
                + "\n"
            )

    async def _ensure_ollama_running(self, db: Session) -> tuple[bool, str]:
        if await self.check_health(db):
            return True, "Ollama is running"
        if not await self._sudo_available():
            return False, "sudo required to start Ollama service"
        if not await self._ollama_unit_exists():
            ok, msg = await self._create_ollama_systemd_unit()
            if not ok:
                return False, msg
        await self._systemctl("daemon-reload", sudo=True)
        await self._systemctl("enable", "--now", "ollama", sudo=True)
        if await self.check_health(db):
            return True, "Ollama started"
        return False, "Ollama did not start"

    def _ensure_schema(self, db: Session) -> None:
        """Ensure ai_config table has new columns even if alembic migration not executed."""
        bind = db.get_bind()
        if bind is None:
            return

        with bind.connect() as conn:
            try:
                result = conn.execute(text("PRAGMA table_info('ai_config')"))
                columns = {row[1] for row in result}
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to inspect ai_config table: %s", exc)
                return

            alterations: list[tuple[str, str]] = []
            if "temperature" not in columns:
                alterations.append(("temperature", "FLOAT DEFAULT 0.1"))
            if "system_prompt" not in columns:
                default_prompt = self.DEFAULT_SYSTEM_PROMPT.replace("'", "''")
                alterations.append(
                    ("system_prompt", f"TEXT DEFAULT '{default_prompt}'")
                )
            if "status" not in columns:
                alterations.append(("status", "VARCHAR(20) DEFAULT 'not_installed'"))

            for column, ddl in alterations:
                try:
                    conn.execute(
                        text(f"ALTER TABLE ai_config ADD COLUMN {column} {ddl}")
                    )
                    logger.info("Added missing column %s to ai_config", column)
                except Exception as exc:  # pragma: no cover
                    logger.error("Failed to add column %s: %s", column, exc)

    def _ensure_config(self, db: Session) -> AIConfig:
        self._ensure_schema(db)
        config = db.query(AIConfig).first()
        if not config:
            config = AIConfig(
                is_installed=False,
                status="not_installed",
                model_name=self.AVAILABLE_MODELS[0]["name"],
                ollama_url=self.ollama_url,
                temperature=0.1,
                system_prompt=self.DEFAULT_SYSTEM_PROMPT,
            )
            db.add(config)
            db.commit()
            db.refresh(config)
            return config

        updated = False
        available_model_names = {model["name"] for model in self.AVAILABLE_MODELS}
        if not config.model_name or config.model_name not in available_model_names:
            config.model_name = self.AVAILABLE_MODELS[0]["name"]
            updated = True
        if not config.ollama_url:
            config.ollama_url = self.ollama_url
            updated = True
        if config.temperature is None:
            config.temperature = 0.1
            updated = True
        if not config.system_prompt:
            config.system_prompt = self.DEFAULT_SYSTEM_PROMPT
            updated = True
        if not config.status:
            config.status = "not_installed"
            updated = True
        if updated:
            db.commit()
            db.refresh(config)
        return config

    def _config_to_status(self, config: AIConfig) -> AIInstallStatus:
        # Determine model path
        model_path = None
        if config.is_installed and config.model_name:
            # Ollama stores models in ~/.ollama/models or /usr/share/ollama/.ollama/models
            user = os.getenv("USER", "root")
            if user == "root":
                model_path = "/usr/share/ollama/.ollama/models"
            else:
                model_path = f"/home/{user}/.ollama/models"

        return AIInstallStatus(
            is_installed=config.is_installed,
            status=config.status,
            model_name=config.model_name,
            model_path=model_path,
            ollama_url=config.ollama_url,
            installed_at=config.installed_at,
            last_health_check=config.last_health_check,
            temperature=config.temperature,
            system_prompt=config.system_prompt,
        )

    def _clamp_temperature(self, value: Optional[float]) -> float:
        if value is None:
            return 0.1
        return max(0.0, min(1.5, value))

    def _validate_model_name(self, model_name: Optional[str]) -> str:
        available = {model["name"] for model in self.AVAILABLE_MODELS}
        if model_name and model_name in available:
            return model_name
        return self.AVAILABLE_MODELS[0]["name"]

    # --------------------------------------------------------------------- #
    # Public helpers
    # --------------------------------------------------------------------- #
    def get_available_models(self) -> List[AIModelInfo]:
        return [AIModelInfo(**model) for model in self.AVAILABLE_MODELS]

    async def get_installed_models(self, db: Session | None = None) -> List[str]:
        """Get list of models currently installed in Ollama."""
        config = None
        if db:
            config = await run_in_threadpool(self._ensure_config, db)

        for ollama_url in self._ollama_url_candidates(config):
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{ollama_url}/api/tags")
                    if response.status_code == 200:
                        data = response.json()
                        models = data.get("models", [])
                        if config is not None and config.ollama_url != ollama_url:
                            config.ollama_url = ollama_url

                            def update():
                                db.commit()

                            await run_in_threadpool(update)
                        # Return list of model names (e.g., "qwen2.5:3b")
                        return [m.get("name", "") for m in models if m.get("name")]
            except Exception as exc:
                logger.error(
                    "Failed to get installed models for %s: %s", ollama_url, exc
                )
        return []

    async def get_status(self, db: Session) -> AIInstallStatus:
        """Get AI installation status."""
        config = await run_in_threadpool(self._ensure_config, db)
        return self._config_to_status(config)

    async def check_health(self, db: Session) -> bool:
        """Check if Ollama is running and accessible."""
        config = await run_in_threadpool(self._ensure_config, db)
        for ollama_url in self._ollama_url_candidates(config):
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    response = await client.get(f"{ollama_url}/api/version")
                    if response.status_code != 200:
                        raise RuntimeError(f"Ollama health HTTP {response.status_code}")

                    config.last_health_check = utc_now()
                    if config.ollama_url != ollama_url:
                        config.ollama_url = ollama_url

                    # Best-effort model list (do not fail health if tags is unavailable)
                    model_present: bool | None = None
                    try:
                        tags = await client.get(f"{ollama_url}/api/tags")
                        if tags.status_code == 200:
                            data = tags.json()
                            models = data.get("models", [])
                            model_names = [m.get("name", "") for m in models]

                            # If Ollama has our model, mark as installed
                            if config.model_name:
                                model_present = any(
                                    config.model_name in name for name in model_names
                                )
                                if model_present:
                                    config.is_installed = True
                                    config.installed_at = (
                                        config.installed_at or utc_now()
                                    )
                                else:
                                    config.is_installed = False
                                    config.installed_at = None

                            logger.info(
                                "Ollama health check passed, models: %s", model_names
                            )
                        else:
                            logger.warning(
                                "Ollama tags endpoint returned %s for %s",
                                tags.status_code,
                                ollama_url,
                            )
                    except Exception as exc:
                        logger.warning(
                            "Ollama tags check failed for %s: %s", ollama_url, exc
                        )

                    if model_present is not None:
                        if model_present:
                            config.status = "ready"
                        elif config.status != "installing":
                            config.status = "not_installed"

                    def commit():
                        db.commit()

                    await run_in_threadpool(commit)
                    return True
            except Exception as exc:
                logger.error("Ollama health check failed for %s: %s", ollama_url, exc)

        config.status = "error"

        def commit_error():
            db.commit()

        await run_in_threadpool(commit_error)
        return False

    async def ensure_model_ready(self, db: Session) -> tuple[bool, str]:
        """Check that Ollama is running and the configured model exists."""
        config = await run_in_threadpool(self._ensure_config, db)
        if not await self.check_health(db):
            return False, "Ollama is not responding"

        model_name = self._validate_model_name(config.model_name)
        installed_models = await self.get_installed_models(db)
        model_present = any(model_name in name for name in installed_models)
        if model_present:
            if not config.is_installed or config.status != "ready":
                config.is_installed = True
                config.status = "ready"
                config.installed_at = config.installed_at or utc_now()

                def commit():
                    db.commit()

                await run_in_threadpool(commit)
            return True, "ready"

        if config.status != "installing":
            config.is_installed = False
            config.status = "not_installed"
            config.installed_at = None

            def commit():
                db.commit()

            await run_in_threadpool(commit)
        return False, f"Model {model_name} is not installed"

    # --------------------------------------------------------------------- #
    # Installation / configuration
    # --------------------------------------------------------------------- #
    async def _install_ollama(
        self, force_install: bool = False
    ) -> AsyncGenerator[str, None]:
        """Install Ollama if not present (or forced) and ensure keys are generated."""
        # Check if ollama is already installed
        if self._ollama_binary_exists() and not force_install:
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 100,
                        "message": "✅ Ollama already installed",
                    }
                )
                + "\n"
            )
        else:
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 1,
                        "message": "📥 Installing Ollama... This may take a few minutes",
                    }
                )
                + "\n"
            )

            # Install ollama using installer service (runs outside backend sandbox)
            job_id = create_install_job("services/ai.sh", ["install"])
            log_path = get_installer_log_path(job_id)

            def _read_log_chunk(path: Path, offset: int) -> tuple[str, int]:
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        data = handle.read()
                        return data, handle.tell()
                except FileNotFoundError:
                    return "", offset

            install_task = asyncio.create_task(
                asyncio.to_thread(start_install_job, job_id, 1800)
            )

            last_pos = 0
            last_progress = 1
            while not install_task.done():
                chunk, last_pos = await asyncio.to_thread(
                    _read_log_chunk, log_path, last_pos
                )
                if chunk:
                    for line in chunk.splitlines():
                        decoded = line.strip()
                        if decoded:
                            percent_match = re.search(r"(\d{1,3}(?:\.\d+)?)%", decoded)
                            if percent_match:
                                try:
                                    pct = float(percent_match.group(1))
                                    if 0 <= pct <= 100:
                                        mapped_int = int(round(pct))
                                        if mapped_int > last_progress:
                                            last_progress = mapped_int
                                            yield (
                                                json.dumps(
                                                    {
                                                        "type": "progress",
                                                        "percent": last_progress,
                                                        "message": "⬇️ Downloading Ollama...",
                                                    }
                                                )
                                                + "\n"
                                            )
                                except ValueError:
                                    pass
                            yield json.dumps({"type": "log", "message": decoded}) + "\n"
                await asyncio.sleep(0.5)

            # Drain any remaining output
            chunk, last_pos = await asyncio.to_thread(
                _read_log_chunk, log_path, last_pos
            )
            if chunk:
                for line in chunk.splitlines():
                    decoded = line.strip()
                    if decoded:
                        percent_match = re.search(r"(\d{1,3}(?:\.\d+)?)%", decoded)
                        if percent_match:
                            try:
                                pct = float(percent_match.group(1))
                                if 0 <= pct <= 100:
                                    mapped_int = int(round(pct))
                                    if mapped_int > last_progress:
                                        last_progress = mapped_int
                                        yield (
                                            json.dumps(
                                                {
                                                    "type": "progress",
                                                    "percent": last_progress,
                                                    "message": "⬇️ Downloading Ollama...",
                                                }
                                            )
                                            + "\n"
                                        )
                            except ValueError:
                                pass
                        yield json.dumps({"type": "log", "message": decoded}) + "\n"

            try:
                result = await install_task
            except Exception as e:
                raise Exception(f"Ollama installation timed out: {e}")

            if result.returncode != 0:
                log_tail = read_installer_log(job_id)
                raise Exception(
                    f"Ollama installation failed: {log_tail or result.stderr or result.stdout or 'unknown error'}"
                )

            if not self._get_ollama_binary():
                # Wait briefly for filesystem to settle / PATH update
                for _ in range(10):
                    await asyncio.sleep(1)
                    if self._get_ollama_binary():
                        break
                if not self._get_ollama_binary():
                    raise Exception("Ollama binary not found after install")

            if last_progress < 100:
                yield (
                    json.dumps(
                        {
                            "type": "progress",
                            "percent": 100,
                            "message": "✅ Ollama installed successfully",
                        }
                    )
                    + "\n"
                )

        yield (
            json.dumps(
                {"type": "progress", "percent": 100, "message": "✅ Ollama ready"}
            )
            + "\n"
        )

    async def _pull_model_direct(
        self, model_name: str, model_size_gb: float
    ) -> AsyncGenerator[str, None]:
        """Pull model directly using ollama CLI with real-time progress parsing."""
        import re

        yield (
            json.dumps(
                {"type": "log", "message": f"📦 Downloading model: {model_name}"}
            )
            + "\n"
        )
        yield (
            json.dumps(
                {
                    "type": "progress",
                    "percent": 30,
                    "message": "📦 Starting download...",
                }
            )
            + "\n"
        )

        ollama_bin = self._get_ollama_binary()
        if not ollama_bin:
            raise Exception("Ollama binary not found")

        # Use stdbuf to disable buffering for real-time output
        try:
            process = await asyncio.create_subprocess_exec(
                "stdbuf",
                "-oL",
                "-eL",
                ollama_bin,
                "pull",
                model_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )
        except FileNotFoundError:
            process = await asyncio.create_subprocess_exec(
                ollama_bin,
                "pull",
                model_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
                env={**os.environ, "PYTHONUNBUFFERED": "1"},
            )

        last_percent = 0
        last_update_time = 0
        last_line = ""

        if process.stdout:
            buffer = b""
            while True:
                try:
                    # Read in larger chunks with timeout
                    chunk = await asyncio.wait_for(
                        process.stdout.read(4096), timeout=1.0
                    )
                    if not chunk:
                        break
                    buffer += chunk
                except asyncio.TimeoutError:
                    # Process buffer even on timeout
                    if process.returncode is not None:
                        break
                    # Continue waiting if process is still running
                    if not buffer:
                        continue

                # Decode and process
                text = buffer.decode("utf-8", errors="replace")
                buffer = b""

                # Split on newline, carriage return, or just process if buffer too large
                lines = re.split(r"[\r\n]+", text)

                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    last_line = line
                    handled = False

                    # Parse ollama pull output
                    if "pulling manifest" in line.lower():
                        yield (
                            json.dumps(
                                {"type": "log", "message": "📋 Pulling manifest..."}
                            )
                            + "\n"
                        )
                        handled = True
                        continue

                    if "verifying" in line.lower():
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 95,
                                    "message": "🔍 Verifying...",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "model_progress",
                                    "percent": 99,
                                    "downloaded": f"{model_size_gb:.1f} GB",
                                    "total": f"{model_size_gb:.1f} GB",
                                    "speed": "",
                                    "message": "🔍 Verifying...",
                                }
                            )
                            + "\n"
                        )
                        handled = True
                        continue

                    if "writing manifest" in line.lower():
                        yield (
                            json.dumps(
                                {"type": "log", "message": "📝 Writing manifest..."}
                            )
                            + "\n"
                        )
                        handled = True
                        continue

                    if line.lower() == "success":
                        yield (
                            json.dumps(
                                {
                                    "type": "progress",
                                    "percent": 100,
                                    "message": "✅ Download complete!",
                                }
                            )
                            + "\n"
                        )
                        yield (
                            json.dumps(
                                {
                                    "type": "model_progress",
                                    "percent": 100,
                                    "downloaded": f"{model_size_gb:.1f} GB",
                                    "total": f"{model_size_gb:.1f} GB",
                                    "speed": "",
                                    "message": "✅ Complete!",
                                }
                            )
                            + "\n"
                        )
                        handled = True
                        continue

                    # Parse progress line: "pulling abc123... 78% ▕████▏ 3.5 GB/4.7 GB 15 MB/s"
                    percent_match = re.search(r"(\d+)%", line)
                    if percent_match:
                        percent = int(percent_match.group(1))

                        # Throttle updates - max once per 0.5 seconds
                        import time

                        current_time = time.time()
                        if current_time - last_update_time < 0.5 and percent < 100:
                            continue
                        last_update_time = current_time

                        # Parse sizes: "3.5 GB/4.7 GB" or "350 MB/4.7 GB"
                        size_match = re.search(
                            r"([\d.]+\s*[KMGT]?B)\s*/\s*([\d.]+\s*[KMGT]?B)", line
                        )
                        downloaded = ""
                        total = ""
                        if size_match:
                            downloaded = size_match.group(1)
                            total = size_match.group(2)
                        else:
                            # Fallback calculation
                            downloaded_gb = (percent / 100) * model_size_gb
                            downloaded = (
                                f"{downloaded_gb:.1f} GB"
                                if downloaded_gb >= 1
                                else f"{int(downloaded_gb * 1024)} MB"
                            )
                            total = f"{model_size_gb:.1f} GB"

                        # Parse speed: "15 MB/s"
                        speed_match = re.search(r"([\d.]+\s*[KMGT]?B/s)", line)
                        speed = speed_match.group(1) if speed_match else ""

                        # Only update if progress increased
                        if percent >= last_percent:
                            last_percent = percent

                            # Scale 30-95% for model download
                            overall_percent = 30 + int(percent * 0.65)

                            message = f"⬇️ {downloaded}"
                            if total:
                                message += f" / {total}"
                            if speed:
                                message += f" ({speed})"

                            yield (
                                json.dumps(
                                    {
                                        "type": "model_progress",
                                        "percent": percent,
                                        "downloaded": downloaded,
                                        "total": total,
                                        "speed": speed,
                                        "message": message,
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
                                    }
                                )
                                + "\n"
                            )
                        handled = True
                        continue

                    if not handled:
                        yield json.dumps({"type": "log", "message": line}) + "\n"

        await process.wait()

        if process.returncode != 0:
            detail = f": {last_line}" if last_line else ""
            raise Exception(
                f"Model download failed with code {process.returncode}{detail}"
            )

    async def install(
        self,
        db: Session,
        model_name: Optional[str] = None,
        temperature: Optional[float] = None,
        system_prompt: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """Install Ollama and a model (streaming logs) - Direct version without intermediate script."""
        if self.active_installation:
            yield (
                json.dumps(
                    {"type": "error", "message": "Installation already in progress"}
                )
                + "\n"
            )
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

            # Stage 1: Initialization
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 0,
                        "message": "🚀 Starting AI installation...",
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

            # Stage 2: Install Ollama (0-25%)
            try:
                async for msg in self._install_ollama():
                    yield msg
            except Exception as e:
                yield (
                    json.dumps(
                        {
                            "type": "error",
                            "message": f"❌ Ollama installation failed: {e}",
                        }
                    )
                    + "\n"
                )
                config.status = "error"
                db.commit()
                return

            # Ensure Ollama service is running before pulling model
            ok, msg = await self._ensure_ollama_running(db)
            if not ok:
                yield (
                    json.dumps(
                        {"type": "error", "message": f"❌ Ollama not running: {msg}"}
                    )
                    + "\n"
                )
                config.status = "error"
                db.commit()
                return

            # Stage 3: Pull model directly (25-95%)
            try:
                async for msg in self._pull_model_direct(selected_model, model_size_gb):
                    yield msg
            except Exception as e:
                yield (
                    json.dumps(
                        {"type": "error", "message": f"❌ Model download failed: {e}"}
                    )
                    + "\n"
                )
                config.status = "error"
                db.commit()
                return

            # Stage 4: Verification (95-100%)
            yield (
                json.dumps(
                    {
                        "type": "progress",
                        "percent": 98,
                        "message": "🔍 Verifying installation...",
                    }
                )
                + "\n"
            )

            # Check if model is available
            installed_models = await self.get_installed_models()
            if any(selected_model in m for m in installed_models):
                yield (
                    json.dumps(
                        {
                            "type": "progress",
                            "percent": 100,
                            "message": "🎉 Installation completed!",
                        }
                    )
                    + "\n"
                )
                yield (
                    json.dumps({"type": "log", "message": "✅ AI is ready to use!"})
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
                        {"type": "error", "message": "❌ Model verification failed"}
                    )
                    + "\n"
                )
                config.status = "error"
                db.commit()

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
