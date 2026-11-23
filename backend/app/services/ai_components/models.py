"""AIModelsMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from tempfile import gettempdir

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


def _ollama_progress_files() -> tuple[Path, ...]:
    """Return only literal Ollama progress files from the system temp directory."""
    temp_root = Path(gettempdir()).resolve()
    matches: list[Path] = []
    for candidate in temp_root.glob("ollama_progress_*"):
        if candidate.parent.resolve() != temp_root:
            continue
        if candidate.is_file() or candidate.is_symlink():
            matches.append(candidate)
    return tuple(sorted(matches, key=str))


class AIModelsMixin:
    async def delete_model(self, db: Session) -> AsyncGenerator[str, None]:
        """Delete only the AI model, keep Ollama installed."""
        config = self._ensure_config(db)
        model_name = config.model_name

        if not model_name:
            yield "❌ Model not installed\n"
            return

        try:
            yield f"🗑️ Deleting model {model_name}...\n"

            # Use ollama rm command to remove the model
            # Try with full path first, then fallback
            ollama_paths = ["/usr/local/bin/ollama", "/usr/bin/ollama", "ollama"]
            ollama_bin = None
            for path in ollama_paths:
                if os.path.exists(path) or path == "ollama":
                    ollama_bin = path
                    break

            if not ollama_bin:
                ollama_bin = "ollama"

            yield f"Using: {ollama_bin}\n"

            process = await asyncio.create_subprocess_exec(
                ollama_bin,
                "rm",
                model_name,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )

            if process.stdout:
                async for line in process.stdout:
                    decoded = line.decode("utf-8").strip()
                    if decoded:
                        yield f"{decoded}\n"

            return_code = await process.wait()

            if return_code == 0:
                yield f"✅ Model {model_name} deleted successfully\n"

                # Get model path for info
                user = os.getenv("USER", "root")
                if user == "root":
                    model_path = "/usr/share/ollama/.ollama/models"
                else:
                    model_path = f"/home/{user}/.ollama/models"

                yield f"📁 Models folder: {model_path}\n"

                # Clear conversation history for this model
                yield "🧹 Clearing chat history...\n"
                db.query(AIConversation).delete()
                db.commit()
                yield "✅ History cleared\n"

                # Update config - model removed but Ollama still installed
                config.is_installed = False
                config.status = "not_installed"
                config.installed_at = None
                db.commit()

                yield "\n🎉 Model completely deleted! Ollama remains installed.\n"
                logger.info("Model %s deleted successfully", model_name)
            else:
                yield f"❌ Model deletion error (code {return_code})\n"
                logger.error("Model deletion failed with code %s", return_code)

        except Exception as exc:
            yield f"❌ Error: {exc}\n"
            logger.error("Model deletion error: %s", exc)

    # --------------------------------------------------------------------- #
    # Uninstall
    # --------------------------------------------------------------------- #
    async def uninstall(self, db: Session) -> AsyncGenerator[str, None]:
        """Uninstall Ollama and remove all AI data."""
        config = self._ensure_config(db)
        try:
            if (
                self.active_installation
                or config.status == "installing"
                or self._read_install_lock()
            ):
                yield "✗ Installation is in progress. Cancel it and try uninstall again.\n"
                return
            config.status = "uninstalling"
            db.commit()

            yield "Starting AI uninstallation...\n"

            job_id = create_install_job("services/ai.sh", ["uninstall"])
            log_path = get_installer_log_path(job_id)

            def _read_log_chunk(path: Path, offset: int) -> tuple[str, int]:
                try:
                    with path.open("r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        data = handle.read()
                        return data, handle.tell()
                except FileNotFoundError:
                    return "", offset

            uninstall_task = asyncio.create_task(
                asyncio.to_thread(start_install_job, job_id, 1800)
            )

            last_pos = 0
            while not uninstall_task.done():
                chunk, last_pos = await asyncio.to_thread(
                    _read_log_chunk, log_path, last_pos
                )
                if chunk:
                    for line in chunk.splitlines():
                        decoded = line.strip()
                        if decoded:
                            yield f"{decoded}\n"
                await asyncio.sleep(0.5)

            chunk, last_pos = await asyncio.to_thread(
                _read_log_chunk, log_path, last_pos
            )
            if chunk:
                for line in chunk.splitlines():
                    decoded = line.strip()
                    if decoded:
                        yield f"{decoded}\n"

            try:
                result = await uninstall_task
            except subprocess.TimeoutExpired:
                raise Exception("Ollama uninstall timed out")

            if result.returncode != 0:
                log_tail = read_installer_log(job_id)
                raise Exception(
                    log_tail or result.stderr or result.stdout or "Uninstall failed"
                )

            yield "Clearing conversation history...\n"
            db.query(AIConversation).delete()
            db.commit()
            yield "✓ History cleared\n"

            config.is_installed = False
            config.status = "not_installed"
            config.installed_at = None
            config.last_health_check = None
            db.commit()

            yield "\n✓ AI Assistant uninstalled successfully!\n"
            logger.info("AI uninstallation completed successfully")
        except Exception as exc:
            yield f"\n✗ Uninstallation error: {exc}\n"
            logger.error("AI uninstallation error: %s", exc)
            config.status = "error"
            db.commit()

    # --------------------------------------------------------------------- #
    # Cancel Installation
    # --------------------------------------------------------------------- #
    async def cancel_install(self, db: Session) -> dict:
        """Cancel ongoing installation and clean up downloaded files."""
        config = self._ensure_config(db)
        killed_processes = []
        cleaned_paths = []

        try:
            logger.info("Cancelling installation...")

            use_sudo = False
            try:
                use_sudo = await self._sudo_available()
            except FileNotFoundError:
                use_sudo = False
            sudo_prefix = ["sudo", "-n"] if use_sudo else []

            # 1. Kill any ollama pull processes (specific to pull operation)
            process = await asyncio.create_subprocess_exec(
                *sudo_prefix,
                "pkill",
                "-TERM",
                "-f",
                "ollama pull",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await process.wait()
            killed_processes.append("ollama pull")

            # Give it a moment to terminate gracefully
            await asyncio.sleep(1)

            # 2. Force kill if still running
            process = await asyncio.create_subprocess_exec(
                *sudo_prefix,
                "pkill",
                "-9",
                "-f",
                "ollama pull",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await process.wait()

            # 3. Kill any curl downloads for ollama
            process = await asyncio.create_subprocess_exec(
                *sudo_prefix,
                "pkill",
                "-9",
                "-f",
                "curl.*ollama",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            await process.wait()
            killed_processes.append("curl")

            # 4. Clean up partial downloads in model directories
            home_dir = Path.home()
            model_dirs = [
                "/usr/share/ollama",
                str(home_dir / ".ollama"),
                "/root/.ollama",
            ]

            for dir_path in model_dirs:
                # Only remove blobs (partial downloads), not entire models folder
                process = await asyncio.create_subprocess_exec(
                    *sudo_prefix,
                    "rm",
                    "-rf",
                    f"{dir_path}/models/blobs",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                await process.wait()
                cleaned_paths.append(f"{dir_path}/models/blobs")

            # 5. Clean up literal temp progress paths. create_subprocess_exec does
            # not expand globs, so resolve the bounded system-temp matches first.
            for progress_path in _ollama_progress_files():
                process = await asyncio.create_subprocess_exec(
                    *sudo_prefix,
                    "rm",
                    "-f",
                    "--",
                    str(progress_path),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                if await process.wait() == 0:
                    cleaned_paths.append(str(progress_path))

            # 6. Reset installation state
            config.status = "not_installed"
            config.is_installed = False
            db.commit()

            logger.info("Installation cancelled successfully")

            return {
                "success": True,
                "message": "Installation cancelled and files cleaned up",
                "killed_processes": killed_processes,
                "cleaned_paths": cleaned_paths,
            }

        except Exception as exc:
            logger.error("Error cancelling installation: %s", exc)
            return {
                "success": False,
                "message": str(exc),
                "killed_processes": killed_processes,
                "cleaned_paths": cleaned_paths,
            }
        finally:
            self.active_installation = False
            self._clear_install_lock()
