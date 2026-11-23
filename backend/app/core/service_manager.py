from __future__ import annotations

import json
import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from config import get_settings

from app.core.service_catalog import ServiceCatalog
from app.schemas.service import (
    ServiceLinks,
    ServiceRequirements,
    ServiceResponse,
    ServiceStatus,
)

logger = logging.getLogger(__name__)

_settings = get_settings()

LOCAL_SCRIPTS_DIR = _settings.SCRIPTS_ROOT / "services"
MAX_OUTPUT_BYTES = 64 * 1024  # output limit (64KB)


class ServiceManager:
    """Manage shell-based service scripts."""

    def __init__(
        self,
        scripts_dir: Optional[Path] = None,
        execution_root: Optional[Path] = None,
        runner_path: Optional[Path] = None,
        catalog: Optional[ServiceCatalog] = None,
    ) -> None:
        self.scripts_dir = scripts_dir or LOCAL_SCRIPTS_DIR
        self.execution_root = execution_root or (_settings.SCRIPTS_ROOT / "services")
        self.runner_path = runner_path or _settings.RUNNER_PATH
        self.catalog = catalog or ServiceCatalog()

    # ------------------------------------------------------------------ public API

    def get_available_services(self) -> List[ServiceResponse]:
        services: List[ServiceResponse] = []
        for entry in self.catalog.all():
            # Fast load without status check
            services.append(self._build_response(entry, skip_status=True))
        return services

    def get_service(self, slug: str) -> ServiceResponse:
        entry = self.catalog.get(slug)
        if entry is None:
            raise FileNotFoundError(f"Service metadata not found for {slug}")
        return self._build_response(entry)

    def install_service(self, name: str, options: Optional[Dict[str, object]] = None) -> str:
        script = self._ensure_script(name)
        env = self._env_with_options(options)
        return self._run_script(script, "install", env)

    def uninstall_service(self, name: str) -> str:
        script = self._ensure_script(name)
        return self._run_script(script, "uninstall")

    def restart_service(self, name: str) -> str:
        script = self._ensure_script(name)
        return self._run_script(script, "restart")

    def start_service(self, name: str) -> str:
        script = self._ensure_script(name)
        return self._run_script(script, "start")

    def stop_service(self, name: str) -> str:
        script = self._ensure_script(name)
        return self._run_script(script, "stop")

    def get_service_status(self, name: str) -> ServiceStatus:
        script = self._ensure_script(name)
        output = self._run_script(script, "status", check=False)

        # try to parse JSON payload from script output
        status_data: Dict[str, Any]
        try:
            status_data = json.loads(output)
        except json.JSONDecodeError:
            status_data = {
                "running": False,
                "installed": False,
                "uptime": None,
                "cpu": None,
                "ram": None,
                "raw_output": output,
            }
        else:
            state_value = status_data.get("state") or status_data.get("status")
            if state_value is not None:
                status_data["state"] = state_value
            if "installed" not in status_data:
                status_data["installed"] = bool(status_data.get("running"))
            ports_value = status_data.get("ports")
            if isinstance(ports_value, str):
                try:
                    status_data["ports"] = json.loads(ports_value)
                except json.JSONDecodeError:
                    status_data["ports"] = [ports_value]

        return ServiceStatus(**status_data)

    def get_service_logs(self, name: str, tail: int = 200) -> str:
        script = self._ensure_script(name)
        env = {"SERVICE_OPTION_TAIL": str(tail)}
        return self._run_script(script, "logs", env, check=False)

    # ------------------------------------------------------------------ helpers

    def _ensure_script(self, name: str) -> Path:
        script = self.scripts_dir / f"{name}.sh"
        if not script.exists():
            raise FileNotFoundError(f"Service script not found: {script}")
        return script

    def _build_response(self, metadata: Dict[str, Any], skip_status: bool = False) -> ServiceResponse:
        slug = metadata.get("id")
        if not slug:
            raise ValueError("Service metadata entry missing id")

        # Skip status check for list (fast load)
        status = None if skip_status else self._safe_status(slug)
        requirements = metadata.get("requirements") or {}
        links = metadata.get("links") or {}

        return ServiceResponse(
            slug=slug,
            name=metadata.get("name", slug.title()),
            description=metadata.get("description"),
            category=metadata.get("category"),
            icon=metadata.get("icon"),
            version=metadata.get("version"),
            features=metadata.get("features", []),
            requirements=ServiceRequirements(**requirements) if requirements else None,
            links=ServiceLinks(**links) if links else None,
            installed=bool(status.installed) if status else False,
            running=bool(status.running) if status else False,
            status=status.state if status else None,
            ports=status.ports if status and status.ports else requirements.get("ports"),
            metrics=status,
        )

    def _safe_status(self, slug: str) -> Optional[ServiceStatus]:
        try:
            return self.get_service_status(slug)
        except FileNotFoundError:
            return None

    def get_all_statuses(self, slugs: Optional[List[str]] = None, workers: int = 4) -> Dict[str, Optional[ServiceStatus]]:
        """Return statuses for multiple services using a thread pool to run checks in parallel.

        If `slugs` is None, checks all services from the catalog. The method returns a
        mapping from slug -> ServiceStatus or None on error.
        """
        if slugs is None:
            slugs = [entry.get("id") for entry in self.catalog.all()]

        results: Dict[str, Optional[ServiceStatus]] = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            future_map = {ex.submit(self._safe_status, slug): slug for slug in slugs}
            for future in as_completed(future_map):
                slug = future_map[future]
                try:
                    results[slug] = future.result()
                except Exception:
                    logger.exception("Failed to get status for %s", slug)
                    results[slug] = None

        return results

    def _run_script(
        self,
        script: Path,
        action: str,
        env: Optional[Dict[str, str]] = None,
        check: bool = True,
    ) -> str:
        execution_script = self._execution_path(script)
        command = ["sudo", str(self.runner_path), str(execution_script)]
        if action:
            command.append(action)
        resolved_env = os.environ.copy()
        if env:
            resolved_env.update(env)

        logger.debug("Executing service script: %s", shlex.join(command))

        try:
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=resolved_env,
                text=True,
                check=check,
                timeout=60,
            )
            output = result.stdout or ""
        except subprocess.CalledProcessError as exc:
            output = exc.stdout or exc.stderr or ""
            logger.warning("Service script %s failed: %s", script, output.strip())
            if check:
                detail = self._truncate_output(output).strip() or f"exit code {exc.returncode}"
                raise RuntimeError(f"Service script {script.name} failed: {detail}") from exc
        except FileNotFoundError as exc:
            logger.error("bash not found: %s", exc)
            if check:
                raise RuntimeError("Runner executable not available") from exc
            return ""
        except subprocess.TimeoutExpired as exc:
            logger.warning("Service script %s timed out", script)
            if check:
                raise RuntimeError(f"Service script {script.name} timed out") from exc
            return self._truncate_output(exc.output or "")
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("Unexpected error running %s: %s", script, exc)
            if check:
                raise RuntimeError(f"Service script {script} failed") from exc
            return ""

        return self._truncate_output(output)

    @staticmethod
    def _env_with_options(options: Optional[Dict[str, object]]) -> Dict[str, str]:
        if not options:
            return {}
        env: Dict[str, str] = {}
        for key, value in options.items():
            env[f"SERVICE_OPTION_{key.upper()}"] = str(value)
        return env

    @staticmethod
    def _truncate_output(output: str, limit: int = MAX_OUTPUT_BYTES) -> str:
        encoded = output.encode("utf-8", errors="ignore")
        if len(encoded) <= limit:
            return output
        truncated = encoded[:limit]
        return truncated.decode("utf-8", errors="ignore") + "\n...[truncated]..."

    def _execution_path(self, script: Path) -> Path:
        try:
            relative = script.relative_to(self.scripts_dir)
        except ValueError:  # pragma: no cover - defensive
            relative = Path(script.name)
        return self.execution_root / relative


__all__ = ["ServiceManager"]
