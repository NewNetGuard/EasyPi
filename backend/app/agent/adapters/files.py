"""File manager fact adapter."""

from __future__ import annotations

import os
import shutil
from typing import Any

from fastapi import HTTPException

from app.services.files_service import FilesService


class FilesAdapter:
    """Expose read-only file manager state."""

    def __init__(self, service: Any | None = None) -> None:
        self.service = service or FilesService()

    def is_safe_path(self, path: str) -> bool:
        return bool(self.service._is_path_safe(path))

    def get_path_info(self, path: str) -> dict[str, Any]:
        resolved = os.path.abspath(path)
        return {
            "path": resolved,
            "exists": os.path.exists(resolved),
            "is_dir": os.path.isdir(resolved),
            "is_file": os.path.isfile(resolved),
            "safe": self.is_safe_path(resolved),
        }

    def get_write_target_info(self, path: str) -> dict[str, Any]:
        resolved = os.path.abspath(path)
        target_exists = os.path.exists(resolved)
        parent = resolved if os.path.isdir(resolved) else (os.path.dirname(resolved) or resolved)
        parent_exists = os.path.exists(parent)
        writable_target = resolved if target_exists else parent
        writable = os.access(writable_target, os.W_OK) if parent_exists else False
        return {
            "path": resolved,
            "parent": parent,
            "parent_exists": parent_exists,
            "writable": writable,
            "requires_sudo": parent_exists and not writable,
        }

    def list_directory(self, path: str = "/home") -> list[dict[str, Any]]:
        try:
            result = self.service.list_directory(path)
            return [item for item in result if isinstance(item, dict)]
        except HTTPException:
            raise

    def read_file(self, path: str) -> dict[str, Any]:
        try:
            result = self.service.read_file(path)
            return result if isinstance(result, dict) else {}
        except HTTPException:
            raise

    def search_files(self, query: str, root_path: str = "/home", limit: int = 50) -> list[dict[str, Any]]:
        try:
            result = self.service.search_files(query, root_path=root_path, limit=limit)
            return [item for item in result if isinstance(item, dict)]
        except HTTPException:
            raise

    def get_disk_usage(self, path: str) -> dict[str, Any]:
        resolved = os.path.abspath(path)
        total, used, free = shutil.disk_usage(resolved if os.path.exists(resolved) else "/")
        return {
            "total": total,
            "used": used,
            "free": free,
            "used_percent": round((used / total) * 100, 1) if total else 0.0,
        }
