from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

from app.core.paths import get_easypi_root

MAX_FILE_BYTES = 8 * 1024 * 1024


class FileManager:
    """Utility class for safe filesystem interactions."""

    FORBIDDEN_PATHS = {
        Path("/etc/shadow"),
        Path("/root"),
        Path("/boot"),
        Path("/sys"),
        Path("/proc"),
    }

    def __init__(self, safe_mode: bool = True, base_dir: Path | None = None) -> None:
        self.safe_mode = safe_mode
        if base_dir is None:
            base_dir = get_easypi_root()
        self.base_dir = base_dir.resolve()

    def list_dir(self, path: str = ".") -> list[dict]:
        folder = self._resolve_path(path)
        if not folder.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {folder}")

        entries: list[dict] = []
        for entry in folder.iterdir():
            if self.safe_mode and entry.name.startswith("."):
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue

            entries.append(
                {
                    "name": entry.name,
                    "path": str(entry),
                    "is_dir": entry.is_dir(),
                    "size": stat.st_size,
                    "modified": stat.st_mtime,
                }
            )

        entries.sort(key=lambda item: (not item["is_dir"], item["name"].lower()))
        return entries

    def read_file(self, path: str) -> str:
        file_path = self._resolve_path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found: {file_path}")
        if file_path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError(f"File is too large to read: {file_path}")
        try:
            with file_path.open("r", encoding="utf-8") as source:
                return source.read(MAX_FILE_BYTES + 1)
        except UnicodeDecodeError:
            raise ValueError(f"Unable to decode file as UTF-8: {file_path}") from None

    def write_file(self, path: str, content: str) -> None:
        file_path = self._resolve_path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(content, encoding="utf-8")

    def delete(self, path: str) -> None:
        target = self._resolve_path(path)
        if target.is_dir():
            for child in target.glob("**/*"):
                self._check_forbidden(child)
            for child in sorted(target.glob("**/*"), reverse=True):
                try:
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                except OSError:
                    continue
            target.rmdir()
        elif target.exists():
            target.unlink()

    def mkdir(self, path: str) -> None:
        directory = self._resolve_path(path)
        directory.mkdir(parents=True, exist_ok=True)

    def upload(self, file: BinaryIO | bytes, dest: str) -> None:
        destination = self._resolve_path(dest)
        destination.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(file, bytes):
            data = file
        else:
            if hasattr(file, "seek"):
                file.seek(0)
            data = file.read(MAX_FILE_BYTES + 1)
            if not isinstance(data, (bytes, bytearray)):
                raise ValueError("Uploaded file must provide bytes data")

        if len(data) > MAX_FILE_BYTES:
            raise ValueError("Uploaded file is too large")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(destination, flags, 0o644)
        with os.fdopen(fd, "wb") as output:
            output.write(data)

    # ------------------------------------------------------------------ helpers

    def _resolve_path(self, path: str) -> Path:
        candidate = Path(path).expanduser()
        if not candidate.is_absolute():
            candidate = (self.base_dir / candidate).resolve()
        else:
            candidate = candidate.resolve()

        try:
            candidate.relative_to(self.base_dir)
        except ValueError:
            raise PermissionError(f"Path outside allowed directory: {candidate}")

        self._check_forbidden(candidate)
        return candidate

    def _check_forbidden(self, path: Path) -> None:
        for forbidden in self.FORBIDDEN_PATHS:
            try:
                if path == forbidden or forbidden in path.parents:
                    raise PermissionError(f"Access denied for path: {path}")
            except RuntimeError:
                continue


__all__ = ["FileManager"]
