"""Helpers for treating remote file names as display data, never as paths."""

from __future__ import annotations

import os
from pathlib import Path


def sanitize_upload_filename(value: object, fallback: str = "upload.bin") -> str:
    raw = str(value or "").replace("\x00", "").replace("\\", "/")
    name = raw.rsplit("/", 1)[-1].strip()
    name = "".join(char for char in name if ord(char) >= 32 and ord(char) != 127)
    if name in {"", ".", ".."}:
        name = fallback

    suffix = Path(name).suffix[:32]
    stem_limit = max(1, 240 - len(suffix))
    stem = Path(name).stem[:stem_limit] or "upload"
    return f"{stem}{suffix}"


def unique_upload_path(directory: Path, filename: object, fallback: str = "upload.bin") -> Path:
    safe_name = sanitize_upload_filename(filename, fallback=fallback)
    candidate = directory / safe_name
    stem, suffix = os.path.splitext(safe_name)
    counter = 1
    while os.path.lexists(candidate):
        candidate = directory / f"{stem}_{counter}{suffix}"
        counter += 1
    return candidate
