"""Shared validation and atomic persistence for Cloud file tags."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Iterable

MAX_TAGS_PER_FILE = 20
MAX_TAG_LENGTH = 32


def normalize_cloud_tags(values: Iterable[str]) -> list[str]:
    """Return a bounded, unique tag list suitable for display and storage."""
    normalized: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        if not isinstance(raw_value, str):
            raise ValueError("Every tag must be text")
        value = " ".join(raw_value.strip().split())
        if not value:
            continue
        if len(value) > MAX_TAG_LENGTH:
            raise ValueError(f"Tags cannot exceed {MAX_TAG_LENGTH} characters")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("Tags cannot contain control characters")
        key = value.casefold()
        if key in seen:
            continue
        seen.add(key)
        normalized.append(value)
        if len(normalized) > MAX_TAGS_PER_FILE:
            raise ValueError(f"A file can have at most {MAX_TAGS_PER_FILE} tags")
    return normalized


def load_cloud_tag_map(path: Path) -> dict[str, list[str]]:
    """Load only valid tag-map entries; malformed metadata fails closed to empty."""
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(raw, dict):
        return {}

    result: dict[str, list[str]] = {}
    for file_id, tags in raw.items():
        if not isinstance(file_id, str) or not isinstance(tags, list):
            continue
        try:
            result[file_id] = normalize_cloud_tags(tags)
        except ValueError:
            continue
    return result


def save_cloud_tag_map(path: Path, data: dict[str, list[str]]) -> None:
    """Atomically replace tag metadata with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
