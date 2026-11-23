"""Descriptor-pinned access to regular files below a trusted storage root."""
from __future__ import annotations

import os
import stat
from pathlib import Path, PurePath
from typing import Iterable


def _parts(relative: str | Path) -> tuple[str, ...]:
    path = PurePath(relative)
    if path.is_absolute() or not path.parts:
        raise OSError("invalid storage path")
    parts = tuple(path.parts)
    if any(part in {"", ".", ".."} or "\x00" in part for part in parts):
        raise OSError("invalid storage path")
    return parts


def _check_suffix(name: str, suffixes: Iterable[str] | None) -> None:
    if suffixes is not None and Path(name).suffix.lower() not in {
        suffix.lower() for suffix in suffixes
    }:
        raise OSError("disallowed storage file type")


def _supports_openat() -> bool:
    return os.open in getattr(os, "supports_dir_fd", set())


def _open_parent(root: Path, parts: tuple[str, ...]) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    current = os.open(root, flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def open_regular_beneath(
    root: str | Path,
    relative: str | Path,
    *,
    suffixes: Iterable[str] | None = None,
) -> tuple[int, os.stat_result]:
    """Open a regular file while pinning every directory below root."""
    root_path = Path(root)
    parts = _parts(relative)
    _check_suffix(parts[-1], suffixes)
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )

    if not _supports_openat():  # Windows development fallback; production is Linux.
        resolved_root = root_path.resolve(strict=True)
        candidate = (resolved_root / Path(*parts)).resolve(strict=True)
        candidate.relative_to(resolved_root)
        fd = os.open(candidate, file_flags)
    else:
        parent_fd = _open_parent(root_path, parts)
        try:
            fd = os.open(parts[-1], file_flags, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)

    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise OSError("storage object is not a regular file")
        return fd, details
    except BaseException:
        os.close(fd)
        raise


def unlink_regular_beneath(
    root: str | Path,
    relative: str | Path,
    *,
    suffixes: Iterable[str] | None = None,
) -> os.stat_result:
    """Delete a regular file through a pinned parent directory."""
    root_path = Path(root)
    parts = _parts(relative)
    _check_suffix(parts[-1], suffixes)

    if not _supports_openat():
        fd, details = open_regular_beneath(root_path, Path(*parts), suffixes=suffixes)
        os.close(fd)
        (root_path.resolve(strict=True) / Path(*parts)).unlink()
        return details

    parent_fd = _open_parent(root_path, parts)
    fd: int | None = None
    try:
        flags = (
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise OSError("storage object is not a regular file")
        current = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (details.st_dev, details.st_ino):
            raise OSError("storage file changed")
        os.unlink(parts[-1], dir_fd=parent_fd)
        return details
    finally:
        if fd is not None:
            os.close(fd)
        os.close(parent_fd)


def rmdir_empty_beneath(root: str | Path, relative: str | Path) -> None:
    """Remove one empty directory through a pinned parent directory."""
    root_path = Path(root)
    parts = _parts(relative)

    if not _supports_openat():
        resolved_root = root_path.resolve(strict=True)
        candidate = (resolved_root / Path(*parts)).resolve(strict=True)
        candidate.relative_to(resolved_root)
        candidate.rmdir()
        return

    parent_fd = _open_parent(root_path, parts)
    child_fd: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        child_fd = os.open(parts[-1], flags, dir_fd=parent_fd)
        if os.listdir(child_fd):
            raise OSError("storage directory is not empty")
        os.rmdir(parts[-1], dir_fd=parent_fd)
    finally:
        if child_fd is not None:
            os.close(child_fd)
        os.close(parent_fd)


__all__ = ["open_regular_beneath", "rmdir_empty_beneath", "unlink_regular_beneath"]
