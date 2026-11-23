#!/usr/bin/env python3
"""Build a private, consistent staging tree for an EasyPi backup."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sqlite3
import stat
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00"
COPY_CHUNK_SIZE = 1024 * 1024
MAC_RE = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def _is_within(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def _is_excluded(path: Path, excludes: tuple[Path, ...]) -> bool:
    return any(path == excluded or _is_within(path, excluded) for excluded in excludes)


def _snapshot_destination(root: Path, source: Path) -> Path:
    """Map one absolute host path below the private staging root."""

    normalized = Path(os.path.abspath(source))
    relative_parts = normalized.parts[1:]
    if not relative_parts:
        raise ValueError("the filesystem root cannot be a backup source")
    return root.joinpath(*relative_parts)


def _open_parent_directory(path: Path) -> tuple[int, str]:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    normalized = Path(os.path.abspath(path))
    parent_fd = os.open("/", directory_flags)
    try:
        for component in normalized.parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        return parent_fd, normalized.name
    except Exception:
        os.close(parent_fd)
        raise


def _open_regular(path: Path) -> int:
    """Open a file without following it or any replaceable parent symlink."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if os.name != "posix":
        return os.open(path, flags)

    parent_fd, name = _open_parent_directory(path)
    try:
        return os.open(name, flags, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _regular_file_header(path: Path) -> bytes:
    fd = _open_regular(path)
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"backup source is not a regular file: {path}")
        return os.read(fd, len(SQLITE_HEADER))
    finally:
        os.close(fd)


def _copy_regular(source: Path, destination: Path) -> None:
    source_fd = _open_regular(source)
    destination_fd: int | None = None
    try:
        details = os.fstat(source_fd)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError(f"backup source is not a regular file: {source}")
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0)
        )
        destination_fd = os.open(destination, destination_flags, 0o600)
        with os.fdopen(source_fd, "rb", closefd=False) as src, os.fdopen(
            destination_fd, "wb", closefd=False
        ) as dst:
            shutil.copyfileobj(src, dst, length=COPY_CHUNK_SIZE)
            dst.flush()
            os.fsync(dst.fileno())
        os.chmod(destination, stat.S_IMODE(details.st_mode))
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)


def _copy_sqlite(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if destination.exists():
        raise FileExistsError(destination)
    parent_fd = -1
    if os.name == "posix":
        parent_fd, name = _open_parent_directory(source)
        # Pin the containing directory so SQLite can safely access the main
        # database and its WAL sidecar through the same directory descriptor.
        sqlite_source = Path(f"/proc/self/fd/{parent_fd}/{name}")
    else:
        sqlite_source = Path(os.path.abspath(source))
    source_uri = f"{sqlite_source.as_uri()}?mode=ro&nofollow=1"
    source_db: sqlite3.Connection | None = None
    destination_db: sqlite3.Connection | None = None
    try:
        source_db = sqlite3.connect(source_uri, uri=True, timeout=30)
        destination_db = sqlite3.connect(destination)
        source_db.backup(destination_db)
        # A staged database must be self-contained; do not leave it configured
        # to expect WAL sidecars that are intentionally excluded from backup.
        destination_db.execute("PRAGMA journal_mode=DELETE")
        result = destination_db.execute("PRAGMA integrity_check").fetchone()
        if result != ("ok",):
            raise ValueError(f"SQLite integrity check failed for {source}")
        destination_db.commit()
    finally:
        if destination_db is not None:
            destination_db.close()
        if source_db is not None:
            source_db.close()
        if parent_fd >= 0:
            os.close(parent_fd)
    os.chmod(destination, 0o600)


def _inventory(source: Path, excludes: tuple[Path, ...]) -> tuple[list[Path], list[Path]]:
    directories: list[Path] = []
    files: list[Path] = []
    if _is_excluded(source, excludes):
        return directories, files
    details = source.lstat()
    if stat.S_ISLNK(details.st_mode):
        raise ValueError(f"backup source may not be a symlink: {source}")
    if stat.S_ISREG(details.st_mode):
        return directories, [source]
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"backup source has an unsupported type: {source}")

    for current, dir_names, file_names in os.walk(source, followlinks=False):
        current_path = Path(current)
        if _is_excluded(current_path, excludes):
            dir_names[:] = []
            continue
        directories.append(current_path)
        kept_dirs: list[str] = []
        for name in sorted(dir_names):
            child = current_path / name
            if _is_excluded(child, excludes):
                continue
            child_details = child.lstat()
            if stat.S_ISLNK(child_details.st_mode):
                raise ValueError(f"backup source may not contain symlinks: {child}")
            if not stat.S_ISDIR(child_details.st_mode):
                raise ValueError(f"backup source has an unsupported type: {child}")
            kept_dirs.append(name)
        dir_names[:] = kept_dirs
        for name in sorted(file_names):
            child = current_path / name
            if _is_excluded(child, excludes):
                continue
            child_details = child.lstat()
            if stat.S_ISLNK(child_details.st_mode):
                raise ValueError(f"backup source may not contain symlinks: {child}")
            if not stat.S_ISREG(child_details.st_mode):
                raise ValueError(f"backup source has an unsupported type: {child}")
            files.append(child)
    return directories, files


def build_snapshot(root: Path, sources: list[Path], excludes: list[Path]) -> None:
    root_details = root.lstat()
    if root.is_symlink() or not stat.S_ISDIR(root_details.st_mode):
        raise ValueError("snapshot root must be a real directory")
    os.chmod(root, 0o700)

    normalized_excludes = tuple(Path(os.path.abspath(path)) for path in excludes)
    all_directories: list[Path] = []
    all_files: list[Path] = []
    for source in sources:
        if not source.is_absolute():
            raise ValueError(f"backup source must be absolute: {source}")
        normalized_source = Path(os.path.abspath(source))
        directories, files = _inventory(normalized_source, normalized_excludes)
        all_directories.extend(directories)
        all_files.extend(files)

    sqlite_files = {
        source for source in all_files if _regular_file_header(source) == SQLITE_HEADER
    }
    sidecars = {
        Path(f"{source}-wal") for source in sqlite_files
    } | {Path(f"{source}-shm") for source in sqlite_files}

    for source in sorted(set(all_directories), key=lambda item: (len(item.parts), str(item))):
        destination = _snapshot_destination(root, source)
        destination.mkdir(parents=True, exist_ok=True, mode=0o700)

    for source in sorted(set(all_files), key=str):
        if source in sidecars:
            continue
        destination = _snapshot_destination(root, source)
        if source in sqlite_files:
            _copy_sqlite(source, destination)
        else:
            _copy_regular(source, destination)


def validate_stealth_snapshot(root: Path) -> None:
    """Reject a backup that captured Chameleon state mid-transition."""

    meta_path = root / "opt/EasyPi/data/netprotection/stealth_meta.json"
    config_path = root / "opt/EasyPi/data/netprotection/stealth_client.conf"
    policy_path = root / "var/lib/easypi/stealth-policy/dns-policy.json"

    def load_object(path: Path) -> dict | None:
        if not path.exists():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"Chameleon state is not a JSON object: {path}")
        return value

    meta = load_object(meta_path)
    policy = load_object(policy_path)
    if policy is not None and (
        policy.get("version") != 1
        or not isinstance(policy.get("enabled"), bool)
        or policy.get("scope") not in {"all", "selected"}
    ):
        raise ValueError("Chameleon root policy has an invalid schema")
    if meta is not None and not isinstance(meta.get("enabled", False), bool):
        raise ValueError("Chameleon metadata has an invalid enabled state")
    meta_enabled = bool(meta and meta.get("enabled") is True)
    policy_enabled = bool(policy and policy.get("enabled") is True)
    if meta_enabled != policy_enabled:
        raise ValueError("Chameleon metadata and root policy are from different states")
    if not meta_enabled:
        return

    if meta is None or policy is None:
        raise ValueError("enabled Chameleon backup is missing metadata or root policy")
    config = load_object(config_path)
    if config is None:
        raise ValueError("enabled Chameleon backup is missing its client configuration")

    scope = meta.get("scope", "all")
    meta_macs = {
        str(device.get("mac", "")).strip().lower()
        for device in meta.get("devices", [])
        if isinstance(device, dict)
        and MAC_RE.fullmatch(str(device.get("mac", "")).strip().lower())
    }
    policy_macs = {str(value).strip().lower() for value in policy.get("macs", [])}
    if (
        policy.get("scope") != scope
        or policy_macs != (meta_macs if scope == "selected" else set())
        or bool(policy.get("block_quic", True)) != bool(meta.get("block_quic", True))
    ):
        raise ValueError("Chameleon metadata and root policy do not describe the same state")

    expected_config = {
        "server_address": meta.get("server_address", ""),
        "psk_key": meta.get("psk_key", ""),
        "reality_server_public_key": meta.get("reality_public", ""),
        "doh_domain": meta.get("doh_domain", ""),
        "buffer_size": int(meta.get("buffer_size") or 1000),
        "reconnect_interval": int(meta.get("reconnect_interval") or 5),
        "fingerprint_mode": meta.get("fingerprint_mode") or "auto",
        "protocol": "http2",
        "verify_server_certificate": True,
        "tun_name": "cham0",
        "mtu": 1420,
    }
    if any(config.get(key) != value for key, value in expected_config.items()):
        raise ValueError("Chameleon metadata and client configuration are inconsistent")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--source", type=Path, action="append", required=True)
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    parser.add_argument("--validate-stealth", action="store_true")
    args = parser.parse_args()
    build_snapshot(args.root, args.source, args.exclude)
    if args.validate_stealth:
        validate_stealth_snapshot(args.root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
