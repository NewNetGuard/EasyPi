"""
File Manager Service

Provides secure file operations with root privileges.
All operations are performed through Python, not shell commands.
"""

import os
import shutil
import logging
import secrets
import stat
import threading
from contextlib import contextmanager
from pathlib import Path
from datetime import datetime
from typing import BinaryIO, Iterator, List, Dict, Any, Optional
from fastapi import HTTPException, UploadFile

logger = logging.getLogger(__name__)

DEFAULT_MAX_UPLOAD_BYTES = 4 * 1024 * 1024 * 1024
UPLOAD_CHUNK_BYTES = 1024 * 1024
MAX_TEXT_READ_BYTES = 8 * 1024 * 1024
FILES_FREE_SPACE_RESERVE = 5 * 1024 * 1024 * 1024
FILES_DEFAULT_MODE = 0o640
FILES_CAPACITY_ERROR = (
    "Not enough disk space. EasyPi keeps 5 GiB free for system operation."
)
_FILES_WRITE_LOCK = threading.Lock()


def _max_upload_bytes() -> int:
    try:
        return max(1, int(os.getenv("EASYPI_MAX_UPLOAD_BYTES", DEFAULT_MAX_UPLOAD_BYTES)))
    except (TypeError, ValueError):
        return DEFAULT_MAX_UPLOAD_BYTES


# Security: paths hidden from the File Manager even though they live under an
# allowed root. These hold credentials/keys — exposing them via a browser file
# manager would leak secrets. (Operational data — logs, picloud, configs — is
# intentionally NOT hidden.)
BLACKLISTED_PATHS = [
    "/opt/EasyPi/.env",                      # app secrets (JWT key, API tokens)
    "/opt/EasyPi/backend/.env",              # protected legacy app secrets
    # Block only the TLS *private keys* — the certs/ folder itself stays
    # browsable so "Open certs folder" works and the public ca.pem/cert.pem
    # can be downloaded (needed to trust DoH/DoT on client devices).
    "/opt/EasyPi/certs/key.pem",             # DoH/DoT server private key
    "/opt/EasyPi/certs/ca-key.pem",          # local CA private key
    "/opt/EasyPi/data/db",                   # main DB: accounts, password hashes, sessions
    "/opt/EasyPi/backend/data/db",           # protected legacy DB location
    "/opt/EasyPi/data/.setup_token",         # initial-setup secret
    "/opt/EasyPi/data/smtp_config.json",     # encrypted SMTP credential
    "/opt/EasyPi/data/netprotection/vault",  # encrypted secrets vault
    "/var/lib/easypi/wireguard",             # VPN client private keys + peer metadata
    "/opt/EasyPi/data/tailscale_state.json",          # encrypted Tailscale auth key + state
    "/opt/EasyPi/backend/data/tailscale_state.json",  # protected legacy location during migration
    "/opt/EasyPi/data/user/tailscale_admin.json",     # Tailscale admin API key (tailnet control)
    "/opt/EasyPi/.update-backups",           # updater backups (contain .env copies)
    "/opt/EasyPi/backend/.venv",             # python virtualenv (libraries, not user content)
    "/proc",
    "/sys",
    "/dev",
]

# The File Manager is scoped to the EasyPi installation tree only. easypi can
# only write under here anyway; keeping the rest of the filesystem out of the
# browser tool limits what a web-side breach could read or exfiltrate.
ALLOWED_ROOTS = ["/opt/EasyPi"]


class FilesService:
    """Service for secure file operations with elevated permissions"""

    @staticmethod
    def resolve_safe_path(path: str) -> Optional[str]:
        """Return a canonical allowed path, or None when access must be denied."""
        try:
            if not path or "\x00" in path or not os.path.isabs(path):
                return None
            normalized = os.path.abspath(os.path.normpath(path))
            resolved = os.path.realpath(normalized)

            for blacklisted in BLACKLISTED_PATHS:
                blocked = os.path.abspath(os.path.normpath(blacklisted))
                blocked_real = os.path.realpath(blocked)
                if any(
                    os.path.commonpath((candidate, protected)) == protected
                    for candidate in (normalized, resolved)
                    for protected in (blocked, blocked_real)
                ):
                    logger.warning(f"Attempted access to blacklisted path: {resolved}")
                    return None

            allowed = False
            for root in ALLOWED_ROOTS:
                allowed_root = os.path.abspath(os.path.normpath(root))
                allowed_real = os.path.realpath(allowed_root)
                if (
                    os.path.commonpath((normalized, allowed_root)) == allowed_root
                    and os.path.commonpath((resolved, allowed_real)) == allowed_real
                ):
                    allowed = True
                    break
            if not allowed:
                logger.warning(f"Path not in allowed roots: {resolved}")
                return None

            return normalized
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return None

    @classmethod
    def _is_path_safe(cls, path: str) -> bool:
        return cls.resolve_safe_path(path) is not None

    @classmethod
    def _require_safe_path(cls, path: str) -> str:
        resolved = cls.resolve_safe_path(path)
        if resolved is None:
            raise HTTPException(status_code=403, detail="Access denied to this path")
        return resolved

    @staticmethod
    def _directory_open_flags() -> int:
        return (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )

    @classmethod
    def _allowed_root_for(cls, path: str) -> str:
        matches = []
        for root in ALLOWED_ROOTS:
            normalized_root = os.path.abspath(os.path.normpath(root))
            if os.path.commonpath((path, normalized_root)) == normalized_root:
                matches.append(normalized_root)
        if not matches:
            raise HTTPException(status_code=403, detail="Access denied to this path")
        return max(matches, key=len)

    @classmethod
    @contextmanager
    def _open_directory_fd(
        cls, path: str, *, create: bool = False
    ) -> Iterator[tuple[int, str]]:
        """Open every directory component without following replaceable symlinks."""
        if os.name != "posix" or not getattr(os, "supports_dir_fd", None):
            raise HTTPException(
                status_code=501,
                detail="Secure file operations require Linux directory descriptors",
            )
        resolved = cls._require_safe_path(path)
        root = cls._allowed_root_for(resolved)
        relative = os.path.relpath(resolved, root)
        parts = [] if relative == "." else Path(relative).parts
        flags = cls._directory_open_flags()
        try:
            current_fd = os.open(root, flags)
        except (NotADirectoryError, OSError) as exc:
            raise HTTPException(status_code=403, detail="Unsafe or unavailable path") from exc
        try:
            for part in parts:
                if part in {"", ".", ".."}:
                    raise HTTPException(status_code=403, detail="Access denied to this path")
                try:
                    next_fd = os.open(part, flags, dir_fd=current_fd)
                except FileNotFoundError:
                    if not create:
                        raise
                    with _FILES_WRITE_LOCK:
                        cls._require_capacity(current_fd, 4096)
                        try:
                            os.mkdir(part, mode=0o755, dir_fd=current_fd)
                        except FileExistsError:
                            pass
                    try:
                        next_fd = os.open(part, flags, dir_fd=current_fd)
                    except OSError as exc:
                        raise HTTPException(
                            status_code=403,
                            detail="Refusing a symbolic link or unsafe directory",
                        ) from exc
                except (NotADirectoryError, OSError) as exc:
                    raise HTTPException(
                        status_code=403,
                        detail="Refusing a symbolic link or unsafe directory",
                    ) from exc
                os.close(current_fd)
                current_fd = next_fd
            yield current_fd, resolved
        finally:
            try:
                os.close(current_fd)
            except OSError:
                pass

    @classmethod
    @contextmanager
    def _open_parent_fd(
        cls, path: str, *, create: bool = False
    ) -> Iterator[tuple[int, str, str]]:
        resolved = cls._require_safe_path(path)
        parent, name = os.path.split(resolved)
        if not name or name in {".", ".."}:
            raise HTTPException(status_code=403, detail="Cannot modify this path")
        with cls._open_directory_fd(parent, create=create) as (parent_fd, _):
            yield parent_fd, name, resolved

    @staticmethod
    def _require_capacity(directory_fd: int, additional_bytes: int = 0) -> None:
        usage = os.fstatvfs(directory_fd)
        free_bytes = usage.f_bavail * usage.f_frsize
        block_size = max(1, usage.f_frsize, usage.f_bsize)
        requested_bytes = max(0, int(additional_bytes))
        allocated_bytes = (
            (requested_bytes + block_size - 1) // block_size
        ) * block_size
        if free_bytes < FILES_FREE_SPACE_RESERVE + allocated_bytes:
            raise HTTPException(status_code=507, detail=FILES_CAPACITY_ERROR)

    @staticmethod
    def _writable_by_current_user(file_stat: os.stat_result) -> bool:
        if os.geteuid() == 0:
            return True
        if file_stat.st_uid == os.geteuid():
            return bool(file_stat.st_mode & stat.S_IWUSR)
        if file_stat.st_gid in os.getgroups():
            return bool(file_stat.st_mode & stat.S_IWGRP)
        return bool(file_stat.st_mode & stat.S_IWOTH)

    @classmethod
    def _existing_replace_mode(cls, parent_fd: int, name: str) -> int:
        try:
            target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return FILES_DEFAULT_MODE
        if not stat.S_ISREG(target_stat.st_mode):
            raise HTTPException(status_code=403, detail="Refusing to replace this item")
        if not cls._writable_by_current_user(target_stat):
            raise HTTPException(
                status_code=403,
                detail="This file is owned by root and cannot be edited from the File Manager.",
            )
        return stat.S_IMODE(target_stat.st_mode)

    @staticmethod
    def _temporary_name() -> str:
        return f".easypi-files-{secrets.token_hex(16)}.tmp"

    @classmethod
    def _open_regular_file(cls, path: str) -> tuple[BinaryIO, os.stat_result, str]:
        with cls._open_parent_fd(path) as (parent_fd, name, resolved):
            flags = (
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0)
            )
            try:
                fd = os.open(name, flags, dir_fd=parent_fd)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail="File not found") from exc
            except OSError as exc:
                raise HTTPException(status_code=403, detail="Refusing an unsafe file") from exc
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                os.close(fd)
                raise HTTPException(status_code=400, detail="Path is not a file")
            return os.fdopen(fd, "rb"), file_stat, resolved

    @classmethod
    def open_binary_file(cls, path: str) -> tuple[BinaryIO, os.stat_result, str]:
        """Open a regular file through its pinned parent directory."""
        return cls._open_regular_file(path)

    @classmethod
    def inspect_path(cls, path: str) -> tuple[os.stat_result, str]:
        """Inspect one path without following its final component as a symlink."""
        with cls._open_parent_fd(path) as (parent_fd, name, resolved):
            try:
                path_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError as exc:
                raise HTTPException(status_code=404, detail="Path not found") from exc
            if stat.S_ISLNK(path_stat.st_mode):
                raise HTTPException(status_code=403, detail="Refusing a symbolic link")
            return path_stat, resolved

    @classmethod
    def _delete_would_contain_protected_path(cls, path: str) -> bool:
        candidates = {os.path.abspath(os.path.normpath(path)), os.path.realpath(path)}
        for blacklisted in BLACKLISTED_PATHS:
            protected_paths = {
                os.path.abspath(os.path.normpath(blacklisted)),
                os.path.realpath(blacklisted),
            }
            for candidate in candidates:
                for protected in protected_paths:
                    if os.path.commonpath((candidate, protected)) == candidate:
                        return True
        return False

    @staticmethod
    def _format_size(size: int) -> str:
        """Format file size in human-readable format"""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"

    def list_directory(self, path: str = "/") -> List[Dict[str, Any]]:
        """List directory contents with metadata"""
        try:
            items = []
            with self._open_directory_fd(path) as (directory_fd, resolved):
                with os.scandir(directory_fd) as entries:
                    for entry in entries:
                        child_path = os.path.join(resolved, entry.name)
                        try:
                            entry_stat = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(entry_stat.st_mode) or not self._is_path_safe(
                                child_path
                            ):
                                continue
                            is_directory = stat.S_ISDIR(entry_stat.st_mode)
                            is_file = stat.S_ISREG(entry_stat.st_mode)
                            if not is_directory and not is_file:
                                continue
                            item = {
                                "name": entry.name,
                                "path": child_path,
                                "type": "directory" if is_directory else "file",
                            }
                            if is_file:
                                item["size"] = entry_stat.st_size
                                item["size_formatted"] = self._format_size(entry_stat.st_size)
                                item["modified"] = datetime.fromtimestamp(
                                    entry_stat.st_mtime
                                ).isoformat()
                            items.append(item)
                        except PermissionError:
                            logger.warning(f"Permission denied for: {child_path}")
                        except FileNotFoundError:
                            continue
            
            # Sort: directories first, then files, alphabetically
            items.sort(key=lambda x: (x["type"] != "directory", x["name"].lower()))
            
            return items
            
        except HTTPException:
            raise
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Path not found")
        except NotADirectoryError:
            raise HTTPException(status_code=400, detail="Path is not a directory")
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except Exception as e:
            logger.error(f"Error listing directory {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def search_files(self, query: str, root_path: str = "/home", limit: int = 50) -> List[Dict[str, Any]]:
        """
        Live search for files and folders.
        Searches recursively from root_path, matching query against file/folder names.
        Case-insensitive partial matching.
        """
        results: List[Dict[str, Any]] = []
        query_lower = query.lower()
        max_depth = 5

        def search_directory(directory_fd: int, display_path: str, depth: int) -> None:
            if len(results) >= limit:
                return
            child_directories: list[tuple[str, str]] = []
            with os.scandir(directory_fd) as entries:
                for entry in entries:
                    if len(results) >= limit:
                        return
                    if entry.name.startswith("."):
                        continue
                    child_path = os.path.join(display_path, entry.name)
                    if not self._is_path_safe(child_path):
                        continue
                    try:
                        entry_stat = entry.stat(follow_symlinks=False)
                    except (PermissionError, FileNotFoundError):
                        continue
                    if stat.S_ISLNK(entry_stat.st_mode):
                        continue
                    if stat.S_ISDIR(entry_stat.st_mode):
                        if query_lower in entry.name.lower():
                            results.append(
                                {
                                    "name": entry.name,
                                    "path": child_path,
                                    "type": "directory",
                                    "parent": display_path,
                                }
                            )
                        if depth < max_depth:
                            child_directories.append((entry.name, child_path))
                    elif stat.S_ISREG(entry_stat.st_mode) and query_lower in entry.name.lower():
                        results.append(
                            {
                                "name": entry.name,
                                "path": child_path,
                                "type": "file",
                                "parent": display_path,
                                "size": entry_stat.st_size,
                                "size_formatted": self._format_size(entry_stat.st_size),
                                "modified": datetime.fromtimestamp(
                                    entry_stat.st_mtime
                                ).isoformat(),
                            }
                        )

            flags = self._directory_open_flags()
            for name, child_path in child_directories:
                if len(results) >= limit:
                    return
                try:
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                except OSError:
                    continue
                try:
                    search_directory(child_fd, child_path, depth + 1)
                finally:
                    os.close(child_fd)

        try:
            with self._open_directory_fd(root_path) as (root_fd, resolved):
                search_directory(root_fd, resolved, 0)
            results.sort(key=lambda x: (x["type"] != "directory", x["name"].lower()))
            return results[:limit]
        except HTTPException:
            raise
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail="Root path not found")
        except NotADirectoryError:
            raise HTTPException(status_code=400, detail="Root path is not a directory")
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except Exception as e:
            logger.error(f"Error searching in {root_path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def read_file(self, path: str) -> Dict[str, Any]:
        """Read file contents"""
        try:
            source, file_stat, resolved = self._open_regular_file(path)
            if file_stat.st_size > MAX_TEXT_READ_BYTES:
                source.close()
                raise HTTPException(status_code=413, detail="Text file is too large to open")
            with source:
                payload = source.read(MAX_TEXT_READ_BYTES + 1)
            if len(payload) > MAX_TEXT_READ_BYTES:
                raise HTTPException(status_code=413, detail="Text file is too large to open")
            content = payload.decode("utf-8", errors="replace")
            if len(content.encode("utf-8", errors="ignore")) > MAX_TEXT_READ_BYTES:
                raise HTTPException(status_code=413, detail="Text file is too large to open")
            
            return {
                "path": resolved,
                "content": content,
                "size": file_stat.st_size,
                "size_formatted": self._format_size(file_stat.st_size),
                "modified": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            }
        except HTTPException:
            raise
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="File is not a text file")
        except PermissionError:
            raise HTTPException(status_code=403, detail="Permission denied")
        except Exception as e:
            logger.error(f"Error reading file {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def write_file(self, path: str, content: str) -> Dict[str, str]:
        """Write content to file"""
        payload = content.encode("utf-8")
        temp_name: Optional[str] = None
        try:
            with self._open_parent_fd(path, create=True) as (parent_fd, name, resolved):
                mode = self._existing_replace_mode(parent_fd, name)
                temp_name = self._temporary_name()
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    with _FILES_WRITE_LOCK:
                        self._require_capacity(parent_fd, max(len(payload), 4096))
                        fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
                        with os.fdopen(fd, "wb") as output:
                            output.write(payload)
                            output.flush()
                            os.fsync(output.fileno())
                            os.fchmod(output.fileno(), mode)
                        os.replace(
                            temp_name,
                            name,
                            src_dir_fd=parent_fd,
                            dst_dir_fd=parent_fd,
                        )
                        temp_name = None
                finally:
                    if temp_name:
                        try:
                            os.unlink(temp_name, dir_fd=parent_fd)
                        except OSError:
                            pass

            logger.info(f"File written: {resolved}")
            return {"status": "success", "path": resolved}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error writing file {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def create_file(self, path: str) -> Dict[str, str]:
        """Create empty file"""
        try:
            with self._open_parent_fd(path, create=True) as (parent_fd, name, resolved):
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    with _FILES_WRITE_LOCK:
                        self._require_capacity(parent_fd, 4096)
                        fd = os.open(name, flags, FILES_DEFAULT_MODE, dir_fd=parent_fd)
                        os.close(fd)
                except FileExistsError as exc:
                    raise HTTPException(status_code=400, detail="File already exists") from exc
                except PermissionError as exc:
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "This location is owned by root and cannot be modified "
                            "from the File Manager."
                        ),
                    ) from exc

            logger.info(f"File created: {resolved}")
            return {"status": "success", "path": resolved}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating file {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def create_folder(self, path: str) -> Dict[str, str]:
        """Create directory"""
        try:
            with self._open_parent_fd(path, create=True) as (parent_fd, name, resolved):
                try:
                    with _FILES_WRITE_LOCK:
                        self._require_capacity(parent_fd, 4096)
                        os.mkdir(name, mode=0o755, dir_fd=parent_fd)
                except FileExistsError as exc:
                    raise HTTPException(status_code=400, detail="Directory already exists") from exc
                except PermissionError as exc:
                    raise HTTPException(
                        status_code=403,
                        detail=(
                            "This location is owned by root and cannot be modified "
                            "from the File Manager."
                        ),
                    ) from exc

            logger.info(f"Directory created: {resolved}")
            return {"status": "success", "path": resolved}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error creating directory {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    def delete(self, path: str) -> Dict[str, str]:
        """Delete file or directory recursively"""
        path = self._require_safe_path(path)
        if self._delete_would_contain_protected_path(path):
            raise HTTPException(
                status_code=403,
                detail="Cannot delete a folder containing protected EasyPi data",
            )
        
        # Extra safety: prevent deletion of critical paths
        critical_paths = ["/", "/home", "/etc", "/opt", "/opt/EasyPi", "/var", "/usr"]
        if path in critical_paths:
            raise HTTPException(status_code=403, detail="Cannot delete critical system path")
        
        try:
            with self._open_parent_fd(path) as (parent_fd, name, resolved):
                try:
                    target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError as exc:
                    raise HTTPException(status_code=404, detail="Path not found") from exc
                if stat.S_ISLNK(target_stat.st_mode):
                    raise HTTPException(status_code=403, detail="Refusing to delete a symbolic link")
                if stat.S_ISDIR(target_stat.st_mode):
                    if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
                        raise HTTPException(status_code=501, detail="Secure directory deletion is unavailable")
                    shutil.rmtree(name, dir_fd=parent_fd)
                    logger.info(f"Directory deleted: {resolved}")
                else:
                    os.unlink(name, dir_fd=parent_fd)
                    logger.info(f"File deleted: {resolved}")

            return {"status": "success", "path": resolved}

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error deleting {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    async def upload_file(self, file: UploadFile, path: str) -> Dict[str, str]:
        """Upload file to specified path"""
        temp_name: Optional[str] = None
        try:
            with self._open_parent_fd(path, create=True) as (parent_fd, name, resolved):
                mode = self._existing_replace_mode(parent_fd, name)
                max_bytes = _max_upload_bytes()
                total = 0
                temp_name = self._temporary_name()
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0)
                )
                try:
                    self._require_capacity(parent_fd, 4096)
                    fd = os.open(temp_name, flags, 0o600, dir_fd=parent_fd)
                    with os.fdopen(fd, "wb") as output:
                        os.fchmod(output.fileno(), mode)
                        while chunk := await file.read(UPLOAD_CHUNK_BYTES):
                            total += len(chunk)
                            if total > max_bytes:
                                raise HTTPException(
                                    status_code=413,
                                    detail="Uploaded file is too large",
                                )
                            with _FILES_WRITE_LOCK:
                                self._require_capacity(parent_fd, len(chunk))
                                output.write(chunk)
                                output.flush()
                        os.fsync(output.fileno())
                    os.replace(
                        temp_name,
                        name,
                        src_dir_fd=parent_fd,
                        dst_dir_fd=parent_fd,
                    )
                    temp_name = None
                finally:
                    if temp_name:
                        try:
                            os.unlink(temp_name, dir_fd=parent_fd)
                        except OSError:
                            pass

            logger.info(f"File uploaded: {resolved} ({total} bytes)")
            return {
                "status": "success",
                "path": resolved,
                "size": total,
                "filename": file.filename or "unknown",
            }

        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Error uploading file to {path}: {e}")
            raise HTTPException(status_code=500, detail=str(e))
