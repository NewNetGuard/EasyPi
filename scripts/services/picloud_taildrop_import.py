#!/usr/bin/env python3
"""Import completed Tailscale Taildrop files into PiCloud."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import logging
import os
import socket
import stat
import subprocess
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import BinaryIO, Callable


DEFAULT_MAX_BYTES = 0
UPLOAD_LIMIT_SETTING = "EASYPI_MAX_UPLOAD_BYTES"
MAX_SETTINGS_FILE_BYTES = 1024 * 1024
COPY_CHUNK_BYTES = 1024 * 1024
FREE_SPACE_RESERVE = 5 * 1024 * 1024 * 1024
STATUS_FILENAME = "status.json"
TAILSCALE_SOCKET_CANDIDATES = (
    Path("/run/tailscale/tailscaled.sock"),
    Path("/var/run/tailscale/tailscaled.sock"),
)
TAILSCALED_CANDIDATES = (Path("/usr/sbin/tailscaled"), Path("/usr/bin/tailscaled"))
SYSTEMCTL_CANDIDATES = (Path("/usr/bin/systemctl"), Path("/bin/systemctl"))
CAPACITY_WARNING_INTERVAL = 300.0
TAILSCALE_RESTART_WARNING_INTERVAL = 300.0
SORT_FOLDERS = ("Photos", "Videos", "Documents", "Music", "Encrypted", "Files")
SORT_EXTENSIONS = {
    "Photos": {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".webp",
        ".bmp",
        ".tiff",
        ".heic",
        ".heif",
        ".raw",
        ".cr2",
        ".nef",
        ".arw",
    },
    "Videos": {
        ".mp4",
        ".mov",
        ".avi",
        ".mkv",
        ".webm",
        ".mpeg",
        ".mpg",
        ".m4v",
        ".wmv",
        ".flv",
    },
    "Documents": {
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".rtf",
        ".odt",
        ".ods",
        ".odp",
        ".csv",
    },
    "Music": {
        ".mp3",
        ".wav",
        ".flac",
        ".aac",
        ".ogg",
        ".m4a",
        ".wma",
        ".opus",
    },
    "Encrypted": {".enc", ".encrypted", ".epec"},
}

logger = logging.getLogger("easypi-taildrop")
_capacity_warning_last: float | None = None


class TaildropCapacityError(RuntimeError):
    """The current transaction cannot preserve the configured disk reserve."""


def _log_deferred_capacity(name: str, declared_size: int) -> None:
    global _capacity_warning_last
    now = time.monotonic()
    previous = _capacity_warning_last
    if previous is None or now - previous >= CAPACITY_WARNING_INTERVAL:
        logger.warning(
            "Deferred Taildrop file %s (%d bytes) because disk space is low; "
            "additional capacity warnings are summarized by this message",
            name,
            declared_size,
        )
        _capacity_warning_last = now


def _truncate_utf8(value: str, maximum_bytes: int) -> str:
    if maximum_bytes <= 0:
        return ""
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore")


def sanitize_filename(value: str, maximum_bytes: int = 255) -> str:
    """Treat a remote Taildrop name as display data, never as a path."""
    raw = value.replace("\x00", "").replace("\\", "/")
    name = raw.rsplit("/", 1)[-1].strip().lstrip(".")
    name = "".join(char for char in name if 32 <= ord(char) != 127)
    if name in {"", ".", ".."}:
        name = "upload.bin"
    stem, suffix = os.path.splitext(name)
    suffix = _truncate_utf8(suffix, min(32, max(0, maximum_bytes // 2)))
    stem_budget = max(1, maximum_bytes - len(suffix.encode("utf-8")))
    stem = _truncate_utf8(stem, stem_budget) or _truncate_utf8("upload", stem_budget)
    return _truncate_utf8(f"{stem}{suffix}", maximum_bytes) or "upload"


def sort_folder_for_filename(filename: str) -> str:
    """Map every received file to the same physical folders used by PiCloud."""
    extension = Path(sanitize_filename(filename)).suffix.lower()
    for folder, extensions in SORT_EXTENSIONS.items():
        if extension in extensions:
            return folder
    return "Files"


def open_directory_no_symlinks(path: Path) -> int:
    """Open an absolute directory one component at a time without following links."""
    if not path.is_absolute():
        raise ValueError("directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    current = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            following = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def require_directory(fd: int, *, owner_uid: int, label: str) -> None:
    details = os.fstat(fd)
    if not stat.S_ISDIR(details.st_mode):
        raise RuntimeError(f"{label} is not a directory")
    if details.st_uid != owner_uid:
        raise RuntimeError(f"{label} has an unexpected owner")
    if details.st_mode & 0o022:
        raise RuntimeError(f"{label} must not be group/world writable")


def open_sort_directory(
    picloud_fd: int,
    filename: str,
    *,
    owner_uid: int,
) -> int:
    folder = sort_folder_for_filename(filename)
    directory_fd = os.open(
        folder,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        dir_fd=picloud_fd,
    )
    try:
        require_directory(
            directory_fd,
            owner_uid=owner_uid,
            label=f"PiCloud {folder} directory",
        )
        return directory_fd
    except Exception:
        os.close(directory_fd)
        raise


def _upload_limit_setting(settings_file: Path) -> str | None:
    """Read only the upload limit from the application settings file.

    This root service must never load that file as its environment: the file
    is a backup-restore target, and loader or interpreter variables placed in
    it would execute attacker-chosen code as root. Every other line is ignored.
    """
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(settings_file, flags)
    except OSError:
        return None
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_SETTINGS_FILE_BYTES:
            return None
        chunks = []
        remaining = MAX_SETTINGS_FILE_BYTES
        while remaining > 0:
            chunk = os.read(fd, min(remaining, COPY_CHUNK_BYTES))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except OSError:
        return None
    finally:
        os.close(fd)
    value = None
    for line in b"".join(chunks).decode("utf-8", errors="replace").splitlines():
        name, separator, raw = line.strip().partition("=")
        if separator and name.strip() == UPLOAD_LIMIT_SETTING:
            # As with a systemd environment file, the last assignment wins.
            value = raw.split("#", 1)[0].strip().strip("\"'")
    return value


def max_upload_bytes(settings_file: Path | None = None) -> int:
    """Return the configured size limit; zero means no fixed limit.

    The shipped unit passes the settings file. Units installed before that
    still provide the value through their environment.
    """
    raw = (
        _upload_limit_setting(settings_file)
        if settings_file is not None
        else os.getenv(UPLOAD_LIMIT_SETTING)
    )
    if raw is None:
        return DEFAULT_MAX_BYTES
    try:
        return max(0, int(raw))
    except ValueError:
        return DEFAULT_MAX_BYTES


def _format_gib(value: int) -> str:
    return f"{value / (1024**3):.1f} GB"


def _capacity_message(deferred: int = 0) -> str:
    message = (
        "Not enough disk space. EasyPi keeps "
        f"{_format_gib(FREE_SPACE_RESERVE)} reserved for system operation. "
        "Free disk space or add storage, then retry."
    )
    if deferred:
        suffix = "file remains" if deferred == 1 else "files remain"
        message = f"{message} {deferred} Taildrop {suffix} waiting."
    return message


def _write_status(
    state_fd: int,
    *,
    owner_gid: int,
    error: str | None,
    free_bytes: int,
    deferred: int = 0,
) -> None:
    payload = json.dumps(
        {
            "version": 1,
            "error": error,
            "free_bytes": max(0, int(free_bytes)),
            "reserve_bytes": FREE_SPACE_RESERVE,
            "deferred_files": max(0, int(deferred)),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        existing_fd = os.open(
            STATUS_FILENAME,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
    except FileNotFoundError:
        existing_fd = -1
    if existing_fd >= 0:
        try:
            if os.read(existing_fd, 4097) == payload:
                return
        finally:
            os.close(existing_fd)

    temporary_name = f".{STATUS_FILENAME}.{uuid.uuid4().hex}.tmp"
    temporary_fd = os.open(
        temporary_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=state_fd,
    )
    try:
        _write_all(temporary_fd, payload)
        os.fchown(temporary_fd, 0, owner_gid)
        os.fchmod(temporary_fd, 0o640)
        os.fsync(temporary_fd)
    finally:
        os.close(temporary_fd)
    try:
        os.replace(
            temporary_name,
            STATUS_FILENAME,
            src_dir_fd=state_fd,
            dst_dir_fd=state_fd,
        )
        os.fsync(state_fd)
    finally:
        try:
            os.unlink(temporary_name, dir_fd=state_fd)
        except FileNotFoundError:
            pass


def _free_bytes(directory_fd: int) -> int:
    filesystem = os.fstatvfs(directory_fd)
    return filesystem.f_bavail * filesystem.f_frsize


def _require_free_bytes(directory_fd: int, additional_bytes: int) -> None:
    required = additional_bytes + FREE_SPACE_RESERVE
    if _free_bytes(directory_fd) < required:
        raise TaildropCapacityError(
            f"insufficient free space for Taildrop transaction; {required} bytes required"
        )


def _require_import_capacity(
    state_fd: int,
    destination_fd: int,
    *,
    state_growth: int,
    destination_growth: int,
    same_filesystem_growth: int,
) -> None:
    if os.fstat(state_fd).st_dev == os.fstat(destination_fd).st_dev:
        _require_free_bytes(state_fd, same_filesystem_growth)
        return
    _require_free_bytes(state_fd, state_growth)
    _require_free_bytes(destination_fd, destination_growth)


def trusted_root_file(
    candidates: tuple[Path, ...], *, socket_file: bool = False
) -> Path | None:
    for candidate in candidates:
        try:
            details = candidate.lstat()
            parent = candidate.parent.stat()
        except OSError:
            continue
        expected = (
            stat.S_ISSOCK(details.st_mode)
            if socket_file
            else stat.S_ISREG(details.st_mode)
        )
        if (
            expected
            and details.st_uid == 0
            and parent.st_uid == 0
            and parent.st_mode & 0o022 == 0
            and (socket_file or details.st_mode & 0o022 == 0)
        ):
            return candidate
    return None


def _name_exists(directory_fd: int, name: str) -> bool:
    try:
        os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def _candidate_name(requested: str, counter: int, name_max: int) -> str:
    safe = sanitize_filename(requested, name_max)
    stem, suffix = os.path.splitext(safe)
    marker = "" if counter == 0 else f"_{counter}"
    marker_bytes = len(marker.encode("utf-8"))
    suffix = _truncate_utf8(suffix, min(32, max(0, name_max - marker_bytes - 1)))
    budget = max(1, name_max - marker_bytes - len(suffix.encode("utf-8")))
    stem = _truncate_utf8(stem, budget) or _truncate_utf8("upload", budget)
    return _truncate_utf8(f"{stem}{marker}{suffix}", name_max)


def unique_name(directory_fd: int, requested: str) -> str:
    try:
        name_max = int(os.fpathconf(directory_fd, "PC_NAME_MAX"))
    except (OSError, ValueError):
        name_max = 255
    for counter in range(1_000_000):
        candidate = _candidate_name(requested, counter, name_max)
        if not _name_exists(directory_fd, candidate):
            return candidate
    raise RuntimeError("unable to allocate a unique PiCloud filename")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: Path, timeout: float = 65.0) -> None:
        super().__init__("local-tailscaled.sock", timeout=timeout)
        self.socket_path = str(socket_path)

    def connect(self) -> None:
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(self.timeout)
        connection.connect(self.socket_path)
        self.sock = connection


class TaildropResponse:
    def __init__(
        self,
        connection: UnixHTTPConnection,
        response: http.client.HTTPResponse,
        size: int,
    ) -> None:
        self.connection = connection
        self.response = response
        self.size = size

    def read(self, amount: int) -> bytes:
        return self.response.read(amount)

    def close(self) -> None:
        self.response.close()
        self.connection.close()


class TaildropLocalAPI:
    def __init__(self, socket_path: Path) -> None:
        self.socket_path = socket_path

    def _request(
        self, method: str, path: str
    ) -> tuple[UnixHTTPConnection, http.client.HTTPResponse]:
        connection = UnixHTTPConnection(self.socket_path)
        connection.request(method, path, headers={"Accept": "application/json"})
        return connection, connection.getresponse()

    @staticmethod
    def _error(response: http.client.HTTPResponse) -> RuntimeError:
        body = response.read(4096).decode("utf-8", errors="replace").strip()
        return RuntimeError(
            f"Tailscale LocalAPI returned HTTP {response.status}: {body}"
        )

    def waiting_files(self, wait_seconds: int = 1) -> list[dict[str, object]]:
        connection, response = self._request(
            "GET", f"/localapi/v0/files/?waitsec={max(0, min(wait_seconds, 5))}"
        )
        try:
            if response.status != 200:
                raise self._error(response)
            payload = json.loads(response.read().decode("utf-8"))
            if payload is None:
                return []
            if not isinstance(payload, list):
                raise RuntimeError("Tailscale LocalAPI returned an invalid file list")
            return [item for item in payload if isinstance(item, dict)]
        finally:
            response.close()
            connection.close()

    def open_file(self, name: str) -> TaildropResponse:
        escaped = urllib.parse.quote(name, safe="")
        connection, response = self._request("GET", f"/localapi/v0/files/{escaped}")
        if response.status != 200:
            try:
                raise self._error(response)
            finally:
                response.close()
                connection.close()
        raw_length = response.getheader("Content-Length")
        try:
            size = int(raw_length or "")
        except ValueError:
            response.close()
            connection.close()
            raise RuntimeError(
                "Tailscale LocalAPI omitted a valid Content-Length"
            ) from None
        return TaildropResponse(connection, response, size)

    def delete_file(self, name: str) -> None:
        escaped = urllib.parse.quote(name, safe="")
        connection, response = self._request("DELETE", f"/localapi/v0/files/{escaped}")
        try:
            if response.status != 204:
                raise self._error(response)
            response.read()
        finally:
            response.close()
            connection.close()


def _waiting_file(item: dict[str, object]) -> tuple[str, int]:
    name = item.get("Name")
    size = item.get("Size")
    if (
        not isinstance(name, str)
        or not name
        or isinstance(size, bool)
        or not isinstance(size, int)
    ):
        raise ValueError("Tailscale returned invalid Taildrop metadata")
    if size < 0:
        raise ValueError("Tailscale returned a negative Taildrop size")
    return name, size


def _receipt_name(source_name: str) -> str:
    key = hashlib.sha256(source_name.encode("utf-8")).hexdigest()
    return f"receipt-{key}.json"


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while storing Taildrop state")
        view = view[written:]


def _write_receipt(state_fd: int, receipt: dict[str, object]) -> None:
    filename = _receipt_name(str(receipt["source_name"]))
    temporary_name = f".receipt-{uuid.uuid4().hex}.tmp"
    temporary_fd = -1
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=state_fd,
        )
        content = json.dumps(receipt, ensure_ascii=False, sort_keys=True).encode(
            "utf-8"
        )
        _write_all(temporary_fd, content)
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.rename(
            temporary_name,
            filename,
            src_dir_fd=state_fd,
            dst_dir_fd=state_fd,
        )
        os.fsync(state_fd)
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=state_fd)
        except FileNotFoundError:
            pass


def _read_receipt(state_fd: int, filename: str) -> dict[str, object]:
    fd = os.open(filename, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=state_fd)
    try:
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or details.st_mode & 0o077
            or details.st_size > 64 * 1024
        ):
            raise RuntimeError("untrusted Taildrop receipt")
        content = b""
        while len(content) <= 64 * 1024:
            chunk = os.read(fd, min(8192, 64 * 1024 + 1 - len(content)))
            if not chunk:
                break
            content += chunk
        receipt = json.loads(content.decode("utf-8"))
    finally:
        os.close(fd)
    if not isinstance(receipt, dict):
        raise RuntimeError("invalid Taildrop receipt")
    source_name = receipt.get("source_name")
    source_size = receipt.get("source_size")
    payload_name = receipt.get("payload_name")
    published_name = receipt.get("published_name")
    temporary_name = receipt.get("temporary_name")
    digest = receipt.get("sha256")
    source_deleted = receipt.get("source_deleted", False)
    if (
        receipt.get("version") not in (1, 2)
        or not isinstance(source_name, str)
        or not source_name
        or isinstance(source_size, bool)
        or not isinstance(source_size, int)
        or source_size < 0
        or not isinstance(payload_name, str)
        or not payload_name.startswith("payload-")
        or "/" in payload_name
        or "\\" in payload_name
        or not isinstance(published_name, str)
        or published_name != sanitize_filename(published_name)
        or not isinstance(temporary_name, str)
        or not temporary_name.startswith(".taildrop-")
        or not temporary_name.endswith(".part")
        or "/" in temporary_name
        or "\\" in temporary_name
        or not isinstance(digest, str)
        or len(digest) != 64
        or any(char not in "0123456789abcdef" for char in digest)
        or not isinstance(source_deleted, bool)
        or filename != _receipt_name(source_name)
    ):
        raise RuntimeError("invalid Taildrop receipt")
    receipt["source_deleted"] = source_deleted
    return receipt


def _stage_stream(
    stream: BinaryIO | TaildropResponse,
    state_fd: int,
    expected_size: int,
    *,
    maximum_bytes: int,
) -> tuple[str, str]:
    temporary_name = f"payload-{uuid.uuid4().hex}"
    temporary_fd = -1
    completed = False
    try:
        temporary_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
            dir_fd=state_fd,
        )
        digest = hashlib.sha256()
        copied = 0
        while True:
            chunk = stream.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            copied += len(chunk)
            if copied > expected_size or (maximum_bytes > 0 and copied > maximum_bytes):
                raise OverflowError("Taildrop stream exceeded its declared size")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(temporary_fd, view)
                if written <= 0:
                    raise OSError("short write while importing Taildrop file")
                view = view[written:]
        if copied != expected_size:
            raise OSError(
                f"incomplete Taildrop stream: received {copied} of {expected_size} bytes"
            )
        os.fsync(temporary_fd)
        os.close(temporary_fd)
        temporary_fd = -1
        os.fsync(state_fd)
        completed = True
        return temporary_name, digest.hexdigest()
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if not completed:
            try:
                os.unlink(temporary_name, dir_fd=state_fd)
            except FileNotFoundError:
                pass


def _stage_waiting_file(
    api: TaildropLocalAPI,
    name: str,
    declared_size: int,
    state_fd: int,
    *,
    maximum_bytes: int,
) -> tuple[str, str]:
    _require_free_bytes(state_fd, declared_size)
    stream = api.open_file(name)
    try:
        if stream.size != declared_size:
            raise OSError("Taildrop size changed between listing and download")
        return _stage_stream(
            stream,
            state_fd,
            declared_size,
            maximum_bytes=maximum_bytes,
        )
    finally:
        stream.close()


def _hash_regular_file(
    directory_fd: int,
    name: str,
    *,
    owner_uids: tuple[int, ...],
    link_counts: tuple[int, ...] = (1,),
) -> tuple[int, str]:
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        details = os.fstat(fd)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid not in owner_uids
            or details.st_nlink not in link_counts
            or details.st_mode & 0o022
        ):
            raise RuntimeError("untrusted Taildrop transaction file")
        digest = hashlib.sha256()
        while chunk := os.read(fd, COPY_CHUNK_BYTES):
            digest.update(chunk)
        return details.st_size, digest.hexdigest()
    finally:
        os.close(fd)


def _publish_receipt(
    state_fd: int,
    destination_fd: int,
    receipt: dict[str, object],
    *,
    owner_uid: int,
    owner_gid: int,
) -> str:
    source_name = str(receipt["source_name"])
    source_size = int(receipt["source_size"])
    payload_name = str(receipt["payload_name"])
    temporary_name = str(receipt["temporary_name"])
    expected_digest = str(receipt["sha256"])
    published_name = str(receipt["published_name"])
    receipt_filename = _receipt_name(source_name)

    if _name_exists(destination_fd, published_name):
        existing_size, existing_digest = _hash_regular_file(
            destination_fd,
            published_name,
            owner_uids=(0, owner_uid),
            link_counts=(1, 2),
        )
        if existing_size == source_size and existing_digest == expected_digest:
            try:
                temporary = os.stat(
                    temporary_name, dir_fd=destination_fd, follow_symlinks=False
                )
                published = os.stat(
                    published_name, dir_fd=destination_fd, follow_symlinks=False
                )
                if (temporary.st_dev, temporary.st_ino) != (
                    published.st_dev,
                    published.st_ino,
                ):
                    raise RuntimeError("Taildrop transaction temporary file conflict")
                os.unlink(temporary_name, dir_fd=destination_fd)
            except FileNotFoundError:
                pass
            published_fd = os.open(
                published_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=destination_fd,
            )
            try:
                os.fchown(published_fd, owner_uid, owner_gid)
                os.fchmod(published_fd, 0o640)
                os.fsync(published_fd)
            finally:
                os.close(published_fd)
            os.fsync(destination_fd)
            try:
                os.unlink(payload_name, dir_fd=state_fd)
            except FileNotFoundError:
                pass
            os.unlink(receipt_filename, dir_fd=state_fd)
            os.fsync(state_fd)
            return published_name
        published_name = unique_name(destination_fd, source_name)
        receipt["published_name"] = published_name
        _write_receipt(state_fd, receipt)

    payload_size, payload_digest = _hash_regular_file(
        state_fd, payload_name, owner_uids=(os.geteuid(),)
    )
    if payload_size != source_size or payload_digest != expected_digest:
        raise RuntimeError("Taildrop transaction payload failed integrity verification")

    source_fd = -1
    temporary_fd = -1
    try:
        source_fd = os.open(
            payload_name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=state_fd,
        )
        try:
            if not _name_exists(destination_fd, temporary_name):
                _require_free_bytes(destination_fd, source_size)
            temporary_fd = os.open(
                temporary_name,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
                dir_fd=destination_fd,
            )
            while chunk := os.read(source_fd, COPY_CHUNK_BYTES):
                _write_all(temporary_fd, chunk)
            os.fsync(temporary_fd)
        except FileExistsError:
            temporary_size, temporary_digest = _hash_regular_file(
                destination_fd,
                temporary_name,
                owner_uids=(0,),
                link_counts=(1,),
            )
            if temporary_size != source_size or temporary_digest != expected_digest:
                raise RuntimeError(
                    "Taildrop transaction temporary file failed verification"
                )
            temporary_fd = os.open(
                temporary_name,
                os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
                dir_fd=destination_fd,
            )
        while True:
            try:
                os.link(
                    temporary_name,
                    published_name,
                    src_dir_fd=destination_fd,
                    dst_dir_fd=destination_fd,
                    follow_symlinks=False,
                )
                break
            except FileExistsError:
                published_name = unique_name(destination_fd, source_name)
                receipt["published_name"] = published_name
                _write_receipt(state_fd, receipt)
        os.unlink(temporary_name, dir_fd=destination_fd)
        os.fchown(temporary_fd, owner_uid, owner_gid)
        os.fchmod(temporary_fd, 0o640)
        os.fsync(temporary_fd)
        os.fsync(destination_fd)
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if temporary_fd >= 0:
            os.close(temporary_fd)
        try:
            os.unlink(temporary_name, dir_fd=destination_fd)
        except FileNotFoundError:
            pass

    os.unlink(payload_name, dir_fd=state_fd)
    os.unlink(receipt_filename, dir_fd=state_fd)
    os.fsync(state_fd)
    return published_name


def recover_receipts(
    state_fd: int,
    destination_fd: int,
    waiting_names: set[str],
    *,
    owner_uid: int,
    owner_gid: int,
    destination_resolver: Callable[[str], int] | None = None,
) -> int:
    receipts: list[dict[str, object]] = []
    deferred = 0
    for filename in os.listdir(state_fd):
        if not filename.startswith("receipt-") or not filename.endswith(".json"):
            continue
        receipt = _read_receipt(state_fd, filename)
        receipts.append(receipt)
        if (
            not bool(receipt["source_deleted"])
            and str(receipt["source_name"]) in waiting_names
        ):
            continue
        resolved_fd = (
            destination_resolver(str(receipt["source_name"]))
            if destination_resolver is not None
            else destination_fd
        )
        try:
            try:
                published_name = _publish_receipt(
                    state_fd,
                    resolved_fd,
                    receipt,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
            except TaildropCapacityError:
                _log_deferred_capacity(
                    str(receipt["source_name"]), int(receipt["source_size"])
                )
                deferred += 1
                continue
        finally:
            if destination_resolver is not None:
                os.close(resolved_fd)
        logger.info("Recovered Taildrop transaction as %s", published_name)

    referenced_payloads = {str(receipt["payload_name"]) for receipt in receipts}
    for filename in os.listdir(state_fd):
        if not filename.startswith("payload-") or filename in referenced_payloads:
            continue
        details = os.stat(filename, dir_fd=state_fd, follow_symlinks=False)
        if (
            stat.S_ISREG(details.st_mode)
            and details.st_uid == os.geteuid()
            and details.st_nlink == 1
            and details.st_mode & 0o077 == 0
        ):
            os.unlink(filename, dir_fd=state_fd)
            logger.warning("Removed an orphaned Taildrop transaction payload")
    os.fsync(state_fd)
    return deferred


def process_waiting_file(
    api: TaildropLocalAPI,
    item: dict[str, object],
    state_fd: int,
    destination_fd: int,
    *,
    owner_uid: int,
    owner_gid: int,
    maximum_bytes: int,
) -> str | None:
    name, declared_size = _waiting_file(item)
    if maximum_bytes > 0 and declared_size > maximum_bytes:
        api.delete_file(name)
        logger.error(
            "Deleted oversized Taildrop file %s (%d bytes)", name, declared_size
        )
        return None

    receipt: dict[str, object] | None = None
    pending_payload: str | None = None
    pending_digest: str | None = None
    try:
        receipt = _read_receipt(state_fd, _receipt_name(name))
    except FileNotFoundError:
        pass

    if receipt is not None:
        if bool(receipt["source_deleted"]):
            _publish_receipt(
                state_fd,
                destination_fd,
                receipt,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            receipt = None
        elif int(receipt["source_size"]) != declared_size:
            _publish_receipt(
                state_fd,
                destination_fd,
                receipt,
                owner_uid=owner_uid,
                owner_gid=owner_gid,
            )
            receipt = None
        else:
            old_size = int(receipt["source_size"])
            _require_import_capacity(
                state_fd,
                destination_fd,
                state_growth=declared_size,
                destination_growth=old_size + declared_size,
                same_filesystem_growth=max(
                    old_size + declared_size,
                    declared_size * 2,
                ),
            )
            pending_payload, pending_digest = _stage_waiting_file(
                api,
                name,
                declared_size,
                state_fd,
                maximum_bytes=maximum_bytes,
            )
            if pending_digest == receipt["sha256"]:
                os.unlink(pending_payload, dir_fd=state_fd)
                api.delete_file(name)
                receipt["source_deleted"] = True
                _write_receipt(state_fd, receipt)
                published_name = _publish_receipt(
                    state_fd,
                    destination_fd,
                    receipt,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
                logger.info(
                    "Imported Taildrop file %s (%d bytes, sha256=%s)",
                    published_name,
                    declared_size,
                    receipt["sha256"],
                )
                return published_name
            try:
                _publish_receipt(
                    state_fd,
                    destination_fd,
                    receipt,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                )
            except Exception:
                os.unlink(pending_payload, dir_fd=state_fd)
                raise
            receipt = None

    if receipt is None:
        if pending_payload is None or pending_digest is None:
            _require_import_capacity(
                state_fd,
                destination_fd,
                state_growth=declared_size,
                destination_growth=declared_size,
                same_filesystem_growth=declared_size * 2,
            )
            pending_payload, pending_digest = _stage_waiting_file(
                api,
                name,
                declared_size,
                state_fd,
                maximum_bytes=maximum_bytes,
            )
        receipt = {
            "version": 2,
            "source_name": name,
            "source_size": declared_size,
            "source_deleted": False,
            "payload_name": pending_payload,
            "published_name": unique_name(destination_fd, name),
            "temporary_name": f".taildrop-{uuid.uuid4().hex}.part",
            "sha256": pending_digest,
        }
        try:
            _write_receipt(state_fd, receipt)
        except Exception:
            os.unlink(pending_payload, dir_fd=state_fd)
            raise

    api.delete_file(name)
    receipt["source_deleted"] = True
    _write_receipt(state_fd, receipt)
    published_name = _publish_receipt(
        state_fd,
        destination_fd,
        receipt,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
    )
    logger.info(
        "Imported Taildrop file %s (%d bytes, sha256=%s)",
        published_name,
        declared_size,
        receipt["sha256"],
    )
    return published_name


def process_waiting_files(
    api: TaildropLocalAPI,
    items: list[dict[str, object]],
    state_fd: int,
    destination_fd: int,
    *,
    owner_uid: int,
    owner_gid: int,
    maximum_bytes: int,
    destination_resolver: Callable[[str], int] | None = None,
) -> tuple[list[str], int]:
    published: list[str] = []
    deferred = 0
    for item in items:
        name, declared_size = _waiting_file(item)
        resolved_fd = (
            destination_resolver(name)
            if destination_resolver is not None
            else destination_fd
        )
        try:
            try:
                result = process_waiting_file(
                    api,
                    item,
                    state_fd,
                    resolved_fd,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    maximum_bytes=maximum_bytes,
                )
            except TaildropCapacityError:
                _log_deferred_capacity(name, declared_size)
                deferred += 1
                continue
        finally:
            if destination_resolver is not None:
                os.close(resolved_fd)
        if result is not None:
            folder = sort_folder_for_filename(name)
            published.append(f"{folder}/{result}" if destination_resolver else result)
    return published, deferred


def purge_legacy_staging(state: Path) -> None:
    """Remove files left by the unsafe CLI-based receiver; never publish them."""
    state_fd = open_directory_no_symlinks(state)
    try:
        require_directory(state_fd, owner_uid=0, label="Taildrop state directory")
        for directory_name in ("incoming", "rejected"):
            try:
                directory_fd = os.open(
                    directory_name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
                    dir_fd=state_fd,
                )
            except FileNotFoundError:
                continue
            try:
                require_directory(directory_fd, owner_uid=0, label=directory_name)
                for name in os.listdir(directory_fd):
                    details = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if stat.S_ISREG(details.st_mode) or stat.S_ISLNK(details.st_mode):
                        os.unlink(name, dir_fd=directory_fd)
            finally:
                os.close(directory_fd)
            try:
                os.rmdir(directory_name, dir_fd=state_fd)
            except OSError:
                pass
    finally:
        os.close(state_fd)


def _partial_files(files_root: Path) -> tuple[list[Path], int]:
    partials: list[Path] = []
    total = 0
    try:
        root_details = files_root.lstat()
        if (
            not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_uid != 0
            or root_details.st_mode & 0o022
        ):
            raise RuntimeError("Tailscale files directory is not trusted")
        profiles = list(files_root.iterdir())
    except FileNotFoundError:
        return partials, total
    for profile in profiles:
        try:
            profile_details = profile.stat(follow_symlinks=False)
        except OSError:
            continue
        if (
            not stat.S_ISDIR(profile_details.st_mode)
            or profile_details.st_uid != 0
            or profile_details.st_mode & 0o022
        ):
            continue
        for candidate in profile.iterdir():
            try:
                details = candidate.stat(follow_symlinks=False)
            except OSError:
                continue
            if (
                candidate.name.endswith(".partial")
                and stat.S_ISREG(details.st_mode)
                and details.st_uid == 0
                and details.st_nlink == 1
            ):
                partials.append(candidate)
                total += details.st_size
    return partials, total


def tailscaled_installed() -> bool:
    """Return whether the optional Tailscale daemon is safely installed."""
    return trusted_root_file(TAILSCALED_CANDIDATES) is not None


def start_tailscaled() -> bool:
    if not tailscaled_installed():
        return False
    systemctl = trusted_root_file(SYSTEMCTL_CANDIDATES)
    if systemctl is None:
        raise RuntimeError("trusted systemctl executable not found")
    subprocess.run(
        [str(systemctl), "start", "tailscaled.service"],
        check=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    return True


def enforce_partial_spool_quota(files_root: Path, maximum_bytes: int) -> bool:
    """Abort active Taildrop reception before partial files can fill the host disk."""
    partials, total = _partial_files(files_root)
    if not partials:
        return False
    filesystem = os.statvfs(files_root)
    free_bytes = filesystem.f_bavail * filesystem.f_frsize
    oversized = maximum_bytes > 0 and total > maximum_bytes
    if not oversized and free_bytes >= FREE_SPACE_RESERVE:
        return False

    systemctl = trusted_root_file(SYSTEMCTL_CANDIDATES)
    if systemctl is None:
        raise RuntimeError("trusted systemctl executable not found")
    logger.critical("Stopping an oversized Taildrop transfer (%d partial bytes)", total)
    try:
        subprocess.run(
            [str(systemctl), "stop", "tailscaled.service"],
            check=True,
            timeout=30,
            stdin=subprocess.DEVNULL,
        )
        current_partials, _ = _partial_files(files_root)
        for candidate in current_partials:
            candidate.unlink(missing_ok=True)
    finally:
        start_tailscaled()
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument(
        "--tailscale-files", type=Path, default=Path("/var/lib/tailscale/files")
    )
    parser.add_argument("--owner", default="easypi")
    parser.add_argument("--group", default="easypi")
    parser.add_argument("--settings-file", type=Path)
    return parser.parse_args()


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Taildrop importer must run as root on Linux")
    import grp
    import pwd

    args = parse_args()
    owner_uid = pwd.getpwnam(args.owner).pw_uid
    owner_gid = grp.getgrnam(args.group).gr_gid
    maximum_bytes = max_upload_bytes(args.settings_file)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    purge_legacy_staging(args.state)
    tailscale_missing_logged = False
    tailscale_restart_warning_last: float | None = None

    while True:
        socket_path = trusted_root_file(TAILSCALE_SOCKET_CANDIDATES, socket_file=True)
        if socket_path is None:
            if not tailscaled_installed():
                if not tailscale_missing_logged:
                    logger.info(
                        "Tailscale is not installed; Taildrop import is waiting for it"
                    )
                    tailscale_missing_logged = True
                tailscale_restart_warning_last = None
                time.sleep(30)
                continue

            tailscale_missing_logged = False
            try:
                start_tailscaled()
            except Exception:
                now = time.monotonic()
                if (
                    tailscale_restart_warning_last is None
                    or now - tailscale_restart_warning_last
                    >= TAILSCALE_RESTART_WARNING_INTERVAL
                ):
                    logger.exception(
                        "Failed to restore tailscaled while its socket was unavailable"
                    )
                    tailscale_restart_warning_last = now
            time.sleep(5)
            continue
        tailscale_missing_logged = False
        tailscale_restart_warning_last = None
        try:
            if enforce_partial_spool_quota(args.tailscale_files, maximum_bytes):
                state_fd = open_directory_no_symlinks(args.state)
                try:
                    _write_status(
                        state_fd,
                        owner_gid=owner_gid,
                        error=_capacity_message(),
                        free_bytes=_free_bytes(state_fd),
                    )
                finally:
                    os.close(state_fd)
                time.sleep(2)
                continue
            state_fd = open_directory_no_symlinks(args.state)
            destination_fd = -1
            try:
                destination_fd = open_directory_no_symlinks(args.destination)
                require_directory(
                    state_fd,
                    owner_uid=0,
                    label="Taildrop state directory",
                )
                require_directory(
                    destination_fd,
                    owner_uid=owner_uid,
                    label="PiCloud storage directory",
                )

                def destination_resolver(filename: str) -> int:
                    return open_sort_directory(
                        destination_fd,
                        filename,
                        owner_uid=owner_uid,
                    )

                api = TaildropLocalAPI(socket_path)
                waiting_files = api.waiting_files(wait_seconds=1)
                waiting_names = {_waiting_file(item)[0] for item in waiting_files}
                recovery_deferred = recover_receipts(
                    state_fd,
                    destination_fd,
                    waiting_names,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    destination_resolver=destination_resolver,
                )
                _, deferred = process_waiting_files(
                    api,
                    waiting_files,
                    state_fd,
                    destination_fd,
                    owner_uid=owner_uid,
                    owner_gid=owner_gid,
                    maximum_bytes=maximum_bytes,
                    destination_resolver=destination_resolver,
                )
                total_deferred = recovery_deferred + deferred
                available = min(_free_bytes(state_fd), _free_bytes(destination_fd))
                capacity_error = total_deferred > 0 or available < FREE_SPACE_RESERVE
                _write_status(
                    state_fd,
                    owner_gid=owner_gid,
                    error=_capacity_message(total_deferred) if capacity_error else None,
                    free_bytes=available,
                    deferred=total_deferred,
                )
                if total_deferred:
                    time.sleep(2)
            finally:
                if destination_fd >= 0:
                    os.close(destination_fd)
                os.close(state_fd)
        except Exception:
            logger.exception("Taildrop import cycle failed")
            time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
