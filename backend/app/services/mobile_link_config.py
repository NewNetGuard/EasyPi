"""Non-secret configuration for the EasyPi Mobile Link public endpoint."""

from __future__ import annotations

import json
import os
import tempfile
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

from app.core.paths import get_data_dir

_LOCK = threading.RLock()
_MAX_CONFIG_BYTES = 4096


@dataclass(frozen=True)
class MobileLinkConfig:
    enabled: bool = False
    public_url: str | None = None


def validate_public_url(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    cleaned = value.strip().rstrip("/")
    parsed = urlsplit(cleaned)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise ValueError("Mobile Link address must be an HTTPS origin without a path, query, or credentials")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Mobile Link address has an invalid port") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Mobile Link address has an invalid port")
    return cleaned


def _config_path() -> Path:
    return get_data_dir() / "user" / "mobile_link.json"


def load_mobile_link_config() -> MobileLinkConfig:
    path = _config_path()
    with _LOCK:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return MobileLinkConfig()
        if path.is_symlink() or not path.is_file() or metadata.st_size > _MAX_CONFIG_BYTES:
            raise RuntimeError("Unsafe Mobile Link configuration file")
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("Could not read Mobile Link configuration") from exc
        if not isinstance(payload, dict):
            raise RuntimeError("Invalid Mobile Link configuration")
        public_url = validate_public_url(payload.get("public_url"))
        enabled = payload.get("enabled", False)
        if not isinstance(enabled, bool):
            raise RuntimeError("Invalid Mobile Link configuration")
        if enabled and public_url is None:
            raise RuntimeError("Enabled Mobile Link requires a public address")
        return MobileLinkConfig(enabled=enabled, public_url=public_url)


def save_mobile_link_config(config: MobileLinkConfig) -> MobileLinkConfig:
    public_url = validate_public_url(config.public_url)
    if config.enabled and public_url is None:
        raise ValueError("Enter the public Mobile Link address before enabling it")
    normalized = MobileLinkConfig(enabled=config.enabled, public_url=public_url)
    path = _config_path()
    with _LOCK:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists() and (path.is_symlink() or not path.is_file()):
            raise RuntimeError("Unsafe Mobile Link configuration file")
        fd, temporary_name = tempfile.mkstemp(prefix=".mobile-link-", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            # mkstemp creates a private file on POSIX. Windows does not expose
            # fchmod, so retain the secure create semantics there.
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(asdict(normalized), handle, ensure_ascii=True, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return normalized
