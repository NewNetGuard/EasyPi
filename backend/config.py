from functools import lru_cache
from pathlib import Path
from typing import Any, Optional
from urllib.parse import unquote, urlsplit
import logging
import secrets
import shutil

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Use centralized paths for PyInstaller compatibility
from app.core.paths import (
    get_easypi_root,
    get_backend_dir,
    get_scripts_dir,
    get_logs_dir,
    get_data_dir,
    get_env_file,
)

ROOT_DIR = get_easypi_root()
BACKEND_DIR = get_backend_dir()
ENV_PATH = get_env_file()

# Generate a default secret if not set
_DEFAULT_SECRET = secrets.token_urlsafe(32)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
    )

    DATABASE_URL: str
    SECRET_KEY: str = _DEFAULT_SECRET
    API_PORT: int = 8000
    API_HOST: str = "127.0.0.1"
    FRONTEND_PORT: int = 4173
    ENV: str = "production"
    LOG_LEVEL: str = "info"
    ENABLE_API_DOCS: bool = False
    ALLOW_DEV_CORS: bool = False
    EASYPI_WEBPUSH_ALLOWED_HOSTS: str = ""
    CORS_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ]
    API_BASE: str = "/api/v1"
    WS_BASE: str = "/ws"
    DASHBOARD_URL: str = "https://easypi.local"
    SCRIPTS_ROOT: Path = get_scripts_dir()
    RUNNER_PATH: Path = get_scripts_dir() / "runner"
    TASK_LOG_DIR: Path = get_logs_dir() / "tasks"
    
    # Logging settings
    LOG_DIR: Path = get_logs_dir()
    LOG_FILE_MAX_BYTES: int = 10 * 1024 * 1024  # 10 MB
    LOG_FILE_BACKUP_COUNT: int = 5  # Keep 5 backup files
    LOG_FORMAT: str = "json"  # "json" or "text"
    LOG_TO_FILE: bool = True  # Enable file logging
    LOG_TO_CONSOLE: bool = True  # Enable console logging
    
    # Pi-Guard NetProtection settings (LEGACY - use NetProtection)
    NETPROTECTION_URL: str = "http://localhost:3000"
    NetProtection_USERNAME: Optional[str] = None
    NetProtection_PASSWORD: Optional[str] = None
    NETPROTECTION_INSTALL_SCRIPT_URL: Optional[str] = None
    NETPROTECTION_INSTALL_SCRIPT_SHA256: Optional[str] = None
    EASYPI_UPDATE_SHA256: Optional[str] = None
    
    # EasyPi NetProtection Settings (replaces NetProtection)
    NETPROTECTION_ENABLED: bool = True
    NETPROTECTION_DNS_PORT: int = 53
    NETPROTECTION_DATA_DIR: Path = get_data_dir() / "netprotection"
    NETPROTECTION_UPSTREAM_DNS: list[str] = [
        "https://dns.quad9.net/dns-query",
        "tls://1.1.1.1:853",
    ]
    NETPROTECTION_CACHE_SIZE: int = 10000
    NETPROTECTION_DEFAULT_PROFILE: str = "balanced"
    
    # AI / Ollama settings
    OLLAMA_URL: str = "http://127.0.0.1:11434"
    
    # HTTPS / Cookie Security
    SECURE_COOKIES: bool = True  # Set cookies with Secure flag
    COOKIE_SAMESITE: str = "Lax"  # SameSite policy: "Lax", "Strict", or "None"
    COOKIE_HTTPONLY: bool = True  # HttpOnly flag for cookies
    TRUSTED_HOSTS: list[str] = ["localhost", "127.0.0.1"]  # Allowed hosts for CORS
    
    # Camera Snapshot Settings
    SNAPSHOT_TIMEOUT_SEC: int = 8  # Overall timeout for ffmpeg process
    SNAPSHOT_STIMEOUT_USEC: int = 5000000  # RTSP socket timeout (5 seconds)
    SNAPSHOT_RETRIES: int = 2  # Number of attempts with different parameters

    # PTZ (pan/tilt/zoom) camera control
    PTZ_ALLOWED_SUBNETS: list[str] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]  # SSRF allow-list: only cameras on these LAN ranges may be contacted
    PTZ_ALLOWED_PORTS: list[int] = [80, 443, 554, 2020, 5000, 8000, 8080, 8081, 8443, 8899, 34567]
    PTZ_CONTINUOUS_MAX_DURATION_S: float = 5.0  # backend-enforced auto-stop for continuous moves
    PTZ_COMMAND_TIMEOUT_S: float = 4.0  # per-command HTTP timeout when contacting a camera
    PTZ_MAX_RESPONSE_BYTES: int = 1048576  # 1 MiB cap on a camera's response body
    PTZ_DISCOVERY_TIMEOUT_S: float = 3.0  # WS-Discovery listen window for ONVIF ProbeMatch replies

    # --- Recording storage guard (ring-buffer / loop recording) ----------
    # Recordings share the filesystem with the databases, so a full disk would
    # break SQLite writes and destabilise the whole Pi. The guard keeps a free
    # margin by deleting the OLDEST recordings first (CCTV loop-recording).
    RECORDINGS_STORAGE_GUARD: bool = True   # master switch for auto-deletion
    RECORDINGS_MIN_FREE_PCT: float = 10.0   # start deleting when free space drops below this
    RECORDINGS_TARGET_FREE_PCT: float = 20.0  # delete oldest until at least this much is free (hysteresis)
    RECORDINGS_RETENTION_DAYS: int = 30     # also delete recordings older than this (0 = disabled)

    @field_validator(
        "API_PORT",
        "FRONTEND_PORT",
        "NETPROTECTION_DNS_PORT",
        "NETPROTECTION_CACHE_SIZE",
        "LOG_FILE_MAX_BYTES",
        "LOG_FILE_BACKUP_COUNT",
        "SNAPSHOT_TIMEOUT_SEC",
        "SNAPSHOT_STIMEOUT_USEC",
        "SNAPSHOT_RETRIES",
        mode="before",
    )
    @classmethod
    def _strip_inline_comment_from_ints(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.split("#", 1)[0].strip()
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def normalize_database_url(cls, v: str) -> str:
        v = v.strip()
        prefix = "sqlite:///"
        if not v.startswith(prefix):
            return v

        raw_path = unquote(v[len(prefix):])
        path = Path(raw_path)
        if path.is_absolute():
            return v

        abs_path = (ROOT_DIR / path).resolve()
        legacy_path = (ROOT_DIR / "backend" / path).resolve()

        if not abs_path.exists() and legacy_path.exists():
            try:
                abs_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(legacy_path, abs_path)
                logging.getLogger("startup").info(
                    "Migrated SQLite DB from %s to %s",
                    legacy_path,
                    abs_path,
                )
            except Exception as exc:
                logging.getLogger("startup").warning(
                    "Failed to migrate SQLite DB from %s to %s: %s",
                    legacy_path,
                    abs_path,
                    exc,
                )

        return f"{prefix}{abs_path.as_posix()}"

    @field_validator("DASHBOARD_URL")
    @classmethod
    def validate_dashboard_url(cls, value: str) -> str:
        """Accept only an absolute HTTP(S) dashboard URL safe for email links."""
        value = value.strip().rstrip("/")
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or any(ord(char) < 32 for char in value)
        ):
            raise ValueError("DASHBOARD_URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
        try:
            _ = parsed.port
        except ValueError as exc:
            raise ValueError("DASHBOARD_URL contains an invalid port") from exc
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
