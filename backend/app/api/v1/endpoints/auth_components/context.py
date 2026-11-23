import json
import hmac
import logging
import secrets
import sys
from dataclasses import dataclass
from io import BytesIO
from datetime import datetime, timezone
from app.utils.time import utc_now
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.security import (
    verify_password,
    get_password_hash,
    create_token_pair,
    decode_access_token,
    decode_refresh_token,
    revoke_token,
    revoke_all_user_sessions,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from app.core.password_policy import validate_password, check_password_strength
from app.core.rate_limit import (
    check_rate_limit,
    check_subject_rate_limit,
    get_client_ip,
    reset_rate_limit,
    reset_subject_rate_limit,
)
from app.core.encryption import decrypt_password, encrypt_password
from app.core.terminal_security import terminal_security, WS_TOKEN_LIFETIME
from app.core.paths import get_user_data_dir
from app.api.deps import require_admin
from app.api.v1.endpoints.users import get_current_user
from app.core.cookie_auth import (
    set_auth_cookies,
    clear_auth_cookies,
    get_refresh_token_from_cookie,
    get_token_from_request,
)

from app.core.totp import (
    generate_totp_secret,
    get_totp_uri,
    generate_qr_code,
    verify_totp,
    generate_backup_codes,
    verify_backup_code,
)
from app.db.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=False)  # Optional auth for some endpoints
router = APIRouter(prefix="/auth", tags=["auth"])
operation_event_service = OperationEventService()

# User data directory - use centralized paths
USER_DATA_DIR = get_user_data_dir()
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)
API_TOKEN_PATH = USER_DATA_DIR / "api_token.txt"
MAX_AVATAR_BYTES = 5 * 1024 * 1024
MAX_AVATAR_PIXELS = 16_000_000


def _verify_user_totp(user: User, code: str) -> bool:
    stored = user.totp_secret or ""
    secret = decrypt_password(stored)
    valid = bool(secret) and verify_totp(secret, code)
    if valid and stored and not stored.startswith("enc:"):
        user.totp_secret = encrypt_password(secret)
    return valid


def _record_auth_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    route: str = "/settings",
    started_at: str | None = None,
) -> None:
    try:
        auth_runtime().operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route=route,
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record authentication event %s: %s", action_id, exc)


def get_avatar_path(user_id: int) -> Path:
    """Get avatar path for specific user."""
    return USER_DATA_DIR / f"avatar_{user_id}.png"


def normalize_avatar_image(contents: bytes) -> bytes:
    """Decode, validate, and re-encode avatar content as a safe PNG."""
    try:
        from PIL import Image, ImageOps, UnidentifiedImageError
    except Exception as exc:  # pragma: no cover
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Image processing dependencies are unavailable",
        ) from exc

    try:
        with Image.open(BytesIO(contents)) as image:
            image.load()
            width, height = image.size
            if width <= 0 or height <= 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Image dimensions are invalid",
                )
            if width * height > MAX_AVATAR_PIXELS:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Image is too large to process safely",
                )

            image = ImageOps.exif_transpose(image)
            if image.mode not in ("RGB", "RGBA"):
                image = image.convert("RGBA" if "A" in image.getbands() else "RGB")

            buffer = BytesIO()
            image.save(buffer, format="PNG", optimize=True)
            normalized = buffer.getvalue()
    except HTTPException:
        raise
    except UnidentifiedImageError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File is not a valid image",
        ) from exc
    except Exception as exc:
        logger.warning("Invalid avatar upload rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to process image",
        ) from exc

    if len(normalized) > MAX_AVATAR_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Processed avatar is too large (max 5MB)",
        )
    return normalized


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=256)
    email: str | None = None
    setup_token: str | None = None  # Required for first user registration

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v, info):
        """Validate password meets policy requirements."""
        # Get username from values if available
        username = info.data.get("username") if info.data else None
        result = validate_password(v, username)
        if not result.is_valid:
            raise ValueError("; ".join(result.errors))
        return v


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds
    user: "UserResponse"


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str | None
    role: str
    is_active: bool
    created_at: datetime
    last_login: datetime | None
    last_login_ip: str | None = None
    last_login_user_agent: str | None = None
    totp_enabled: bool = False


# 2FA Models
class TwoFactorSetupResponse(BaseModel):
    secret: str
    qr_code: str  # Base64 PNG
    uri: str


class TwoFactorEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=6)


class TwoFactorVerifyRequest(BaseModel):
    code: str = Field(
        min_length=6, max_length=10
    )  # 6 for TOTP, 9 for backup (XXXX-XXXX)


class TwoFactorBackupCodesResponse(BaseModel):
    backup_codes: list[str]


class LoginWith2FARequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)
    totp_code: str | None = None


class RegistrationStatusResponse(BaseModel):
    registration_allowed: bool
    requires_setup_token: bool
    message: str
    setup_token: str | None = None


class RecoveryLoginRequest(BaseModel):
    recovery_token: str | None = Field(default=None, min_length=1, max_length=256)
    totp_code: str | None = Field(
        default=None, min_length=6, max_length=10
    )  # 6 for TOTP, 9 for backup


class RecoveryLoginResponse(BaseModel):
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    user: UserResponse | None = None
    message: str
    requires_2fa: bool = False


def auth_runtime():
    """Resolve facade overrides while keeping route modules acyclic."""
    return sys.modules.get("app.api.v1.endpoints.auth", sys.modules[__name__])


__all__ = [
    "ACCESS_TOKEN_EXPIRE_MINUTES",
    "APIRouter",
    "API_TOKEN_PATH",
    "BaseModel",
    "BytesIO",
    "ConfigDict",
    "Depends",
    "Field",
    "File",
    "FileResponse",
    "HTTPAuthorizationCredentials",
    "HTTPBearer",
    "HTTPException",
    "JSONResponse",
    "LoginRequest",
    "LoginWith2FARequest",
    "MAX_AVATAR_BYTES",
    "MAX_AVATAR_PIXELS",
    "OperationEventService",
    "Path",
    "RecoveryLoginRequest",
    "RecoveryLoginResponse",
    "RefreshTokenRequest",
    "RegisterRequest",
    "RegistrationStatusResponse",
    "Request",
    "Session",
    "TokenResponse",
    "TwoFactorBackupCodesResponse",
    "TwoFactorEnableRequest",
    "TwoFactorSetupResponse",
    "TwoFactorVerifyRequest",
    "USER_DATA_DIR",
    "UploadFile",
    "User",
    "UserResponse",
    "UserSession",
    "WS_TOKEN_LIFETIME",
    "_record_auth_event",
    "_verify_user_totp",
    "auth_runtime",
    "check_password_strength",
    "check_rate_limit",
    "check_subject_rate_limit",
    "clear_auth_cookies",
    "create_token_pair",
    "dataclass",
    "datetime",
    "decode_access_token",
    "decode_refresh_token",
    "decrypt_password",
    "encrypt_password",
    "field_validator",
    "generate_backup_codes",
    "generate_qr_code",
    "generate_totp_secret",
    "get_avatar_path",
    "get_client_ip",
    "get_current_user",
    "get_db",
    "get_password_hash",
    "get_refresh_token_from_cookie",
    "get_token_from_request",
    "get_totp_uri",
    "get_user_data_dir",
    "hmac",
    "json",
    "logger",
    "logging",
    "normalize_avatar_image",
    "operation_event_service",
    "require_admin",
    "reset_rate_limit",
    "reset_subject_rate_limit",
    "revoke_all_user_sessions",
    "revoke_token",
    "router",
    "secrets",
    "security",
    "select",
    "set_auth_cookies",
    "status",
    "terminal_security",
    "timezone",
    "update",
    "utc_now",
    "validate_password",
    "verify_backup_code",
    "verify_password",
    "verify_totp",
]
