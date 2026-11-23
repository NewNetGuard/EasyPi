"""Authentication profile routes."""

from __future__ import annotations

# ruff: noqa: F401

from app.api.deps import get_current_user as get_authenticated_user
from app.api.v1.endpoints.auth_components.context import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    APIRouter,
    API_TOKEN_PATH,
    BaseModel,
    BytesIO,
    ConfigDict,
    Depends,
    Field,
    File,
    FileResponse,
    HTTPAuthorizationCredentials,
    HTTPBearer,
    HTTPException,
    JSONResponse,
    LoginRequest,
    LoginWith2FARequest,
    MAX_AVATAR_BYTES,
    MAX_AVATAR_PIXELS,
    OperationEventService,
    Path,
    RecoveryLoginRequest,
    RecoveryLoginResponse,
    RefreshTokenRequest,
    RegisterRequest,
    RegistrationStatusResponse,
    Request,
    Session,
    TokenResponse,
    TwoFactorBackupCodesResponse,
    TwoFactorEnableRequest,
    TwoFactorSetupResponse,
    TwoFactorVerifyRequest,
    USER_DATA_DIR,
    UploadFile,
    User,
    UserResponse,
    UserSession,
    WS_TOKEN_LIFETIME,
    _record_auth_event,
    _verify_user_totp,
    auth_runtime,
    check_password_strength,
    check_rate_limit,
    clear_auth_cookies,
    create_token_pair,
    dataclass,
    datetime,
    decode_access_token,
    decode_refresh_token,
    decrypt_password,
    encrypt_password,
    field_validator,
    generate_backup_codes,
    generate_qr_code,
    generate_totp_secret,
    get_avatar_path,
    get_client_ip,
    get_current_user,
    get_db,
    get_password_hash,
    get_refresh_token_from_cookie,
    get_token_from_request,
    get_totp_uri,
    get_user_data_dir,
    hmac,
    json,
    logger,
    logging,
    normalize_avatar_image,
    operation_event_service,
    require_admin,
    reset_rate_limit,
    revoke_all_user_sessions,
    revoke_token,
    router,
    secrets,
    security,
    select,
    set_auth_cookies,
    status,
    terminal_security,
    timezone,
    update,
    utc_now,
    validate_password,
    verify_backup_code,
    verify_password,
    verify_totp,
)


@router.get("/me", response_model=UserResponse)
async def me(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> UserResponse:
    """Get current user info with session validation."""
    # Get token from cookie or header
    token = auth_runtime().get_token_from_request(request)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid token",
        )

    # Decode token with session validation
    try:
        from app.core.security import decode_access_token

        payload = decode_access_token(token, db=db)
        user_id = payload.get("sub")

        if not user_id:
            raise ValueError("Invalid token")

        # Get user from database
        result = db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated",
            )

        return UserResponse.model_validate(user)

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


@router.get("/admin-check")
async def admin_check(_admin: User = Depends(require_admin)) -> dict[str, bool]:
    """Small nginx auth_request target for admin-only large uploads."""

    return {"admin": True}


@router.get("/go2rtc-check")
async def go2rtc_check(
    request: Request,
    _user: User = Depends(get_authenticated_user),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    """Authorize nginx camera playback without exposing go2rtc management."""
    from app.api.v1.endpoints.camera_helpers import normalize_stream_name
    from app.core.go2rtc_proxy import validate_go2rtc_proxy_request
    from app.models.camera import Camera

    names = (
        normalize_stream_name(name, camera_id)
        for name, camera_id in db.query(Camera.name, Camera.id).all()
    )
    try:
        validate_go2rtc_proxy_request(
            request.headers.get("X-Original-URI", ""),
            request.headers.get("X-Original-Method", ""),
            names,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Camera proxy request is not permitted",
        ) from exc
    return {"allowed": True}


@router.post("/avatar")
async def upload_avatar(
    request: Request,
    file: UploadFile = File(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Upload user avatar image."""
    started_at = datetime.now(timezone.utc).isoformat()
    # Get current user
    current_user = auth_runtime().get_current_user(request, credentials, db)
    subtitle = f"User - {current_user.username}"

    # Validate file type
    if not file.content_type or not file.content_type.startswith("image/"):
        _record_auth_event(
            action_id="auth.avatar.upload",
            title="Update avatar",
            subtitle=subtitle,
            status="failed",
            message="File must be an image",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="File must be an image"
        )

    # Validate file size (max 5MB)
    contents = await file.read(MAX_AVATAR_BYTES + 1)
    if len(contents) > MAX_AVATAR_BYTES:
        _record_auth_event(
            action_id="auth.avatar.upload",
            title="Update avatar",
            subtitle=subtitle,
            status="failed",
            message="Avatar file is too large",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="File too large (max 5MB)"
        )

    try:
        normalized_avatar = normalize_avatar_image(contents)
        # Save avatar with user ID
        avatar_path = get_avatar_path(current_user.id)
        with open(avatar_path, "wb") as f:
            f.write(normalized_avatar)

        logger.info(
            f"Avatar uploaded successfully for user {current_user.id}: {len(normalized_avatar)} bytes"
        )
        _record_auth_event(
            action_id="auth.avatar.upload",
            title="Update avatar",
            subtitle=subtitle,
            status="success",
            message="Avatar uploaded successfully",
            started_at=started_at,
        )
        return {"success": True, "message": "Avatar uploaded successfully"}
    except Exception as e:
        if isinstance(e, HTTPException):
            _record_auth_event(
                action_id="auth.avatar.upload",
                title="Update avatar",
                subtitle=subtitle,
                status="failed",
                message=str(e.detail),
                started_at=started_at,
            )
            raise
        logger.error(f"Failed to save avatar: {e}")
        _record_auth_event(
            action_id="auth.avatar.upload",
            title="Update avatar",
            subtitle=subtitle,
            status="failed",
            message="Failed to save avatar",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save avatar",
        )


@router.get("/avatar")
async def get_avatar(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Get user avatar image - always returns valid PNG."""
    current_user = auth_runtime().get_current_user(request, credentials, db)
    avatar_path = get_avatar_path(current_user.id)

    # User has custom avatar
    if avatar_path.exists():
        return FileResponse(
            avatar_path, media_type="image/png", headers={"Cache-Control": "no-cache"}
        )

    # Generate placeholder with user initials
    from PIL import Image, ImageDraw, ImageFont
    from fastapi.responses import StreamingResponse

    # Get user initials
    username = current_user.username or "U"
    initial = username[0].upper()

    # Generate professional colors from username hash (blue/teal/purple palette)
    import hashlib

    color_hash = int(hashlib.sha256(username.encode()).hexdigest()[:6], 16)

    # Choose from professional color palette
    colors = [
        (59, 130, 246),  # Blue
        (16, 185, 129),  # Green
        (139, 92, 246),  # Purple
        (6, 182, 212),  # Cyan
        (251, 146, 60),  # Orange
        (236, 72, 153),  # Pink (darker)
    ]
    bg_color = colors[color_hash % len(colors)]

    # Create image
    img = Image.new("RGB", (128, 128), bg_color)
    draw = ImageDraw.Draw(img)

    # Draw initial with very large font to fill the circle
    try:
        font = ImageFont.truetype(
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 96
        )
    except Exception:
        font = ImageFont.load_default()

    # Center text
    bbox = draw.textbbox((0, 0), initial, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    position = (
        (128 - text_width) // 2 - bbox[0],
        (128 - text_height) // 2 - bbox[1],
    )

    draw.text(position, initial, fill=(255, 255, 255), font=font)

    # Return as PNG stream
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)

    return StreamingResponse(
        buf, media_type="image/png", headers={"Cache-Control": "max-age=3600"}
    )


@router.delete("/avatar")
async def delete_avatar(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Delete user avatar."""
    started_at = datetime.now(timezone.utc).isoformat()
    current_user = auth_runtime().get_current_user(request, credentials, db)
    subtitle = f"User - {current_user.username}"
    avatar_path = get_avatar_path(current_user.id)
    if avatar_path.exists():
        avatar_path.unlink()
        _record_auth_event(
            action_id="auth.avatar.delete",
            title="Delete avatar",
            subtitle=subtitle,
            status="success",
            message="Avatar deleted",
            started_at=started_at,
        )
        return {"success": True, "message": "Avatar deleted"}
    _record_auth_event(
        action_id="auth.avatar.delete",
        title="Delete avatar",
        subtitle=subtitle,
        status="success",
        message="No avatar to delete",
        started_at=started_at,
    )
    return {"success": True, "message": "No avatar to delete"}


@router.get("/api-token")
async def get_api_token(
    _admin: User = Depends(require_admin),
):
    """Get current API token (or generate if not exists)."""
    if auth_runtime().API_TOKEN_PATH.exists():
        token = auth_runtime().API_TOKEN_PATH.read_text().strip()
        # Return masked version
        if len(token) > 12:
            masked = token[:8] + "..." + token[-4:]
        else:
            masked = "****"
        return {"token_masked": masked, "has_token": True}
    return {"token_masked": None, "has_token": False}


@router.post("/api-token/generate")
async def generate_api_token(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """Generate a new API token."""
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Security - {current_user.username}"
    # Rate limit: 5 attempts per 5 minutes
    auth_runtime().check_rate_limit(request, "api_token")

    # Generate secure random token
    token = "easypi_" + secrets.token_urlsafe(32)

    try:
        auth_runtime().API_TOKEN_PATH.write_text(token)
        logger.info("New API token generated")
        _record_auth_event(
            action_id="auth.api-token.generate",
            title="Generate API token",
            subtitle=subtitle,
            status="success",
            message="A new API token was generated",
            started_at=started_at,
        )

        # Return the full token (only shown once!)
        return {
            "token": token,
            "message": "New token generated. Save it now - it won't be shown again!",
        }
    except Exception as e:
        logger.error(f"Failed to save API token: {e}")
        _record_auth_event(
            action_id="auth.api-token.generate",
            title="Generate API token",
            subtitle=subtitle,
            status="failed",
            message="Failed to generate API token",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate token",
        )


class ApiTokenVerifyRequest(BaseModel):
    token: str = Field(min_length=1, max_length=512)


@router.post("/api-token/verify")
async def verify_api_token(payload: ApiTokenVerifyRequest, request: Request):
    """Verify if an API token is valid."""
    # Unauthenticated secret-verification oracle: rate-limit it, and take the token from the
    # body (never a URL/query param, so it can't leak into nginx/access logs).
    auth_runtime().check_rate_limit(request, "login")
    if not auth_runtime().API_TOKEN_PATH.exists():
        return {"valid": False, "message": "No token configured"}

    stored_token = auth_runtime().API_TOKEN_PATH.read_text().strip()
    if secrets.compare_digest(payload.token, stored_token):
        return {"valid": True, "message": "Token is valid"}
    return {"valid": False, "message": "Invalid token"}


__all__ = [
    "ApiTokenVerifyRequest",
    "admin_check",
    "delete_avatar",
    "generate_api_token",
    "get_api_token",
    "get_avatar",
    "me",
    "upload_avatar",
    "verify_api_token",
]
