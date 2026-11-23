"""Authentication security routes."""

from __future__ import annotations

# ruff: noqa: F401

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


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=8, max_length=256)

    @field_validator("new_password")
    @classmethod
    def validate_new_password(cls, v):
        """Validate new password meets policy requirements."""
        result = validate_password(v)
        if not result.is_valid:
            raise ValueError("; ".join(result.errors))
        return v


@router.post("/change-password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Change current user's password and revoke all other sessions."""
    started_at = datetime.now(timezone.utc).isoformat()
    # Rate limit: 3 attempts per minute
    auth_runtime().check_rate_limit(request, "password_change")

    try:
        from app.core.security import decode_access_token

        # Accept token from httpOnly cookie or Authorization header
        token = auth_runtime().get_token_from_request(request)
        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated",
            )

        token_payload = decode_access_token(token, db=db)
        user_id = token_payload.get("sub")
        current_jti = token_payload.get("jti")

        if not user_id:
            raise ValueError("Invalid token")

        # Get user from database
        result = db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()

        if not user:
            _record_auth_event(
                action_id="auth.password.change",
                title="Change password",
                subtitle="Security - Unknown user",
                status="failed",
                message="User not found",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
            )

        subtitle = f"Security - {user.username}"

        # Verify current password
        if not auth_runtime().verify_password(
            payload.current_password, user.password_hash
        ):
            _record_auth_event(
                action_id="auth.password.change",
                title="Change password",
                subtitle=subtitle,
                status="failed",
                message="Current password is incorrect",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect",
            )

        # Update password
        user.password_hash = get_password_hash(payload.new_password)

        # Revoke all other sessions (security: invalidate all tokens on password change)
        revoked_count = revoke_all_user_sessions(user.id, db, exclude_jti=current_jti)

        db.commit()

        logger.info(
            f"Password changed for user: {user.username}, revoked {revoked_count} other sessions"
        )
        _record_auth_event(
            action_id="auth.password.change",
            title="Change password",
            subtitle=subtitle,
            status="success",
            message=f"Password changed and {revoked_count} other sessions were revoked",
            started_at=started_at,
        )

        # Reset rate limit after successful change
        auth_runtime().reset_rate_limit(request, "password_change")

        return {
            "success": True,
            "message": f"Password changed successfully. {revoked_count} other sessions logged out.",
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Password change error: {e}")
        _record_auth_event(
            action_id="auth.password.change",
            title="Change password",
            subtitle="Security - Password",
            status="failed",
            message="Invalid token",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


class PasswordStrengthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)
    username: str | None = None


@router.post(
    "/password/check-strength",
    summary="Check password strength",
    description="Validate password strength and get improvement suggestions.",
)
async def check_password_strength_endpoint(
    payload: PasswordStrengthRequest, request: Request
) -> dict:
    """
    Check password strength without authentication.

    Returns:
        - strength: weak/fair/good/strong/very_strong
        - score: 0-100
        - is_valid: Whether password meets policy
        - errors: List of policy violations
        - suggestions: Improvement tips
        - criteria: Which requirements are met
    """
    # Public, unauthenticated + does non-trivial work -> bound it so it can't be a CPU-DoS.
    auth_runtime().check_rate_limit(request, "api_default")
    result = validate_password(payload.password, payload.username)
    feedback = check_password_strength(payload.password)

    return {
        "is_valid": result.is_valid,
        "strength": result.strength.value,
        "score": result.score,
        "errors": result.errors,
        "suggestions": result.suggestions,
        "criteria": feedback["criteria"],
        "policy": {
            "min_length": 8,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_digit": True,
            "require_special": False,
            "reject_common": True,
        },
    }


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
async def setup_2fa(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> TwoFactorSetupResponse:
    """Generate 2FA secret and QR code for setup."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        user = auth_runtime().get_current_user(request, credentials, db)
        subtitle = f"Security - {user.username}"

        if user.totp_enabled:
            _record_auth_event(
                action_id="auth.2fa.setup",
                title="Set up two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="2FA is already enabled",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled"
            )

        # Generate new secret
        secret = generate_totp_secret()
        uri = get_totp_uri(secret, user.username)
        qr_code = generate_qr_code(uri)

        # Store secret temporarily (not enabled yet)
        user.totp_secret = encrypt_password(secret)
        db.commit()
        _record_auth_event(
            action_id="auth.2fa.setup",
            title="Set up two-factor authentication",
            subtitle=subtitle,
            status="success",
            message="Generated a new 2FA secret and QR code",
            started_at=started_at,
        )

        return TwoFactorSetupResponse(secret=secret, qr_code=qr_code, uri=uri)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA setup error: {e}")
        _record_auth_event(
            action_id="auth.2fa.setup",
            title="Set up two-factor authentication",
            subtitle="Security - 2FA",
            status="failed",
            message="Failed to set up 2FA",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to setup 2FA",
        )


@router.post("/2fa/enable", response_model=TwoFactorBackupCodesResponse)
async def enable_2fa(
    payload: TwoFactorEnableRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> TwoFactorBackupCodesResponse:
    """Verify TOTP code and enable 2FA. Returns backup codes."""
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        user = auth_runtime().get_current_user(request, credentials, db)
        subtitle = f"Security - {user.username}"

        if user.totp_enabled:
            _record_auth_event(
                action_id="auth.2fa.enable",
                title="Enable two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="2FA is already enabled",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is already enabled"
            )

        if not user.totp_secret:
            _record_auth_event(
                action_id="auth.2fa.enable",
                title="Enable two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="Please set up 2FA first",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Please setup 2FA first"
            )

        auth_runtime().check_subject_rate_limit(user.id, "two_factor_verification")

        # Verify the code
        if not _verify_user_totp(user, payload.code):
            _record_auth_event(
                action_id="auth.2fa.enable",
                title="Enable two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="Invalid verification code",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )

        auth_runtime().reset_subject_rate_limit(user.id, "two_factor_verification")

        # Generate backup codes
        plain_codes, hashed_codes = generate_backup_codes(10)

        # Enable 2FA
        user.totp_enabled = True
        user.backup_codes = json.dumps(hashed_codes)
        db.commit()

        logger.info(f"2FA enabled for user: {user.username}")
        _record_auth_event(
            action_id="auth.2fa.enable",
            title="Enable two-factor authentication",
            subtitle=subtitle,
            status="success",
            message="2FA enabled and backup codes generated",
            started_at=started_at,
        )

        return TwoFactorBackupCodesResponse(backup_codes=plain_codes)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA enable error: {e}")
        _record_auth_event(
            action_id="auth.2fa.enable",
            title="Enable two-factor authentication",
            subtitle="Security - 2FA",
            status="failed",
            message="Failed to enable 2FA",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to enable 2FA",
        )


@router.post("/2fa/disable")
async def disable_2fa(
    payload: TwoFactorVerifyRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    """Disable 2FA (requires current TOTP code)."""
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        user = auth_runtime().get_current_user(request, credentials, db)
        subtitle = f"Security - {user.username}"

        if not user.totp_enabled:
            _record_auth_event(
                action_id="auth.2fa.disable",
                title="Disable two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="2FA is not enabled",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled"
            )

        auth_runtime().check_subject_rate_limit(user.id, "two_factor_verification")

        # Verify the code
        if not _verify_user_totp(user, payload.code):
            _record_auth_event(
                action_id="auth.2fa.disable",
                title="Disable two-factor authentication",
                subtitle=subtitle,
                status="failed",
                message="Invalid verification code",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )

        auth_runtime().reset_subject_rate_limit(user.id, "two_factor_verification")

        # Disable 2FA
        user.totp_enabled = False
        user.totp_secret = None
        user.backup_codes = None
        db.commit()

        logger.info(f"2FA disabled for user: {user.username}")
        _record_auth_event(
            action_id="auth.2fa.disable",
            title="Disable two-factor authentication",
            subtitle=subtitle,
            status="success",
            message="Two-factor authentication disabled",
            started_at=started_at,
        )

        return {"success": True, "message": "Two-factor authentication disabled"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA disable error: {e}")
        _record_auth_event(
            action_id="auth.2fa.disable",
            title="Disable two-factor authentication",
            subtitle="Security - 2FA",
            status="failed",
            message="Failed to disable 2FA",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to disable 2FA",
        )


@router.get("/2fa/status")
async def get_2fa_status(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    """Get 2FA status for current user."""
    try:
        user = auth_runtime().get_current_user(request, credentials, db)

        backup_codes_count = 0
        if user.backup_codes:
            try:
                backup_codes_count = len(json.loads(user.backup_codes))
            except (TypeError, json.JSONDecodeError) as exc:
                logger.warning(
                    "Invalid stored 2FA backup-code metadata for user %s: %s",
                    user.id,
                    exc,
                )

        return {
            "enabled": user.totp_enabled,
            "backup_codes_remaining": backup_codes_count,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"2FA status error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get 2FA status",
        )


@router.post("/2fa/backup-codes", response_model=TwoFactorBackupCodesResponse)
async def regenerate_backup_codes(
    payload: TwoFactorVerifyRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> TwoFactorBackupCodesResponse:
    """Regenerate backup codes (requires current TOTP code)."""
    started_at = datetime.now(timezone.utc).isoformat()

    try:
        user = auth_runtime().get_current_user(request, credentials, db)
        subtitle = f"Security - {user.username}"

        if not user.totp_enabled:
            _record_auth_event(
                action_id="auth.2fa.backup-codes",
                title="Regenerate backup codes",
                subtitle=subtitle,
                status="failed",
                message="2FA is not enabled",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="2FA is not enabled"
            )

        auth_runtime().check_subject_rate_limit(user.id, "two_factor_verification")

        # Verify the code
        if not _verify_user_totp(user, payload.code):
            _record_auth_event(
                action_id="auth.2fa.backup-codes",
                title="Regenerate backup codes",
                subtitle=subtitle,
                status="failed",
                message="Invalid verification code",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid verification code",
            )

        auth_runtime().reset_subject_rate_limit(user.id, "two_factor_verification")

        # Generate new backup codes
        plain_codes, hashed_codes = generate_backup_codes(10)
        user.backup_codes = json.dumps(hashed_codes)
        db.commit()

        logger.info(f"Backup codes regenerated for user: {user.username}")
        _record_auth_event(
            action_id="auth.2fa.backup-codes",
            title="Regenerate backup codes",
            subtitle=subtitle,
            status="success",
            message="Backup codes regenerated",
            started_at=started_at,
        )

        return TwoFactorBackupCodesResponse(backup_codes=plain_codes)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Backup codes regeneration error: {e}")
        _record_auth_event(
            action_id="auth.2fa.backup-codes",
            title="Regenerate backup codes",
            subtitle="Security - 2FA",
            status="failed",
            message="Failed to regenerate backup codes",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to regenerate backup codes",
        )


__all__ = [
    "PasswordChangeRequest",
    "PasswordStrengthRequest",
    "change_password",
    "check_password_strength_endpoint",
    "disable_2fa",
    "enable_2fa",
    "get_2fa_status",
    "regenerate_backup_codes",
    "setup_2fa",
]
