"""Authentication sessions routes."""

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


@router.get("/sessions")
async def list_sessions(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> list[dict]:
    """List all active sessions for current user."""
    try:
        user = auth_runtime().get_current_user(request, credentials, db)
        user_id = user.id

        result = db.execute(
            select(UserSession)
            .where(UserSession.user_id == user_id)
            .where(UserSession.is_active.is_(True))
            .order_by(UserSession.last_active.desc())
        )
        sessions = result.scalars().all()

        # Try to get current session jti from refresh token if available
        current_jti = None

        return [s.to_response(current_jti=current_jti) for s in sessions]

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List sessions error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list sessions",
        )


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke a specific session."""
    started_at = datetime.now(timezone.utc).isoformat()
    token = auth_runtime().get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    try:
        from app.core.security import decode_access_token

        user = auth_runtime().get_current_user(request, credentials, db)
        decode_access_token(token, db=db)
        user_id = user.id
        subtitle = f"Security - User {user_id}"

        result = db.execute(
            select(UserSession)
            .where(UserSession.id == session_id)
            .where(UserSession.user_id == user_id)
        )
        session = result.scalar_one_or_none()

        if not session:
            _record_auth_event(
                action_id="auth.session.revoke",
                title="Revoke session",
                subtitle=subtitle,
                status="failed",
                message="Session not found",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Session not found"
            )

        # Revoke the session
        session.is_active = False
        session.revoked_at = utc_now()

        db.commit()

        logger.info(f"Session {session_id} revoked for user {user_id}")
        _record_auth_event(
            action_id="auth.session.revoke",
            title="Revoke session",
            subtitle=subtitle,
            status="success",
            message=f"Session {session_id} revoked successfully",
            started_at=started_at,
        )

        return {"success": True, "message": "Session revoked successfully"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Revoke session error: {e}")
        _record_auth_event(
            action_id="auth.session.revoke",
            title="Revoke session",
            subtitle="Security - Sessions",
            status="failed",
            message="Failed to revoke session",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke session",
        )


@router.delete("/sessions")
async def revoke_all_sessions(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
) -> dict:
    """Revoke all sessions except current."""
    started_at = datetime.now(timezone.utc).isoformat()
    token = auth_runtime().get_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )

    try:
        from app.core.security import decode_access_token

        user = auth_runtime().get_current_user(request, credentials, db)
        decode_access_token(token, db=db)
        user_id = user.id
        subtitle = f"Security - User {user_id}"

        result = db.execute(
            select(UserSession)
            .where(UserSession.user_id == user_id)
            .where(UserSession.is_active.is_(True))
        )
        sessions = result.scalars().all()

        revoked_count = 0
        for session in sessions:
            session.is_active = False
            session.revoked_at = utc_now()
            revoked_count += 1

        db.commit()

        logger.info(f"Revoked {revoked_count} sessions for user {user_id}")
        _record_auth_event(
            action_id="auth.session.revoke-all",
            title="Revoke all sessions",
            subtitle=subtitle,
            status="success",
            message=f"Revoked {revoked_count} sessions",
            started_at=started_at,
        )

        return {
            "success": True,
            "message": f"Revoked {revoked_count} sessions",
            "count": revoked_count,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Revoke all sessions error: {e}")
        _record_auth_event(
            action_id="auth.session.revoke-all",
            title="Revoke all sessions",
            subtitle="Security - Sessions",
            status="failed",
            message="Failed to revoke sessions",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to revoke sessions",
        )


__all__ = [
    "list_sessions",
    "revoke_all_sessions",
    "revoke_session",
]
