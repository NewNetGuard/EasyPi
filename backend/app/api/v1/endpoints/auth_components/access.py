"""Authentication access routes."""

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


@router.get(
    "/csrf",
    response_model=dict,
    summary="Get CSRF token",
    description="Get the current CSRF token. Use this if the cookie is not readable.",
)
async def get_csrf_token(request: Request):
    """
    Get the current CSRF token.

    This endpoint returns the CSRF token from the cookie, or generates a new one.
    This allows the frontend to get the token even if the cookie is HttpOnly.
    """
    from app.core.csrf import get_csrf_token_from_request

    token = get_csrf_token_from_request(request)
    return {"csrf_token": token}


@router.get(
    "/registration-status",
    response_model=RegistrationStatusResponse,
    summary="Check registration status",
    description="Check if public registration is allowed and if setup token is required.",
)
async def get_registration_status(
    db: Session = Depends(get_db),
) -> RegistrationStatusResponse:
    """
    Check the current registration status.

    Returns:
    - registration_allowed: True if registration is currently possible
    - requires_setup_token: True if a setup token is required (first user)
    - message: Human-readable status message
    """
    user_count = db.query(User).count()

    if user_count == 0:
        return RegistrationStatusResponse(
            registration_allowed=True,
            requires_setup_token=True,
            setup_token=None,
            message="First user registration. Enter the setup token shown on the EasyPi console.",
        )
    else:
        return RegistrationStatusResponse(
            registration_allowed=False,
            requires_setup_token=False,
            setup_token=None,
            message="Public registration is disabled. Contact administrator.",
        )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register new user",
    description="Create a new user account. Rate limited to 3 attempts per 5 minutes.",
)
async def register(
    payload: RegisterRequest, request: Request, db: Session = Depends(get_db)
) -> TokenResponse:
    """
    Register a new user account.

    - **username**: Unique username (3-50 characters)
    - **email**: Valid email address (optional)
    - **password**: Strong password (min 8 characters)

    Returns access and refresh tokens on success.
    """

    # Rate limit: 3 attempts per 5 minutes
    auth_runtime().check_rate_limit(request, "register")

    # Check if this is the first user registration or subsequent
    user_count = db.query(User).count()

    if user_count == 0:
        # First user - require setup token
        from app.db.init_db import has_setup_token, verify_setup_token

        if not has_setup_token():
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Setup token not generated. Please restart the server.",
            )

        if not payload.setup_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Setup token required for first user registration. Check server console.",
            )

        if not verify_setup_token(payload.setup_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid setup token"
            )

        role = "admin"
        # Token will be cleared after successful registration
    else:
        # Subsequent registration - public registration disabled
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled. Contact administrator.",
        )

    # Check if username already exists
    result = db.execute(select(User).where(User.username == payload.username))
    existing_user = result.scalar_one_or_none()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    # Check if email already exists
    if payload.email:
        result = db.execute(select(User).where(User.email == payload.email))
        existing_email = result.scalar_one_or_none()

        if existing_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered",
            )

    # Capture session metadata for immediate post-registration session.
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Unknown")

    # Create new user (role already determined above)
    hashed_password = get_password_hash(payload.password)
    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hashed_password,
        role=role,
        is_active=True,
        created_at=utc_now(),
        last_login=utc_now(),
        last_login_ip=client_ip,
        last_login_user_agent=user_agent,
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Preserve the user-supplied setup token as the recovery credential, but
    # never leave the plaintext token on disk after registration.
    if role == "admin":
        from app.db.init_db import promote_setup_token_to_recovery

        if promote_setup_token_to_recovery(payload.setup_token or ""):
            logger.info(
                f"First admin user '{new_user.username}' registered. "
                "Recovery token preserved."
            )
        else:
            logger.critical(
                "First administrator was created, but setup-token promotion failed"
            )

    # Create token pair (access + refresh)
    token_data = {
        "sub": new_user.id,
        "username": new_user.username,
        "role": new_user.role,
    }
    access_token, refresh_token, refresh_jti, refresh_expires = create_token_pair(
        token_data
    )

    # Create session record
    session = UserSession(
        user_id=new_user.id,
        token_jti=refresh_jti,
        ip_address=client_ip,
        user_agent=user_agent,
        expires_at=refresh_expires,
    )
    db.add(session)
    db.commit()

    # Response contains only user info - tokens are in httpOnly cookies only!
    response_data = {
        "message": "Registration successful",
        "user": UserResponse.model_validate(new_user).model_dump(mode="json"),
    }
    response = JSONResponse(content=response_data, status_code=status.HTTP_201_CREATED)

    # Set httpOnly cookies (the ONLY place tokens exist)
    set_auth_cookies(response, access_token, refresh_token, request)

    return response


@router.post(
    "/login",
    summary="User login",
    description="Authenticate with username/password. Returns JWT tokens. Requires 2FA code if enabled.",
)
async def login(
    payload: LoginWith2FARequest, request: Request, db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.

    - **username**: User's username
    - **password**: User's password
    - **totp_code**: 6-digit TOTP code (required if 2FA is enabled)

    Rate limited: 5 attempts per minute, blocked for 5 minutes after exceeding.
    """

    # Rate limit: 5 attempts per minute, block for 5 min after exceeded
    auth_runtime().check_rate_limit(request, "login")
    # This account-scoped bucket survives successful logins to other accounts.
    auth_runtime().check_subject_rate_limit(
        payload.username, "login", get_client_ip(request)
    )

    # Find user by username
    result = db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify password
    if not auth_runtime().verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user is active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
        )

    # Check 2FA if enabled
    if user.totp_enabled:
        if not payload.totp_code:
            # Return special response indicating 2FA is required
            return {
                "requires_2fa": True,
                "message": "Two-factor authentication code required",
            }

        # Verify TOTP code
        is_valid = _verify_user_totp(user, payload.totp_code)

        # If TOTP failed, try backup code
        if not is_valid and user.backup_codes:
            is_valid, updated_codes = verify_backup_code(
                payload.totp_code, user.backup_codes
            )
            if is_valid:
                user.backup_codes = updated_codes
                logger.warning(f"Backup code used for {user.username}")

        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid two-factor authentication code",
            )

    # Update last login with IP and User-Agent
    user.last_login = utc_now()

    user.last_login_ip = get_client_ip(request)
    client_ip = user.last_login_ip

    # Get User-Agent
    user.last_login_user_agent = request.headers.get("User-Agent", "Unknown")

    db.commit()

    # Create token pair (access + refresh)
    token_data = {"sub": user.id, "username": user.username, "role": user.role}
    access_token, refresh_token, refresh_jti, refresh_expires = create_token_pair(
        token_data
    )

    # Create session record
    session = UserSession(
        user_id=user.id,
        token_jti=refresh_jti,
        ip_address=client_ip,
        user_agent=user.last_login_user_agent,
        expires_at=refresh_expires,
    )
    db.add(session)
    db.commit()

    logger.info(f"Login successful for {user.username}")

    # Reset rate limit after successful login
    auth_runtime().reset_rate_limit(request, "login")
    auth_runtime().reset_subject_rate_limit(user.username, "login", client_ip)

    # Response contains only user info - tokens are in httpOnly cookies only!
    # This prevents XSS from stealing tokens
    response_data = {
        "message": "Login successful",
        "user": UserResponse.model_validate(user).model_dump(mode="json"),
    }
    response = JSONResponse(content=response_data)

    # Set httpOnly cookies (the ONLY place tokens exist)
    set_auth_cookies(response, access_token, refresh_token, request)

    return response


@router.post(
    "/recovery-login",
    response_model=RecoveryLoginResponse,
    summary="Recovery login with token or 2FA",
    description="Login using recovery token or 2FA if you forgot your password.",
)
async def recovery_login(
    payload: RecoveryLoginRequest, request: Request, db: Session = Depends(get_db)
) -> RecoveryLoginResponse:
    """
    Login using recovery token or 2FA.

    Two recovery methods available:
    1. **Recovery Token** - permanent token shown during first setup
    2. **2FA Code** - if two-factor authentication is enabled

    Use this if you forgot your password. After login, change your password in settings.
    """

    # Rate limit: 3 attempts per 5 minutes
    auth_runtime().check_rate_limit(request, "recovery")

    if not payload.recovery_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Recovery token is required"
        )

    from app.db.init_db import has_recovery_token, verify_recovery_token

    if not has_recovery_token():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recovery token not configured",
        )
    if not verify_recovery_token(payload.recovery_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid recovery credentials",
        )

    result = db.execute(
        select(User)
        .where(User.role == "admin", User.is_active.is_(True))
        .order_by(User.id)
        .limit(1)
    )
    admin_user = result.scalar_one_or_none()
    recovery_method = "token"

    if admin_user and admin_user.totp_enabled:
        if not payload.totp_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Two-factor authentication code is required",
            )
        is_valid = _verify_user_totp(admin_user, payload.totp_code)
        if not is_valid and admin_user.backup_codes:
            is_valid, updated_codes = verify_backup_code(
                payload.totp_code, admin_user.backup_codes
            )
            if is_valid:
                admin_user.backup_codes = updated_codes
                logger.warning(f"Backup code used for recovery: {admin_user.username}")
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid recovery credentials",
            )
        recovery_method = "token+2fa"

    if not admin_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="No admin user found"
        )

    # Update last login
    admin_user.last_login = utc_now()
    admin_user.last_login_ip = get_client_ip(request)
    admin_user.last_login_user_agent = request.headers.get("User-Agent", "Unknown")
    db.commit()

    # Create token pair
    token_data = {
        "sub": admin_user.id,
        "username": admin_user.username,
        "role": admin_user.role,
    }
    access_token, refresh_token, refresh_jti, refresh_expires = create_token_pair(
        token_data
    )

    # Create session record
    session = UserSession(
        user_id=admin_user.id,
        token_jti=refresh_jti,
        ip_address=admin_user.last_login_ip,
        user_agent=admin_user.last_login_user_agent,
        expires_at=refresh_expires,
    )
    db.add(session)
    db.commit()

    logger.warning(
        f"Recovery login via {recovery_method} for user '{admin_user.username}'"
    )
    auth_runtime().reset_rate_limit(request, "recovery")

    # Response contains only user info - tokens are in httpOnly cookies only!
    response_data = {
        "message": "Recovery login successful. Please change your password in settings.",
        "user": UserResponse.model_validate(admin_user).model_dump(mode="json"),
        "requires_2fa": False,
    }
    response = JSONResponse(content=response_data)

    # Set httpOnly cookies (the ONLY place tokens exist)
    set_auth_cookies(response, access_token, refresh_token, request)

    return response


@router.post("/refresh")
async def refresh_access_token(request: Request, db: Session = Depends(get_db)):
    """Refresh access token using refresh token from cookie or body."""
    try:
        # Get refresh token from cookie first, then body
        refresh_token = get_refresh_token_from_cookie(request)

        if not refresh_token:
            # Fall back to body for API clients
            try:
                body = await request.json()
                refresh_token = body.get("refresh_token")
            except Exception as exc:
                logger.debug("Refresh request body did not contain valid JSON: %s", exc)

        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token required",
            )

        # Decode and validate refresh token WITH session check
        token_payload = decode_refresh_token(refresh_token, db=db)
        user_id = token_payload.get("sub")
        old_jti = token_payload.get("jti")

        if not user_id:
            raise ValueError("Invalid token payload")

        # End the read transaction opened by token validation, then atomically
        # claim this one-time refresh token. Two concurrent requests cannot both
        # rotate the same session.
        db.rollback()
        revoked_at = utc_now()
        claim = db.execute(
            update(UserSession)
            .where(
                UserSession.token_jti == old_jti,
                UserSession.user_id == int(user_id),
                UserSession.is_active.is_(True),
            )
            .values(is_active=False, revoked_at=revoked_at)
        )

        if claim.rowcount != 1:
            db.rollback()
            logger.warning(f"Refresh attempt with invalid/revoked jti={old_jti}")
            raise ValueError("Session has been revoked")

        # Get user from database (convert user_id to int as JWT sub is always string)
        result = db.execute(select(User).where(User.id == int(user_id)))
        user = result.scalar_one_or_none()

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="User account is disabled"
            )

        # Create new token pair with new session
        token_data = {"sub": user.id, "username": user.username, "role": user.role}
        new_access_token, new_refresh_token, new_jti, new_expires = create_token_pair(
            token_data
        )

        # Create new session with rotated jti
        new_session = UserSession(
            user_id=user.id,
            token_jti=new_jti,
            ip_address=get_client_ip(request),
            user_agent=request.headers.get("User-Agent"),
            expires_at=new_expires,
        )
        db.add(new_session)
        db.commit()

        logger.info(
            f"Token refreshed for {user.username}, old_jti={old_jti}, new_jti={new_jti}"
        )

        # Response contains only user info - tokens are in httpOnly cookies only!
        response_data = {
            "message": "Token refreshed",
            "user": UserResponse.model_validate(user).model_dump(mode="json"),
        }
        response = JSONResponse(content=response_data)

        # Set new httpOnly cookies (the ONLY place tokens exist)
        set_auth_cookies(response, new_access_token, new_refresh_token, request)

        return response

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post("/logout")
async def logout(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """Logout user, revoke session, and clear cookies."""
    # Get token from cookie or header
    token = auth_runtime().get_token_from_request(request)

    if token:
        # Revoke token and deactivate session in DB
        revoke_token(token, db=db)
        logger.info("User logged out, session revoked")

    # Create response that clears cookies
    response = JSONResponse(content={"message": "Successfully logged out"})
    clear_auth_cookies(response, request)

    return response


__all__ = [
    "get_csrf_token",
    "get_registration_status",
    "login",
    "logout",
    "recovery_login",
    "refresh_access_token",
    "register",
]
