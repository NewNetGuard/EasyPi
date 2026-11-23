"""Authentication websocket routes."""

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


@dataclass(frozen=True)
class WebSocketTokenClaims:
    user_id: int
    session_jti: str


_ws_tokens: dict[str, tuple[WebSocketTokenClaims, float]] = {}


def cleanup_ws_tokens():
    """Remove expired WebSocket tokens."""
    import time

    now = time.time()
    expired = [k for k, v in _ws_tokens.items() if v[1] < now]
    for k in expired:
        del _ws_tokens[k]


def verify_ws_token(token: str) -> WebSocketTokenClaims | None:
    """Consume a WebSocket token and return its session-bound claims."""
    import time

    cleanup_ws_tokens()
    if token in _ws_tokens:
        claims, expires_at = _ws_tokens[token]
        if time.time() < expires_at:
            # Token is single-use - remove after verification
            del _ws_tokens[token]
            return claims
    return None


@router.post("/ws-token")
async def get_ws_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Get a temporary token for WebSocket authentication.

    WebSocket connections cannot use httpOnly cookies, so this endpoint
    provides a short-lived (30 seconds) single-use token that can be
    passed as a query parameter.

    Rate limited to prevent brute force attacks.
    """
    import time

    # Rate limit to prevent abuse
    auth_runtime().check_rate_limit(request, "ws_token")

    # Get current user from cookie or header
    current_user = auth_runtime().get_current_user(request, credentials, db)
    access_token = auth_runtime().get_token_from_request(request)
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    token_payload = decode_access_token(access_token, db=db)
    session_jti = str(token_payload.get("jti") or "")
    if not session_jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session"
        )

    # Generate temporary token
    ws_token = secrets.token_urlsafe(32)

    # Store with 30 second expiry
    claims = WebSocketTokenClaims(
        user_id=current_user.id,
        session_jti=session_jti,
    )
    _ws_tokens[ws_token] = (claims, time.time() + 30)

    # Cleanup old tokens periodically
    cleanup_ws_tokens()

    return {"ws_token": ws_token, "expires_in": 30}


@router.post("/terminal-ws-token")
async def get_terminal_ws_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db),
):
    """
    Get a temporary token for terminal WebSocket authentication.

    This token is bound to client IP and User-Agent, single-use,
    and short-lived for maximum security.
    """
    auth_runtime().check_rate_limit(request, "terminal_ws_token")

    current_user = auth_runtime().get_current_user(request, credentials, db)
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "")
    if not user_agent:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User-Agent required",
        )

    allowed, reason = terminal_security.is_ip_allowed(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=reason,
        )

    can_create, reason = terminal_security.can_create_session(current_user.id)
    if not can_create:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=reason,
        )

    ws_token = secrets.token_urlsafe(32)
    access_token = auth_runtime().get_token_from_request(request)
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )
    token_payload = decode_access_token(access_token, db=db)
    session_jti = str(token_payload.get("jti") or "")
    if not session_jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session"
        )
    terminal_security.create_token(
        token_str=ws_token,
        user_id=current_user.id,
        username=current_user.username,
        client_ip=client_ip,
        user_agent=user_agent,
        session_jti=session_jti,
    )

    return {
        "ws_token": ws_token,
        "expires_in": WS_TOKEN_LIFETIME,
    }


__all__ = [
    "WebSocketTokenClaims",
    "_ws_tokens",
    "cleanup_ws_tokens",
    "get_terminal_ws_token",
    "get_ws_token",
    "verify_ws_token",
]
