"""
CSRF (Cross-Site Request Forgery) Protection Module.

Provides CSRF token generation, validation, and middleware for FastAPI.
Uses double-submit cookie pattern with HMAC for token integrity.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Optional, Set
import logging

from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from config import get_settings
from app.core.cookie_auth import ACCESS_TOKEN_COOKIE, auth_cookie_secure

settings = get_settings()
logger = logging.getLogger("easypi.csrf")


# CSRF Configuration
CSRF_TOKEN_LENGTH = 32  # bytes
CSRF_TOKEN_LIFETIME = 3600 * 4  # 4 hours
CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "_csrf_token"

# Safe HTTP methods that don't require CSRF validation
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

# Paths that are exempt from CSRF (public endpoints)
CSRF_EXEMPT_PATHS: Set[str] = {
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/registration-status",
    "/api/v1/auth/recovery-login",
    # A new phone has no bearer token yet. This endpoint accepts only a
    # high-entropy, five-minute, single-use pairing code.
    "/api/v1/mobile/pairing/complete",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/health",
    "/healthz",
    "/ws",
}

# Prefixes that are exempt (WebSocket, non-auth endpoints)
CSRF_EXEMPT_PREFIXES = (
    "/ws/",
    # Note: /api/v1/ is NOT exempt - CSRF required for cookie auth
    # Bearer token requests are checked separately in _is_exempt
)


def generate_csrf_secret() -> str:
    """Generate a random CSRF secret."""
    return secrets.token_hex(CSRF_TOKEN_LENGTH)


def generate_csrf_token(secret: str, timestamp: Optional[int] = None) -> str:
    """
    Generate a CSRF token with timestamp and HMAC signature.
    
    Format: {timestamp}.{random_nonce}.{hmac_signature}
    
    Args:
        secret: The CSRF secret (per-session or global)
        timestamp: Optional timestamp (defaults to current time)
        
    Returns:
        A signed CSRF token
    """
    if timestamp is None:
        timestamp = int(time.time())
    
    nonce = secrets.token_hex(16)
    
    # Create HMAC signature
    message = f"{timestamp}.{nonce}".encode()
    signature = hmac.new(
        secret.encode(),
        message,
        hashlib.sha256
    ).hexdigest()
    
    return f"{timestamp}.{nonce}.{signature}"


def validate_csrf_token(token: str, secret: str, max_age: int = CSRF_TOKEN_LIFETIME) -> bool:
    """
    Validate a CSRF token.
    
    Args:
        token: The CSRF token to validate
        secret: The CSRF secret
        max_age: Maximum token age in seconds
        
    Returns:
        True if valid, False otherwise
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            logger.debug("CSRF token invalid format")
            return False
        
        timestamp_str, nonce, signature = parts
        timestamp = int(timestamp_str)
        
        # Check token age
        current_time = int(time.time())
        if current_time - timestamp > max_age:
            logger.debug(f"CSRF token expired: age={current_time - timestamp}s")
            return False
        
        # Verify HMAC signature
        message = f"{timestamp}.{nonce}".encode()
        expected_signature = hmac.new(
            secret.encode(),
            message,
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            logger.debug("CSRF token signature mismatch")
            return False
        
        return True
        
    except (ValueError, AttributeError) as e:
        logger.debug(f"CSRF token validation error: {e}")
        return False


def get_csrf_secret() -> str:
    """Get the CSRF secret from settings or generate one."""
    # Use SECRET_KEY as base for CSRF secret (derived)
    return hashlib.sha256(
        f"csrf_{settings.SECRET_KEY}".encode()
    ).hexdigest()


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware.
    
    Implements double-submit cookie pattern:
    1. Sets a CSRF cookie with the token
    2. Requires the token in a header for unsafe methods (never reads the body)
    3. Validates token signature and timestamp
    
    Note: API endpoints using JWT Bearer tokens are exempt by default
    since they are already protected against CSRF (token in header).
    """
    
    def __init__(
        self,
        app,
        secret: Optional[str] = None,
        cookie_name: str = CSRF_COOKIE_NAME,
        header_name: str = CSRF_HEADER_NAME,
        form_field: str = CSRF_FORM_FIELD,
        safe_methods: Set[str] = SAFE_METHODS,
        exempt_paths: Set[str] = CSRF_EXEMPT_PATHS,
        exempt_prefixes: tuple = CSRF_EXEMPT_PREFIXES,
        cookie_secure: Optional[bool] = None,  # Auto-detect when None
        cookie_httponly: bool = False,  # Must be readable by JS
        cookie_samesite: str = "lax",
    ):
        super().__init__(app)
        self.secret = secret or get_csrf_secret()
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.form_field = form_field
        self.safe_methods = safe_methods
        self.exempt_paths = exempt_paths
        self.exempt_prefixes = exempt_prefixes
        self.cookie_secure = cookie_secure
        self.cookie_httponly = cookie_httponly
        self.cookie_samesite = cookie_samesite

    def _is_secure_context(self, request: Request) -> bool:
        """Determine whether cookies should be marked Secure for this request."""
        if self.cookie_secure is not None:
            return self.cookie_secure

        return auth_cookie_secure(request)
    
    def _is_exempt(self, request: Request) -> bool:
        """Check if the request path is exempt from CSRF validation."""
        path = request.url.path
        
        # Check exact matches
        if path in self.exempt_paths:
            return True
        
        # Check prefixes
        for prefix in self.exempt_prefixes:
            if path.startswith(prefix):
                return True
        
        # Check if using Bearer token (API requests)
        auth_header = request.headers.get("Authorization", "")
        if (
            auth_header.startswith("Bearer ")
            and not request.cookies.get(ACCESS_TOKEN_COOKIE)
        ):
            return True
        
        return False
    
    async def dispatch(
        self,
        request: Request,
        call_next: RequestResponseEndpoint
    ) -> Response:
        """Process the request and validate CSRF token if needed."""
        
        # Get or generate CSRF token from cookie
        csrf_cookie = request.cookies.get(self.cookie_name)
        
        if not csrf_cookie or not validate_csrf_token(csrf_cookie, self.secret):
            # Generate new token
            csrf_cookie = generate_csrf_token(self.secret)
        
        # Make token available to downstream handlers (e.g., csrf-token endpoint).
        request.state.csrf_token = csrf_cookie

        # For safe methods or exempt paths, just set cookie and continue
        if request.method in self.safe_methods or self._is_exempt(request):
            response = await call_next(request)
            
            # Always set/refresh the CSRF cookie
            response.set_cookie(
                key=self.cookie_name,
                value=csrf_cookie,
                max_age=CSRF_TOKEN_LIFETIME,
                path="/",
                secure=self._is_secure_context(request),
                httponly=self.cookie_httponly,
                samesite=self.cookie_samesite,
            )
            
            return response
        
        # For unsafe methods, validate CSRF token
        # Check header first
        submitted_token = request.headers.get(self.header_name)
        
        # Never parse an unauthenticated form to discover a token. Multipart
        # parsing can spool gigabytes before authentication dependencies run.
        # Browser clients must send the double-submit token in the header.
        
        # Validate submitted token against cookie
        if not submitted_token:
            logger.warning(f"CSRF token missing for {request.method} {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token missing"}
            )
        
        # Both tokens must be valid and match
        if not validate_csrf_token(submitted_token, self.secret):
            logger.warning(f"CSRF token invalid for {request.method} {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token invalid"}
            )
        
        # Tokens must match (double-submit pattern)
        if not hmac.compare_digest(submitted_token, csrf_cookie):
            logger.warning(f"CSRF token mismatch for {request.method} {request.url.path}")
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token mismatch"}
            )
        
        # Token valid, proceed with request
        response = await call_next(request)
        
        # Refresh cookie
        response.set_cookie(
            key=self.cookie_name,
            value=csrf_cookie,
            max_age=CSRF_TOKEN_LIFETIME,
            path="/",
            secure=self._is_secure_context(request),
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
        )
        
        return response


# ============================================================================
# CSRF Token Endpoint Helper
# ============================================================================

def get_csrf_token_from_request(request: Request) -> str:
    """
    Get or generate a CSRF token for the current request.
    
    Use this in template rendering to include CSRF token in forms.
    """
    state_token = getattr(request.state, "csrf_token", None)
    if state_token and validate_csrf_token(state_token, get_csrf_secret()):
        return state_token

    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    
    if csrf_cookie and validate_csrf_token(csrf_cookie, get_csrf_secret()):
        return csrf_cookie
    
    return generate_csrf_token(get_csrf_secret())


# ============================================================================
# FastAPI Dependency
# ============================================================================

async def verify_csrf_token(request: Request) -> bool:
    """
    FastAPI dependency to verify CSRF token.
    
    Use this for endpoints that need explicit CSRF validation:
    
    @router.post("/form-submit")
    async def submit_form(csrf_valid: bool = Depends(verify_csrf_token)):
        ...
    """
    secret = get_csrf_secret()
    
    # Get token from cookie
    csrf_cookie = request.cookies.get(CSRF_COOKIE_NAME)
    if not csrf_cookie:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF cookie missing"
        )
    
    # Get submitted token
    submitted_token = request.headers.get(CSRF_HEADER_NAME)
    
    # Same header-only contract as the middleware; do not consume the body.
    
    if not submitted_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token not provided"
        )
    
    # Validate both tokens
    if not validate_csrf_token(csrf_cookie, secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF cookie invalid"
        )
    
    if not validate_csrf_token(submitted_token, secret):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token invalid"
        )
    
    if not hmac.compare_digest(submitted_token, csrf_cookie):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token mismatch"
        )
    
    return True
