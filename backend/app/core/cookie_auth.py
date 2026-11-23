"""
Cookie-based Authentication Module.

Provides secure httpOnly cookie handling for JWT tokens.
Prevents XSS attacks by making tokens inaccessible from JavaScript.
"""
from __future__ import annotations

import ipaddress
import logging
from typing import Optional

from fastapi import Request, Response

from config import get_settings

settings = get_settings()
logger = logging.getLogger("easypi.cookie_auth")

# Cookie configuration
ACCESS_TOKEN_COOKIE = "easypi_access_token"
REFRESH_TOKEN_COOKIE = "easypi_refresh_token"

# Token expiration (should match security.py)
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Increased from 15 to prevent frequent 401s during polling
REFRESH_TOKEN_EXPIRE_DAYS = 7


def _is_localhost_host(host_header: str) -> bool:
    """Return True only for an exact localhost/loopback Host value."""
    value = host_header.strip().lower()
    if value.startswith("["):
        hostname = value[1:].split("]", 1)[0]
    else:
        hostname = value.split(":", 1)[0]
    return hostname in {"localhost", "127.0.0.1", "::1"}


def is_direct_localhost_request(request: Request) -> bool:
    """Allow HTTP development cookies only for a real loopback TCP peer."""
    if not _is_localhost_host(request.headers.get("host", "")):
        return False

    client = request.client
    if client is None:
        return False

    try:
        return ipaddress.ip_address(client.host).is_loopback
    except ValueError:
        return False


def is_secure_context(request: Request) -> bool:
    """
    Check if request is in a secure context (HTTPS).
    
    Local HTTP is allowed only when both Host and the TCP peer are loopback.
    """
    # Check X-Forwarded-Proto header (set by nginx/proxy)
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    if forwarded_proto == "https":
        return True
    
    # Check if using HTTPS directly
    if request.url.scheme == "https":
        return True
    
    return False


def auth_cookie_secure(request: Request) -> bool:
    """Require Secure except for direct loopback HTTP development."""
    return is_secure_context(request) or not is_direct_localhost_request(request)


def get_cookie_domain(request: Request) -> Optional[str]:
    """
    Get the domain for setting cookies.
    
    Returns None for same-origin (browser will use current host).
    """
    # For same-origin setup (nginx proxy), don't set domain
    # This makes cookie available only to the exact host
    return None


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str],
    request: Request,
) -> None:
    """
    Set authentication cookies on the response.
    
    Args:
        response: FastAPI Response object
        access_token: JWT access token
        refresh_token: JWT refresh token (optional)
        request: Request object to determine secure context
    """
    secure = auth_cookie_secure(request)
    domain = get_cookie_domain(request)

    # Access token cookie
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",  # Available to all paths
        domain=domain,
        secure=secure,  # Only HTTPS (or localhost)
        httponly=True,  # Not accessible from JavaScript
        samesite="lax",  # Lax: allows same-site navigation
    )
    
    # Refresh token cookie
    if refresh_token:
        response.set_cookie(
            key=REFRESH_TOKEN_COOKIE,
            value=refresh_token,
            max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
            path="/api/v1/auth",  # Only sent to auth endpoints
            domain=domain,
            secure=secure,
            httponly=True,
            samesite="lax",
        )
    
    logger.debug(f"Auth cookies set (secure={secure})")


def clear_auth_cookies(response: Response, request: Request) -> None:
    """
    Clear authentication cookies (logout).
    
    Args:
        response: FastAPI Response object
        request: Request object
    """
    domain = get_cookie_domain(request)
    secure = auth_cookie_secure(request)
    
    # Clear access token
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path="/",
        domain=domain,
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    
    # Clear refresh token
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path="/api/v1/auth",
        domain=domain,
        secure=secure,
        httponly=True,
        samesite="strict",
    )
    
    logger.debug("Auth cookies cleared")


def get_access_token_from_cookie(request: Request) -> Optional[str]:
    """
    Extract access token from cookie.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Access token string or None
    """
    return request.cookies.get(ACCESS_TOKEN_COOKIE)


def get_refresh_token_from_cookie(request: Request) -> Optional[str]:
    """
    Extract refresh token from cookie.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Refresh token string or None
    """
    return request.cookies.get(REFRESH_TOKEN_COOKIE)


def get_token_from_request(request: Request) -> Optional[str]:
    """
    Get access token from request - tries cookie first, then header.
    
    This allows gradual migration and API clients using Bearer tokens.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Access token string or None
    """
    # 1. Try httpOnly cookie first (most secure)
    token = get_access_token_from_cookie(request)
    if token:
        return token
    
    # 2. Fall back to Authorization header (for API clients)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]  # Remove "Bearer " prefix
    
    return None
