from __future__ import annotations

import logging
from typing import Generator, TYPE_CHECKING

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db.session import get_db as _get_db
from app.core.cookie_auth import get_token_from_request

if TYPE_CHECKING:
    from app.models.user import User

logger = logging.getLogger(__name__)

# Use auto_error=False since we also check cookies
security = HTTPBearer(auto_error=False)
# Use auto_error=False for optional authentication
security_optional = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session."""
    yield from _get_db()


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> "User":
    """Get current authenticated user from cookie or header."""
    from app.core.security import decode_access_token
    from app.models.user import User
    from sqlalchemy import select
    
    # Get token from cookie first, then header
    token = get_token_from_request(request)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )
    
    try:
        payload = decode_access_token(token, db=db)
        user_id = payload.get("sub")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
            )
        
        # Verify user exists and is active
        result = db.execute(select(User).where(User.id == int(user_id)))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found",
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account deactivated",
            )
        
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )


def require_admin(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> "User":
    """Require admin role for access."""
    user = get_current_user(request, credentials, db)
    
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    
    return user


__all__ = ["get_db", "get_current_user", "require_admin", "security", "security_optional"]
