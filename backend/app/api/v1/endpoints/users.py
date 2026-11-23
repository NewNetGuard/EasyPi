"""
User Management Endpoints

Admin-only endpoints for managing users:
- List all users
- Create new user
- Update user (role, active status)
- Delete user
- Reset user password
"""

import logging
from contextlib import nullcontext
from datetime import datetime, timezone
from typing import ContextManager, Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select, func
from sqlalchemy.orm import Session

from app.core.security import (
    get_password_hash,
    decode_access_token,
)
from app.core.cookie_auth import get_token_from_request
from app.core.password_policy import validate_password
from app.core.rate_limit import check_rate_limit
from app.db.session import get_db
from app.models.user import User
from app.models.session import UserSession
from app.services.operation_event_service import OperationEventService
from app.services.push_notification_service import PushNotificationService, get_push_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/users", tags=["users"])
security = HTTPBearer(auto_error=False)
operation_event_service = OperationEventService()


def _revoke_user_push_subscriptions(
    user_id: int,
    push_service: PushNotificationService | None = None,
) -> None:
    """Fail the account mutation if durable push revocation cannot be completed."""
    try:
        (push_service or get_push_service()).remove_user_subscriptions(user_id)
    except RuntimeError as exc:
        logger.error("Could not revoke push subscriptions for user %s", user_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not revoke user push subscriptions",
        ) from exc


def _record_user_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/users",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record user event %s: %s", action_id, exc)


# ============== Pydantic Models ==============

class UserCreateRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: Optional[str] = None
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="user", pattern="^(admin|user)$")
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v, info):
        """Validate password meets policy requirements."""
        username = info.data.get('username') if info.data else None
        result = validate_password(v, username)
        if not result.is_valid:
            raise ValueError("; ".join(result.errors))
        return v


class UserUpdateRequest(BaseModel):
    email: Optional[str] = None
    role: Optional[str] = Field(default=None, pattern="^(admin|user)$")
    is_active: Optional[bool] = None


class UserPasswordResetRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=256)
    
    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v):
        """Validate password meets policy requirements."""
        result = validate_password(v)
        if not result.is_valid:
            raise ValueError("; ".join(result.errors))
        return v


class UserListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    totp_enabled: bool
    sessions_count: int = 0

class UserDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    last_login_ip: Optional[str]
    last_login_user_agent: Optional[str]
    totp_enabled: bool

# ============== Helper Functions ==============

def get_current_user(request: Request, credentials: HTTPAuthorizationCredentials, db: Session) -> User:
    """Get current user from token (cookie or header) with session validation."""
    # Try cookie first, then header
    token = get_token_from_request(request)
    
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    try:
        # Pass db session for session validation
        payload = decode_access_token(token, db=db)
        user_id = payload.get("sub")
        
        if not user_id:
            raise ValueError("Invalid token")
        
        # Convert to int for DB query (JWT sub is always a string)
        result = db.execute(select(User).where(User.id == int(user_id)))
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account is deactivated"
            )
        
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )


def require_admin(request: Request, credentials: HTTPAuthorizationCredentials, db: Session) -> User:
    """Require admin role."""
    user = get_current_user(request, credentials, db)
    
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    
    return user


# ============== Endpoints ==============

@router.get("", response_model=List[UserListResponse],
            summary="List all users",
            description="Get a list of all users with their session counts. Admin only.")
async def list_users(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> List[UserListResponse]:
    """
    List all users in the system.
    
    **Requires admin role.**
    
    Returns user info including:
    - Basic profile (username, email, role)
    - Account status (active, 2FA enabled)
    - Session count
    """
    require_admin(request, credentials, db)
    
    # Get all users with session counts
    result = db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    
    response = []
    for user in users:
        # Count active sessions for this user
        session_count = db.execute(
            select(func.count(UserSession.id))
            .where(UserSession.user_id == user.id)
            .where(UserSession.is_active.is_(True))
        ).scalar() or 0
        
        user_data = UserListResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
            created_at=user.created_at,
            last_login=user.last_login,
            totp_enabled=user.totp_enabled,
            sessions_count=session_count
        )
        response.append(user_data)
    
    return response


@router.get("/{user_id}", response_model=UserDetailResponse)
async def get_user(
    user_id: int,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> UserDetailResponse:
    """Get user details (admin only)."""
    require_admin(request, credentials, db)
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserDetailResponse.model_validate(user)


@router.post("", response_model=UserDetailResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> UserDetailResponse:
    """Create a new user (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    # Rate limit
    check_rate_limit(request, "admin_action")
    
    # Check if username exists
    result = db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        detail = "Username already exists"
        _record_user_event(
            action_id="users.create",
            title="Create user",
            subtitle=f"Users · {payload.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    # Check if email exists (if provided)
    if payload.email:
        result = db.execute(select(User).where(User.email == payload.email))
        if result.scalar_one_or_none():
            detail = "Email already exists"
            _record_user_event(
                action_id="users.create",
                title="Create user",
                subtitle=f"Users · {payload.username}",
                status="failed",
                message=detail,
                started_at=started_at,
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    # Create user
    new_user = User(
        username=payload.username,
        email=payload.email,
        password_hash=get_password_hash(payload.password),
        role=payload.role,
        is_active=True,
        created_at=datetime.now(timezone.utc)
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    logger.info(f"User {new_user.username} created by admin {admin.username}")
    _record_user_event(
        action_id="users.create",
        title="Create user",
        subtitle=f"Users · {new_user.username}",
        status="success",
        message=f"User {new_user.username} created by admin {admin.username}",
        started_at=started_at,
    )
    return UserDetailResponse.model_validate(new_user)


@router.patch("/{user_id}", response_model=UserDetailResponse)
async def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> UserDetailResponse:
    """Update user (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        detail = "User not found"
        _record_user_event(
            action_id="users.update",
            title="Update user",
            subtitle=f"Users · ID {user_id}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    
    # Prevent demoting yourself
    if user.id == admin.id and payload.role and payload.role != "admin":
        detail = "Cannot demote yourself"
        _record_user_event(
            action_id="users.update",
            title="Update user",
            subtitle=f"Users · {user.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    # Prevent deactivating yourself
    if user.id == admin.id and payload.is_active is False:
        detail = "Cannot deactivate yourself"
        _record_user_event(
            action_id="users.update",
            title="Update user",
            subtitle=f"Users · {user.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    # Check email uniqueness if changing
    if payload.email and payload.email != user.email:
        result = db.execute(select(User).where(User.email == payload.email))
        if result.scalar_one_or_none():
            detail = "Email already exists"
            _record_user_event(
                action_id="users.update",
                title="Update user",
                subtitle=f"Users · {user.username}",
                status="failed",
                message=detail,
                started_at=started_at,
            )
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    push_service = get_push_service() if payload.is_active is False else None
    guard: ContextManager[None] = (
        push_service.user_subscription_guard(user_id)
        if push_service is not None
        else nullcontext()
    )
    with guard:
        if push_service is not None:
            _revoke_user_push_subscriptions(user_id, push_service)

        # Update fields while registration is excluded for a deactivation.
        if payload.email and payload.email != user.email:
            user.email = payload.email

        if payload.role is not None:
            user.role = payload.role

        if payload.is_active is not None:
            user.is_active = payload.is_active

            # If deactivating, revoke all sessions
            if not payload.is_active:
                db.execute(
                    UserSession.__table__.update()
                    .where(UserSession.user_id == user_id)
                    .values(is_active=False)
                )

        db.commit()
    db.refresh(user)
    
    logger.info(f"User {user.username} updated by admin {admin.username}")
    _record_user_event(
        action_id="users.update",
        title="Update user",
        subtitle=f"Users · {user.username}",
        status="success",
        message=f"User {user.username} updated by admin {admin.username}",
        started_at=started_at,
    )
    return UserDetailResponse.model_validate(user)


@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Delete user (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        detail = "User not found"
        _record_user_event(
            action_id="users.delete",
            title="Delete user",
            subtitle=f"Users · ID {user_id}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    
    # Prevent deleting yourself
    if user.id == admin.id:
        detail = "Cannot delete yourself"
        _record_user_event(
            action_id="users.delete",
            title="Delete user",
            subtitle=f"Users · {user.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    username = user.username

    push_service = get_push_service()
    with push_service.user_subscription_guard(user_id):
        _revoke_user_push_subscriptions(user_id, push_service)

        # Delete user sessions first
        db.execute(
            UserSession.__table__.delete().where(UserSession.user_id == user_id)
        )

        # Delete user while subscription registration is excluded.
        db.delete(user)
        db.commit()
    
    logger.info(f"User {username} deleted by admin {admin.username}")
    _record_user_event(
        action_id="users.delete",
        title="Delete user",
        subtitle=f"Users · {username}",
        status="success",
        message=f"User {username} deleted by admin {admin.username}",
        started_at=started_at,
    )
    return {"success": True, "message": f"User {username} deleted"}


@router.post("/{user_id}/reset-password")
async def reset_user_password(
    user_id: int,
    payload: UserPasswordResetRequest,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Reset user password (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    # Rate limit
    check_rate_limit(request, "admin_action")
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        detail = "User not found"
        _record_user_event(
            action_id="users.reset-password",
            title="Reset user password",
            subtitle=f"Users · ID {user_id}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    if user.id == admin.id:
        detail = "Use your personal security settings to change your own password"
        _record_user_event(
            action_id="users.reset-password",
            title="Reset user password",
            subtitle=f"Users · {user.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    # Update password
    user.password_hash = get_password_hash(payload.new_password)
    
    # Revoke all sessions to force re-login
    db.execute(
        UserSession.__table__.update()
        .where(UserSession.user_id == user_id)
        .values(is_active=False)
    )
    
    db.commit()
    
    logger.info(f"Password reset for {user.username} by admin {admin.username}")
    _record_user_event(
        action_id="users.reset-password",
        title="Reset user password",
        subtitle=f"Users · {user.username}",
        status="success",
        message=f"Password reset for {user.username} by admin {admin.username}",
        started_at=started_at,
    )
    return {"success": True, "message": f"Password reset for {user.username}"}


@router.post("/{user_id}/disable-2fa")
async def disable_user_2fa(
    user_id: int,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Disable 2FA for a user (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        detail = "User not found"
        _record_user_event(
            action_id="users.disable-2fa",
            title="Disable user 2FA",
            subtitle=f"Users · ID {user_id}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)

    if user.id == admin.id:
        detail = "Use your personal security settings to disable your own 2FA"
        _record_user_event(
            action_id="users.disable-2fa",
            title="Disable user 2FA",
            subtitle=f"Users · {user.username}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    
    if not user.totp_enabled:
        message = "2FA is not enabled for this user"
        _record_user_event(
            action_id="users.disable-2fa",
            title="Disable user 2FA",
            subtitle=f"Users · {user.username}",
            status="success",
            message=message,
            started_at=started_at,
        )
        return {"success": True, "message": message}
    
    # Disable 2FA
    user.totp_enabled = False
    user.totp_secret = None
    user.backup_codes = None
    
    db.commit()
    
    logger.info(f"2FA disabled for {user.username} by admin {admin.username}")
    _record_user_event(
        action_id="users.disable-2fa",
        title="Disable user 2FA",
        subtitle=f"Users · {user.username}",
        status="success",
        message=f"2FA disabled for {user.username} by admin {admin.username}",
        started_at=started_at,
    )
    return {"success": True, "message": f"2FA disabled for {user.username}"}


@router.post("/{user_id}/revoke-sessions")
async def revoke_user_sessions(
    user_id: int,
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> dict:
    """Revoke all sessions for a user (admin only)."""
    started_at = datetime.now(timezone.utc).isoformat()
    admin = require_admin(request, credentials, db)
    
    result = db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        detail = "User not found"
        _record_user_event(
            action_id="users.revoke-sessions",
            title="Revoke user sessions",
            subtitle=f"Users · ID {user_id}",
            status="failed",
            message=detail,
            started_at=started_at,
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
    
    # Revoke all sessions
    result = db.execute(
        UserSession.__table__.update()
        .where(UserSession.user_id == user_id)
        .where(UserSession.is_active.is_(True))
        .values(is_active=False)
    )
    
    db.commit()
    
    count = result.rowcount
    logger.info(f"Revoked {count} sessions for {user.username} by admin {admin.username}")
    _record_user_event(
        action_id="users.revoke-sessions",
        title="Revoke user sessions",
        subtitle=f"Users · {user.username}",
        status="success",
        message=f"Revoked {count} sessions for {user.username} by admin {admin.username}",
        started_at=started_at,
    )
    return {"success": True, "message": f"Revoked {count} sessions for {user.username}"}
