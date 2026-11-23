from datetime import datetime, timedelta
from app.utils.time import utc_now
from typing import Optional, Tuple
import uuid
import logging

import jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from sqlalchemy import select

from config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Balance between security and UX
REFRESH_TOKEN_EXPIRE_DAYS = 7


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against a hash."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Generate password hash."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, session_id: str = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    
    # Ensure 'sub' is a string (JWT spec requirement)
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    
    if expires_delta:
        expire = utc_now() + expires_delta
    else:
        expire = utc_now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": "access",
        "jti": session_id or str(uuid.uuid4()),  # Use shared session_id if provided
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT refresh token (longer-lived)."""
    to_encode = data.copy()
    
    # Ensure 'sub' is a string (JWT spec requirement)
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    
    if expires_delta:
        expire = utc_now() + expires_delta
    else:
        expire = utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "jti": str(uuid.uuid4()),
    })
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def create_token_pair(data: dict) -> Tuple[str, str, str, datetime]:
    """Create both access and refresh tokens with shared session_id.
    
    Returns:
        Tuple of (access_token, refresh_token, session_id, refresh_expires)
    """
    # Generate shared session_id for both tokens
    session_id = str(uuid.uuid4())
    refresh_expires = utc_now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Create access token with shared session_id
    access_token = create_access_token(data, session_id=session_id)
    
    # Create refresh token with same session_id
    to_encode = data.copy()
    
    # Ensure 'sub' is a string (JWT spec requirement)
    if "sub" in to_encode:
        to_encode["sub"] = str(to_encode["sub"])
    
    to_encode.update({
        "exp": refresh_expires,
        "type": "refresh",
        "jti": session_id,  # Same session_id as access token
    })
    refresh_token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)
    
    return access_token, refresh_token, session_id, refresh_expires


def decode_access_token(token: str, expected_type: str = "access", db: Session = None) -> dict:
    """Decode and verify JWT token with session validation."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check token type
        token_type = payload.get("type", "access")
        if token_type != expected_type:
            raise ValueError(f"Invalid token type: expected {expected_type}, got {token_type}")
        
        jti = payload.get("jti")
        user_id = payload.get("sub")
        
        # Validate session in database if db session provided
        if db and jti and user_id:
            from app.models.session import UserSession
            from app.models.user import User
            
            session = db.execute(
                select(UserSession).where(
                    UserSession.token_jti == jti,
                    UserSession.user_id == int(user_id),
                    UserSession.is_active.is_(True)
                )
            ).scalar_one_or_none()
            
            # No active session for this jti = the session was revoked (logout / "revoke all
            # sessions" / password change) or the session store was reset. The session store
            # is authoritative: reject the token instead of resurrecting it. Rehydrating here
            # used to let a revoked-but-unexpired token keep working (and would fully bypass
            # revocation if sessions were ever hard-deleted instead of soft-deactivated).
            if not session:
                raise ValueError("Session revoked or not found")

            if session.expires_at < utc_now():
                logger.warning(f"Token validation failed: session expired for jti={jti}")
                session.is_active = False
                db.commit()
                raise ValueError("Session has expired")
            
            # Check if user is active
            user = db.execute(select(User).where(User.id == int(user_id))).scalar_one_or_none()
            if not user or not user.is_active:
                logger.debug(f"Token validation failed: user inactive for user_id={user_id}")
                session.is_active = False
                db.commit()
                raise ValueError("User account is deactivated")
            
            # Update last_active
            session.last_active = utc_now()
            db.commit()
        
        return payload
    except jwt.ExpiredSignatureError as e:
        raise ValueError(f"Token has expired: {str(e)}")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")
    except jwt.DecodeError as e:
        raise ValueError(f"Token decode error: {str(e)}")
    except Exception as e:
        raise ValueError(f"Token validation failed: {str(e)}")


def decode_refresh_token(token: str, db: Session = None) -> dict:
    """Decode and verify refresh token with session validation."""
    return decode_access_token(token, expected_type="refresh", db=db)


def revoke_token(token: str, db: Session = None) -> bool:
    """Revoke a token by deactivating its session in DB."""
    try:
        # Decode without validation to get jti even if expired
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
        jti = payload.get("jti")
        
        if jti and db:
            from app.models.session import UserSession
            session = db.execute(
                select(UserSession).where(UserSession.token_jti == jti)
            ).scalar_one_or_none()
            
            if session:
                session.is_active = False
                session.revoked_at = utc_now()
                db.commit()
                logger.info(f"Token revoked: jti={jti}")
                return True
        return False
    except Exception as e:
        logger.error(f"Failed to revoke token: {e}")
        return False


def revoke_all_user_sessions(user_id: int, db: Session, exclude_jti: str = None) -> int:
    """Revoke all sessions for a user (e.g., on password change, security event).
    
    Args:
        user_id: User ID to revoke sessions for
        db: Database session
        exclude_jti: Optional jti to exclude (e.g., current session)
    
    Returns:
        Number of sessions revoked
    """
    from app.models.session import UserSession
    
    query = select(UserSession).where(
        UserSession.user_id == user_id,
        UserSession.is_active.is_(True)
    )
    
    if exclude_jti:
        query = query.where(UserSession.token_jti != exclude_jti)
    
    sessions = db.execute(query).scalars().all()
    count = 0
    
    for session in sessions:
        session.is_active = False
        session.revoked_at = utc_now()
        count += 1
    
    db.commit()
    logger.info(f"Revoked {count} sessions for user_id={user_id}")
    return count


def verify_admin_role(user_role: str) -> bool:
    """Check if user has admin role."""
    return user_role == "admin"
