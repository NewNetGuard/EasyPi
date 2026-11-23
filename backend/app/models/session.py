"""User session model for tracking active sessions."""
from datetime import datetime
from app.utils.time import utc_now
from typing import Optional
import uuid

from sqlalchemy import String, DateTime, Boolean, Text, Integer, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


def generate_session_id() -> str:
    return str(uuid.uuid4())


class UserSession(Base):
    """Track user login sessions for security."""
    
    __tablename__ = "user_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_session_id)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Token identifier (jti from JWT)
    token_jti: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    
    # Session metadata
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv4 or IPv6
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    device_name: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # Parsed from user agent
    location: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)  # City, Country (from IP)
    
    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    last_active: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    
    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    
    def to_response(self, current_jti: str = None) -> dict:
        """Convert to API response format."""
        return {
            "id": self.id,
            "ip_address": self.ip_address or "Unknown",
            "device_name": self.device_name or self._parse_device_name(),
            "location": self.location or "Unknown",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_active": self.last_active.isoformat() if self.last_active else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_current": self.token_jti == current_jti if current_jti else False,
            "is_active": self.is_active,
        }
    
    def _parse_device_name(self) -> str:
        """Parse device name from user agent."""
        if not self.user_agent:
            return "Unknown Device"
        
        ua = self.user_agent.lower()
        
        # Mobile devices
        if "iphone" in ua:
            return "iPhone"
        if "ipad" in ua:
            return "iPad"
        if "android" in ua:
            if "mobile" in ua:
                return "Android Phone"
            return "Android Tablet"
        
        # Desktop browsers
        if "windows" in ua:
            if "edge" in ua:
                return "Windows (Edge)"
            if "chrome" in ua:
                return "Windows (Chrome)"
            if "firefox" in ua:
                return "Windows (Firefox)"
            return "Windows"
        if "macintosh" in ua or "mac os" in ua:
            if "safari" in ua and "chrome" not in ua:
                return "Mac (Safari)"
            if "chrome" in ua:
                return "Mac (Chrome)"
            if "firefox" in ua:
                return "Mac (Firefox)"
            return "Mac"
        if "linux" in ua:
            if "chrome" in ua:
                return "Linux (Chrome)"
            if "firefox" in ua:
                return "Linux (Firefox)"
            return "Linux"
        
        return "Unknown Device"
