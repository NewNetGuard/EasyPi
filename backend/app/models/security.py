"""
Security Models

Database models for security scan results and firewall rules.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from app.utils.time import utc_now

from app.models.base import Base


class SecurityScan(Base):
    """Security scan result model"""
    __tablename__ = "security_scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_date = Column(DateTime, default=utc_now)
    critical_count = Column(Integer, default=0)
    warning_count = Column(Integer, default=0)
    passed_count = Column(Integer, default=0)
    scan_data = Column(Text)  # JSON string with full scan results


class FirewallRule(Base):
    """UFW firewall rule model"""
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    source = Column(String(100), default="any")
    action = Column(String(20), default="allow")
    created_at = Column(DateTime, default=utc_now)
    is_active = Column(Boolean, default=True)


class PasswordChangeLog(Base):
    """Track password changes for security monitoring"""
    __tablename__ = "password_change_logs"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), nullable=False, unique=True)
    changed_at = Column(DateTime, default=utc_now)
    changed_by = Column(String(50))

