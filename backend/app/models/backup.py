"""
Backup Job Model
"""

from sqlalchemy import Column, Integer, String, BigInteger, DateTime, Enum as SQLEnum
from sqlalchemy.sql import func
import enum

from app.models.base import Base


class BackupStatus(str, enum.Enum):
    """Backup status enum"""
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class BackupType(str, enum.Enum):
    """Backup type enum"""
    FULL = "full"
    CONFIG = "config"


class BackupJob(Base):
    """Backup job model"""
    __tablename__ = "backup_jobs"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    type = Column(SQLEnum(BackupType), nullable=False)
    size_bytes = Column(BigInteger, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(SQLEnum(BackupStatus), default=BackupStatus.RUNNING)
    file_path = Column(String(512), nullable=True)
    error_message = Column(String(1024), nullable=True)
