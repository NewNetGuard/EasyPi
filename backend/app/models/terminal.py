from datetime import datetime
from app.utils.time import utc_now
from typing import Optional

from sqlalchemy import String, Text, DateTime, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class TerminalSession(Base):
    """Terminal session audit log."""
    
    __tablename__ = "terminal_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    username: Mapped[str] = mapped_column(String(100), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    # Relationships
    commands = relationship("TerminalCommand", back_populates="session", cascade="all, delete-orphan")


class TerminalCommand(Base):
    """Individual command execution audit log."""
    
    __tablename__ = "terminal_commands"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(Integer, ForeignKey("terminal_sessions.id"), nullable=False)
    command: Mapped[str] = mapped_column(Text, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    output_length: Mapped[int] = mapped_column(Integer, default=0)  # Length of output in bytes
    
    # Relationships
    session = relationship("TerminalSession", back_populates="commands")
