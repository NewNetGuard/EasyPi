from __future__ import annotations

import enum
from typing import Any, Dict, Optional

from sqlalchemy import Enum, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, UUIDMixin


class TaskStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"


class TaskExecution(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "task_executions"

    task_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    user: Mapped[str] = mapped_column(String(64), nullable=False)
    script: Mapped[str] = mapped_column(String(255), nullable=False)
    action: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    args: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    status: Mapped[TaskStatus] = mapped_column(
        Enum(
            TaskStatus,
            name="task_status",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
        default=TaskStatus.QUEUED,
        server_default=TaskStatus.QUEUED.value,
    )
    exit_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    log_path: Mapped[str] = mapped_column(String(255), nullable=False)


__all__ = ["TaskExecution", "TaskStatus"]
