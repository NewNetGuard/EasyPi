from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class BackupCreate(BaseModel):
    """Schema for creating a backup"""
    type: Literal["full", "config"]
    name: Optional[str] = Field(None, max_length=255)
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v: str | None) -> str | None:
        if v is not None:
            # Remove dangerous characters
            v = v.strip()
            if not v:
                return None
            # Only allow alphanumeric, spaces, hyphens, underscores
            import re
            if not re.match(r'^[\w\s\-]+$', v):
                raise ValueError('Name contains invalid characters')
        return v


class BackupResponse(BaseModel):
    """Schema for backup response"""
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    type: str
    size: str
    size_bytes: int
    created_at: datetime
    status: str
    error_message: Optional[str] = None


class BackupRestoreStatusResponse(BaseModel):
    status: Literal["idle", "running", "success", "failed-rolled-back", "failed"]
    archive: Optional[str] = None
    updated_at: Optional[datetime] = None


class BackupRestore(BaseModel):
    filename: str


class BackupSchedule(BaseModel):
    cron: str


class RecoveryKeyExportRequest(BaseModel):
    current_password: SecretStr = Field(min_length=1, max_length=256)
    package_passphrase: SecretStr = Field(min_length=12, max_length=1024)
    totp_code: Optional[str] = Field(default=None, min_length=6, max_length=16)


__all__ = [
    "BackupResponse",
    "BackupRestoreStatusResponse",
    "BackupCreate",
    "BackupRestore",
    "BackupSchedule",
    "RecoveryKeyExportRequest",
]
