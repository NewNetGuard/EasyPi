from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base
from app.utils.time import utc_now


class MobilePairingChallenge(Base):
    __tablename__ = "mobile_pairing_challenges"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    created_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    tailscale_exit_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class MobileDevice(Base):
    __tablename__ = "mobile_devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    photo_folder: Mapped[str | None] = mapped_column(String(100), nullable=True)
    protection_client_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    chameleon_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    home_tunnel_public_key: Mapped[str | None] = mapped_column(
        String(512), nullable=True, unique=True, index=True
    )
    home_tunnel_address: Mapped[str | None] = mapped_column(
        String(64), nullable=True, unique=True, index=True
    )
    home_tunnel_state: Mapped[str] = mapped_column(
        String(16), default="inactive", nullable=False, index=True
    )
    home_tunnel_credential_epoch: Mapped[int] = mapped_column(default=0, nullable=False)
    home_tunnel_last_handshake_at: Mapped[datetime | None] = mapped_column(
        DateTime, nullable=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    tailscale_exit_node: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
