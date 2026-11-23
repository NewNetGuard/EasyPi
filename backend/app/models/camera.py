"""Camera model for database."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from urllib.parse import quote

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.models.base import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class Camera(Base):
    """IP Camera model."""
    __tablename__ = "cameras"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(100), nullable=False, unique=True)
    ip = Column(String(45), nullable=False)  # IPv6 compatible
    port = Column(Integer, default=554)
    username = Column(String(100), default="")
    password = Column(String(255), default="")  # encrypted in prod
    rtsp_path = Column(String(255), default="/stream1")
    brand = Column(String(100), nullable=True)
    model = Column(String(100), nullable=True)
    location = Column(String(255), nullable=True)
    status = Column(String(20), default="offline")  # online, offline, recording, error
    last_seen = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # --- PTZ (pan/tilt/zoom) control layer -------------------------------
    # Which adapter drives this camera ("null"/"onvif"/"thingino"); NULL/absent
    # means no PTZ (fail-closed). ``ptz_capabilities_json`` holds the detected
    # capability booleans only -- never credentials or SOAP. The tokens identify
    # the ONVIF media profile / PTZ configuration. None of these touch the RTSP
    # URL, so the video stream is unaffected.
    ptz_adapter = Column(String(32), nullable=True)
    ptz_detected = Column(Boolean, default=False)
    ptz_capabilities_json = Column(Text, nullable=True)
    ptz_profile_token = Column(String(255), nullable=True)
    ptz_configuration_token = Column(String(255), nullable=True)
    ptz_last_probe_at = Column(DateTime(timezone=True), nullable=True)
    ptz_probe_error = Column(String(255), nullable=True)
    # Optional, dedicated PTZ/ONVIF credentials -- kept separate from the RTSP
    # username/password so adding them never rewrites the video URL. Encrypted.
    ptz_username = Column(String(100), nullable=True)
    ptz_secret = Column(String(255), nullable=True)
    # ONVIF HTTP/control port (distinct from the RTSP ``port``). Learned from
    # WS-Discovery (the camera reports its own XAddr) so control works whatever
    # port the camera uses; NULL falls back to the ONVIF default (80).
    onvif_port = Column(Integer, nullable=True)

    def has_auth(self) -> bool:
        """Check if camera has authentication configured."""
        return bool(self.username and self.password)

    def has_ptz_auth(self) -> bool:
        """Whether dedicated PTZ credentials are configured."""
        return bool(self.ptz_username or self.ptz_secret)

    def get_ptz_credentials(self) -> tuple[str, str]:
        """Return (username, decrypted secret) for PTZ control.

        Uses the dedicated PTZ credentials when set, else falls back to the RTSP
        username/password (cameras often share one admin login). Decryption
        happens here so callers never handle the ciphertext.
        """
        from app.core.encryption import decrypt_password

        if self.ptz_username or self.ptz_secret:
            user = self.ptz_username or ""
            secret = decrypt_password(self.ptz_secret) if self.ptz_secret else ""
        else:
            user = self.username or ""
            secret = decrypt_password(self.password) if self.password else ""
        return user, secret

    def get_ptz_capabilities(self) -> dict:
        """Return the persisted PTZ capabilities as a dict ({} if none/invalid).

        Never contains secrets -- only the detected capability booleans.
        """
        import json

        if not self.ptz_capabilities_json:
            return {}
        try:
            data = json.loads(self.ptz_capabilities_json)
        except (ValueError, TypeError):
            return {}
        return data if isinstance(data, dict) else {}

    def get_rtsp_url(self) -> str:
        """Get a full RTSP URL after revalidating the stored network target."""
        from app.core.encryption import decrypt_password
        from app.services.ptz.ssrf import resolve_and_pin

        pinned_ip, pinned_port = resolve_and_pin(self.ip, self.port)
        base_url = "rtsp://"
        if self.username:
            password = decrypt_password(self.password) if self.password else ""
            base_url += (
                f"{quote(self.username, safe='')}:"
                f"{quote(password, safe='')}@"
            )
        host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        base_url += f"{host}:{pinned_port}{self.rtsp_path}"
        return base_url

    def to_response(self) -> dict:
        """Convert to API response format (no password exposed)."""
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "port": self.port,
            "username": self.username,
            "hasAuth": self.has_auth(),
            "hasPtzAuth": self.has_ptz_auth(),
            "ptzUsername": self.ptz_username or "",
            "onvifPort": self.onvif_port,
            "rtspPath": self.rtsp_path,
            "brand": self.brand,
            "model": self.model,
            "location": self.location,
            "status": self.status,
            "lastSeen": self.last_seen.isoformat() if self.last_seen else None,
            "createdAt": self.created_at.isoformat() if self.created_at else "",
            "updatedAt": self.updated_at.isoformat() if self.updated_at else "",
        }


class CameraSettingsModel(Base):
    """Global camera settings storage."""
    __tablename__ = "camera_settings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    key = Column(String(100), unique=True, nullable=False)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
