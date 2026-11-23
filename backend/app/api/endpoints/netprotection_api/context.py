"""
EasyPi NetProtection API Endpoints

REST API для управления DNS-защитой.
Заменяет NetProtection API.
"""

# This module intentionally centralizes imports shared by route groups.
# ruff: noqa: F401

from fastapi import (
    APIRouter,
    Body,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
)
from typing import Any, Dict, List, Literal, Optional
from datetime import datetime, timezone
import logging
import os
import json
import re
import sys
import time
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from app.api.deps import require_admin
from app.models.user import User
from app.services.firewall_service import firewall_service
from app.services.netprotection_service import (
    DeviceAnomalyStoreError,
    ScheduleStoreError,
    netprotection_service,
)
from app.services.operation_event_service import OperationEventService
from app.services.threat_service import threat_service
from app.utils.sanitize import (
    sanitize_domain,
    sanitize_mac as _sanitize_mac,
    validate_ip,
)

logger = logging.getLogger(__name__)


def sanitize_mac(value: Any) -> str:
    return _sanitize_mac(value).lower()


# A latched bypass "leak" alert is shown as ACTIVE only while it stays fresh. An
# actively-bypassing device keeps emitting events, so its timestamp is refreshed
# and the alert persists; once the device stops (or drops off the network) and
# nothing refreshes it within this window, the alert ages out of the banner on
# its own instead of nagging forever. Tunable via env.
BYPASS_ALERT_TTL_SEC = int(os.environ.get("EASYPI_BYPASS_ALERT_TTL_SEC", "900"))
operation_event_service = OperationEventService()
PORNOGRAPHY_PARENTAL_SHORTCUT = "pornography"


def _active_operation_event_service() -> OperationEventService:
    """Honor the legacy facade's replaceable event recorder."""
    facade = sys.modules.get("app.api.endpoints.netprotection")
    if facade is not None:
        return getattr(facade, "operation_event_service", operation_event_service)
    return operation_event_service


def _record_netprotection_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        _active_operation_event_service().record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/guard-security",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record netprotection event %s: %s", action_id, exc)


# ============ Pydantic Models ============


class ConfigUpdate(BaseModel):
    """Configuration update request."""

    protection_enabled: Optional[bool] = None
    safe_search: Optional[bool] = None
    parental_control: Optional[bool] = None
    cache_size: Optional[int] = None
    cache_ttl: Optional[int] = None
    block_response: Optional[str] = None
    upstream_dns: Optional[List[str]] = None
    shield_profile: Optional[str] = None


class EncryptedDnsUpdate(BaseModel):
    """Encrypted DNS (DoH/DoT) update request."""

    doh_enabled: Optional[bool] = None
    dot_enabled: Optional[bool] = None


class MatcherCreate(BaseModel):
    """Create new matcher."""

    name: str
    kind: str = Field(..., pattern="^(exact|wildcard|regex|blocklist|ip|asn)$")
    pattern: Optional[str] = None
    url: Optional[str] = None
    action: str = Field(default="deny", pattern="^(allow|deny|redirect|observe)$")
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = True
    tags: List[str] = []


class MatcherUpdate(BaseModel):
    """Update matcher."""

    name: Optional[str] = None
    pattern: Optional[str] = None
    url: Optional[str] = None
    action: Optional[str] = None
    priority: Optional[int] = None
    enabled: Optional[bool] = None
    tags: Optional[List[str]] = None


class DomainAction(BaseModel):
    """Domain action request."""

    domain: str
    type: Optional[str] = "exact"  # exact, wildcard, regex
    comment: Optional[str] = None
    enabled: Optional[bool] = True


class ShieldProfileSet(BaseModel):
    """Set shield profile."""

    profile_id: str


class DeviceUpdate(BaseModel):
    """Update device settings."""

    name: Optional[str] = None
    shield_profile: Optional[str] = None
    enabled: Optional[bool] = None
    parental: Optional[bool] = None
    safesearch: Optional[bool] = None
    blocked_services: Optional[List[str]] = None
    profile_id: Optional[str] = None
    # IP-based app blocking (Telegram, WhatsApp, Signal, Tor)
    blocked_apps: Optional[List[str]] = None


class FirewallToggleRequest(BaseModel):
    """Firewall enabled toggle."""

    enabled: bool


class DeviceRuleRequest(BaseModel):
    """Device-specific allow or block rule."""

    type: str = Field(..., pattern="^(block|allow)$")
    domain: str


class ThreatBanRequest(BaseModel):
    """Manual threat ban request."""

    ip: str
    reason: str = "Manual ban"
    type: Optional[str] = None
    permanent: bool = False
    duration: Optional[int] = None


class ThreatUnbanRequest(BaseModel):
    """Manual threat unban request."""

    ip: str
    type: Optional[str] = None


class MonitoringSettingsRequest(BaseModel):
    """Threat monitoring settings update."""

    ssh_threshold: Optional[int] = Field(None, ge=1, le=1000)
    auto_ban: Optional[bool] = None
