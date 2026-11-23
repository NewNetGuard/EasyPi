from __future__ import annotations

import uuid
from datetime import datetime
from ..time_utils import utc_now
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


def generate_id(prefix: str = "") -> str:
    """Generate a short unique ID with optional prefix."""
    short_uuid = uuid.uuid4().hex[:12]
    return f"{prefix}_{short_uuid}" if prefix else short_uuid


class MatcherKind(str, Enum):
    """Types of domain matching rules."""
    
    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"
    IP = "ip"
    ASN = "asn"


class VerdictAction(str, Enum):
    """Possible verdict outcomes."""
    
    ALLOW = "allow"
    DENY = "deny"
    REDIRECT = "redirect"
    OBSERVE = "observe"


class DeviceKind(str, Enum):
    """Device type classifications."""
    
    PC = "pc"
    PHONE = "phone"
    TABLET = "tablet"
    TV = "tv"
    IOT = "iot"
    GAMING = "gaming"
    UNKNOWN = "unknown"


class ShieldPreset(str, Enum):
    """Built-in shield profile presets."""
    
    STRICT = "strict"
    BALANCED = "balanced"
    KIDS = "kids"
    MINIMAL = "minimal"
    CUSTOM = "custom"


class EvidenceItem(BaseModel):
    """Single piece of evidence contributing to a verdict."""
    
    source: str = Field(
        ...,
        description="Origin of the signal (e.g., 'matcher:deny_list', 'intel:cname_chain')",
    )
    signal: str = Field(
        ...,
        description="Human-readable description of the observation",
    )
    weight: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Contribution weight to confidence score",
    )
    timestamp: datetime = Field(default_factory=utc_now)


class Verdict(BaseModel):
    """Final decision for a DNS flow."""
    
    flow_id: str = Field(default_factory=lambda: generate_id("fl"))
    action: VerdictAction = Field(default=VerdictAction.ALLOW)
    confidence: int = Field(
        default=100,
        ge=0,
        le=100,
        description="Confidence score (0-100)",
    )
    evidence: list[EvidenceItem] = Field(default_factory=list)
    redirect_target: str | None = Field(
        default=None,
        description="Target IP for redirect action",
    )
    domain: str = Field(..., description="Queried domain")
    query_type: str = Field(default="A", description="DNS query type")
    device_id: str | None = Field(default=None)
    processing_time_ms: float = Field(default=0.0)
    timestamp: datetime = Field(default_factory=utc_now)
    cached: bool = Field(default=False)


class Matcher(BaseModel):
    """Domain matching rule."""
    
    id: str = Field(default_factory=lambda: generate_id("mt"))
    kind: MatcherKind = Field(default=MatcherKind.EXACT)
    pattern: str = Field(..., description="Pattern to match against domain")
    action: VerdictAction = Field(default=VerdictAction.DENY)
    priority: int = Field(
        default=100,
        ge=0,
        le=10000,
        description="Higher priority rules are evaluated first",
    )
    enabled: bool = Field(default=True)
    redirect_target: str | None = Field(
        default=None,
        description="Target IP/domain for redirect action",
    )
    tags: list[str] = Field(default_factory=list)
    comment: str = Field(default="")
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    hit_count: int = Field(default=0)
    last_hit_at: datetime | None = Field(default=None)
    
    @field_validator("pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Pattern cannot be empty")
        return v.strip().lower()


class MatcherCreate(BaseModel):
    """Schema for creating a new matcher."""
    
    kind: MatcherKind = Field(default=MatcherKind.EXACT)
    pattern: str
    action: VerdictAction = Field(default=VerdictAction.DENY)
    priority: int = Field(default=100, ge=0, le=10000)
    enabled: bool = Field(default=True)
    tags: list[str] = Field(default_factory=list)
    comment: str = Field(default="")


class MatcherUpdate(BaseModel):
    """Schema for updating a matcher."""
    
    kind: MatcherKind | None = None
    pattern: str | None = None
    action: VerdictAction | None = None
    priority: int | None = Field(default=None, ge=0, le=10000)
    enabled: bool | None = None
    tags: list[str] | None = None
    comment: str | None = None


class Device(BaseModel):
    """Detected network device."""
    
    id: str = Field(default_factory=lambda: generate_id("dv"))
    mac_address: str = Field(..., description="MAC address (normalized)")
    ip_address: str | None = Field(default=None)
    hostname: str | None = Field(default=None)
    kind: DeviceKind = Field(default=DeviceKind.UNKNOWN)
    vendor: str | None = Field(default=None, description="Vendor from OUI lookup")
    shield_profile: ShieldPreset = Field(default=ShieldPreset.BALANCED)
    custom_matchers: list[str] = Field(
        default_factory=list,
        description="List of matcher IDs specific to this device",
    )
    friendly_name: str | None = Field(default=None)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    total_flows: int = Field(default=0)
    blocked_flows: int = Field(default=0)
    is_active: bool = Field(default=True)
    
    @field_validator("mac_address")
    @classmethod
    def normalize_mac(cls, v: str) -> str:
        clean = v.replace(":", "").replace("-", "").replace(".", "").lower()
        if len(clean) != 12:
            raise ValueError("Invalid MAC address length")
        return ":".join(clean[i:i+2] for i in range(0, 12, 2))


class DeviceUpdate(BaseModel):
    """Schema for updating device settings."""
    
    kind: DeviceKind | None = None
    shield_profile: ShieldPreset | None = None
    friendly_name: str | None = None
    custom_matchers: list[str] | None = None


class ShieldProfile(BaseModel):
    """Shield protection profile configuration."""
    
    id: str = Field(default_factory=lambda: generate_id("sh"))
    name: str
    preset: ShieldPreset = Field(default=ShieldPreset.CUSTOM)
    description: str = Field(default="")
    
    block_advertising: bool = Field(default=True)
    block_tracking: bool = Field(default=True)
    block_malware: bool = Field(default=True)
    block_phishing: bool = Field(default=True)
    block_adult: bool = Field(default=False)
    block_social: bool = Field(default=False)
    block_gaming: bool = Field(default=False)
    block_streaming: bool = Field(default=False)
    
    enforce_safesearch: bool = Field(default=False)
    enforce_youtube_restricted: bool = Field(default=False)
    
    custom_matchers: list[str] = Field(default_factory=list)
    
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Schedule(BaseModel):
    """Time-based access schedule."""
    
    id: str = Field(default_factory=lambda: generate_id("sc"))
    name: str
    device_ids: list[str] = Field(default_factory=list)
    
    days: list[Literal["mon", "tue", "wed", "thu", "fri", "sat", "sun"]] = Field(
        default_factory=lambda: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    )
    start_time: str = Field(
        default="00:00",
        description="Start time in HH:MM format",
    )
    end_time: str = Field(
        default="23:59",
        description="End time in HH:MM format",
    )
    
    action: VerdictAction = Field(
        default=VerdictAction.DENY,
        description="Action to apply during schedule",
    )
    override_profile: ShieldPreset | None = Field(
        default=None,
        description="Profile to apply during schedule",
    )
    
    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utc_now)
    
    @field_validator("start_time", "end_time")
    @classmethod
    def validate_time_format(cls, v: str) -> str:
        parts = v.split(":")
        if len(parts) != 2:
            raise ValueError("Time must be in HH:MM format")
        h, m = int(parts[0]), int(parts[1])
        if not (0 <= h <= 23 and 0 <= m <= 59):
            raise ValueError("Invalid time value")
        return f"{h:02d}:{m:02d}"


class FlowRecord(BaseModel):
    """Chronicle flow log entry."""
    
    id: str = Field(default_factory=lambda: generate_id("fr"))
    flow_id: str = Field(..., description="Reference to verdict flow_id")
    
    domain: str
    query_type: str = Field(default="A")
    
    device_id: str | None = None
    device_ip_hash: str | None = Field(
        default=None,
        description="Anonymized IP hash",
    )
    
    action: VerdictAction
    confidence: int = Field(ge=0, le=100)
    
    primary_evidence: str | None = Field(
        default=None,
        description="Main reason for verdict",
    )
    
    response_ip: str | None = None
    response_code: str | None = Field(default="NOERROR")
    
    upstream_used: str | None = None
    cached: bool = Field(default=False)
    processing_time_ms: float = Field(default=0.0)
    
    timestamp: datetime = Field(default_factory=utc_now)


class MetricsSnapshot(BaseModel):
    """Aggregated metrics for a time period."""
    
    period_start: datetime
    period_end: datetime
    
    total_flows: int = Field(default=0)
    allowed_flows: int = Field(default=0)
    denied_flows: int = Field(default=0)
    redirected_flows: int = Field(default=0)
    observed_flows: int = Field(default=0)
    
    cached_responses: int = Field(default=0)
    upstream_queries: int = Field(default=0)
    
    avg_response_time_ms: float = Field(default=0.0)
    p95_response_time_ms: float = Field(default=0.0)
    
    unique_domains: int = Field(default=0)
    unique_devices: int = Field(default=0)
    
    top_blocked_domains: list[tuple[str, int]] = Field(default_factory=list)
    top_allowed_domains: list[tuple[str, int]] = Field(default_factory=list)
    
    evidence_breakdown: dict[str, int] = Field(
        default_factory=dict,
        description="Count by evidence source",
    )


class SystemHealth(BaseModel):
    """Guardian health check status."""
    
    status: Literal["healthy", "degraded", "critical", "safe_mode"] = "healthy"
    
    dns_listener_up: bool = Field(default=False)
    upstream_reachable: bool = Field(default=False)
    database_ok: bool = Field(default=False)
    
    uptime_seconds: int = Field(default=0)
    memory_usage_mb: float = Field(default=0.0)
    cpu_percent: float = Field(default=0.0)
    
    flows_per_second: float = Field(default=0.0)
    cache_hit_ratio: float = Field(default=0.0)
    
    last_error: str | None = None
    last_check: datetime = Field(default_factory=utc_now)
    
    consecutive_failures: int = Field(default=0)
    safe_mode_active: bool = Field(default=False)
    safe_mode_since: datetime | None = None
