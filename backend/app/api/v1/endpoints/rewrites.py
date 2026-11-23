"""
DNS Rewrites API Endpoints

CRUD operations for custom DNS rewrite rules.
Security hardened with rate limiting and input validation.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime, timezone
from threading import Lock
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Depends, Query, Request
from pydantic import BaseModel, Field, field_validator
import ipaddress

try:
    from app.api.deps import require_admin
    from app.core.rate_limit import get_client_ip
    from app.models.user import User
    from app.services.operation_event_service import OperationEventService
except ModuleNotFoundError:
    from backend.app.api.deps import require_admin
    from backend.app.core.rate_limit import get_client_ip
    from backend.app.models.user import User
    from backend.app.services.operation_event_service import OperationEventService

# Import rewrite manager
try:
    from easypi_netprotection.rewrites import (
        get_rewrite_manager, 
        RewriteRule, 
        RewriteType,
    )
    REWRITES_AVAILABLE = True
except ImportError:
    REWRITES_AVAILABLE = False
    # Define placeholder types for when NetProtection is not available
    RewriteRule = None
    RewriteType = None
    get_rewrite_manager = None


logger = logging.getLogger(__name__)
router = APIRouter()
operation_event_service = OperationEventService()


def _record_rewrite_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
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
        logger.warning("Failed to record rewrite event %s: %s", action_id, exc)


# ═══════════════════════════════════════════════════════════════════════════════
# RATE LIMITING
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self, calls: int = 30, period: int = 60):
        """
        Args:
            calls: Max calls allowed per period
            period: Time window in seconds
        """
        self.calls = calls
        self.period = period
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()
    
    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed."""
        now = time.time()
        
        with self._lock:
            # Clean old entries
            self._requests[key] = [
                t for t in self._requests[key] 
                if now - t < self.period
            ]
            
            if len(self._requests[key]) >= self.calls:
                return False
            
            self._requests[key].append(now)
            return True
    
    def remaining(self, key: str) -> int:
        """Get remaining calls for key."""
        now = time.time()
        
        with self._lock:
            valid = [
                t for t in self._requests.get(key, [])
                if now - t < self.period
            ]
            return max(0, self.calls - len(valid))


# Rate limiters
_write_limiter = RateLimiter(calls=30, period=60)   # 30 writes/min
_read_limiter = RateLimiter(calls=120, period=60)   # 120 reads/min


def check_write_rate_limit(request: Request):
    """Rate limit write operations."""
    client_ip = get_client_ip(request)
    if not _write_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Max 30 write operations per minute.",
            headers={"Retry-After": "60"},
        )


def check_read_rate_limit(request: Request):
    """Rate limit read operations."""
    client_ip = get_client_ip(request)
    if not _read_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded. Max 120 read operations per minute.",
            headers={"Retry-After": "60"},
        )


# ═══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class RewriteRuleCreate(BaseModel):
    """Request model for creating a rewrite rule."""
    
    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Domain pattern (supports * wildcard)",
        json_schema_extra={"example": "*.ads.example.com"},
    )
    answer: str = Field(
        ...,
        description="Target answer (IP, domain, or empty for special types)",
        json_schema_extra={"example": "192.168.1.100"},
    )
    rewrite_type: str = Field(
        default="A",
        description="Type: A, AAAA, CNAME, NXDOMAIN, NODATA, REFUSED, PASSTHROUGH",
    )
    comment: str = Field(
        default="",
        max_length=500,
        description="Optional description",
    )
    priority: int = Field(
        default=0,
        ge=0,
        le=1000,
        description="Higher priority rules are evaluated first",
    )
    enabled: bool = Field(
        default=True,
        description="Whether the rule is active",
    )
    
    @field_validator("rewrite_type")
    @classmethod
    def validate_type(cls, v):
        valid = ["A", "AAAA", "CNAME", "NXDOMAIN", "NODATA", "REFUSED", "PASSTHROUGH"]
        if v.upper() not in valid:
            raise ValueError(f"Invalid type. Must be one of: {', '.join(valid)}")
        return v.upper()
    
    @field_validator("answer")
    @classmethod
    def validate_answer(cls, v, info):
        rt = info.data.get("rewrite_type", "A").upper() if info.data else "A"
        
        if rt == "A":
            try:
                ip = ipaddress.ip_address(v)
                if ip.version != 4:
                    raise ValueError("A record requires IPv4 address")
            except ValueError:
                raise ValueError(f"Invalid IPv4 address: {v}")
        
        elif rt == "AAAA":
            try:
                ip = ipaddress.ip_address(v)
                if ip.version != 6:
                    raise ValueError("AAAA record requires IPv6 address")
            except ValueError:
                raise ValueError(f"Invalid IPv6 address: {v}")
        
        elif rt == "CNAME":
            if not v or len(v) > 253:
                raise ValueError("CNAME target must be a valid domain")
        
        return v


class RewriteRuleUpdate(BaseModel):
    """Request model for updating a rewrite rule."""
    
    domain: Optional[str] = Field(None, min_length=1, max_length=253)
    answer: Optional[str] = None
    rewrite_type: Optional[str] = None
    comment: Optional[str] = Field(None, max_length=500)
    priority: Optional[int] = Field(None, ge=0, le=1000)
    enabled: Optional[bool] = None


class RewriteRuleResponse(BaseModel):
    """Response model for a rewrite rule."""
    
    id: str
    domain: str
    answer: str
    rewrite_type: str
    enabled: bool
    comment: str
    priority: int
    created_at: str
    updated_at: str


class RewriteListResponse(BaseModel):
    """Response model for list of rules."""
    
    rules: list[RewriteRuleResponse]
    total: int


class RewriteStatsResponse(BaseModel):
    """Response model for rewrite statistics."""
    
    total_rules: int
    enabled_rules: int
    disabled_rules: int
    wildcard_rules: int
    max_rules: int
    cache_hits: int
    cache_misses: int
    hit_rate: float
    parse_errors: int
    validation_errors: int
    load_errors: int
    save_errors: int
    healthy: bool


class RewriteTestRequest(BaseModel):
    """Request model for testing a domain against rewrites."""
    
    domain: str = Field(..., description="Domain to test")


class RewriteTestResponse(BaseModel):
    """Response model for rewrite test."""
    
    domain: str
    matched: bool
    rule_id: Optional[str] = None
    rewritten_answer: Optional[str] = None
    rewrite_type: Optional[str] = None
    comment: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# HELPER
# ═══════════════════════════════════════════════════════════════════════════════

def _get_manager():
    """Get rewrite manager or raise error if unavailable."""
    if not REWRITES_AVAILABLE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="DNS Rewrites module not available. NetProtection not installed.",
        )
    return get_rewrite_manager()


def _rule_to_response(rule: "RewriteRule") -> RewriteRuleResponse:
    """Convert RewriteRule to response model."""
    return RewriteRuleResponse(
        id=rule.id,
        domain=rule.domain,
        answer=rule.answer,
        rewrite_type=rule.rewrite_type.value,
        enabled=rule.enabled,
        comment=rule.comment,
        priority=rule.priority,
        created_at=rule.created_at.isoformat(),
        updated_at=rule.updated_at.isoformat(),
    )


# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/rewrites", response_model=RewriteListResponse)
async def list_rewrites(
    request: Request,
    enabled_only: bool = Query(False, description="Only return enabled rules"),
    current_user: User = Depends(require_admin),
):
    """
    List all DNS rewrite rules.
    
    Returns rules sorted by priority (highest first).
    """
    check_read_rate_limit(request)
    manager = _get_manager()
    rules = manager.list_all()
    
    if enabled_only:
        rules = [r for r in rules if r.enabled]
    
    return RewriteListResponse(
        rules=[_rule_to_response(r) for r in rules],
        total=len(rules),
    )


@router.post("/rewrites", response_model=RewriteRuleResponse, status_code=201)
async def create_rewrite(
    request: Request,
    rule: RewriteRuleCreate,
    current_user: User = Depends(require_admin),
):
    """
    Create a new DNS rewrite rule.
    
    **Wildcards:** Use `*` for wildcard matching:
    - `*.example.com` matches `foo.example.com`, `bar.example.com`
    - `ads.*` matches `ads.foo.com`, `ads.bar.net`
    
    **Types:**
    - `A`: Rewrite to IPv4 address
    - `AAAA`: Rewrite to IPv6 address
    - `CNAME`: Redirect to another domain
    - `NXDOMAIN`: Return "domain not found"
    - `NODATA`: Return empty response
    - `REFUSED`: Return "query refused"
    - `PASSTHROUGH`: Disable rewrite for this pattern
    
    **Security:**
    - Protected zones (localhost, local, home.arpa) cannot have NXDOMAIN rules
    - Wildcards must have minimum specificity
    - CNAME loops are detected and blocked
    """
    check_write_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    try:
        new_rule = manager.add(
            domain=rule.domain,
            answer=rule.answer,
            rewrite_type=RewriteType(rule.rewrite_type),
            comment=rule.comment,
            priority=rule.priority,
            enabled=rule.enabled,
        )
        
        # Sanitized log — don't expose full domain/IP
        logger.info(f"Created rewrite rule: {new_rule.id[:8]}... ({rule.rewrite_type})")
        _record_rewrite_event(
            action_id="rewrites.create",
            title="Create DNS rewrite",
            subtitle="Rewrites - Rule",
            status="success",
            message=f"Created rewrite rule: {new_rule.id}",
            started_at=started_at,
        )
        return _rule_to_response(new_rule)
        
    except ValueError as e:
        _record_rewrite_event(
            action_id="rewrites.create",
            title="Create DNS rewrite",
            subtitle="Rewrites - Rule",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


@router.get("/rewrites/stats", response_model=RewriteStatsResponse)
async def get_rewrite_stats(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """Get statistics for the rewrite system."""
    check_read_rate_limit(request)
    manager = _get_manager()
    stats = manager.stats()

    return RewriteStatsResponse(
        total_rules=stats["total_rules"],
        enabled_rules=stats["enabled_rules"],
        disabled_rules=stats["disabled_rules"],
        wildcard_rules=stats.get("wildcard_rules", 0),
        max_rules=stats.get("max_rules", 5000),
        cache_hits=stats["cache_hits"],
        cache_misses=stats["cache_misses"],
        hit_rate=round(stats["hit_rate"], 4),
        parse_errors=stats.get("parse_errors", 0),
        validation_errors=stats.get("validation_errors", 0),
        load_errors=stats.get("load_errors", 0),
        save_errors=stats.get("save_errors", 0),
        healthy=stats.get("healthy", True),
    )


@router.get("/rewrites/{rule_id}", response_model=RewriteRuleResponse)
async def get_rewrite(
    request: Request,
    rule_id: str,
    current_user: User = Depends(require_admin),
):
    """Get a specific rewrite rule by ID."""
    check_read_rate_limit(request)
    manager = _get_manager()
    rule = manager.get(rule_id)
    
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rewrite rule not found",
        )
    
    return _rule_to_response(rule)


@router.put("/rewrites/{rule_id}", response_model=RewriteRuleResponse)
async def update_rewrite(
    request: Request,
    rule_id: str,
    update: RewriteRuleUpdate,
    current_user: User = Depends(require_admin),
):
    """Update an existing rewrite rule."""
    check_write_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    # Build update dict with only provided fields
    update_data = update.model_dump(exclude_none=True)
    
    if not update_data:
        _record_rewrite_event(
            action_id="rewrites.update",
            title="Update DNS rewrite",
            subtitle=f"Rewrites - {rule_id}",
            status="failed",
            message="No fields to update",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update",
        )
    
    try:
        updated = manager.update(rule_id, **update_data)
    except ValueError as e:
        _record_rewrite_event(
            action_id="rewrites.update",
            title="Update DNS rewrite",
            subtitle=f"Rewrites - {rule_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    
    if not updated:
        _record_rewrite_event(
            action_id="rewrites.update",
            title="Update DNS rewrite",
            subtitle=f"Rewrites - {rule_id}",
            status="failed",
            message="Rewrite rule not found",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rewrite rule not found",
        )
    
    logger.info(f"Updated rewrite rule {rule_id[:8]}...")
    _record_rewrite_event(
        action_id="rewrites.update",
        title="Update DNS rewrite",
        subtitle=f"Rewrites - {rule_id}",
        status="success",
        message="Rewrite rule updated",
        started_at=started_at,
    )
    return _rule_to_response(updated)


@router.delete("/rewrites/{rule_id}")
async def delete_rewrite(
    request: Request,
    rule_id: str,
    current_user: User = Depends(require_admin),
):
    """Delete a rewrite rule."""
    check_write_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()
    
    if not manager.delete(rule_id):
        _record_rewrite_event(
            action_id="rewrites.delete",
            title="Delete DNS rewrite",
            subtitle=f"Rewrites - {rule_id}",
            status="failed",
            message="Rewrite rule not found",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rewrite rule not found",
        )
    
    logger.info(f"Deleted rewrite rule {rule_id[:8]}...")
    _record_rewrite_event(
        action_id="rewrites.delete",
        title="Delete DNS rewrite",
        subtitle=f"Rewrites - {rule_id}",
        status="success",
        message="Rewrite rule deleted",
        started_at=started_at,
    )
    return {"success": True, "message": "Rule deleted"}


@router.post("/rewrites/test", response_model=RewriteTestResponse)
async def test_rewrite(
    request: Request,
    test_request: RewriteTestRequest,
    current_user: User = Depends(require_admin),
):
    """
    Test if a domain matches any rewrite rule.
    
    Use this to verify rules work as expected before deployment.
    """
    check_read_rate_limit(request)
    manager = _get_manager()
    match = manager.lookup(test_request.domain)
    
    if match:
        return RewriteTestResponse(
            domain=test_request.domain,
            matched=True,
            rule_id=match.rule.id,
            rewritten_answer=match.rewritten_answer,
            rewrite_type=match.rewrite_type.value,
            comment=match.rule.comment,
        )
    
    return RewriteTestResponse(
        domain=test_request.domain,
        matched=False,
    )


@router.post("/rewrites/reload")
async def reload_rewrites(
    request: Request,
    current_user: User = Depends(require_admin),
):
    """Reload rewrite rules from disk."""
    check_write_rate_limit(request)
    manager = _get_manager()
    started_at = datetime.now(timezone.utc).isoformat()

    if manager.reload():
        _record_rewrite_event(
            action_id="rewrites.reload",
            title="Reload DNS rewrites",
            subtitle="Rewrites - Runtime",
            status="success",
            message="Rewrites reloaded",
            started_at=started_at,
        )
        return {"success": True, "message": "Rewrites reloaded"}

    _record_rewrite_event(
        action_id="rewrites.reload",
        title="Reload DNS rewrites",
        subtitle="Rewrites - Runtime",
        status="failed",
        message="Failed to reload rewrites",
        started_at=started_at,
    )
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to reload rewrites",
    )


@router.delete("/rewrites")
async def clear_all_rewrites(
    request: Request,
    confirm: bool = Query(False, description="Must be true to confirm deletion"),
    current_user: User = Depends(require_admin),
):
    """
    Delete ALL rewrite rules.
    
    **WARNING:** This action cannot be undone!
    """
    check_write_rate_limit(request)
    started_at = datetime.now(timezone.utc).isoformat()

    if not confirm:
        _record_rewrite_event(
            action_id="rewrites.clear",
            title="Clear DNS rewrites",
            subtitle="Rewrites - Runtime",
            status="failed",
            message="Set confirm=true to delete all rules",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Set confirm=true to delete all rules",
        )
    
    manager = _get_manager()
    count = manager.clear_all()
    
    logger.warning(f"Cleared all {count} rewrite rules")
    _record_rewrite_event(
        action_id="rewrites.clear",
        title="Clear DNS rewrites",
        subtitle="Rewrites - Runtime",
        status="success",
        message=f"Deleted {count} rewrite rules",
        started_at=started_at,
    )
    return {"success": True, "deleted_count": count}
