"""NetProtection policy routes."""

from typing import Literal

from app.services.netprotection_components.policy_data import normalize_list_domain

from .context import (
    APIRouter,
    HTTPException,
    Query,
    Depends,
    Optional,
    datetime,
    timezone,
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    require_admin,
    User,
    netprotection_service,
    _record_netprotection_event,
    MatcherCreate,
    MatcherUpdate,
    DomainAction,
)

router = APIRouter()

# ============ Verdicts (Query Log) ============


@router.get("/verdicts")
async def get_verdicts(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    search: Optional[str] = None,
    verdict_type: Optional[str] = Query(
        None, pattern="^(allow|deny|redirect|observe)$"
    ),
    include_system: bool = Query(
        True,
        description="Include resolver-internal loopback queries",
    ),
    _admin: User = Depends(require_admin),
):
    """
    Get verdict log (DNS query history with evidence).

    Similar to NetProtection's query log but includes Evidence chain.
    Stored in SQLite for persistence across restarts.
    """
    return await netprotection_service.get_verdicts(
        offset=offset,
        limit=limit,
        search=search,
        verdict_type=verdict_type,
        include_system=include_system,
    )


@router.get("/verdicts/stats")
async def get_verdicts_stats(
    period: str = Query("24h", pattern="^(24h|7d)$"),
    _admin: User = Depends(require_admin),
):
    """Get query log statistics including security metrics with hourly breakdown."""
    # Get total stats
    totals = await netprotection_service.get_query_log_stats()

    # Get hourly breakdown from get_stats()
    stats = await netprotection_service.get_stats()
    dns_queries = stats.get("dns_queries", [])
    blocked_filtering = stats.get("blocked_filtering", [])

    # Build hourly array
    hourly = []
    for i in range(24):
        total = dns_queries[i] if i < len(dns_queries) else 0
        blocked = blocked_filtering[i] if i < len(blocked_filtering) else 0
        allowed = total - blocked
        hourly.append(
            {"hour": i, "total": total, "blocked": blocked, "allowed": allowed}
        )

    return {**totals, "hourly": hourly}


@router.delete("/verdicts")
async def clear_verdicts(
    older_than_days: int = Query(
        0, ge=0, le=90, description="Clear entries older than N days (0=all, max 90)"
    ),
    _admin: User = Depends(require_admin),
):
    """
    Clear query log entries.

    Args:
        older_than_days: Clear entries older than this many days (0 = clear all, max 90)

    Note: older_than_days is capped at 90 to prevent disabling TTL cleanup.
    """
    # Cap to prevent retention bypass
    if older_than_days > 90:
        older_than_days = 90

    cleared = await netprotection_service.clear_query_log(older_than_days)
    return {"cleared": cleared, "message": f"Cleared {cleared} entries"}


@router.put("/verdicts/config")
async def update_query_log_config(
    enabled: bool = Query(None, description="Enable/disable query logging"),
    store_evidence: bool = Query(
        None, description="Store evidence_summary (may contain PII)"
    ),
    store_response_ips: bool = Query(
        None, description="Store response IPs (infrastructure disclosure)"
    ),
    retention_days: int = Query(
        None, ge=1, le=90, description="Retention period (1-90 days)"
    ),
    _admin: User = Depends(require_admin),
):
    """
    Update query log configuration.

    Privacy controls:
    - store_evidence: Evidence summary may contain PII, disable for privacy
    - store_response_ips: Response IPs reveal infrastructure, disable for privacy
    - retention_days: Shorter retention = less stored data (max 90 days)
    """
    config = {}
    if enabled is not None:
        config["enabled"] = enabled
    if store_evidence is not None:
        config["store_evidence"] = store_evidence
    if store_response_ips is not None:
        config["store_response_ips"] = store_response_ips
    if retention_days is not None:
        config["retention_days"] = min(retention_days, 90)

    return await netprotection_service.update_query_log_config(config)


@router.get("/verdicts/{flow_id}")
async def get_verdict_detail(flow_id: str, _admin: User = Depends(require_admin)):
    """Get single verdict with full evidence."""
    verdict = await netprotection_service.get_verdict_by_flow_id(flow_id)
    if not verdict:
        raise HTTPException(status_code=404, detail="Verdict not found")
    return verdict


# ============ Shadow Domains ============


class ShadowDomainAction(BaseModel):
    """Action on shadow domain."""

    action: str = Field(..., pattern="^(promote|dismiss)$")
    notes: Optional[str] = None


@router.get("/shadow/domains")
async def get_shadow_domains(
    status: Optional[str] = Query(
        None, pattern="^(observing|blocked|approved|auto_blocked)$"
    ),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _admin: User = Depends(require_admin),
):
    """
    Get domains from Shadow Mode.

    Status filters:
    - observing: All domains (overview)
    - blocked: User manually blocked
    - approved: User manually approved
    - auto_blocked: Auto-blocked by Shadow Mode
    """
    return await netprotection_service.get_shadow_domains(
        status=status, limit=limit, offset=offset
    )


@router.get("/shadow/stats")
async def get_shadow_stats(_admin: User = Depends(require_admin)):
    """Get shadow mode statistics."""
    return await netprotection_service.get_shadow_stats()


@router.post("/shadow/domains/{domain}/action")
async def shadow_domain_action(
    domain: str, action_req: ShadowDomainAction, _admin: User = Depends(require_admin)
):
    """
    Take action on a shadow domain.

    Actions:
    - promote: Add domain to blocklist
    - dismiss: Approve as safe and add the domain to the allowlist
    """
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.shadow_domain_action(
            domain=domain,
            action=action_req.action,
            user="admin",
            notes=action_req.notes,
        )
        _record_netprotection_event(
            action_id="netprotection.shadow.domain-action",
            title="Apply shadow domain action",
            subtitle=f"Guard Security · {domain}",
            status="success" if result.get("success", True) else "failed",
            message=result.get(
                "message", f"Action '{action_req.action}' applied to {domain}"
            ),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.shadow.domain-action",
            title="Apply shadow domain action",
            subtitle=f"Guard Security · {domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


# ============ Matchers (Rules) ============


@router.get("/matchers")
async def get_matchers(_admin: User = Depends(require_admin)):
    """Get all matchers (blocklist rules)."""
    return await netprotection_service.get_matchers()


@router.post("/matchers")
async def create_matcher(matcher: MatcherCreate, _admin: User = Depends(require_admin)):
    """Create new matcher."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.add_matcher(matcher.model_dump())
        _record_netprotection_event(
            action_id="netprotection.matchers.create",
            title="Create matcher",
            subtitle=f"Guard Security · {matcher.name}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Matcher created: {matcher.name}"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.matchers.create",
            title="Create matcher",
            subtitle=f"Guard Security · {matcher.name}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.put("/matchers/{matcher_id}")
async def update_matcher(
    matcher_id: str, updates: MatcherUpdate, _admin: User = Depends(require_admin)
):
    """Update matcher."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.update_matcher(
        matcher_id, updates.model_dump(exclude_none=True)
    )
    if not result:
        _record_netprotection_event(
            action_id="netprotection.matchers.update",
            title="Update matcher",
            subtitle=f"Guard Security · {matcher_id}",
            status="failed",
            message="Matcher not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Matcher not found")
    _record_netprotection_event(
        action_id="netprotection.matchers.update",
        title="Update matcher",
        subtitle=f"Guard Security · {matcher_id}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Matcher updated: {matcher_id}"),
        started_at=started_at,
    )
    return result


@router.delete("/matchers/{matcher_id}")
async def delete_matcher(matcher_id: str, _admin: User = Depends(require_admin)):
    """Delete matcher."""
    started_at = datetime.now(timezone.utc).isoformat()
    if await netprotection_service.delete_matcher(matcher_id):
        _record_netprotection_event(
            action_id="netprotection.matchers.delete",
            title="Delete matcher",
            subtitle=f"Guard Security · {matcher_id}",
            status="success",
            message=f"Matcher deleted: {matcher_id}",
            started_at=started_at,
        )
        return {"success": True}
    _record_netprotection_event(
        action_id="netprotection.matchers.delete",
        title="Delete matcher",
        subtitle=f"Guard Security · {matcher_id}",
        status="failed",
        message="Matcher not found",
        started_at=started_at,
    )
    raise HTTPException(status_code=404, detail="Matcher not found")


# ============ Blocked & Allowed ============

class DomainDecision(BaseModel):
    """The user's latest decision for one exact host."""

    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=3, max_length=253)
    decision: Literal["allow", "block"]

    @field_validator("domain")
    @classmethod
    def _valid_hostname(cls, value: str) -> str:
        return normalize_list_domain(value)


@router.get("/blocked-overview")
async def get_blocked_overview(
    period: Literal["24h", "7d"] = Query("24h"),
    client_id: Optional[str] = Query(None, max_length=64),
    _admin: User = Depends(require_admin),
):
    """Network-wide blocks split into sites and trackers, plus user-allowed domains."""
    return await netprotection_service.get_blocked_overview(
        period=period, client_id=client_id
    )


@router.post("/domain-decision")
async def set_domain_decision(
    request: DomainDecision, _admin: User = Depends(require_admin)
):
    """Unblock (allow) or block again one host; the latest decision wins."""
    started_at = datetime.now(timezone.utc).isoformat()
    title = "Unblock domain" if request.decision == "allow" else "Block domain again"
    try:
        result = await netprotection_service.set_domain_decision(
            request.domain, request.decision
        )
    except Exception as exc:
        _record_netprotection_event(
            action_id=f"netprotection.domain-decision.{request.decision}",
            title=title,
            subtitle=f"Guard Security · {request.domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        if isinstance(exc, ValueError):
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raise
    _record_netprotection_event(
        action_id=f"netprotection.domain-decision.{request.decision}",
        title=title,
        subtitle=f"Guard Security · {request.domain}",
        status="success" if result.get("success") else "failed",
        message=f"{title}: {request.domain}",
        started_at=started_at,
    )
    return result


# ============ Whitelist / Blacklist ============


@router.get("/whitelist")
async def get_whitelist(_admin: User = Depends(require_admin)):
    """Get user whitelist."""
    domains = await netprotection_service.get_whitelist()
    return {"domains": domains}


@router.post("/whitelist")
async def add_to_whitelist(
    request: DomainAction, _admin: User = Depends(require_admin)
):
    """Add domain to whitelist."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.add_to_whitelist(
            domain=request.domain, domain_type=request.type, comment=request.comment
        )
        _record_netprotection_event(
            action_id="netprotection.whitelist.add",
            title="Add whitelist domain",
            subtitle=f"Guard Security · {request.domain}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Added {request.domain} to whitelist"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.whitelist.add",
            title="Add whitelist domain",
            subtitle=f"Guard Security · {request.domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        if isinstance(exc, ValueError):
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raise


@router.delete("/whitelist/{domain}")
async def remove_from_whitelist(domain: str, _admin: User = Depends(require_admin)):
    """Remove domain from whitelist."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.remove_from_whitelist(domain)
        _record_netprotection_event(
            action_id="netprotection.whitelist.delete",
            title="Remove whitelist domain",
            subtitle=f"Guard Security · {domain}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Removed {domain} from whitelist"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.whitelist.delete",
            title="Remove whitelist domain",
            subtitle=f"Guard Security · {domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise


@router.get("/blacklist")
async def get_blacklist(_admin: User = Depends(require_admin)):
    """Get user blacklist."""
    domains = await netprotection_service.get_blacklist()
    return {"domains": domains}


@router.post("/blacklist")
async def add_to_blacklist(
    request: DomainAction, _admin: User = Depends(require_admin)
):
    """Add domain to blacklist."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.add_to_blacklist(
            domain=request.domain, domain_type=request.type, comment=request.comment
        )
        _record_netprotection_event(
            action_id="netprotection.blacklist.add",
            title="Add blacklist domain",
            subtitle=f"Guard Security · {request.domain}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Added {request.domain} to blacklist"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.blacklist.add",
            title="Add blacklist domain",
            subtitle=f"Guard Security · {request.domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        if isinstance(exc, ValueError):
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        raise


@router.delete("/blacklist/{domain}")
async def remove_from_blacklist(domain: str, _admin: User = Depends(require_admin)):
    """Remove domain from blacklist."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.remove_from_blacklist(domain)
        _record_netprotection_event(
            action_id="netprotection.blacklist.delete",
            title="Remove blacklist domain",
            subtitle=f"Guard Security · {domain}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Removed {domain} from blacklist"),
            started_at=started_at,
        )
        return result
    except Exception as exc:
        _record_netprotection_event(
            action_id="netprotection.blacklist.delete",
            title="Remove blacklist domain",
            subtitle=f"Guard Security · {domain}",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise
