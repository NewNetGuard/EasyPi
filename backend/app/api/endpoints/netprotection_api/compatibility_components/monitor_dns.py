"""NetProtection monitor dns compatibility routes."""

from __future__ import annotations

# ruff: noqa: F401

from app.api.endpoints.netprotection_api.compatibility_components.context import (
    APIRouter,
    Any,
    BYPASS_ALERT_TTL_SEC,
    Body,
    Depends,
    DeviceRuleRequest,
    Dict,
    FirewallToggleRequest,
    HTTPException,
    List,
    MonitoringSettingsRequest,
    Optional,
    PORNOGRAPHY_PARENTAL_SHORTCUT,
    ThreatBanRequest,
    ThreatUnbanRequest,
    User,
    _record_netprotection_event,
    datetime,
    firewall_service,
    json,
    logger,
    netprotection_service,
    require_admin,
    router,
    sanitize_domain,
    sanitize_mac,
    threat_service,
    time,
    timezone,
    validate_ip,
)


@router.get("/monitoring/status")
async def get_monitoring_status_compat(_admin: User = Depends(require_admin)):
    """Get threat monitoring status."""
    return await threat_service.get_status()


@router.post("/monitoring/start")
async def start_monitoring_compat(_admin: User = Depends(require_admin)):
    """Start threat monitoring."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.start_monitoring()
    _record_netprotection_event(
        action_id="netprotection.monitoring.start",
        title="Start threat monitoring",
        subtitle="Guard Security · Security monitor",
        status="success",
        message=result.get("message", "Threat monitoring started"),
        started_at=started_at,
    )
    return {"success": True, **result}


@router.post("/monitoring/stop")
async def stop_monitoring_compat(_admin: User = Depends(require_admin)):
    """Stop threat monitoring."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.stop_monitoring()
    _record_netprotection_event(
        action_id="netprotection.monitoring.stop",
        title="Stop threat monitoring",
        subtitle="Guard Security · Security monitor",
        status="success",
        message=result.get("message", "Threat monitoring stopped"),
        started_at=started_at,
    )
    return {"success": True, **result}


@router.post("/monitoring/settings")
async def update_monitoring_settings_compat(
    settings: MonitoringSettingsRequest,
    _admin: User = Depends(require_admin),
):
    """Update threat monitoring settings."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.update_settings(
        ssh_threshold=settings.ssh_threshold,
        auto_ban=settings.auto_ban,
    )
    _record_netprotection_event(
        action_id="netprotection.monitoring.settings",
        title="Update threat monitoring settings",
        subtitle="Guard Security · Security monitor",
        status="success",
        message="Threat monitoring settings updated",
        started_at=started_at,
    )
    return result


@router.get("/dns/rewrites")
async def get_dns_rewrites_compat(_admin: User = Depends(require_admin)):
    """Get DNS rewrites in the Guard Security shape."""
    try:
        rewrites = await netprotection_service.get_rewrites()
        return [
            {
                "id": f"{rewrite.get('domain', '')}_{rewrite.get('answer', '')}",
                "domain": rewrite.get("domain", ""),
                "answer": rewrite.get("answer", ""),
            }
            for rewrite in (rewrites or [])
        ]
    except Exception as e:
        logger.error("Error getting DNS rewrites: %s", e)
        return []


@router.post("/dns/rewrite")
async def add_dns_rewrite_compat(
    data: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Add a DNS rewrite."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        domain = sanitize_domain(data.get("domain") or "")
        answer = str(data.get("answer") or "").strip()
        if not domain or domain == "unknown":
            _record_netprotection_event(
                action_id="netprotection.dns.rewrite.add",
                title="Add DNS rewrite",
                subtitle="Guard Security · DNS settings",
                status="failed",
                message="Domain is required",
                started_at=started_at,
            )
            raise HTTPException(status_code=400, detail="Domain is required")
        if not answer:
            _record_netprotection_event(
                action_id="netprotection.dns.rewrite.add",
                title="Add DNS rewrite",
                subtitle=f"Guard Security · {domain}",
                status="failed",
                message="Answer (IP or domain) is required",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=400, detail="Answer (IP or domain) is required"
            )
        await netprotection_service.add_rewrite(domain, answer)
        _record_netprotection_event(
            action_id="netprotection.dns.rewrite.add",
            title="Add DNS rewrite",
            subtitle=f"Guard Security · {domain}",
            status="success",
            message=f"DNS rewrite added for {domain}",
            started_at=started_at,
        )
        return {"success": True, "message": f"DNS rewrite added for {domain}"}
    except ValueError as e:
        _record_netprotection_event(
            action_id="netprotection.dns.rewrite.add",
            title="Add DNS rewrite",
            subtitle=f"Guard Security · {data.get('domain') or 'DNS settings'}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error adding DNS rewrite: %s", e)
        _record_netprotection_event(
            action_id="netprotection.dns.rewrite.add",
            title="Add DNS rewrite",
            subtitle=f"Guard Security · {data.get('domain') or 'DNS settings'}",
            status="failed",
            message="Failed to add DNS rewrite",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Failed to add DNS rewrite")


@router.delete("/dns/rewrite")
async def delete_dns_rewrite_compat(
    domain: str,
    answer: str,
    _admin: User = Depends(require_admin),
):
    """Delete a DNS rewrite."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        sanitized_domain = sanitize_domain(domain)
        if not sanitized_domain or sanitized_domain == "unknown":
            _record_netprotection_event(
                action_id="netprotection.dns.rewrite.delete",
                title="Delete DNS rewrite",
                subtitle="Guard Security · DNS settings",
                status="failed",
                message="Domain is required",
                started_at=started_at,
            )
            raise HTTPException(status_code=400, detail="Domain is required")
        await netprotection_service.delete_rewrite(
            sanitized_domain, str(answer or "").strip()
        )
        _record_netprotection_event(
            action_id="netprotection.dns.rewrite.delete",
            title="Delete DNS rewrite",
            subtitle=f"Guard Security · {sanitized_domain}",
            status="success",
            message=f"DNS rewrite deleted for {sanitized_domain}",
            started_at=started_at,
        )
        return {
            "success": True,
            "message": f"DNS rewrite deleted for {sanitized_domain}",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting DNS rewrite: %s", e)
        _record_netprotection_event(
            action_id="netprotection.dns.rewrite.delete",
            title="Delete DNS rewrite",
            subtitle=f"Guard Security · {domain or 'DNS settings'}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/dns/cache/clear")
async def clear_dns_cache_compat(_admin: User = Depends(require_admin)):
    """Clear the in-memory DNS cache."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.clear_dns_cache()
        _record_netprotection_event(
            action_id="netprotection.dns.cache.clear",
            title="Clear DNS cache",
            subtitle="Guard Security · DNS settings",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", "DNS cache cleared"),
            started_at=started_at,
        )
        return result
    except Exception as e:
        logger.error("Error clearing DNS cache: %s", e)
        _record_netprotection_event(
            action_id="netprotection.dns.cache.clear",
            title="Clear DNS cache",
            subtitle="Guard Security · DNS settings",
            status="failed",
            message="Failed to clear DNS cache",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Failed to clear DNS cache")


@router.post("/dns/test-upstream")
async def test_upstream_dns_compat(
    data: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Test upstream DNS servers."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        servers = data.get("servers", [])
        if not isinstance(servers, list):
            _record_netprotection_event(
                action_id="netprotection.dns.test-upstream",
                title="Test upstream DNS",
                subtitle="Guard Security · DNS settings",
                status="failed",
                message="Servers must be a list",
                started_at=started_at,
            )
            raise HTTPException(status_code=400, detail="Servers must be a list")
        result = await netprotection_service.test_upstream_dns(servers)
        _record_netprotection_event(
            action_id="netprotection.dns.test-upstream",
            title="Test upstream DNS",
            subtitle="Guard Security · DNS settings",
            status="success" if result.get("success", True) else "failed",
            message=result.get(
                "message", f"Tested upstream servers: {', '.join(servers)}"
            ),
            started_at=started_at,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error testing upstream DNS: %s", e)
        _record_netprotection_event(
            action_id="netprotection.dns.test-upstream",
            title="Test upstream DNS",
            subtitle="Guard Security · DNS settings",
            status="failed",
            message="Failed to test upstream DNS",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Failed to test upstream DNS")


@router.get("/dns/upstream")
async def get_upstream_servers(_admin: User = Depends(require_admin)):
    """Get the resolver's real upstream DNS servers (from its live TOML config)."""
    return await netprotection_service.get_upstream_servers()


@router.put("/dns/upstream")
async def set_upstream_servers(
    data: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Set upstream DNS servers — writes the resolver config and reloads it."""
    started_at = datetime.now(timezone.utc).isoformat()
    servers = data.get("servers", [])
    if not isinstance(servers, list):
        raise HTTPException(status_code=400, detail="Servers must be a list")
    result = await netprotection_service.set_upstream_servers(servers)
    _record_netprotection_event(
        action_id="netprotection.dns.set-upstream",
        title="Update upstream DNS",
        subtitle="Guard Security · DNS settings",
        status="success" if result.get("success") else "failed",
        message=result.get("error")
        or f"Upstream DNS updated ({len(servers)} server(s))",
        started_at=started_at,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=400, detail=result.get("error", "Failed to update upstream DNS")
        )
    return result


@router.post("/stats/reset")
async def reset_statistics_compat(_admin: User = Depends(require_admin)):
    """Reset Guard Security statistics."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.reset_stats()
        if not result.get("success", True):
            raise HTTPException(
                status_code=500,
                detail=result.get("error") or "Failed to reset statistics",
            )
        _record_netprotection_event(
            action_id="netprotection.stats.reset",
            title="Reset Guard Security statistics",
            subtitle="Guard Security · Statistics",
            status="success",
            message=result.get("message", "Statistics reset successfully"),
            started_at=started_at,
        )
        return {
            "success": True,
            "message": result.get("message", "Statistics reset successfully"),
        }
    except HTTPException:
        _record_netprotection_event(
            action_id="netprotection.stats.reset",
            title="Reset Guard Security statistics",
            subtitle="Guard Security · Statistics",
            status="failed",
            message="Failed to reset statistics",
            started_at=started_at,
        )
        raise
    except Exception as e:
        logger.error("Error resetting stats: %s", e)
        _record_netprotection_event(
            action_id="netprotection.stats.reset",
            title="Reset Guard Security statistics",
            subtitle="Guard Security · Statistics",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/reset-settings")
async def reset_all_settings_compat(_admin: User = Depends(require_admin)):
    """Reset Guard Security settings to a safe default baseline."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        await netprotection_service.reset_stats()
        await netprotection_service.clear_query_log()
        await netprotection_service.clear_dns_cache()
        _record_netprotection_event(
            action_id="netprotection.settings.reset",
            title="Reset Guard Security settings",
            subtitle="Guard Security · Advanced",
            status="success",
            message="Settings reset to defaults",
            started_at=started_at,
        )
        return {"success": True, "message": "Settings reset to defaults"}
    except Exception as e:
        logger.error("Error resetting settings: %s", e)
        _record_netprotection_event(
            action_id="netprotection.settings.reset",
            title="Reset Guard Security settings",
            subtitle="Guard Security · Advanced",
            status="failed",
            message="Failed to reset settings",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Failed to reset settings")


__all__ = [
    "add_dns_rewrite_compat",
    "clear_dns_cache_compat",
    "delete_dns_rewrite_compat",
    "get_dns_rewrites_compat",
    "get_monitoring_status_compat",
    "get_upstream_servers",
    "reset_all_settings_compat",
    "reset_statistics_compat",
    "set_upstream_servers",
    "start_monitoring_compat",
    "stop_monitoring_compat",
    "test_upstream_dns_compat",
    "update_monitoring_settings_compat",
]
