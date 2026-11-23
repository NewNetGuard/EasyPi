"""NetProtection rules threats compatibility routes."""

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
from app.api.endpoints.netprotection_api.compatibility_components.firewall_parental import (
    _is_private_ip,
)


def _managed_client_for_device(
    clients: List[Dict[str, Any]], device_ip: str
) -> Optional[Dict[str, Any]]:
    observed_mac = netprotection_service._resolve_mac_from_arp(device_ip)
    if observed_mac:
        matched = next(
            (item for item in clients if sanitize_mac(item.get("mac")) == observed_mac),
            None,
        )
        if matched:
            return matched
    return next(
        (
            item
            for item in clients
            if not sanitize_mac(item.get("mac"))
            and (device_ip in (item.get("ids") or []) or item.get("ip") == device_ip)
        ),
        None,
    )


@router.get("/devices/{device_ip}/rules")
async def get_device_rules_compat(
    device_ip: str,
    _admin: User = Depends(require_admin),
):
    """Get device-specific allow or block rules for a device IP."""
    if not validate_ip(device_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address")

    clients_data = await netprotection_service.get_clients()
    clients = clients_data.get("clients", [])
    client = _managed_client_for_device(clients, device_ip)

    device_rules = []
    if client:
        for domain in client.get("custom_blocked_domains", []) or []:
            sanitized = sanitize_domain(domain)
            if sanitized and sanitized != "unknown":
                device_rules.append({"type": "block", "domain": sanitized})
        for domain in client.get("custom_allowed_domains", []) or []:
            sanitized = sanitize_domain(domain)
            if sanitized and sanitized != "unknown":
                device_rules.append({"type": "allow", "domain": sanitized})

    return {"ip": device_ip, "rules": device_rules}


@router.post("/devices/{device_ip}/rules")
async def add_device_rule_compat(
    device_ip: str,
    payload: DeviceRuleRequest,
    _admin: User = Depends(require_admin),
):
    """Add a device-specific allow or block rule."""
    started_at = datetime.now(timezone.utc).isoformat()
    if not validate_ip(device_ip):
        _record_netprotection_event(
            action_id="netprotection.devices.rule.add",
            title="Add device rule",
            subtitle=f"Guard Security · {device_ip or 'Devices'}",
            status="failed",
            message="Invalid IP address",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid IP address")

    domain = sanitize_domain(payload.domain)
    if not domain or domain == "unknown":
        _record_netprotection_event(
            action_id="netprotection.devices.rule.add",
            title="Add device rule",
            subtitle=f"Guard Security · {device_ip}",
            status="failed",
            message="Domain is required",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Domain is required")

    clients_data = await netprotection_service.get_clients()
    clients = clients_data.get("clients", [])
    client = _managed_client_for_device(clients, device_ip)

    if not client:
        observed_mac = netprotection_service._resolve_mac_from_arp(device_ip)
        if not observed_mac:
            raise HTTPException(
                status_code=409, detail="Device MAC is not currently discoverable"
            )
        client = {
            "name": f"Device {device_ip}",
            "ids": [device_ip],
            "mac": observed_mac,
            "use_global_settings": False,
            "filtering_enabled": True,
            "parental_enabled": False,
            "safebrowsing_enabled": False,
            "safesearch_enabled": False,
            "use_global_blocked_services": False,
            "blocked_services": [],
            "custom_blocked_domains": [domain] if payload.type == "block" else [],
            "custom_allowed_domains": [domain] if payload.type == "allow" else [],
        }
        await netprotection_service.add_client(client)
        _record_netprotection_event(
            action_id="netprotection.devices.rule.add",
            title="Add device rule",
            subtitle=f"Guard Security · {device_ip}",
            status="success",
            message=f"Added {payload.type} rule for {domain}",
            started_at=started_at,
        )
        return {
            "success": True,
            "ip": device_ip,
            "type": payload.type,
            "domain": domain,
        }

    client["ip"] = device_ip
    client["ids"] = [device_ip]

    blocked = set(client.get("custom_blocked_domains", []) or [])
    allowed = set(client.get("custom_allowed_domains", []) or [])
    if payload.type == "block":
        blocked.add(domain)
        allowed.discard(domain)
    else:
        allowed.add(domain)
        blocked.discard(domain)

    client["custom_blocked_domains"] = sorted(blocked)
    client["custom_allowed_domains"] = sorted(allowed)
    client_name = client.get("name") or f"Device {device_ip}"
    await netprotection_service.update_client(client_name, client)
    _record_netprotection_event(
        action_id="netprotection.devices.rule.add",
        title="Add device rule",
        subtitle=f"Guard Security · {device_ip}",
        status="success",
        message=f"Added {payload.type} rule for {domain}",
        started_at=started_at,
    )
    return {"success": True, "ip": device_ip, "type": payload.type, "domain": domain}


@router.delete("/devices/{device_ip}/rules")
async def remove_device_rule_compat(
    device_ip: str,
    payload: DeviceRuleRequest,
    _admin: User = Depends(require_admin),
):
    """Remove a device-specific allow or block rule."""
    started_at = datetime.now(timezone.utc).isoformat()
    if not validate_ip(device_ip):
        _record_netprotection_event(
            action_id="netprotection.devices.rule.delete",
            title="Remove device rule",
            subtitle=f"Guard Security · {device_ip or 'Devices'}",
            status="failed",
            message="Invalid IP address",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid IP address")

    domain = sanitize_domain(payload.domain)
    if not domain or domain == "unknown":
        _record_netprotection_event(
            action_id="netprotection.devices.rule.delete",
            title="Remove device rule",
            subtitle=f"Guard Security · {device_ip}",
            status="failed",
            message="Domain is required",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Domain is required")

    clients_data = await netprotection_service.get_clients()
    clients = clients_data.get("clients", [])
    client = _managed_client_for_device(clients, device_ip)

    if not client:
        _record_netprotection_event(
            action_id="netprotection.devices.rule.delete",
            title="Remove device rule",
            subtitle=f"Guard Security · {device_ip}",
            status="success",
            message=f"No existing rule found for {domain}",
            started_at=started_at,
        )
        return {
            "success": True,
            "ip": device_ip,
            "type": payload.type,
            "domain": domain,
        }

    blocked = set(client.get("custom_blocked_domains", []) or [])
    allowed = set(client.get("custom_allowed_domains", []) or [])
    if payload.type == "block":
        blocked.discard(domain)
    else:
        allowed.discard(domain)

    client["custom_blocked_domains"] = sorted(blocked)
    client["custom_allowed_domains"] = sorted(allowed)
    client_name = client.get("name") or f"Device {device_ip}"
    await netprotection_service.update_client(client_name, client)
    _record_netprotection_event(
        action_id="netprotection.devices.rule.delete",
        title="Remove device rule",
        subtitle=f"Guard Security · {device_ip}",
        status="success",
        message=f"Removed {payload.type} rule for {domain}",
        started_at=started_at,
    )
    return {"success": True, "ip": device_ip, "type": payload.type, "domain": domain}


@router.get("/threats")
async def get_threats_compat(_admin: User = Depends(require_admin)):
    """Get active threat detections in the Guard Security shape."""
    try:
        threats = await threat_service.get_threats(limit=100)
        formatted = []
        for index, threat in enumerate(threats):
            formatted.append(
                {
                    "id": str(index),
                    "ip": threat["ip"],
                    "type": threat["type"],
                    "severity": threat["severity"],
                    "level": threat["severity"],
                    "description": threat["description"],
                    "count": threat["count"],
                    "attempts": threat["count"],
                    "first_seen": threat["first_seen"],
                    "firstSeen": threat["first_seen"],
                    "last_seen": threat["last_seen"],
                    "lastSeen": threat["last_seen"],
                    "blocked": threat["blocked"],
                    "autoBlocked": threat["blocked"],
                    "country": "Unknown",
                }
            )
        return formatted
    except Exception as e:
        logger.error("Error getting threats: %s", e)
        return []


@router.post("/threats/clear")
async def clear_threats_compat(_admin: User = Depends(require_admin)):
    """Clear all non-banned threat records (the 'attack log'). Bans are kept."""
    started_at = datetime.now(timezone.utc).isoformat()
    cleared = await threat_service.clear_threats()
    _record_netprotection_event(
        action_id="netprotection.threats.clear",
        title="Clear threat log",
        subtitle="Guard Security · Security monitor",
        status="success",
        message=f"Cleared {cleared} threat record(s)",
        started_at=started_at,
    )
    return {"success": True, "cleared": cleared}


@router.post("/threat/ban")
async def ban_ip_compat(
    data: ThreatBanRequest,
    _admin: User = Depends(require_admin),
):
    """Ban a threat IP and mark it blocked."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        ip = data.ip.strip()
        if not ip or len(ip) < 7:
            _record_netprotection_event(
                action_id="netprotection.threat.ban",
                title="Ban threat IP",
                subtitle="Guard Security · Security monitor",
                status="failed",
                message=f"Invalid IP address: {ip}",
                started_at=started_at,
            )
            raise HTTPException(status_code=400, detail=f"Invalid IP address: {ip}")
        if _is_private_ip(ip):
            _record_netprotection_event(
                action_id="netprotection.threat.ban",
                title="Ban threat IP",
                subtitle=f"Guard Security · {ip}",
                status="failed",
                message=f"Cannot ban private/local IP address: {ip}",
                started_at=started_at,
            )
            raise HTTPException(
                status_code=400,
                detail=f"Cannot ban private/local IP address: {ip}. This protects you from locking yourself out.",
            )

        await firewall_service.block_ip(
            ip, duration=data.duration if not data.permanent else None
        )
        await threat_service.mark_blocked(ip, threat_type=data.type, reason=data.reason)
        _record_netprotection_event(
            action_id="netprotection.threat.ban",
            title="Ban threat IP",
            subtitle=f"Guard Security · {ip}",
            status="success",
            message=f"IP {ip} banned for {data.type or 'all threats'}",
            started_at=started_at,
        )
        return {
            "success": True,
            "message": f"IP {ip} banned for {data.type or 'all threats'}",
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error banning IP: %s", e)
        _record_netprotection_event(
            action_id="netprotection.threat.ban",
            title="Ban threat IP",
            subtitle=f"Guard Security · {getattr(data, 'ip', '') or 'Security monitor'}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat/unban")
async def unban_ip_compat(
    data: ThreatUnbanRequest,
    _admin: User = Depends(require_admin),
):
    """Unban a threat IP and mark it unblocked."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        ip = data.ip.strip()
        await firewall_service.unblock_ip(ip)
        await threat_service.mark_unblocked(ip, threat_type=data.type)
        _record_netprotection_event(
            action_id="netprotection.threat.unban",
            title="Unban threat IP",
            subtitle=f"Guard Security · {ip}",
            status="success",
            message=f"IP {ip} unbanned",
            started_at=started_at,
        )
        return {"success": True, "message": f"IP {ip} unbanned"}
    except Exception as e:
        logger.error("Error unbanning IP: %s", e)
        _record_netprotection_event(
            action_id="netprotection.threat.unban",
            title="Unban threat IP",
            subtitle=f"Guard Security · {getattr(data, 'ip', '') or 'Security monitor'}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/banned-ips")
async def get_banned_ips_compat(_admin: User = Depends(require_admin)):
    """Get currently banned IPs."""
    try:
        return await threat_service.get_banned_threats()
    except Exception as e:
        logger.error("Error getting banned IPs: %s", e)
        return []


__all__ = [
    "_managed_client_for_device",
    "add_device_rule_compat",
    "ban_ip_compat",
    "clear_threats_compat",
    "get_banned_ips_compat",
    "get_device_rules_compat",
    "get_threats_compat",
    "remove_device_rule_compat",
    "unban_ip_compat",
]
