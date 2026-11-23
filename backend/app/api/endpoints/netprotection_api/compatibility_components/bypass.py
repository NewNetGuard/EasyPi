"""NetProtection bypass compatibility routes."""

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


@router.get("/parental/fail-closed")
async def get_fail_closed_status_compat(_admin: User = Depends(require_admin)):
    """Get active fail-closed devices for the Guard Security UI."""
    try:
        active_ips = set(await netprotection_service.list_fail_closed_clients())
        if not active_ips:
            return {"count": 0, "devices": []}

        meta_by_ip = netprotection_service.get_fail_closed_triggers()
        ip_to_client: dict[str, dict[str, str]] = {}
        try:
            clients_result = await netprotection_service.get_clients()
            for client in clients_result.get("clients", []) or []:
                if not isinstance(client, dict):
                    continue
                name = str(client.get("name") or "").strip()
                client_id = (
                    str(client.get("id") or client.get("name") or "").strip() or None
                )
                ids = client.get("ids") or []
                if isinstance(ids, list):
                    for raw in ids:
                        ip = str(raw or "").strip()
                        if validate_ip(ip):
                            ip_to_client.setdefault(
                                ip, {"name": name, "id": client_id or ""}
                            )
                ip = str(client.get("ip") or "").strip()
                if validate_ip(ip):
                    ip_to_client.setdefault(ip, {"name": name, "id": client_id or ""})
        except Exception:
            ip_to_client = {}

        def group_label(groups: list[str], tor_bridge: bool = False) -> str:
            if tor_bridge:
                return "Tor Bridges"
            labels = {
                "doh": "Encrypted DNS (DoH/DoT)",
                "vpn": "VPN",
                "proxy": "Proxy",
                "tor": "Tor",
                "smartdns": "Smart DNS",
            }
            parts = [labels.get(group, group) for group in groups if group]
            return " / ".join(parts) if parts else "Bypass"

        devices = []
        for ip in sorted(active_ips):
            client_info = ip_to_client.get(ip) or {}
            entry = meta_by_ip.get(ip) if isinstance(meta_by_ip, dict) else None
            entry = entry if isinstance(entry, dict) else {}
            groups = (
                entry.get("groups") if isinstance(entry.get("groups"), list) else []
            )
            domain = entry.get("domain")
            tor_bridge = bool(entry.get("tor_bridge"))
            if not tor_bridge and domain:
                tor_bridge = netprotection_service._is_tor_bridge_domain(domain)
            devices.append(
                {
                    "ip": ip,
                    "name": client_info.get("name") or ip,
                    "id": (client_info.get("id") or "").strip() or None,
                    "domain": domain,
                    "triggered_at": entry.get("triggered_at"),
                    "groups": groups,
                    "tor_bridge": tor_bridge,
                    "group_label": group_label(groups, tor_bridge),
                }
            )

        return {"count": len(devices), "devices": devices}
    except Exception as e:
        logger.error("Error getting fail-closed status: %s", e)
        return {"count": 0, "devices": []}


@router.post("/parental/fail-closed/{client_ip}/restore")
async def restore_fail_closed_ip_compat(
    client_ip: str,
    _admin: User = Depends(require_admin),
):
    """Restore internet for a quarantined client IP."""
    started_at = datetime.now(timezone.utc).isoformat()
    client_ip = str(client_ip or "").strip()
    if not netprotection_service._is_valid_ipv4(client_ip):
        _record_netprotection_event(
            action_id="netprotection.parental.fail-closed.restore",
            title="Restore quarantined client",
            subtitle=f"Guard Security · {client_ip or 'Parental controls'}",
            status="failed",
            message="Invalid IPv4 address",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")

    result = await netprotection_service.unquarantine_client(client_ip)
    if not result.get("success"):
        _record_netprotection_event(
            action_id="netprotection.parental.fail-closed.restore",
            title="Restore quarantined client",
            subtitle=f"Guard Security · {client_ip}",
            status="failed",
            message=result.get("error") or "Failed to restore internet",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500, detail=result.get("error") or "Failed to restore internet"
        )
    _record_netprotection_event(
        action_id="netprotection.parental.fail-closed.restore",
        title="Restore quarantined client",
        subtitle=f"Guard Security · {client_ip}",
        status="success",
        message=result.get("message", "Internet access restored"),
        started_at=started_at,
    )
    return {
        "success": True,
        "ip": client_ip,
        "message": result.get("message", "Internet access restored"),
    }


@router.get("/parental/bypass")
async def get_bypass_alerts_compat(_admin: User = Depends(require_admin)):
    """Get anti-bypass alerts and quarantine state for the Guard Security UI."""
    try:
        await netprotection_service.process_bypass_events()

        bypass_meta_by_ip = netprotection_service.get_bypass_events()
        fail_closed_ips = set(await netprotection_service.list_fail_closed_clients())
        fail_closed_meta_by_ip = netprotection_service.get_fail_closed_triggers()

        ip_to_client: dict[str, dict[str, str]] = {}
        mac_to_client: dict[str, dict[str, str]] = {}
        try:
            clients_result = await netprotection_service.get_clients()
            for client in clients_result.get("clients", []) or []:
                if not isinstance(client, dict):
                    continue
                name = str(client.get("name") or "").strip()
                client_id = (
                    str(client.get("id") or client.get("name") or "").strip() or None
                )
                bypass_mode = str(client.get("bypass_mode") or "warn").strip().lower()
                mac = sanitize_mac(client.get("mac"))
                if mac:
                    mac_to_client.setdefault(
                        mac,
                        {
                            "name": name,
                            "id": client_id or "",
                            "bypass_mode": bypass_mode,
                        },
                    )
                ids = client.get("ids") or []
                if isinstance(ids, list):
                    for raw in ids:
                        ip = str(raw or "").strip()
                        if validate_ip(ip):
                            ip_to_client.setdefault(
                                ip,
                                {
                                    "name": name,
                                    "id": client_id or "",
                                    "bypass_mode": bypass_mode,
                                },
                            )
                ip = str(client.get("ip") or "").strip()
                if validate_ip(ip):
                    ip_to_client.setdefault(
                        ip,
                        {
                            "name": name,
                            "id": client_id or "",
                            "bypass_mode": bypass_mode,
                        },
                    )
        except Exception:
            ip_to_client = {}
            mac_to_client = {}

        def group_label(groups: list[str], tor_bridge: bool = False) -> str:
            if tor_bridge:
                return "Tor Bridges"
            labels = {
                "doh": "Encrypted DNS (DoH/DoT)",
                "vpn": "VPN",
                "proxy": "Proxy",
                "tor": "Tor",
                "smartdns": "Smart DNS",
            }
            parts = [labels.get(group, group) for group in groups if group]
            return " / ".join(parts) if parts else "Bypass"

        alert_ips: set[str] = set()
        alert_groups_by_ip: dict[str, list[str]] = {}
        now_ts = time.time()
        for ip, entry in (bypass_meta_by_ip or {}).items():
            if not validate_ip(ip) or not isinstance(entry, dict):
                continue
            if not bool(entry.get("leak", False)):
                continue
            if entry.get("policy_enforced") is not True:
                continue
            raw_groups = (
                entry.get("groups") if isinstance(entry.get("groups"), list) else []
            )
            policy_groups = netprotection_service._policy_relevant_bypass_groups(
                ip, raw_groups
            )
            if not policy_groups:
                continue
            ts = entry.get("ts")
            if ts is None:
                continue
            try:
                ts_val = float(ts)
            except Exception:
                continue
            # Stale leak: the device isn't actively bypassing anymore (offline or
            # stopped) and nothing refreshed the event within the TTL — don't nag.
            if (now_ts - ts_val) > BYPASS_ALERT_TTL_SEC:
                continue
            ack_ts = entry.get("ack_ts")
            try:
                ack_val = float(ack_ts) if ack_ts is not None else None
            except Exception:
                ack_val = None
            if ack_val is not None and ts_val <= ack_val:
                continue
            alert_ips.add(ip)
            alert_groups_by_ip[ip] = policy_groups

        ips = sorted(alert_ips | fail_closed_ips)
        devices = []
        for ip in ips:
            client_info = ip_to_client.get(ip) or {}
            if not client_info and mac_to_client:
                try:
                    mac = netprotection_service._resolve_mac_from_arp(ip)
                except Exception:
                    mac = ""
                if mac:
                    client_info = mac_to_client.get(mac) or {}
            bypass_mode = str(client_info.get("bypass_mode") or "warn").strip().lower()
            quarantine = ip in fail_closed_ips

            entry = None
            if ip in alert_ips:
                entry = bypass_meta_by_ip.get(ip)
            if not isinstance(entry, dict):
                entry = (
                    fail_closed_meta_by_ip.get(ip)
                    if isinstance(fail_closed_meta_by_ip, dict)
                    else None
                )
            entry = entry if isinstance(entry, dict) else {}

            groups = alert_groups_by_ip.get(ip)
            if groups is None:
                groups = (
                    entry.get("groups") if isinstance(entry.get("groups"), list) else []
                )
            domain = entry.get("domain")
            tor_bridge = bool(entry.get("tor_bridge"))
            if not tor_bridge and domain:
                tor_bridge = netprotection_service._is_tor_bridge_domain(domain)
            source_hint = (
                entry.get("source_hint")
                if entry.get("source_hint")
                else netprotection_service._infer_bypass_source_hint(domain)
            )

            devices.append(
                {
                    "ip": ip,
                    "name": client_info.get("name") or ip,
                    "id": (client_info.get("id") or "").strip() or None,
                    "bypass_mode": bypass_mode,
                    "quarantine": quarantine,
                    "domain": domain,
                    "triggered_at": entry.get("triggered_at"),
                    "groups": groups,
                    "tor_bridge": tor_bridge,
                    "group_label": group_label(groups, tor_bridge),
                    "source_hint": source_hint,
                    "leak": bool(entry.get("leak", False)),
                    "has_alert": ip in alert_ips,
                }
            )

        return {"count": len(devices), "devices": devices}
    except Exception as e:
        logger.error("Error getting bypass alerts: %s", e)
        return {"count": 0, "devices": []}


@router.get("/parental/bypass-blocked")
async def get_bypass_blocked_compat(_admin: User = Depends(require_admin)):
    """Per-device counts of bypass attempts BLOCKED at the network layer.

    Reads the per-device firewall REJECT counters (DoH/DoT/VPN/proxy/Tor/SmartDNS)
    so the UI can show "N bypass attempts blocked" for each protected device. This
    is the force-block that stops encrypted-DNS/VPN bypass on the gateway.
    """
    try:
        counters = await netprotection_service._read_bypass_reject_counters()
        ip_to_name: dict[str, str] = {}
        try:
            clients_result = await netprotection_service.get_clients()
            for client in clients_result.get("clients", []) or []:
                if not isinstance(client, dict):
                    continue
                name = str(client.get("name") or "").strip()
                candidates = list(client.get("ids") or [])
                candidates.append(client.get("ip"))
                for raw in candidates:
                    ip = str(raw or "").strip()
                    if validate_ip(ip) and name:
                        ip_to_name.setdefault(ip, name)
        except Exception:
            ip_to_name = {}

        devices = []
        total_blocked = 0
        for ip, channels in (counters or {}).items():
            if not validate_ip(ip) or not isinstance(channels, dict):
                continue
            ch = {
                k: int(v)
                for k, v in channels.items()
                if isinstance(v, (int, float)) and int(v) > 0
            }
            dev_total = sum(ch.values())
            if dev_total <= 0:
                continue
            total_blocked += dev_total
            devices.append(
                {
                    "ip": ip,
                    "name": ip_to_name.get(ip) or ip,
                    "total": dev_total,
                    "channels": ch,
                }
            )
        devices.sort(key=lambda d: d.get("total", 0), reverse=True)
        return {
            "count": len(devices),
            "total_blocked": total_blocked,
            "devices": devices,
        }
    except Exception as e:
        logger.error("Error getting bypass-blocked: %s", e)
        return {"count": 0, "total_blocked": 0, "devices": []}


@router.get("/parental/bypass-history")
async def get_bypass_history_compat(_admin: User = Depends(require_admin)):
    """Persistent per-device history of bypass attempts (DoH/DoT/VPN/proxy/Tor/…).

    Unlike the live firewall counters, this accumulates over time and survives
    reboots — so a parent can see who has been trying to escape filtering, on which
    channels, and when (first/last seen).
    """
    try:
        history = netprotection_service.get_bypass_history() or {}
        ip_to_name: dict[str, str] = {}
        try:
            clients_result = await netprotection_service.get_clients()
            for client in clients_result.get("clients", []) or []:
                if not isinstance(client, dict):
                    continue
                name = str(client.get("name") or "").strip()
                candidates = list(client.get("ids") or [])
                candidates.append(client.get("ip"))
                for raw in candidates:
                    ip = str(raw or "").strip()
                    if validate_ip(ip) and name:
                        ip_to_name.setdefault(ip, name)
        except Exception:
            ip_to_name = {}

        devices = []
        total_all = 0
        for ip, h in history.items():
            if not validate_ip(ip) or not isinstance(h, dict):
                continue
            channels = {
                k: int(v)
                for k, v in (h.get("channels") or {}).items()
                if isinstance(v, (int, float)) and int(v) > 0
            }
            total = int(h.get("total", 0) or 0)
            if total <= 0:
                continue
            total_all += total
            devices.append(
                {
                    "ip": ip,
                    "name": ip_to_name.get(ip) or ip,
                    "total": total,
                    "channels": channels,
                    "first_seen": h.get("first_seen"),
                    "last_seen": h.get("last_seen"),
                    "last_domain": h.get("last_domain"),
                }
            )
        devices.sort(key=lambda d: str(d.get("last_seen") or ""), reverse=True)
        return {"count": len(devices), "total_all": total_all, "devices": devices}
    except Exception as e:
        logger.error("Error getting bypass-history: %s", e)
        return {"count": 0, "total_all": 0, "devices": []}


@router.post("/parental/bypass-history/clear")
async def clear_bypass_history_compat(_admin: User = Depends(require_admin)):
    """Reset the accumulated bypass history (does not touch live alerts)."""
    try:
        netprotection_service.clear_bypass_history()
        return {"success": True}
    except Exception as e:
        logger.error("Error clearing bypass-history: %s", e)
        raise HTTPException(status_code=500, detail="Failed to clear bypass history")


@router.post("/parental/bypass/{client_ip}/mode")
async def set_bypass_mode_compat(
    client_ip: str,
    payload: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Set anti-bypass mode for a client IP."""
    started_at = datetime.now(timezone.utc).isoformat()
    client_ip = str(client_ip or "").strip()
    if not netprotection_service._is_valid_ipv4(client_ip):
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.mode",
            title="Set bypass mode",
            subtitle=f"Guard Security · {client_ip or 'Parental controls'}",
            status="failed",
            message="Invalid IPv4 address",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")

    mode = str(payload.get("mode") or "").strip().lower()
    if mode not in {"warn", "quarantine", "log_only"}:
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.mode",
            title="Set bypass mode",
            subtitle=f"Guard Security · {client_ip}",
            status="failed",
            message="Invalid mode",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid mode")

    quarantine_now = bool(payload.get("quarantine_now", False))

    try:
        result = await netprotection_service.set_bypass_mode_by_ip(client_ip, mode)
    except ValueError as e:
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.mode",
            title="Set bypass mode",
            subtitle=f"Guard Security · {client_ip}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error("Error setting bypass mode for %s: %s", client_ip, e)
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.mode",
            title="Set bypass mode",
            subtitle=f"Guard Security · {client_ip}",
            status="failed",
            message="Failed to update bypass mode",
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail="Failed to update bypass mode")

    try:
        netprotection_service.acknowledge_bypass_event(client_ip)
    except Exception as exc:
        logger.warning(
            "Bypass mode changed for %s but alert acknowledgement failed: %s",
            client_ip,
            exc,
        )

    applied_quarantine = False
    if mode == "quarantine" and quarantine_now:
        quarantine_result = await netprotection_service.quarantine_client(client_ip)
        applied_quarantine = bool(quarantine_result.get("success"))

    response = {
        "success": True,
        "ip": client_ip,
        "mode": mode,
        "quarantine_now": applied_quarantine,
    }
    if isinstance(result, dict):
        if result.get("sync") is not None:
            response["sync"] = result.get("sync")
        if result.get("ip_blocking") is not None:
            response["ip_blocking"] = result.get("ip_blocking")
    _record_netprotection_event(
        action_id="netprotection.parental.bypass.mode",
        title="Set bypass mode",
        subtitle=f"Guard Security · {client_ip}",
        status="success",
        message=f"Bypass mode set to {mode}"
        + (" with immediate quarantine" if applied_quarantine else ""),
        started_at=started_at,
    )
    return response


@router.post("/parental/bypass/{client_ip}/ack")
async def acknowledge_bypass_alert_compat(
    client_ip: str,
    _admin: User = Depends(require_admin),
):
    """Acknowledge the current bypass alert for an IP."""
    started_at = datetime.now(timezone.utc).isoformat()
    client_ip = str(client_ip or "").strip()
    if not netprotection_service._is_valid_ipv4(client_ip):
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.ack",
            title="Acknowledge bypass alert",
            subtitle=f"Guard Security · {client_ip or 'Parental controls'}",
            status="failed",
            message="Invalid IPv4 address",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")

    ok = netprotection_service.acknowledge_bypass_event(client_ip)
    if not ok:
        _record_netprotection_event(
            action_id="netprotection.parental.bypass.ack",
            title="Acknowledge bypass alert",
            subtitle=f"Guard Security · {client_ip}",
            status="failed",
            message="Failed to acknowledge bypass alert",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500, detail="Failed to acknowledge bypass alert"
        )
    _record_netprotection_event(
        action_id="netprotection.parental.bypass.ack",
        title="Acknowledge bypass alert",
        subtitle=f"Guard Security · {client_ip}",
        status="success",
        message="Bypass alert acknowledged",
        started_at=started_at,
    )
    return {"success": True, "ip": client_ip}


__all__ = [
    "acknowledge_bypass_alert_compat",
    "clear_bypass_history_compat",
    "get_bypass_alerts_compat",
    "get_bypass_blocked_compat",
    "get_bypass_history_compat",
    "get_fail_closed_status_compat",
    "restore_fail_closed_ip_compat",
    "set_bypass_mode_compat",
]
