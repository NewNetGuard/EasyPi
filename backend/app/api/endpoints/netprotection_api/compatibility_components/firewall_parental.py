"""NetProtection firewall parental compatibility routes."""

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


def _is_private_ip(ip: str) -> bool:
    """Never ban local or private addresses from the UI."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_parental_client(client: dict[str, Any]) -> bool:
    """Return whether a managed device was explicitly added to Parental Controls."""
    marker = client.get("parental_managed")
    if isinstance(marker, bool):
        return marker

    # Migration for records written before parental membership had its own
    # field. Ordinary admission records only enable Safe Browsing, so that
    # default must not make every allowed LAN device appear in this section.
    return bool(
        client.get("parental_enabled")
        or client.get("safesearch_enabled")
        or client.get("blocked_services")
    )


def _parental_client_name(client: dict[str, Any]) -> str:
    """Return the Parental Controls label without changing device identity."""
    return str(client.get("parental_name") or client.get("name") or "").strip()


def _device_record_name(
    clients: list[dict[str, Any]], requested_name: str, normalized_mac: str
) -> str:
    """Choose an internal device name that cannot reserve a parental label."""
    used = {
        str(item.get("name") or "").strip()
        for item in clients
        if isinstance(item, dict)
    }
    if requested_name not in used:
        return requested_name

    suffix = normalized_mac.replace(":", "")[-6:] or "device"
    base = f"Device-{suffix}"
    candidate = base
    counter = 2
    while candidate in used:
        candidate = f"{base}-{counter}"
        counter += 1
    return candidate


def _format_firewall_rules(rules: list[dict]) -> list[dict]:
    formatted = []
    for rule in rules:
        is_ipv6 = rule.get("ipv6", False)
        port = str(rule.get("port", "any"))
        protocol = rule.get("protocol", "tcp")
        action = rule.get("target", "accept").upper()
        direction = rule.get("direction", "IN")
        interface = rule.get("interface", "")
        if direction == "FWD":
            name = "forward" + (f" via {interface}" if interface else "")
        else:
            name = f"{port}/{protocol}" + (f" on {interface}" if interface else "")
        if is_ipv6:
            name += " (IPv6)"
        formatted.append(
            {
                "id": str(rule.get("id", "")),
                "name": name,
                "action": action,
                "protocol": protocol,
                "port": port,
                "source": rule.get("source", "any"),
                "destination": rule.get("destination", "any"),
                "enabled": True,
                "priority": rule.get("id", 0),
                "createdAt": rule.get("created_at", datetime.now().isoformat()),
                "hits": int(rule.get("hits", 0) or 0),
                "ipv6": is_ipv6,
            }
        )
    return formatted


@router.get("/firewall/rules")
async def get_firewall_rules_compat(_admin: User = Depends(require_admin)):
    """Get firewall rules in the Guard Security shape."""
    try:
        rules = await firewall_service.get_rules()
        return _format_firewall_rules(rules)
    except Exception as e:
        logger.error("Error getting firewall rules: %s", e)
        return []


@router.post("/firewall/rule")
async def add_firewall_rule_compat(
    rule: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Add a simple firewall rule."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        action = str(rule.get("action", "allow")).lower()
        protocol = str(rule.get("protocol", "tcp"))
        port = str(rule.get("port", "any"))
        source = str(rule.get("source", "any"))
        result = await firewall_service.add_rule_simple(
            action=action,
            protocol=protocol,
            port=port,
            source=source,
        )
        _record_netprotection_event(
            action_id="netprotection.firewall.add-rule",
            title="Add Guard firewall rule",
            subtitle=f"Guard Security · Firewall {protocol.upper()}/{port}",
            status="success",
            message=result.get("message", "Firewall rule added"),
            started_at=started_at,
        )
        return {
            "success": True,
            "message": result.get("message", "Firewall rule added"),
        }
    except Exception as e:
        logger.error("Error adding firewall rule: %s", e)
        _record_netprotection_event(
            action_id="netprotection.firewall.add-rule",
            title="Add Guard firewall rule",
            subtitle=f"Guard Security · Firewall {str(rule.get('protocol', 'tcp')).upper()}/{str(rule.get('port', 'any'))}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/firewall/rule/{rule_id}")
async def delete_firewall_rule_compat(
    rule_id: str,
    _admin: User = Depends(require_admin),
):
    """Delete a firewall rule by id."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        # Delete by the rule's UFW number directly — unambiguous, and the UI always
        # refetches after each change so the number is current. (Reconstructing the
        # rule from parsed params could misfire on interface-bound / forward rules.)
        if not str(rule_id).isdigit():
            raise HTTPException(status_code=400, detail=f"Invalid rule id: {rule_id}")
        await firewall_service.delete_rule_simple(int(rule_id))
        refreshed = await firewall_service.get_rules()
        _record_netprotection_event(
            action_id="netprotection.firewall.delete-rule",
            title="Delete Guard firewall rule",
            subtitle=f"Guard Security · Firewall rule #{rule_id}",
            status="success",
            message="Rule deleted",
            started_at=started_at,
        )
        return {
            "success": True,
            "message": "Rule deleted",
            "rules": _format_firewall_rules(refreshed),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error deleting firewall rule: %s", e)
        _record_netprotection_event(
            action_id="netprotection.firewall.delete-rule",
            title="Delete Guard firewall rule",
            subtitle=f"Guard Security · Firewall rule #{rule_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))
    _record_netprotection_event(
        action_id="netprotection.firewall.delete-rule",
        title="Delete Guard firewall rule",
        subtitle=f"Guard Security · Firewall rule #{rule_id}",
        status="success",
        message="Rule deleted",
        started_at=started_at,
    )


@router.post("/firewall/toggle")
async def toggle_firewall_compat(
    request: FirewallToggleRequest,
    _admin: User = Depends(require_admin),
):
    """Enable or disable the firewall."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await firewall_service.toggle_firewall(request.enabled)
        _record_netprotection_event(
            action_id="netprotection.firewall.toggle",
            title="Toggle Guard firewall",
            subtitle="Guard Security · Firewall",
            status="success",
            message=result.get("message", "Firewall updated"),
            started_at=started_at,
        )
        return {"success": True, "message": result.get("message", "")}
    except Exception as e:
        logger.error("Error toggling firewall: %s", e)
        _record_netprotection_event(
            action_id="netprotection.firewall.toggle",
            title="Toggle Guard firewall",
            subtitle="Guard Security · Firewall",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/parental/status")
async def get_parental_status_compat(_admin: User = Depends(require_admin)):
    """Return parental and safe-search state from the current config."""
    try:
        config = await netprotection_service.get_config()
        return {
            "parental_enabled": bool(config.get("parental_control", False)),
            "safesearch_enabled": bool(config.get("safe_search", False)),
        }
    except Exception as e:
        logger.error("Error getting parental status: %s", e)
        return {"parental_enabled": False, "safesearch_enabled": False}


@router.post("/parental/toggle")
async def toggle_parental_compat(
    data: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Enable or disable parental mode."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        enabled = bool(data.get("enabled", False))
        await netprotection_service.update_config({"parental_control": enabled})
        _record_netprotection_event(
            action_id="netprotection.parental.toggle",
            title="Toggle parental controls",
            subtitle="Guard Security · Parental controls",
            status="success",
            message="Parental controls enabled"
            if enabled
            else "Parental controls disabled",
            started_at=started_at,
        )
        return {"success": True, "enabled": enabled}
    except Exception as e:
        logger.error("Error toggling parental control: %s", e)
        _record_netprotection_event(
            action_id="netprotection.parental.toggle",
            title="Toggle parental controls",
            subtitle="Guard Security · Parental controls",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/parental/safesearch")
async def toggle_safesearch_compat(
    data: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Enable or disable safe search."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        enabled = bool(data.get("enabled", False))
        await netprotection_service.update_config({"safe_search": enabled})
        _record_netprotection_event(
            action_id="netprotection.parental.safesearch",
            title="Toggle safe search",
            subtitle="Guard Security · Parental controls",
            status="success",
            message="Safe search enabled" if enabled else "Safe search disabled",
            started_at=started_at,
        )
        return {"success": True, "enabled": enabled}
    except Exception as e:
        logger.error("Error toggling safe search: %s", e)
        _record_netprotection_event(
            action_id="netprotection.parental.safesearch",
            title="Toggle safe search",
            subtitle="Guard Security · Parental controls",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/parental/clients")
async def get_parental_clients_compat(
    include_all: bool = False,
    _admin: User = Depends(require_admin),
):
    """Get parental clients, or all managed clients for device inventory."""
    try:
        await netprotection_service.process_fail_closed_requests()
        result = await netprotection_service.get_clients()
        clients = result.get("clients", [])
        fail_closed_ips = set(await netprotection_service.list_fail_closed_clients())

        bindings_by_profile: dict[str, list[dict]] = {}
        try:
            bindings_path = netprotection_service.data_dir / "bindings.json"
            if bindings_path.exists():
                bindings_payload = json.loads(
                    bindings_path.read_text(encoding="utf-8", errors="ignore")
                )
                for binding in bindings_payload.get("bindings", []) or []:
                    if not isinstance(binding, dict):
                        continue
                    profile_id = str(binding.get("profile_id") or "").strip()
                    if not profile_id:
                        continue
                    bindings_by_profile.setdefault(profile_id, []).append(binding)
        except Exception:
            bindings_by_profile = {}

        formatted = []
        for client in clients:
            parental_managed = _is_parental_client(client)
            if not include_all and not parental_managed:
                continue
            client_ids = client.get("ids", []) or []
            if not isinstance(client_ids, list):
                client_ids = []
            client_ip = client_ids[0] if client_ids else (client.get("ip", "") or "")
            blocked_services = [
                item
                for item in (client.get("blocked_services", []) or [])
                if isinstance(item, str)
            ]
            uses_parental_shortcut = PORNOGRAPHY_PARENTAL_SHORTCUT in blocked_services
            effective_parental_enabled = bool(
                client.get("parental_enabled", False) or uses_parental_shortcut
            )
            blocked_services = [
                item
                for item in blocked_services
                if item != PORNOGRAPHY_PARENTAL_SHORTCUT
            ]
            custom_domains = client.get("custom_blocked_domains", []) or []
            client_id = str(client.get("id") or client.get("name", ""))
            client_mac = sanitize_mac(client.get("mac"))

            all_blocked = blocked_services + custom_domains
            if effective_parental_enabled:
                all_blocked = [item for item in all_blocked if item != "adult"]
                if PORNOGRAPHY_PARENTAL_SHORTCUT not in all_blocked:
                    all_blocked.insert(0, PORNOGRAPHY_PARENTAL_SHORTCUT)
            all_blocked = list(dict.fromkeys(all_blocked))

            dns_last_seen = None
            dns_query_count = None
            dns_blocked_count = None
            try:
                profile_id = f"parental_device_{client_id}" if client_id else ""
                candidates = (
                    bindings_by_profile.get(profile_id, []) if profile_id else []
                )
                best = None
                best_dt = None
                for binding in candidates:
                    binding_type = (
                        str(binding.get("binding_type") or "").lower().strip()
                    )
                    binding_value = str(binding.get("value") or "").strip()
                    if (
                        binding_type == "ip"
                        and client_ip
                        and binding_value != client_ip
                    ):
                        continue
                    if (
                        binding_type == "mac"
                        and client_mac
                        and binding_value != client_mac
                    ):
                        continue
                    raw_seen = binding.get("last_seen")
                    if not raw_seen:
                        continue
                    try:
                        binding_dt = datetime.fromisoformat(str(raw_seen))
                    except Exception:
                        binding_dt = None
                    if binding_dt is None:
                        continue
                    if best_dt is None or binding_dt > best_dt:
                        best_dt = binding_dt
                        best = binding
                if best is not None:
                    dns_last_seen = best.get("last_seen")
                    dns_query_count = best.get("query_count")
                    dns_blocked_count = best.get("blocked_count")
            except Exception:
                pass

            formatted.append(
                {
                    "id": client_id,
                    "name": _parental_client_name(client),
                    "record_name": client.get("name", ""),
                    "ids": client_ids
                    if client_ids
                    else ([client_ip] if client_ip else []),
                    "ip": client_ip,
                    "mac": client_mac or None,
                    "parental_managed": parental_managed,
                    "parental_enabled": effective_parental_enabled,
                    "safesearch_enabled": client.get("safesearch_enabled", False),
                    "safebrowsing_enabled": client.get("safebrowsing_enabled", False),
                    "filtering_enabled": client.get("filtering_enabled", True),
                    "shield_profile": client.get("shield_profile"),
                    "blocked_services": all_blocked,
                    "use_global_settings": client.get("use_global_settings", True),
                    "fail_closed": bool(client_ip and client_ip in fail_closed_ips),
                    "dns_last_seen": dns_last_seen,
                    "dns_query_count": dns_query_count,
                    "dns_blocked_count": dns_blocked_count,
                }
            )
        return formatted
    except Exception as e:
        logger.error("Error getting parental clients: %s", e)
        return []


@router.get("/parental/whatsapp-block-mode")
async def get_whatsapp_block_mode_compat(_admin: User = Depends(require_admin)):
    """Get the global WhatsApp blocking mode."""
    try:
        result = await netprotection_service.get_whatsapp_block_mode()
        mode = str(result.get("mode") or "balanced").strip().lower()
        if mode not in {"balanced", "aggressive"}:
            mode = "balanced"
        return {"success": bool(result.get("success", True)), "mode": mode}
    except Exception as e:
        logger.error("Error getting WhatsApp block mode: %s", e)
        raise HTTPException(status_code=500, detail="Failed to get WhatsApp block mode")


@router.put("/parental/whatsapp-block-mode")
async def set_whatsapp_block_mode_compat(
    payload: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Set the global WhatsApp blocking mode."""
    started_at = datetime.now(timezone.utc).isoformat()
    mode = str(payload.get("mode") or "").strip().lower()
    if mode not in {"balanced", "aggressive"}:
        _record_netprotection_event(
            action_id="netprotection.parental.whatsapp-mode",
            title="Set WhatsApp block mode",
            subtitle="Guard Security · Parental controls",
            status="failed",
            message="Invalid mode",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail="Invalid mode")
    result = await netprotection_service.set_whatsapp_block_mode(mode)
    if not result.get("success"):
        _record_netprotection_event(
            action_id="netprotection.parental.whatsapp-mode",
            title="Set WhatsApp block mode",
            subtitle="Guard Security · Parental controls",
            status="failed",
            message=result.get("error") or "Failed to set WhatsApp block mode",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500,
            detail=result.get("error") or "Failed to set WhatsApp block mode",
        )
    _record_netprotection_event(
        action_id="netprotection.parental.whatsapp-mode",
        title="Set WhatsApp block mode",
        subtitle="Guard Security · Parental controls",
        status="success",
        message=f"WhatsApp blocking mode set to {mode}",
        started_at=started_at,
    )
    return {"success": True, "mode": mode}


@router.post("/parental/client")
async def add_parental_client_compat(
    client: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Add a new or already-managed device to Parental Controls."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        payload = dict(client or {})
        payload["parental_managed"] = True
        requested_name = str(payload.get("name") or "").strip()
        if not requested_name:
            raise ValueError("Device name is required")
        normalized_mac = sanitize_mac(payload.get("mac"))
        clients_result = await netprotection_service.get_clients()
        clients = [
            item
            for item in clients_result.get("clients", [])
            if isinstance(item, dict)
        ]
        if any(
            _is_parental_client(item)
            and _parental_client_name(item) == requested_name
            and sanitize_mac(item.get("mac")) != normalized_mac
            for item in clients
        ):
            raise ValueError(f"Parental device '{requested_name}' already exists")
        existing = next(
            (
                item
                for item in clients
                if normalized_mac
                and sanitize_mac(item.get("mac")) == normalized_mac
            ),
            None,
        )
        if existing is not None:
            merged = dict(existing)
            payload.pop("name", None)
            merged.update(payload)
            merged["parental_name"] = requested_name
            result = await netprotection_service.update_parental_client_transactional(
                str(existing.get("name") or ""), merged
            )
        else:
            payload["name"] = _device_record_name(
                clients, requested_name, normalized_mac
            )
            payload["parental_name"] = requested_name
            result = await netprotection_service.add_parental_client_transactional(
                payload
            )
        _record_netprotection_event(
            action_id="netprotection.parental.client.create",
            title="Create managed client",
            subtitle=f"Guard Security · {client.get('name') or client.get('client_name') or 'Managed client'}",
            status="success" if result.get("success", True) else "failed",
            message=result.get(
                "message",
                f"Managed client created: {client.get('name') or client.get('client_name') or 'client'}",
            ),
            started_at=started_at,
        )
        return result
    except Exception as e:
        logger.error("Error adding client: %s", e)
        _record_netprotection_event(
            action_id="netprotection.parental.client.create",
            title="Create managed client",
            subtitle=f"Guard Security · {client.get('name') or client.get('client_name') or 'Managed client'}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/parental/client/{client_name}")
async def update_parental_client_compat(
    client_name: str,
    client: dict = Body(...),
    _admin: User = Depends(require_admin),
):
    """Update a managed client."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        payload = dict(client or {})
        payload["parental_managed"] = True
        clients_result = await netprotection_service.get_clients()
        existing = next(
            (
                item
                for item in clients_result.get("clients", [])
                if isinstance(item, dict)
                and (
                    item.get("name") == client_name
                    or _parental_client_name(item) == client_name
                )
            ),
            None,
        )
        if existing is not None:
            merged = dict(existing)
            requested_name = str(payload.pop("name", None) or client_name).strip()
            merged.update(payload)
            merged["parental_name"] = requested_name
            payload = merged
        result = await netprotection_service.update_parental_client_transactional(
            str(existing.get("name") or client_name) if existing else client_name,
            payload,
        )
        _record_netprotection_event(
            action_id="netprotection.parental.client.update",
            title="Update managed client",
            subtitle=f"Guard Security · {client_name}",
            status="success" if result.get("success", True) else "failed",
            message=result.get("message", f"Managed client updated: {client_name}"),
            started_at=started_at,
        )
        return result
    except Exception as e:
        logger.error("Error updating client %s: %s", client_name, e)
        _record_netprotection_event(
            action_id="netprotection.parental.client.update",
            title="Update managed client",
            subtitle=f"Guard Security · {client_name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/parental/client/{client_name}")
async def delete_parental_client_compat(
    client_name: str,
    _admin: User = Depends(require_admin),
):
    """Remove parental settings without deleting the admitted device identity."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        clients_result = await netprotection_service.get_clients()
        existing = next(
            (
                item
                for item in clients_result.get("clients", [])
                if isinstance(item, dict)
                and (
                    item.get("name") == client_name
                    or _parental_client_name(item) == client_name
                )
            ),
            None,
        )
        if existing is None:
            raise ValueError(f"Client '{client_name}' not found")
        payload = dict(existing)
        payload.pop("parental_name", None)
        payload.update(
            {
                "parental_managed": False,
                "parental_enabled": False,
                "safesearch_enabled": False,
                "blocked_services": [],
            }
        )
        if str(payload.get("shield_profile") or "").lower() == "kids":
            payload["shield_profile"] = "balanced"
        result = await netprotection_service.update_parental_client_transactional(
            str(existing.get("name") or client_name), payload
        )
        _record_netprotection_event(
            action_id="netprotection.parental.client.delete",
            title="Remove device from parental controls",
            subtitle=f"Guard Security · {client_name}",
            status="success" if result.get("success", True) else "failed",
            message=result.get(
                "message", f"Parental controls removed: {client_name}"
            ),
            started_at=started_at,
        )
        return result
    except Exception as e:
        logger.error("Error deleting client %s: %s", client_name, e)
        _record_netprotection_event(
            action_id="netprotection.parental.client.delete",
            title="Delete managed client",
            subtitle=f"Guard Security · {client_name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/parental/client/{client_name}/restore-internet")
async def restore_parental_client_internet_compat(
    client_name: str,
    _admin: User = Depends(require_admin),
):
    """Restore internet for a client by name."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        clients_result = await netprotection_service.get_clients()
        client_ip = ""
        for client in clients_result.get("clients", []):
            if client.get("name") != client_name:
                continue
            ids = client.get("ids", []) or []
            if isinstance(ids, list) and ids:
                client_ip = str(ids[0] or "").strip()
            if not client_ip:
                client_ip = str(client.get("ip") or "").strip()
            break

        if not client_ip:
            raise HTTPException(
                status_code=404, detail=f"Client '{client_name}' not found"
            )
        if not validate_ip(client_ip):
            raise HTTPException(
                status_code=400, detail=f"Client '{client_name}' has invalid IP"
            )

        result = await netprotection_service.unquarantine_client(client_ip)
        if not result.get("success"):
            raise HTTPException(
                status_code=500,
                detail=result.get("error") or "Failed to restore internet",
            )

        response = {
            "success": True,
            "name": client_name,
            "ip": client_ip,
            "message": result.get("message", "Internet access restored"),
        }
        _record_netprotection_event(
            action_id="netprotection.parental.client.restore-internet",
            title="Restore client internet",
            subtitle=f"Guard Security · {client_name}",
            status="success",
            message=response["message"],
            started_at=started_at,
        )
        return response
    except HTTPException:
        _record_netprotection_event(
            action_id="netprotection.parental.client.restore-internet",
            title="Restore client internet",
            subtitle=f"Guard Security · {client_name}",
            status="failed",
            message="Failed to restore client internet",
            started_at=started_at,
        )
        raise
    except Exception as e:
        logger.error("Error restoring internet for %s: %s", client_name, e)
        _record_netprotection_event(
            action_id="netprotection.parental.client.restore-internet",
            title="Restore client internet",
            subtitle=f"Guard Security · {client_name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/parental/blocked-services")
async def get_blocked_services_list_compat(_admin: User = Depends(require_admin)):
    """Get blockable services for the parental UI."""
    return await netprotection_service.get_blocked_services_list()


__all__ = [
    "_format_firewall_rules",
    "_is_private_ip",
    "add_firewall_rule_compat",
    "add_parental_client_compat",
    "delete_firewall_rule_compat",
    "delete_parental_client_compat",
    "get_blocked_services_list_compat",
    "get_firewall_rules_compat",
    "get_parental_clients_compat",
    "get_parental_status_compat",
    "get_whatsapp_block_mode_compat",
    "restore_parental_client_internet_compat",
    "set_whatsapp_block_mode_compat",
    "toggle_firewall_compat",
    "toggle_parental_compat",
    "toggle_safesearch_compat",
    "update_parental_client_compat",
]
