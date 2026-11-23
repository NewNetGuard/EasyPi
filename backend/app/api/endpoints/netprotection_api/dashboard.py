"""NetProtection dashboard routes."""

from .context import (
    APIRouter,
    HTTPException,
    Query,
    Depends,
    Body,
    Any,
    Dict,
    List,
    Optional,
    re,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    require_admin,
    User,
    netprotection_service,
    logger,
)
from typing import Literal

router = APIRouter()

# ============ Dashboard & Statistics ============


@router.get("/dashboard")
async def get_dashboard(_admin: User = Depends(require_admin)):
    """Get dashboard overview."""
    try:
        await netprotection_service.get_status()
        stats = await netprotection_service.get_dashboard_stats()
        config = await netprotection_service.get_config()

        # Get top blocked from verdicts (today only)
        verdicts = await netprotection_service.get_verdicts(
            limit=1000, verdict_type="deny", today_only=True
        )

        # Count top blocked domains
        domain_counts = {}
        for v in verdicts.get("data", []):
            domain = v.get("domain", "")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

        top_blocked = [
            {"domain": domain, "hits": count}
            for domain, count in sorted(
                domain_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
        ]

        return {
            "configured": True,
            "protectionStatus": {
                "enabled": config.get("protection_enabled", True),
                "disabledUntil": None,
            },
            "totalQueries": stats["total_queries"],
            "blockedToday": stats["blocked_today"],
            "blockPercentage": stats["block_percentage"],
            "activeBlocklists": stats["active_blocklists"],
            "blockedDomains": stats["blocked_domains"],
            "activeThreats": stats["active_threats"],
            "topBlocked": top_blocked,
            "cacheHitRate": stats.get("cache_hit_rate", 0),
            "avgResponseTime": stats.get("avg_response_time_ms", 0),
        }
    except Exception as e:
        logger.error(f"Error getting dashboard: {e}")
        return {
            "configured": False,
            "protectionStatus": {"enabled": False, "disabledUntil": None},
            "totalQueries": 0,
            "blockedToday": 0,
            "blockPercentage": 0,
            "activeBlocklists": 0,
            "blockedDomains": 0,
            "activeThreats": 0,
            "topBlocked": [],
        }


class TelegramAlertConfig(BaseModel):
    bot_token: Optional[str] = None
    chat_id: Optional[str] = None
    enabled: Optional[bool] = None


@router.get("/alerts/telegram")
async def get_telegram_alert_config(_admin: User = Depends(require_admin)):
    """Telegram alert channel status (token never returned)."""
    from app.services.telegram_alert_service import get_telegram_alerts

    return get_telegram_alerts().status()


@router.post("/alerts/telegram")
async def set_telegram_alert_config(
    body: TelegramAlertConfig, _admin: User = Depends(require_admin)
):
    """Configure the Telegram alert channel (bot token + chat id + enabled)."""
    from app.services.telegram_alert_service import get_telegram_alerts

    ta = get_telegram_alerts()
    ta.set_config(bot_token=body.bot_token, chat_id=body.chat_id, enabled=body.enabled)
    return {"success": True, **ta.status()}


@router.post("/alerts/telegram/test")
async def test_telegram_alert(_admin: User = Depends(require_admin)):
    """Send a test alert to the configured Telegram chat."""
    from app.services.telegram_alert_service import get_telegram_alerts

    ta = get_telegram_alerts()
    st = ta.status()
    if not (st.get("has_token") and st.get("chat_id")):
        raise HTTPException(status_code=400, detail="Set a bot token and chat id first")
    result = await ta.send("✅ <b>EasyPi test alert</b>\nTelegram alerts are working.")
    if not result.get("ok"):
        raise HTTPException(
            status_code=400,
            detail=f"Telegram send failed: {result.get('detail') or result.get('error')}",
        )
    return {"success": True}


class VpnConfigImport(BaseModel):
    config: str = Field(
        ...,
        max_length=262144,
        description="Full WireGuard or OpenVPN client config from the VPN provider",
    )


class OpenVpnCredentials(BaseModel):
    username: str = Field(..., min_length=1, max_length=256)
    password: SecretStr = Field(..., min_length=1, max_length=4096)

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if any(ch in value for ch in ("\n", "\r", "\x00")):
            raise ValueError("username contains forbidden control characters")
        return value


class RoutingConflictConfirmation(BaseModel):
    confirm_routing_conflict: bool = False


def _routing_operation_result(result: Dict[str, Any]) -> Dict[str, Any]:
    conflict = result.get("conflict")
    if isinstance(conflict, dict):
        raise HTTPException(status_code=409, detail=conflict)
    return result


@router.get("/vpn/status")
async def outbound_vpn_status(_admin: User = Depends(require_admin)):
    """Outbound VPN client status: configured / running / endpoint / handshake /
    transfer / kill-switch."""
    from app.services.vpn_client_service import get_vpn_client_service

    return await get_vpn_client_service().status()


@router.post("/vpn/import")
async def outbound_vpn_import(
    body: VpnConfigImport, _admin: User = Depends(require_admin)
):
    """Import + validate a WireGuard provider config (private key stored 600, never returned)."""
    from app.services.vpn_client_service import get_vpn_client_service

    try:
        return get_vpn_client_service().import_config(body.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/vpn/enable")
async def outbound_vpn_enable(
    body: Optional[RoutingConflictConfirmation] = Body(default=None),
    _admin: User = Depends(require_admin),
):
    """Bring the tunnel up and route the whole network through it (with kill-switch)."""
    from app.services.vpn_client_service import get_vpn_client_service

    result = await get_vpn_client_service().enable(
        confirm_routing_conflict=bool(body and body.confirm_routing_conflict)
    )
    _routing_operation_result(result)
    if not result.get("success", True) and result.get("error"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/vpn/credentials")
async def outbound_vpn_credentials(
    body: OpenVpnCredentials,
    _admin: User = Depends(require_admin),
):
    """Store OpenVPN credentials through the root encrypted credential broker."""
    from app.services.vpn_client_service import get_vpn_client_service

    try:
        return get_vpn_client_service().save_credentials(
            body.username,
            body.password.get_secret_value(),
        )
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/vpn/credentials")
async def outbound_vpn_delete_credentials(_admin: User = Depends(require_admin)):
    """Remove saved OpenVPN credentials without exposing their value."""
    from app.services.vpn_client_service import get_vpn_client_service

    try:
        return get_vpn_client_service().delete_credentials()
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/vpn/disable")
async def outbound_vpn_disable(_admin: User = Depends(require_admin)):
    """Tear the tunnel + routing + kill-switch down (traffic returns to normal WAN)."""
    from app.services.vpn_client_service import get_vpn_client_service

    result = await get_vpn_client_service().disable()
    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get("error") or "Failed to disable Internet Encryption",
        )
    return result


@router.delete("/vpn/config")
async def outbound_vpn_delete(_admin: User = Depends(require_admin)):
    """Disable and remove the stored VPN config."""
    from app.services.vpn_client_service import get_vpn_client_service

    return await get_vpn_client_service().delete_config()


class VpnDevice(BaseModel):
    mac: str
    name: str = ""
    ip: Optional[str] = None


class VpnTargets(BaseModel):
    scope: str = Field(
        "all", description="'all' = whole network, 'selected' = only the listed devices"
    )
    devices: List[VpnDevice] = Field(default_factory=list)
    confirm_routing_conflict: bool = False


@router.post("/vpn/targets")
async def outbound_vpn_targets(body: VpnTargets, _admin: User = Depends(require_admin)):
    """Set routing scope (whole network vs selected devices). Applies live if running."""
    from app.services.vpn_client_service import get_vpn_client_service

    try:
        result = await get_vpn_client_service().set_targets(
            body.scope,
            [d.model_dump() for d in body.devices],
            confirm_routing_conflict=body.confirm_routing_conflict,
        )
        return _routing_operation_result(result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Stealth VPN (anti-DPI / Chameleon) — 3 tabs: Client / Server / Profile ────────
class StealthClientCfg(BaseModel):
    server_address: Optional[str] = Field(default=None, max_length=320)
    shield_preset: Optional[str] = Field(default=None, max_length=320)
    doh_domain: Optional[str] = Field(default=None, max_length=253)
    buffer_size: Optional[int] = Field(default=None, ge=64, le=65535)
    reconnect_interval: Optional[int] = Field(default=None, ge=1, le=300)
    block_quic: Optional[bool] = None
    fingerprint_mode: Optional[Literal["auto", "mobile", "desktop"]] = None
    psk_key: Optional[str] = Field(default=None, max_length=64)
    reality_public: Optional[str] = Field(default=None, max_length=64)


class StealthServerCfg(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=15)
    user: str = Field(default="root", min_length=1, max_length=32)
    port: int = Field(default=22, ge=1, le=65535)
    password: str = Field(default="", max_length=1024)
    remote_path: str = Field(default="/opt/chameleon-server", max_length=64)
    acme_terms_accepted: bool = False
    domain: str = Field(default="", max_length=253)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        from app.utils.network_security import require_public_ipv4

        return require_public_ipv4(value, label="Stealth VPS")

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]{0,31}", value):
            raise ValueError("Invalid SSH username")
        return value

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("SSH password cannot contain NUL")
        return value

    @field_validator("remote_path")
    @classmethod
    def validate_remote_path(cls, value: str) -> str:
        if value.rstrip("/") != "/opt/chameleon-server":
            raise ValueError("Unsupported remote path")
        return "/opt/chameleon-server"


class StealthHostKeyTrust(BaseModel):
    fingerprint: str = Field(pattern=r"^SHA256:[A-Za-z0-9+/]{43}$", max_length=50)


class StealthTargets(BaseModel):
    scope: str = Field("all", description="'all' or 'selected'")
    devices: List[VpnDevice] = Field(default_factory=list)
    confirm_routing_conflict: bool = False


def _stealth():
    from app.services.stealth_service import get_stealth_service

    return get_stealth_service()


def _stealth_operation_result(result: Dict[str, Any]) -> Dict[str, Any]:
    if result.get("busy"):
        raise HTTPException(
            status_code=409, detail=result.get("log") or "Stealth Deployment is busy"
        )
    return result


@router.get("/stealth/status")
async def stealth_status(_admin: User = Depends(require_admin)):
    """Full stealth status: client settings, tunnel state, server SSH config, log."""
    return await _stealth().status()


# ── Client tab ────────────────────────────────────────────────────────────────
@router.post("/stealth/client")
async def stealth_save_client(
    body: StealthClientCfg, _admin: User = Depends(require_admin)
):
    """Save client settings and apply them immediately when Stealth is active."""
    try:
        return await _stealth().save_client_and_apply(
            **body.model_dump(exclude_none=True)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/stealth/generate/psk")
async def stealth_gen_psk(_admin: User = Depends(require_admin)):
    """Generate a fresh 32-byte PSK (stored 600, returned once for display)."""
    return _stealth().generate_psk()


@router.post("/stealth/generate/reality")
async def stealth_gen_reality(_admin: User = Depends(require_admin)):
    """Generate a fresh public marker value; no unused private key is persisted."""
    return _stealth().generate_reality()


@router.post("/stealth/enable")
async def stealth_enable(
    body: Optional[RoutingConflictConfirmation] = Body(default=None),
    _admin: User = Depends(require_admin),
):
    """Start the stealth tunnel and route traffic through it (own kill-switch)."""
    result = await _stealth().enable(
        confirm_routing_conflict=bool(body and body.confirm_routing_conflict)
    )
    _routing_operation_result(result)
    if not result.get("success", True) and result.get("error"):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


@router.post("/stealth/disable")
async def stealth_disable(_admin: User = Depends(require_admin)):
    """Stop the stealth tunnel and tear down its routing/kill-switch."""
    result = await _stealth().disable()
    if not result.get("success", True):
        raise HTTPException(
            status_code=400,
            detail=result.get("error") or "Failed to disable Stealth safely",
        )
    return result


@router.post("/stealth/targets")
async def stealth_targets(body: StealthTargets, _admin: User = Depends(require_admin)):
    """Set stealth routing scope (whole network vs selected devices)."""
    try:
        result = await _stealth().set_targets(
            body.scope,
            [d.model_dump() for d in body.devices],
            confirm_routing_conflict=body.confirm_routing_conflict,
        )
        return _routing_operation_result(result)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/stealth/reset-profile")
async def stealth_reset_profile(_admin: User = Depends(require_admin)):
    """Reset the learned traffic profile."""
    return await _stealth().reset_profile()


@router.delete("/stealth/config")
async def stealth_delete(_admin: User = Depends(require_admin)):
    """Disable and remove the stored stealth config."""
    return _stealth_operation_result(await _stealth().delete_config())


# ── Server tab (deploy chameleon-server to the user's VPS over SSH) ───────────────
@router.post("/stealth/server")
async def stealth_save_server(
    body: StealthServerCfg, _admin: User = Depends(require_admin)
):
    """Save VPS settings; secrets are encrypted by the system credential broker."""
    try:
        return _stealth().save_server(
            body.host,
            body.user,
            body.port,
            body.password,
            body.remote_path,
            body.acme_terms_accepted,
            body.domain,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post("/stealth/server/domain-tls")
async def stealth_configure_domain_tls(_admin: User = Depends(require_admin)):
    """Configure DuckDNS, trusted TLS and the Stealth domain endpoint as one transaction."""
    return _stealth_operation_result(await _stealth().configure_domain_tls())


@router.delete("/stealth/server/domain-tls")
async def stealth_remove_domain_tls(_admin: User = Depends(require_admin)):
    """Safely switch to IP Shield, then remove the stored domain identity."""
    return _stealth_operation_result(await _stealth().remove_domain_tls())


@router.post("/stealth/server/check")
async def stealth_check_ssh(_admin: User = Depends(require_admin)):
    """Test the SSH connection to the VPS."""
    return _stealth_operation_result(await _stealth().check_ssh())


@router.post("/stealth/server/trust-host-key")
async def stealth_trust_host_key(
    body: StealthHostKeyTrust, _admin: User = Depends(require_admin)
):
    """Pin the SSH host key after the administrator confirms its fingerprint."""
    return _stealth_operation_result(
        await _stealth().trust_ssh_host_key(body.fingerprint)
    )


@router.post("/stealth/server/deploy")
async def stealth_deploy(_admin: User = Depends(require_admin)):
    """Deploy + start chameleon-server on the VPS with the generated keys."""
    return _stealth_operation_result(await _stealth().deploy_server())


@router.post("/stealth/server/stop")
async def stealth_stop_server(_admin: User = Depends(require_admin)):
    """Stop chameleon-server on the VPS."""
    return _stealth_operation_result(await _stealth().stop_server())


@router.post("/stealth/server/uninstall")
async def stealth_uninstall_server(_admin: User = Depends(require_admin)):
    """Remove chameleon-server from the VPS (stop + disable + delete unit & dir)."""
    return _stealth_operation_result(await _stealth().uninstall_server())


@router.post("/stealth/server/logs")
async def stealth_server_logs(_admin: User = Depends(require_admin)):
    """Fetch the chameleon-server journal from the VPS (diagnosis)."""
    return await _stealth().server_logs()


@router.get("/onboarding")
async def get_onboarding(_admin: User = Depends(require_admin)):
    """First-run guide: which setup steps are done + the agent's next-step guidance."""
    try:
        return await netprotection_service.get_onboarding_status()
    except Exception as e:
        logger.error(f"Error getting onboarding status: {e}")
        return {
            "steps": [],
            "completedCount": 0,
            "totalCount": 0,
            "requiredDone": False,
            "allDone": False,
            "nextStep": None,
            "piIp": None,
            "narrative": "",
        }


@router.get("/analytics")
async def get_analytics(
    period: str = Query("24h", pattern="^(24h|7d)$"),
    _admin: User = Depends(require_admin),
):
    """Deeper analytics: threat-category breakdown, per-device summary, insights."""
    try:
        return await netprotection_service.get_analytics(period)
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        return {
            "period": period,
            "threatCategories": [],
            "devices": [],
            "insights": [],
            "comparison": {},
            "peakHour": None,
        }


@router.get("/analytics/device")
async def get_device_analytics(
    client_id: str = Query(...),
    period: str = Query("24h", pattern="^(24h|7d)$"),
    search: Optional[str] = Query(None),
    _admin: User = Depends(require_admin),
):
    """Drill-down analytics for one device (top domains + category mix).

    Optional `search` filters the recently-visited list to matching domains for
    that device (so a specific site is findable however busy the device is).
    """
    try:
        return await netprotection_service.get_device_detail(client_id, period, search)
    except Exception as e:
        logger.error(f"Error getting device analytics: {e}")
        return {"recent": [], "topQueried": [], "topBlocked": [], "categories": []}


@router.get("/stats")
async def get_stats(
    period: str = Query("24h", pattern="^(24h|7d)$"),
    _admin: User = Depends(require_admin),
):
    """Get statistics for the selected period (24h / 7d)."""
    try:
        return await netprotection_service.get_period_stats(period)
    except Exception as e:
        logger.error(f"Error getting NetProtection stats: {e}")
        return {
            "totalQueries": 0,
            "blocked": 0,
            "blockRate": 0,
            "queryTrend": [],
            "blockTrend": [],
            "topBlocked": [],
            "topClients": [],
            "topQueried": [],
            "avgResponseTime": None,
        }
