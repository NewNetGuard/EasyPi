"""NetProtection service control routes."""

from .context import (
    APIRouter,
    HTTPException,
    Depends,
    datetime,
    timezone,
    BaseModel,
    Field,
    require_admin,
    User,
    netprotection_service,
    logger,
    _record_netprotection_event,
    ConfigUpdate,
    EncryptedDnsUpdate,
)

router = APIRouter()

# ============ Status & Config Endpoints ============


@router.get("/status")
async def get_status():
    """
    Get NetProtection status.
    Public endpoint for setup wizard.
    """
    try:
        status = await netprotection_service.get_status()
        return {
            "configured": status.get("running", False),
            "available": status.get("available", False),
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        return {"configured": False, "available": False}


@router.get("/status/full")
async def get_full_status(_admin: User = Depends(require_admin)):
    """Get detailed NetProtection status."""
    status = await netprotection_service.get_status()
    try:
        dashboard = await netprotection_service.get_dashboard_stats()
        status["stats"] = {
            "total_queries": dashboard.get("total_queries", 0),
            "blocked_queries": dashboard.get("blocked_today", 0),
        }
        status["blocklist_domains"] = dashboard.get("blocked_domains", 0)
    except Exception:
        # Keep status lightweight if stats collection fails.
        status["stats"] = {"total_queries": 0, "blocked_queries": 0}
        status["blocklist_domains"] = 0
    return status


@router.get("/config")
async def get_config(_admin: User = Depends(require_admin)):
    """Get current configuration."""
    return await netprotection_service.get_config()


@router.put("/config")
async def update_config(config: ConfigUpdate, _admin: User = Depends(require_admin)):
    """Update configuration."""
    started_at = datetime.now(timezone.utc).isoformat()
    updates = config.model_dump(exclude_none=True)
    result = await netprotection_service.update_config(updates)
    _record_netprotection_event(
        action_id="netprotection.config.update",
        title="Update NetProtection config",
        subtitle="Guard Security · Core settings",
        status="success" if result.get("success", True) else "failed",
        message=result.get(
            "message",
            f"Updated settings: {', '.join(sorted(updates.keys()))}"
            if updates
            else "No settings changed",
        ),
        started_at=started_at,
    )
    return result


@router.get("/encrypted-dns")
async def get_encrypted_dns(_admin: User = Depends(require_admin)):
    """Get Encrypted DNS (DoH/DoT) settings."""
    result = await netprotection_service.get_encrypted_dns_settings()
    if not result.get("success", True):
        raise HTTPException(
            status_code=503, detail=result.get("error", "NetProtection not available")
        )
    return result


@router.put("/encrypted-dns")
async def update_encrypted_dns(
    config: EncryptedDnsUpdate, _admin: User = Depends(require_admin)
):
    """Update Encrypted DNS (DoH/DoT) settings."""
    started_at = datetime.now(timezone.utc).isoformat()
    updates = config.model_dump(exclude_none=True)
    result = await netprotection_service.update_encrypted_dns_settings(updates)
    _record_netprotection_event(
        action_id="netprotection.encrypted-dns.update",
        title="Update encrypted DNS",
        subtitle="Guard Security · DoH/DoT",
        status="success" if result.get("success", True) else "failed",
        message=result.get(
            "message",
            f"Updated encrypted DNS settings: {', '.join(sorted(updates.keys()))}"
            if updates
            else "Encrypted DNS settings updated",
        ),
        started_at=started_at,
    )
    if not result.get("success", True):
        raise HTTPException(
            status_code=503, detail=result.get("error", "NetProtection not available")
        )
    return result


@router.post("/encrypted-dns/generate-certs")
async def generate_encrypted_dns_certs(
    force: bool = False, _admin: User = Depends(require_admin)
):
    """Generate TLS certificates for Encrypted DNS (DoH/DoT).

    Pass ?force=true to renew the server certificate even when it is valid.
    The installed EasyPi Root CA is preserved.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.generate_tls_certs(force=force)
    _record_netprotection_event(
        action_id="netprotection.encrypted-dns.generate-certs",
        title="Generate encrypted DNS certificates",
        subtitle="Guard Security · DoH/DoT",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", "Encrypted DNS certificates generated"),
        started_at=started_at,
    )
    if not result.get("success", True):
        raise HTTPException(
            status_code=503,
            detail=result.get("error", "Failed to generate certificates"),
        )
    return result


class TrustedCertRequest(BaseModel):
    domain: str = Field(..., description="DuckDNS domain, e.g. myhome.duckdns.org")
    token: str = Field(..., description="DuckDNS account token")
    email: str = Field("", description="Optional email for expiry notices")


@router.get("/encrypted-dns/trusted-cert")
async def get_trusted_cert_status(_admin: User = Depends(require_admin)):
    """Report whether DoH/DoT serve a trusted (Let's Encrypt) cert or self-signed,
    plus domain, expiry and DDNS state."""
    return await netprotection_service.trusted_cert_status()


@router.post("/encrypted-dns/trusted-cert")
async def setup_trusted_cert(
    body: TrustedCertRequest, _admin: User = Depends(require_admin)
):
    """Obtain a free trusted Let's Encrypt certificate for a DuckDNS domain and serve
    it on DoH/DoT — so Android Private DNS accepts it — with auto-renew and a DDNS
    updater keeping the domain pointed at this box."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.setup_trusted_cert(
        fqdn=body.domain,
        token=body.token,
        email=body.email or "",
    )
    _record_netprotection_event(
        action_id="netprotection.encrypted-dns.trusted-cert",
        title="Set up trusted DNS certificate",
        subtitle="Guard Security · DoH/DoT",
        status="success" if result.get("success") else "failed",
        message=(
            result.get("error") or f"Trusted certificate issued for {body.domain}"
        ),
        started_at=started_at,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=400, detail=result.get("error", "Failed to obtain certificate")
        )
    return result


# ============ Service Control ============


@router.post("/start")
async def start_service(_admin: User = Depends(require_admin)):
    """Start NetProtection DNS service."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.start_service()
    if not result.get("success", False):
        _record_netprotection_event(
            action_id="netprotection.start",
            title="Start NetProtection",
            subtitle="Guard Security · DNS runtime",
            status="failed",
            message=result.get("error", "Failed to start NetProtection"),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500, detail=result.get("error", "Failed to start NetProtection")
        )
    _record_netprotection_event(
        action_id="netprotection.start",
        title="Start NetProtection",
        subtitle="Guard Security · DNS runtime",
        status="success",
        message=result.get("message", "NetProtection started"),
        started_at=started_at,
    )
    return result


@router.post("/stop")
async def stop_service(_admin: User = Depends(require_admin)):
    """Stop NetProtection DNS service."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.stop_service()
    if not result.get("success", False):
        _record_netprotection_event(
            action_id="netprotection.stop",
            title="Stop NetProtection",
            subtitle="Guard Security · DNS runtime",
            status="failed",
            message=result.get("error", "Failed to stop NetProtection"),
            started_at=started_at,
        )
        raise HTTPException(
            status_code=500, detail=result.get("error", "Failed to stop NetProtection")
        )
    _record_netprotection_event(
        action_id="netprotection.stop",
        title="Stop NetProtection",
        subtitle="Guard Security · DNS runtime",
        status="success",
        message=result.get("message", "NetProtection stopped"),
        started_at=started_at,
    )
    return result


class TransparentDnsRequest(BaseModel):
    """Transparent DNS toggle request."""

    enabled: bool


@router.post("/transparent-dns")
async def toggle_transparent_dns(
    request: TransparentDnsRequest, _admin: User = Depends(require_admin)
):
    """
    Enable/disable transparent DNS interception.

    When enabled, all DNS traffic on the network is intercepted
    via iptables and redirected to NetProtection.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.toggle_transparent_dns(request.enabled)
    _record_netprotection_event(
        action_id="netprotection.transparent-dns",
        title="Update transparent DNS",
        subtitle="Guard Security · DNS interception",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", "Transparent DNS settings updated"),
        started_at=started_at,
    )
    return result


# ============ Protection Control ============


@router.post("/protection/enable")
async def enable_protection(_admin: User = Depends(require_admin)):
    """Enable DNS protection."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.enable_protection()
    _record_netprotection_event(
        action_id="netprotection.protection.enable",
        title="Enable DNS protection",
        subtitle="Guard Security · Protection state",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", "DNS protection enabled"),
        started_at=started_at,
    )
    return result


@router.post("/protection/disable")
async def disable_protection(_admin: User = Depends(require_admin)):
    """Disable DNS protection."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.disable_protection()
    _record_netprotection_event(
        action_id="netprotection.protection.disable",
        title="Disable DNS protection",
        subtitle="Guard Security · Protection state",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", "DNS protection disabled"),
        started_at=started_at,
    )
    return result
