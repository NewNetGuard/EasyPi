"""NetProtection blocklists routes."""

from .context import (
    APIRouter,
    HTTPException,
    Depends,
    UploadFile,
    File,
    Form,
    datetime,
    timezone,
    BaseModel,
    Field,
    require_admin,
    User,
    netprotection_service,
    _record_netprotection_event,
)

router = APIRouter()

# ============ Blocklists (Two-layer system) ============
# Layer 1: verified_blocklist.txt - CC0/MIT only (safe)
# Layer 2: custom_blocklist.txt - User sources (at their risk)
# Combined: effective_blocklist.txt - Production ready


class CustomSourceAdd(BaseModel):
    """Add custom blocklist source."""

    url: str
    name: str
    format: str = Field(..., pattern="^(hosts|domains|adblock)$")
    user_confirmed_risks: bool = False


@router.get("/blocklists/status")
async def get_blocklist_status(_admin: User = Depends(require_admin)):
    """Get status of all blocklist layers."""
    return await netprotection_service.get_blocklist_status()


@router.get("/blocklists/verified/sources")
async def get_verified_sources(_admin: User = Depends(require_admin)):
    """Get hardcoded verified CC0/MIT sources."""
    return await netprotection_service.get_verified_sources()


@router.put("/blocklists/verified/sources/{source_id}")
async def set_verified_source_enabled(
    source_id: str,
    enabled: bool = True,
    user_confirmed_risks: bool = False,
    _admin: User = Depends(require_admin),
):
    """Enable/disable a verified source. Enabling a non-permissive (GPL / NonCommercial)
    source requires user_confirmed_risks=true — the list is then fetched to the user's OWN
    device; EasyPi never bundles or redistributes it."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        success = await netprotection_service.set_verified_source_enabled(
            source_id, enabled, user_confirmed_risks
        )
    except ValueError:
        _record_netprotection_event(
            action_id="netprotection.blocklists.verified.toggle",
            title="Toggle verified source",
            subtitle=f"Guard Security · {source_id}",
            status="failed",
            message="License consent required",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=400, detail="Must confirm understanding of license risks"
        )
    if not success:
        _record_netprotection_event(
            action_id="netprotection.blocklists.verified.toggle",
            title="Toggle verified source",
            subtitle=f"Guard Security · {source_id}",
            status="failed",
            message="Source not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Source not found")
    _record_netprotection_event(
        action_id="netprotection.blocklists.verified.toggle",
        title="Toggle verified source",
        subtitle=f"Guard Security · {source_id}",
        status="success",
        message=f"Verified source {'enabled' if enabled else 'disabled'}: {source_id}",
        started_at=started_at,
    )
    return {"success": True}


@router.post("/blocklists/generate")
async def generate_blocklists(_admin: User = Depends(require_admin)):
    """
    Generate all blocklist layers:
    1. Delete existing blocklists (clean start)
    2. Download verified sources → verified_blocklist.txt
    3. Download custom sources → custom_blocklist.txt
    4. Combine → effective_blocklist.txt

    Custom failures don't affect verified layer.
    Always does a clean regeneration (deletes old files first).
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = await netprotection_service.generate_blocklists(force_clean=True)
    _record_netprotection_event(
        action_id="netprotection.blocklists.generate",
        title="Generate blocklists",
        subtitle="Guard Security · Blocklists",
        status="failed" if "error" in result else "success",
        message=result.get("error") or result.get("message") or "Blocklists generated",
        started_at=started_at,
    )
    if "error" in result:
        raise HTTPException(status_code=429, detail=result["error"])
    return result


@router.get("/blocklists/use-custom")
async def get_use_custom_blocklist(_admin: User = Depends(require_admin)):
    """Check if using custom blocklist."""
    return netprotection_service.get_use_custom_blocklist()


@router.post("/blocklists/use-custom")
async def set_use_custom_blocklist(
    enabled: bool = True, _admin: User = Depends(require_admin)
):
    """
    Switch between verified and custom blocklist.

    - enabled=true: Use custom blocklist (user-uploaded file)
    - enabled=false: Use verified blocklist (CC0/MIT sources, safe)

    Custom blocklist must exist (upload a file first).
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = netprotection_service.set_use_custom_blocklist(enabled)
    _record_netprotection_event(
        action_id="netprotection.blocklists.use-custom",
        title="Switch blocklist source",
        subtitle="Guard Security · Blocklists",
        status="success" if result.get("success") else "failed",
        message=result.get(
            "message",
            "Using custom blocklist" if enabled else "Using verified blocklist",
        ),
        started_at=started_at,
    )
    if not result.get("success"):
        raise HTTPException(
            status_code=400,
            detail=result.get("error", "Cannot enable custom blocklist"),
        )
    return result


@router.delete("/blocklists/clear")
async def clear_blocklists(_admin: User = Depends(require_admin)):
    """
    Delete all blocklist files.
    Use this to reset blocklists before regenerating.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    result = netprotection_service.clear_blocklists()
    _record_netprotection_event(
        action_id="netprotection.blocklists.clear",
        title="Clear blocklists",
        subtitle="Guard Security · Blocklists",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", "Blocklists cleared"),
        started_at=started_at,
    )
    return result


@router.get("/blocklists/progress")
async def get_generation_progress(_admin: User = Depends(require_admin)):
    """Get current blocklist generation progress."""
    return await netprotection_service.get_blocklist_progress()


@router.get("/blocklists/custom/sources")
async def get_custom_sources(_admin: User = Depends(require_admin)):
    """Get user-added custom sources."""
    return await netprotection_service.get_custom_sources()


@router.post("/blocklists/custom/add")
async def add_custom_source(
    data: CustomSourceAdd, _admin: User = Depends(require_admin)
):
    """
    Add custom blocklist source.
    Requires user confirmation of license risks.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    if not data.user_confirmed_risks:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.add",
            title="Add custom blocklist source",
            subtitle=f"Guard Security · {data.name}",
            status="failed",
            message="Must confirm understanding of license risks",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=400, detail="Must confirm understanding of license risks"
        )

    try:
        result = await netprotection_service.add_custom_source(
            url=data.url, name=data.name, format=data.format, user_confirmed=True
        )
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.add",
            title="Add custom blocklist source",
            subtitle=f"Guard Security · {data.name}",
            status="success",
            message=f"Custom source added: {data.name}",
            started_at=started_at,
        )
        return {"success": True, "source": result}
    except ValueError as e:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.add",
            title="Add custom blocklist source",
            subtitle=f"Guard Security · {data.name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/blocklists/custom/upload")
async def upload_custom_blocklist(
    file: UploadFile = File(...),
    name: str = Form(...),
    format: str = Form(...),
    user_confirmed_risks: bool = Form(...),
    _admin: User = Depends(require_admin),
):
    """
    Upload a blocklist file from user's computer.
    File is saved locally and registered as a custom source.
    Format can be 'auto' for automatic detection.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    if not user_confirmed_risks:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="failed",
            message="Must confirm understanding of license risks",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=400, detail="Must confirm understanding of license risks"
        )

    if format not in ("hosts", "domains", "adblock", "auto"):
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="failed",
            message="Format must be one of: hosts, domains, adblock, auto",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=400,
            detail="Format must be one of: hosts, domains, adblock, auto",
        )

    # Read file content
    try:
        max_upload_bytes = 32 * 1024 * 1024
        content = await file.read(max_upload_bytes + 1)
        if len(content) > max_upload_bytes:
            raise HTTPException(status_code=413, detail="Blocklist file is too large")
        content_str = content.decode("utf-8", errors="ignore")
    except HTTPException:
        raise
    except Exception as e:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="failed",
            message=f"Failed to read file: {e}",
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=f"Failed to read file: {e}")

    # Validate content (at least some non-comment lines)
    lines = [
        line.strip()
        for line in content_str.split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]
    if len(lines) < 1:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="failed",
            message="File appears to be empty or contains only comments",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=400, detail="File appears to be empty or contains only comments"
        )

    # Save file locally
    try:
        result = await netprotection_service.add_custom_source_from_file(
            name=name, content=content_str, format=format, user_confirmed=True
        )
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="success",
            message=f"Uploaded custom blocklist: {name}",
            started_at=started_at,
        )
        return {
            "success": True,
            "source": result,
            "entries_count": result.get("domain_count", len(lines)),
        }
    except ValueError as e:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.upload",
            title="Upload custom blocklist",
            subtitle=f"Guard Security · {name}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=400, detail=str(e))


@router.delete("/blocklists/custom/{source_id}")
async def remove_custom_source(source_id: str, _admin: User = Depends(require_admin)):
    """Remove custom blocklist source."""
    started_at = datetime.now(timezone.utc).isoformat()
    success = await netprotection_service.remove_custom_source(source_id)
    if not success:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.delete",
            title="Remove custom blocklist source",
            subtitle=f"Guard Security · {source_id}",
            status="failed",
            message="Source not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Source not found")
    _record_netprotection_event(
        action_id="netprotection.blocklists.custom.delete",
        title="Remove custom blocklist source",
        subtitle=f"Guard Security · {source_id}",
        status="success",
        message=f"Removed custom source: {source_id}",
        started_at=started_at,
    )
    return {"success": True}


@router.put("/blocklists/custom/{source_id}")
async def set_custom_source_enabled(
    source_id: str, enabled: bool = True, _admin: User = Depends(require_admin)
):
    """Enable/disable a custom source."""
    started_at = datetime.now(timezone.utc).isoformat()
    success = await netprotection_service.set_custom_source_enabled(source_id, enabled)
    if not success:
        _record_netprotection_event(
            action_id="netprotection.blocklists.custom.toggle",
            title="Toggle custom blocklist source",
            subtitle=f"Guard Security · {source_id}",
            status="failed",
            message="Source not found",
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail="Source not found")
    _record_netprotection_event(
        action_id="netprotection.blocklists.custom.toggle",
        title="Toggle custom blocklist source",
        subtitle=f"Guard Security · {source_id}",
        status="success",
        message=f"Custom source {'enabled' if enabled else 'disabled'}: {source_id}",
        started_at=started_at,
    )
    return {"success": True}


# ============ Metrics (for Chronicle) ============


@router.get("/metrics")
async def get_metrics(_admin: User = Depends(require_admin)):
    """Get aggregated metrics (no PII)."""
    stats = await netprotection_service.get_stats()

    return {
        "queries_total": stats["num_dns_queries"],
        "blocked_total": stats["num_blocked_filtering"],
        "cache_hits": 0,
        "avg_latency_ms": stats.get("avg_processing_time", 0),
        "uptime_seconds": 0,
    }
