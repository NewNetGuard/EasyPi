"""NetProtection schedules routes."""

from .context import (
    APIRouter,
    HTTPException,
    Query,
    Depends,
    List,
    Optional,
    datetime,
    timezone,
    BaseModel,
    Field,
    require_admin,
    User,
    DeviceAnomalyStoreError,
    ScheduleStoreError,
    netprotection_service,
    _record_netprotection_event,
)

router = APIRouter()

# ============ Schedules (Policy Engine) ============


class ScheduleRule(BaseModel):
    """Rule within a schedule."""

    id: Optional[str] = None
    type: str = Field(default="block", pattern="^(block|allow)$")
    target: str
    target_type: str = Field(default="category", pattern="^(category|domain|all)$")
    days: List[int] = Field(default=[1, 2, 3, 4, 5])  # 0=Sunday, 1=Monday, etc.
    start_time: str = "00:00"  # HH:MM format
    end_time: str = "23:59"


class ScheduleCreate(BaseModel):
    """Create new schedule."""

    name: str
    enabled: bool = True
    profile_id: Optional[str] = None
    device_ips: Optional[List[str]] = None
    device_macs: Optional[List[str]] = None  # durable device binding (survives DHCP)
    rules: List[ScheduleRule] = []


class ScheduleUpdate(BaseModel):
    """Update schedule."""

    name: Optional[str] = None
    enabled: Optional[bool] = None
    profile_id: Optional[str] = None
    device_ips: Optional[List[str]] = None
    device_macs: Optional[List[str]] = None
    rules: Optional[List[ScheduleRule]] = None


@router.get("/schedules")
async def get_schedules(_admin: User = Depends(require_admin)):
    """Get all schedules."""
    try:
        return await netprotection_service.get_schedules()
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.get("/schedules/enforcement-status")
async def get_schedule_enforcement_status(_admin: User = Depends(require_admin)):
    """Is schedule blocking enforced at the gateway (unbypassable) or DNS-only?"""
    return await netprotection_service.get_schedule_enforcement_status()


@router.post("/schedules")
async def create_schedule(
    schedule: ScheduleCreate, _admin: User = Depends(require_admin)
):
    """Create a new schedule."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.create_schedule(schedule.model_dump())
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    _record_netprotection_event(
        action_id="netprotection.schedules.create",
        title="Create schedule",
        subtitle=f"Guard Security · {schedule.name}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Created schedule: {schedule.name}"),
        started_at=started_at,
    )
    return result


@router.get("/schedules/{schedule_id}")
async def get_schedule(schedule_id: str, _admin: User = Depends(require_admin)):
    """Get schedule details."""
    try:
        result = await netprotection_service.get_schedule(schedule_id)
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return result


@router.put("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str, schedule: ScheduleUpdate, _admin: User = Depends(require_admin)
):
    """Update a schedule."""
    started_at = datetime.now(timezone.utc).isoformat()
    updates = schedule.model_dump(exclude_none=True)
    try:
        result = await netprotection_service.update_schedule(schedule_id, updates)
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _record_netprotection_event(
        action_id="netprotection.schedules.update",
        title="Update schedule",
        subtitle=f"Guard Security · {schedule_id}",
        status="success" if result.get("success", True) else "failed",
        message=result.get("message", f"Updated schedule: {schedule_id}"),
        started_at=started_at,
    )
    return result


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, _admin: User = Depends(require_admin)):
    """Delete a schedule."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        success = await netprotection_service.delete_schedule(schedule_id)
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not success:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _record_netprotection_event(
        action_id="netprotection.schedules.delete",
        title="Delete schedule",
        subtitle=f"Guard Security · {schedule_id}",
        status="success",
        message=f"Deleted schedule: {schedule_id}",
        started_at=started_at,
    )
    return {"success": True, "deleted": schedule_id}


@router.post("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str, enabled: bool = True, _admin: User = Depends(require_admin)
):
    """Toggle schedule enabled/disabled."""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await netprotection_service.toggle_schedule(schedule_id, enabled)
    except ScheduleStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    if not result:
        raise HTTPException(status_code=404, detail="Schedule not found")
    _record_netprotection_event(
        action_id="netprotection.schedules.toggle",
        title="Toggle schedule",
        subtitle=f"Guard Security · {schedule_id}",
        status="success" if result.get("success", True) else "failed",
        message=result.get(
            "message", f"{'Enabled' if enabled else 'Disabled'} schedule: {schedule_id}"
        ),
        started_at=started_at,
    )
    return result


# ============ Devices with Baseline & Anomaly Detection ============


@router.get("/devices/baseline")
async def get_devices_with_baseline(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    _admin: User = Depends(require_admin),
):
    """Get all devices with baseline information."""
    return await netprotection_service.get_devices_with_baseline(page, page_size)


@router.get("/devices/{device_id}/baseline")
async def get_device_baseline(device_id: str, _admin: User = Depends(require_admin)):
    """Get device baseline behavior."""
    result = await netprotection_service.get_device_baseline(device_id)
    if not result:
        raise HTTPException(status_code=404, detail="Device not found")
    return result


@router.get("/devices/{device_id}/anomalies")
async def get_device_anomalies(device_id: str, _admin: User = Depends(require_admin)):
    """Get detected anomalies for device."""
    try:
        return await netprotection_service.get_device_anomalies(device_id)
    except DeviceAnomalyStoreError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
