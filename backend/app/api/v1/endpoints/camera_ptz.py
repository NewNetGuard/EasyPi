"""PTZ (pan/tilt/zoom) camera-control API.

Uniform across camera vendors: the adapter behind each camera is chosen
server-side. Every endpoint re-checks the caller's role via the policy module
and re-validates the command against the camera's real capabilities — a hidden
frontend button is not a security boundary. No command touches the RTSP/go2rtc
video path, so a PTZ failure never affects the stream.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db, require_admin
from app.api.v1.endpoints.camera_helpers import get_camera_or_404
from app.core.rate_limit import check_ptz_rate_limit
from app.models.user import User
from app.schemas.ptz import (
    PTZAdapterSelectRequest,
    PTZDiscoverRequest,
    PTZMoveRequest,
    PTZPresetCreateRequest,
)
from app.services.ptz import discovery, policy, service
from app.services.ptz.base import CameraSnapshot
from app.services.ptz.registry import (
    RESERVED_ADAPTERS,
    available_adapters,
    build_adapter,
)
from app.services.ptz.session import session_manager

router = APIRouter(tags=["camera-ptz"])


# --- discovery: admin, network-wide (no camera yet) -----------------------
@router.post("/discover")
def ptz_discover(body: PTZDiscoverRequest | None = None, user: User = Depends(require_admin)):
    """Find ONVIF cameras on the local network via WS-Discovery (admin only).

    Returns candidate devices ({ip, onvif_port, name, ...}) that answered — the
    camera reports its own address and port, so no scanning/guessing. An optional
    ``ip`` adds a directed unicast probe (cross-subnet / multicast-blocked nets).
    Every address is SSRF-validated (LAN-only, never EasyPi itself). Nothing is
    added or authenticated to here; the admin picks a result and adds it normally.
    """
    check_ptz_rate_limit(user.id, "_network", "discover", limit_name="ptz_discover")
    targets = [body.ip] if (body and body.ip) else None
    devices = discovery.discover(targets=targets)
    return {"devices": devices, "count": len(devices)}

_MOVE_METHODS = {
    "continuous": "continuous_move",
    "relative": "relative_move",
    "absolute": "absolute_move",
}


def _busy() -> HTTPException:
    return HTTPException(
        status.HTTP_409_CONFLICT, "Another PTZ command is in progress for this camera"
    )


# --- read: any authenticated user -----------------------------------------
@router.get("/{camera_id}/ptz/capabilities")
def ptz_capabilities(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_view(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "capabilities")
    return service.build_capabilities_response(camera)


@router.get("/{camera_id}/ptz/position")
def ptz_position(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_view(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "position")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    pos, rid = service.execute(camera, user, "get_position", adapter.get_position, gate=False)
    return {"pan": pos.pan, "tilt": pos.tilt, "zoom": pos.zoom, "request_id": rid}


@router.get("/{camera_id}/ptz/presets")
def ptz_get_presets(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_view(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "get_presets")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    presets, _ = service.execute(camera, user, "get_presets", adapter.get_presets, gate=False)
    return {"presets": [{"token": p.token, "name": p.name} for p in presets]}


# --- control: any authenticated user --------------------------------------
@router.post("/{camera_id}/ptz/move")
def ptz_move(
    camera_id: str,
    body: PTZMoveRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_control(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "move")
    # fail-closed: the requested move mode must be a real capability
    if not service.current_capabilities(camera).supports_mode(body.mode):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, f"Camera does not support {body.mode} move"
        )
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    method = getattr(adapter, _MOVE_METHODS[body.mode])
    if not session_manager.acquire(camera.id, timeout=2.0):
        raise _busy()
    try:
        _, rid = service.execute(
            camera, user, "move",
            lambda: method(body.pan, body.tilt, body.zoom, body.speed),
            gate=False, request_id=session_manager.new_request_id(),
        )
        if body.mode == "continuous":
            session_manager.start_continuous(camera.id, rid, adapter.stop)
    finally:
        session_manager.release(camera.id)
    return {"ok": True, "request_id": rid, "command": "move", "mode": body.mode}


@router.post("/{camera_id}/ptz/stop")
def ptz_stop(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_control(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "stop")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    session_manager.stop(camera.id)  # highest priority: cancel any active session first
    _, rid = service.execute(camera, user, "stop", adapter.stop, gate=False)
    return {"ok": True, "request_id": rid, "command": "stop"}


@router.post("/{camera_id}/ptz/home")
def ptz_go_home(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_control(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "go_home")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    if not session_manager.acquire(camera.id, timeout=2.0):
        raise _busy()
    try:
        _, rid = service.execute(camera, user, "go_home", adapter.go_home)
    finally:
        session_manager.release(camera.id)
    return {"ok": True, "request_id": rid, "command": "go_home"}


@router.post("/{camera_id}/ptz/presets/{token}/goto")
def ptz_goto_preset(
    camera_id: str, token: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_control(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "goto_preset")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    if not session_manager.acquire(camera.id, timeout=2.0):
        raise _busy()
    try:
        _, rid = service.execute(camera, user, "goto_preset", lambda: adapter.goto_preset(token))
    finally:
        session_manager.release(camera.id)
    return {"ok": True, "request_id": rid, "command": "goto_preset"}


# --- administration: admin only -------------------------------------------
@router.post("/{camera_id}/ptz/detect")
def ptz_detect(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_administer(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "detect", limit_name="ptz_detect")
    return service.detect(camera, db, user)


@router.post("/{camera_id}/ptz/adapter")
def ptz_set_adapter(
    camera_id: str,
    body: PTZAdapterSelectRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_administer(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "set_adapter")
    name = body.adapter.strip().lower()
    if name not in (set(available_adapters()) | set(RESERVED_ADAPTERS)):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Unknown PTZ adapter")
    camera.ptz_adapter = name
    camera.ptz_detected = False  # capabilities are now stale until re-detect
    camera.ptz_capabilities_json = None
    camera.ptz_probe_error = None
    db.commit()
    return service.build_capabilities_response(camera)


@router.post("/{camera_id}/ptz/home/set")
def ptz_set_home(
    camera_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_administer(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "set_home")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    _, rid = service.execute(camera, user, "set_home", adapter.set_home)
    return {"ok": True, "request_id": rid, "command": "set_home"}


@router.post("/{camera_id}/ptz/presets")
def ptz_create_preset(
    camera_id: str,
    body: PTZPresetCreateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_administer(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "create_preset")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    preset, rid = service.execute(
        camera, user, "create_preset", lambda: adapter.create_preset(body.name)
    )
    return {"ok": True, "request_id": rid, "preset": {"token": preset.token, "name": preset.name}}


@router.delete("/{camera_id}/ptz/presets/{token}")
def ptz_delete_preset(
    camera_id: str, token: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)
):
    camera = get_camera_or_404(db, camera_id)
    policy.ensure_can_administer(user, camera)
    check_ptz_rate_limit(user.id, camera.id, "delete_preset")
    adapter = build_adapter(CameraSnapshot.from_camera(camera))
    _, rid = service.execute(camera, user, "delete_preset", lambda: adapter.delete_preset(token))
    return {"ok": True, "request_id": rid, "command": "delete_preset"}


__all__ = ["router"]
