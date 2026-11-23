"""PTZ orchestration used by the API endpoints.

Ties together capability gating (fail-closed), the adapter, the audit log and
error->HTTP mapping so the endpoints stay thin. Nothing here talks to the video
pipeline; a PTZ failure never touches go2rtc.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable, Optional, Tuple

from fastapi import HTTPException

from app.services.ptz.audit import audit
from app.services.ptz.base import CameraSnapshot
from app.services.ptz.capabilities import NULL_CAPABILITIES, PTZCapabilities
from app.services.ptz.errors import PTZError
from app.services.ptz.registry import get_adapter_class, is_implemented
from app.services.ptz.session import session_manager

# Order EasyPi auto-probes protocols in when detecting a camera with no adapter
# pinned. ONVIF is the cross-vendor standard, so it is tried first; a vendor-only
# camera falls through to Thingino.
DETECTION_ORDER = ["onvif", "thingino"]


def _uid(user) -> Optional[int]:
    return getattr(user, "id", None)


def current_capabilities(camera) -> PTZCapabilities:
    """The camera's usable PTZ capabilities, fail-closed.

    Unknown/unimplemented adapter, or not-yet-detected, or invalid stored data
    all resolve to "no PTZ" so a dangerous command can never be gated open by a
    stale or bogus capability blob.
    """
    adapter_name = getattr(camera, "ptz_adapter", None)
    if not is_implemented(adapter_name):
        return NULL_CAPABILITIES
    if not getattr(camera, "ptz_detected", False):
        return PTZCapabilities(available=False, adapter=adapter_name or "null")
    data = camera.get_ptz_capabilities() or {}
    return PTZCapabilities(**{**data, "adapter": adapter_name})


def build_capabilities_response(camera) -> dict:
    caps = current_capabilities(camera)
    last = getattr(camera, "ptz_last_probe_at", None)
    return {
        **caps.model_dump(),
        "detected": bool(getattr(camera, "ptz_detected", False)),
        "last_probe_at": last.isoformat() if last else None,
        "probe_error": getattr(camera, "ptz_probe_error", None),
    }


def execute(
    camera,
    user,
    command: str,
    fn: Callable,
    *,
    gate: bool = True,
    request_id: Optional[str] = None,
) -> Tuple[object, str]:
    """Run one adapter call: capability-gate (fail-closed), audit, map errors."""
    request_id = request_id or session_manager.new_request_id()
    adapter_name = getattr(camera, "ptz_adapter", None) or "null"
    cam_id = getattr(camera, "id", None)
    uid = _uid(user)

    if gate and not current_capabilities(camera).supports(command):
        audit(
            user_id=uid, camera_id=cam_id, adapter=adapter_name,
            command=command, result="unsupported", request_id=request_id,
        )
        raise HTTPException(status_code=400, detail=f"Camera does not support PTZ command: {command}")

    try:
        result = fn()
    except PTZError as exc:
        audit(
            user_id=uid, camera_id=cam_id, adapter=adapter_name,
            command=command, result=f"error:{exc.code}", request_id=request_id,
        )
        raise HTTPException(status_code=exc.status_code, detail=exc.message)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - never leak a raw exception/secret
        audit(
            user_id=uid, camera_id=cam_id, adapter=adapter_name,
            command=command, result="error", request_id=request_id, detail=repr(exc),
        )
        raise HTTPException(status_code=502, detail="PTZ command failed")

    audit(
        user_id=uid, camera_id=cam_id, adapter=adapter_name,
        command=command, result="ok", request_id=request_id,
    )
    return result, request_id


def detect(camera, db, user=None) -> dict:
    """(Re-)detect PTZ support and persist the result.

    Stage 2 only has the Null adapter, so detection concludes "no PTZ"; Stage
    3/4 will probe Thingino/ONVIF here and select the first that works. The probe
    result (never secrets) is stored on the camera row.
    """
    request_id = session_manager.new_request_id()
    snapshot = CameraSnapshot.from_camera(camera)

    # If an admin has pinned a specific adapter, probe only that; otherwise auto-
    # probe the detection order and pick the first that reports PTZ available.
    pinned = getattr(camera, "ptz_adapter", None)
    order = [pinned] if pinned in DETECTION_ORDER else DETECTION_ORDER

    caps = NULL_CAPABILITIES
    chosen = "null"
    # Keep every adapter's failure reason (not just the last), so the stored
    # probe_error tells the admin why each protocol was rejected -- otherwise the
    # last adapter tried masks the real cause (e.g. an ONVIF auth rejection hidden
    # behind a vendor adapter's own error).
    errors: list[str] = []
    for name in order:
        try:
            probed = get_adapter_class(name)(snapshot).probe()
        except PTZError as exc:
            errors.append(f"{name}: {exc.message}")
            continue
        except Exception:  # noqa: BLE001
            errors.append(f"{name}: probe failed")
            continue
        if probed.available:
            caps, chosen, errors = probed, name, []
            break

    camera.ptz_adapter = chosen
    camera.ptz_detected = True
    camera.ptz_capabilities_json = caps.model_dump_json()
    camera.ptz_last_probe_at = datetime.now(timezone.utc)
    camera.ptz_probe_error = ("; ".join(errors))[:255] or None
    db.commit()

    audit(
        user_id=_uid(user), camera_id=getattr(camera, "id", None),
        adapter=camera.ptz_adapter, command="detect",
        result="ok" if not errors else "probe_error", request_id=request_id,
    )
    return build_capabilities_response(camera)


__all__ = ["current_capabilities", "build_capabilities_response", "execute", "detect"]
