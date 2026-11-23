"""Camera fact adapter for agent modules."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from app.api.v1.endpoints.camera_helpers import get_go2rtc_rtsp_url
from app.db.session import SessionLocal
from app.models.camera import Camera
from app.services.mediamtx_client import mediamtx_client
from app.services.recording_service import recording_service
from app.services.snapshot_service import snapshot_service


class CamerasAdapter:
    """Expose read-only camera and recording state."""

    def __init__(
        self,
        *,
        recordings: Any | None = None,
        snapshots: Any | None = None,
        mediamtx: Any | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.recordings = recordings or recording_service
        self.snapshots = snapshots or snapshot_service
        self.mediamtx = mediamtx or mediamtx_client
        self.session_factory = session_factory or SessionLocal

    async def list_cameras(self) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            cameras = db.query(Camera).order_by(Camera.created_at.desc()).all()
            return [camera.to_response() for camera in cameras]
        finally:
            db.close()

    async def get_recording_status(self, camera_id: str) -> dict[str, Any]:
        status = await self.recordings.get_recording_status(camera_id)
        return status if isinstance(status, dict) else {}

    def get_all_recordings(self) -> list[dict[str, Any]]:
        recordings = self.recordings.get_all_recordings()
        return [item for item in recordings if isinstance(item, dict)]

    def list_snapshots(self, camera_name: str | None = None) -> list[dict[str, Any]]:
        snapshots = self.snapshots.list_snapshots(camera_name=camera_name)
        return [item for item in snapshots if isinstance(item, dict)]

    def get_storage_usage(self) -> dict[str, Any]:
        usage = self.recordings.get_storage_usage()
        return usage if isinstance(usage, dict) else {}

    def get_snapshot_storage_usage(self) -> dict[str, Any]:
        method = getattr(self.recordings, "get_snapshots_storage_info", None)
        if not callable(method):
            return {}
        usage = method()
        return usage if isinstance(usage, dict) else {}

    def is_export_supported(self) -> bool:
        return False

    async def ensure_ffmpeg_installed(self) -> dict[str, Any]:
        result = await self.recordings.ensure_ffmpeg_installed()
        return result if isinstance(result, dict) else {}

    async def capture_snapshot(self, camera_name: str) -> dict[str, Any]:
        db = self.session_factory()
        try:
            camera = self._find_camera(db, camera_name)
            if camera is None:
                return {"success": False, "message": f'Camera "{camera_name}" was not found.'}
            result = await self.recordings.capture_snapshot(
                camera_id=camera.id,
                camera_name=camera.name,
                rtsp_url=get_go2rtc_rtsp_url(camera.name, camera.id),
            )
            return result if isinstance(result, dict) else {"success": False, "message": "Unexpected snapshot result"}
        finally:
            db.close()

    async def get_stream_info(self, camera_name: str) -> dict[str, Any] | None:
        db = self.session_factory()
        try:
            camera = self._find_camera(db, camera_name)
            if camera is None:
                return None
            info = await self.mediamtx.get_stream_info(camera.id)
            return info if isinstance(info, dict) else None
        finally:
            db.close()

    async def start_recording(self, camera_name: str) -> dict[str, Any]:
        db = self.session_factory()
        try:
            camera = self._find_camera(db, camera_name)
            if camera is None:
                return {"success": False, "message": f'Camera "{camera_name}" was not found.'}
            result = await self.recordings.start_recording(
                camera_id=camera.id,
                camera_name=camera.name,
                rtsp_url=get_go2rtc_rtsp_url(camera.name, camera.id),
            )
            if result.get("success"):
                camera.status = "recording"
                camera.last_seen = datetime.now(timezone.utc)
                db.commit()
            return result if isinstance(result, dict) else {"success": False, "message": "Unexpected recording result"}
        finally:
            db.close()

    async def stop_recording(self, camera_name: str) -> dict[str, Any]:
        db = self.session_factory()
        try:
            camera = self._find_camera(db, camera_name)
            if camera is None:
                return {"success": False, "message": f'Camera "{camera_name}" was not found.'}
            result = await self.recordings.stop_recording(camera.id)
            if not isinstance(result, dict):
                return {"success": False, "message": "The recorder did not confirm that recording stopped."}
            if bool(result.get("success")):
                camera.status = "online"
                camera.last_seen = datetime.now(timezone.utc)
                db.commit()
            return dict(result)
        finally:
            db.close()

    async def restart_recording(self, camera_name: str) -> dict[str, Any]:
        stop_result = await self.stop_recording(camera_name)
        if not bool(stop_result.get("success", False)):
            failure = dict(stop_result)
            failure["success"] = False
            failure.setdefault(
                "message",
                "The recorder did not confirm that the existing recording stopped.",
            )
            return failure
        return await self.start_recording(camera_name)

    def _find_camera(self, db: Any, value: str) -> Camera | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        cameras = db.query(Camera).order_by(Camera.created_at.desc()).all()
        for camera in cameras:
            if normalized in {
                str(camera.id).strip().lower(),
                str(camera.name or "").strip().lower(),
                str(camera.ip or "").strip().lower(),
            }:
                return camera
        return None
