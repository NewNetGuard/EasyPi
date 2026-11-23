"""IP cameras agent module."""

from __future__ import annotations

import re

from app.agent.adapters.cameras import CamerasAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class CamerasAgent:
    """Explain camera, recording, and snapshot state from local facts."""

    name = "cameras_agent"
    _KEYWORDS = (
        "camera",
        "cameras",
        "recording",
        "recordings",
        "snapshot",
        "stream",
        "live view",
        "rtsp",
        "webrtc",
        "black screen",
        "export",
        "clip",
        "add camera",
        "onboard",
    )
    _ROUTES = ("camera",)

    def __init__(self, adapter: CamerasAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 100

        if any(token in route for token in self._ROUTES):
            score += 35

        if request.target:
            score += 10

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        tab = str(request.tab or "").strip().lower()
        question = " ".join(part for part in (request.question.lower(), tab) if part)
        route = (request.route or "").lower()
        target = str(request.target or "").strip()

        if not any(keyword in question or keyword in target.lower() for keyword in self._KEYWORDS) and "camera" not in route:
            return None

        cameras = await self.adapter.list_cameras()
        if not cameras:
            return AgentResponse(
                category="service",
                target="ip-cameras",
                matched=True,
                title="No cameras configured",
                summary="No IP cameras are set up yet — live view, recording, and snapshots are unavailable until you add one.",
                confidence="high",
                section="ip-cameras",
                subsection="overview",
                module=self.name,
                checks_run=["camera_inventory"],
                facts=[AgentFact("Configured cameras", "0")],
                reason_chain=[
                    "The local camera inventory was queried.",
                    "No camera records were found in the database.",
                ],
                recommendations=[
                    "Add a camera from the IP Cameras page using its RTSP URL (e.g. rtsp://user:pass@camera-ip:554/stream).",
                    "Once added, you can watch live, record, and capture snapshots.",
                ],
            )

        camera = self._find_camera(target or request.question, cameras)
        if camera is None:
            if tab == "recordings":
                return self._recordings_overview_response(cameras)
            if "add camera" in request.question.lower() or "onboard" in request.question.lower():
                return self._onboarding_response(cameras)
            return self._overview_response(cameras)

        return await self._camera_response(camera, question)

    def _recordings_overview_response(self, cameras: list[dict[str, object]]) -> AgentResponse:
        recordings = self.adapter.get_all_recordings()
        storage = self.adapter.get_storage_usage()
        return AgentResponse(
            category="service",
            target="camera-recordings",
            matched=True,
            title="Camera recordings diagnostics",
            summary=(
                f"The Recordings tab contains {len(recordings)} saved clip(s) across {len(cameras)} configured camera(s)."
                if recordings
                else "The Recordings tab is available, but no saved camera clips were found."
            ),
            confidence="high",
            section="ip-cameras",
            subsection="recordings",
            module=self.name,
            checks_run=["camera_inventory", "camera_recordings", "camera_storage"],
            facts=[
                AgentFact("Configured cameras", str(len(cameras))),
                AgentFact("Saved recordings", str(len(recordings))),
                AgentFact("Storage usage", str(storage.get("total_size_human") or "Unknown")),
            ],
            reason_chain=[
                "The active IP Cameras tab was identified as Recordings.",
                "Saved clips and camera storage were read from the same local sources used by the page.",
            ],
            recommendations=[
                "Select a specific camera or clip when you need recording-level diagnostics.",
            ],
        )

    async def _camera_response(self, camera: dict[str, object], question: str) -> AgentResponse:
        camera_id = str(camera.get("id") or "")
        camera_name = str(camera.get("name") or "Unknown camera")
        status = str(camera.get("status") or "unknown").lower()
        source_failures: list[str] = []
        try:
            recording_status = await self.adapter.get_recording_status(camera_id)
        except Exception as exc:
            recording_status = {}
            source_failures.append(f"{type(exc).__name__}: {exc}")
        # Explain is a read-only path.  Installing/checking FFmpeg through the
        # recording service may invoke apt, so availability is deliberately
        # left unknown until a dedicated side-effect-free status API exists.
        ffmpeg_status: dict[str, object] | None = None
        stream_info = await self._get_stream_info(camera_name)
        recordings = self.adapter.get_all_recordings()
        snapshots = self.adapter.list_snapshots(camera_name=camera_name)
        storage = self.adapter.get_storage_usage()
        snapshot_storage = self._get_snapshot_storage_usage()
        export_supported = self._export_supported()

        camera_recordings = [item for item in recordings if self._recording_matches_camera(item, camera)]
        latest_recording = camera_recordings[0] if camera_recordings else None
        is_recording = bool(recording_status.get("recording"))
        stream_ready = self._stream_ready(stream_info)

        facts = [
            AgentFact("Camera", camera_name),
            AgentFact("IP", str(camera.get("ip") or "Unknown")),
            AgentFact("Status", status or "unknown", "critical" if status in {"offline", "error"} else "info"),
            AgentFact("Recording active", self._yes_no(is_recording)),
            AgentFact("Saved recordings", str(len(camera_recordings))),
            AgentFact("Snapshots", str(len(snapshots))),
            AgentFact("Storage usage", str(storage.get("total_size_human") or "Unknown")),
            AgentFact(
                "FFmpeg available",
                "Unknown",
                "warning",
            ),
        ]
        for failure in source_failures:
            facts.append(AgentFact("Source failure", failure, "warning"))
        facts.append(
            AgentFact(
                "Live stream",
                "Ready" if stream_ready else ("Unavailable" if stream_info is None else "Not ready"),
                "info" if stream_ready else "warning",
            )
        )
        facts.append(
            AgentFact(
                "Live stream ready",
                "Yes" if stream_ready else ("Unknown" if not stream_info else "No"),
                "info" if stream_ready else "warning",
            )
        )
        if snapshot_storage:
            facts.append(
                AgentFact(
                    "Snapshot storage",
                    str(snapshot_storage.get("size_human") or snapshot_storage.get("total_size_human") or "Unknown"),
                )
            )
        facts.append(AgentFact("Clip export supported", self._yes_no(export_supported), "info" if export_supported else "warning"))
        if camera.get("lastSeen"):
            facts.append(AgentFact("Last seen", str(camera.get("lastSeen"))))
        if latest_recording is not None:
            facts.append(AgentFact("Latest recording", str(latest_recording.get("created_at") or "Unknown")))
        if isinstance(stream_info, dict):
            if "sourceReady" in stream_info:
                facts.append(
                    AgentFact(
                        "Source ready",
                        self._yes_no(bool(stream_info.get("sourceReady"))),
                        "info" if bool(stream_info.get("sourceReady")) else "warning",
                    )
                )
            if "readers" in stream_info:
                facts.append(AgentFact("Readers", str(stream_info.get("readers"))))

        if "export" in question or "clip" in question:
            if latest_recording is None:
                return AgentResponse(
                    category="service",
                    target=camera_name,
                    matched=True,
                    title=f"{camera_name} export diagnostics",
                    summary=f"EasyPi cannot export a clip for {camera_name} because no saved recording is currently available.",
                    confidence="high",
                    section="ip-cameras",
                    subsection="recordings",
                    module=self.name,
                    checks_run=["camera_inventory", "recording_storage"],
                    facts=facts,
                    reason_chain=[
                        "The camera exists in the local inventory.",
                        "No saved recording was found for this camera, so there is no clip candidate to export.",
                    ],
                    recommendations=[
                        "Record a clip first before using export-related workflows.",
                    ],
                )
            if not export_supported:
                return AgentResponse(
                    category="service",
                    target=camera_name,
                    matched=True,
                    title=f"{camera_name} export diagnostics",
                    summary="EasyPi supports whole-recording playback and download, not time-range clip extraction.",
                    confidence="high",
                    section="ip-cameras",
                    subsection="recordings",
                    module=self.name,
                    checks_run=["camera_inventory", "recording_storage", "export_capability"],
                    facts=facts,
                    reason_chain=[
                        "The camera has a saved recording that could become an export source.",
                        "This release exposes the complete recording rather than a partial export.",
                    ],
                    recommendations=[
                        "Play or download the complete recording from the Recordings tab.",
                    ],
                )

        if ("live" in question or "stream" in question or "black" in question or "webrtc" in question) and stream_info is None:
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} live view diagnostics",
                summary=f"EasyPi could not confirm a ready live stream for {camera_name}.",
                confidence="high",
                section="ip-cameras",
                subsection="live-view",
                module=self.name,
                source_status="unavailable",
                checks_run=["camera_inventory", "stream_info", "recording_status"],
                facts=facts,
                reason_chain=[
                    "The camera exists in the local inventory.",
                    "No ready MediaMTX stream info was returned for this camera.",
                ],
                recommendations=[
                    "Check go2rtc or MediaMTX stream registration and the RTSP source URL.",
                    "If the camera is online, retry live view after refreshing the stream pipeline.",
                ],
            )

        if ("live" in question or "stream" in question or "black" in question or "webrtc" in question) and not stream_ready:
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} live view diagnostics",
                summary=f"EasyPi sees a registered stream path for {camera_name}, but the live stream is not ready yet.",
                confidence="high",
                section="ip-cameras",
                subsection="live-view",
                module=self.name,
                source_status="partial",
                checks_run=["camera_inventory", "stream_info", "recording_status"],
                facts=facts,
                reason_chain=[
                    "The camera exists in the local inventory.",
                    "The MediaMTX path exists, but the stream is not marked ready by the local stream info.",
                ],
                recommendations=[
                    "Check the RTSP source URL, credentials, and whether MediaMTX can pull the source stream.",
                    "Retry live view after the stream path becomes ready.",
                ],
            )

        if "snapshot" in question and not snapshots:
            facts.append(AgentFact("Snapshot capture success", "Unknown (not tested)", "warning"))
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} snapshot diagnostics",
                summary=(
                    f"Snapshot capture success for {camera_name} is unknown because diagnostics are read-only; "
                    "no saved snapshot is currently available."
                ),
                confidence="low",
                section="ip-cameras",
                subsection="snapshots",
                module=self.name,
                checks_run=["camera_inventory", "snapshot_inventory", "recording_status"],
                facts=facts,
                reason_chain=[
                    "No saved snapshots were found for this camera.",
                    "The explain endpoint did not capture a new snapshot or write a media file.",
                ],
                recommendations=[
                    "Use the explicit Snapshot action in IP Cameras if you want to run a confirmed capture test.",
                ],
            )

        if "storage" in question and snapshot_storage:
            snapshot_size = str(snapshot_storage.get("size_human") or snapshot_storage.get("total_size_human") or "").strip()
            if snapshot_size:
                return AgentResponse(
                    category="service",
                    target=camera_name,
                    matched=True,
                    title=f"{camera_name} snapshot storage diagnostics",
                    summary=f"EasyPi is currently storing snapshot data for {camera_name} in addition to recordings.",
                    confidence="medium",
                    section="ip-cameras",
                    subsection="storage",
                    module=self.name,
                    checks_run=["camera_inventory", "recording_storage", "snapshot_storage"],
                    facts=facts,
                    reason_chain=[
                        "Camera recording and snapshot storage usage were inspected locally.",
                        "Snapshot storage metadata is available for this camera workflow.",
                    ],
                    recommendations=[
                        "Clean up old snapshots together with recordings if media storage keeps growing unexpectedly.",
                    ],
                )

        if status in {"offline", "error"} and is_recording:
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} camera state conflict",
                summary=f"Camera state is inconsistent: {camera_name} is marked offline while recording is reported active.",
                confidence="low",
                section="ip-cameras",
                subsection="recordings",
                module=self.name,
                checks_run=["camera_inventory", "recording_status"],
                facts=facts,
                reason_chain=["Inventory and recording runtime report contradictory states."],
                recommendations=["Verify the live camera and recorder processes before changing either state."],
            )

        if status in {"offline", "error"}:
            partial = f" A dependency also failed with {source_failures[0]}." if source_failures else ""
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} is offline",
                summary=f"EasyPi currently sees {camera_name} as offline.{partial}",
                confidence="low" if source_failures else "high",
                section="ip-cameras",
                subsection="live-view",
                module=self.name,
                checks_run=["camera_inventory", "recording_status", "recording_storage"],
                facts=facts,
                reason_chain=[
                    "The camera status stored in EasyPi is offline or error.",
                    "Current recording state was checked to confirm there is no active capture.",
                ],
                recommendations=[
                    "Check camera power, network reachability, and RTSP credentials.",
                    "Open live view after the camera returns online.",
                ],
            )

        if is_recording:
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} is recording",
                summary=f"EasyPi is actively recording {camera_name}.",
                confidence="high",
                section="ip-cameras",
                subsection="recordings",
                module=self.name,
                checks_run=["camera_inventory", "recording_status", "recording_storage"],
                facts=facts,
                reason_chain=[
                    "The camera exists in the local inventory.",
                    "The recording service reports an active recording process for this camera.",
                ],
                recommendations=[
                    "If clips still do not appear, inspect the recordings list and storage usage.",
                ],
            )

        if "record" in question and not camera_recordings:
            if ffmpeg_status is not None and not bool(ffmpeg_status.get("success", True)):
                facts.append(AgentFact("FFmpeg issue", str(ffmpeg_status.get("message") or "Unknown"), "critical"))
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"No recordings found for {camera_name}",
                summary=f"EasyPi did not find saved recordings for {camera_name}.",
                confidence="high",
                section="ip-cameras",
                subsection="recordings",
                module=self.name,
                checks_run=["camera_inventory", "recording_status", "recording_storage"],
                facts=facts,
                reason_chain=[
                    "The camera exists in the local inventory.",
                    "The recording storage does not contain saved clips for this camera.",
                ],
                recommendations=[
                    "Start recording for the camera and verify FFmpeg is installed.",
                    "Check camera reachability and RTSP settings if recording should already exist.",
                ],
            )

        if ("storage" in question or "full" in question or "space" in question) and str(storage.get("total_size_human") or "").strip():
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title=f"{camera_name} storage diagnostics",
                summary=f"EasyPi storage usage for camera media is currently {storage.get('total_size_human') or 'in use'}.",
                confidence="medium",
                section="ip-cameras",
                subsection="storage",
                module=self.name,
                checks_run=["camera_inventory", "recording_storage"],
                facts=facts,
                reason_chain=[
                    "Camera media storage usage was inspected.",
                    "Stored recordings and snapshots contribute to current camera storage use.",
                ],
                recommendations=[
                    "Clean up old recordings or snapshots if storage pressure becomes visible elsewhere.",
                ],
            )

        return AgentResponse(
            category="service",
            target=camera_name,
            matched=True,
            title=f"{camera_name} camera diagnostics",
            summary=f"{camera_name} is configured and currently not recording.",
            confidence="medium",
            section="ip-cameras",
            subsection="overview",
            module=self.name,
            checks_run=["camera_inventory", "recording_status", "recording_storage", "stream_info"],
            facts=facts,
            reason_chain=[
                "The camera exists in the local inventory.",
                "No active recording process is running for this camera.",
            ],
            recommendations=[
                "Use Start Recording if continuous recording should be active.",
                "Check live view and snapshots if you want to validate the stream first.",
            ],
        )

    def _overview_response(self, cameras: list[dict[str, object]]) -> AgentResponse:
        online = sum(1 for camera in cameras if str(camera.get("status") or "").lower() in {"online", "recording"})
        offline = sum(1 for camera in cameras if str(camera.get("status") or "").lower() in {"offline", "error"})
        storage = self.adapter.get_storage_usage()
        facts = [
            AgentFact("Configured cameras", str(len(cameras))),
            AgentFact("Online cameras", str(online)),
            AgentFact("Offline cameras", str(offline), "warning" if offline else "info"),
            AgentFact("Stored media", str(storage.get("file_count") or 0)),
            AgentFact("Storage usage", str(storage.get("total_size_human") or "Unknown")),
        ]
        return AgentResponse(
            category="service",
            target="ip-cameras",
            matched=True,
            title="Camera overview",
            summary="EasyPi camera inventory and storage status were collected successfully.",
            confidence="medium",
            section="ip-cameras",
            subsection="overview",
            module=self.name,
            checks_run=["camera_inventory", "recording_storage"],
            facts=facts,
            reason_chain=[
                "The local camera inventory was queried.",
                "Recording and snapshot storage usage was inspected.",
            ],
            recommendations=[
                "Include the camera name in your question for a specific diagnosis.",
            ],
        )

    def _onboarding_response(self, cameras: list[dict[str, object]]) -> AgentResponse:
        facts = [
            AgentFact("Configured cameras", str(len(cameras))),
            AgentFact(
                "Existing camera names",
                ", ".join(str(camera.get("name") or "Unknown") for camera in cameras[:3]) or "None",
            ),
        ]
        if cameras:
            summary = "EasyPi already has configured cameras, so onboarding should add a new camera only if it is not already present."
            confidence = "medium"
            reason_chain = [
                "The local camera inventory was inspected before onboarding guidance.",
                "One or more cameras already exist in the current EasyPi configuration.",
            ]
        else:
            summary = "EasyPi has no configured cameras yet, so onboarding can start with a new RTSP camera entry."
            confidence = "high"
            reason_chain = [
                "The local camera inventory was inspected before onboarding guidance.",
                "No cameras are currently configured on this EasyPi instance.",
            ]
        return AgentResponse(
            category="service",
            target="ip-cameras",
            matched=True,
            title="Camera onboarding diagnostics",
            summary=summary,
            confidence=confidence,
            section="ip-cameras",
            subsection="onboarding",
            module=self.name,
            checks_run=["camera_inventory"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Add the camera name, IP address, and working RTSP credentials before testing live view or recording.",
                "Use live view or snapshot checks immediately after onboarding to validate the stream path.",
            ],
        )

    def _find_camera(self, value: str, cameras: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return cameras[0] if len(cameras) == 1 else None

        best_match = None
        best_length = 0
        for camera in cameras:
            camera_id = str(camera.get("id") or "").strip().lower()
            name = str(camera.get("name") or "").strip().lower()
            ip_address = str(camera.get("ip") or "").strip().lower()
            if normalized in {camera_id, name, ip_address}:
                return camera
            if name and name in normalized and len(name) > best_length:
                best_match = camera
                best_length = len(name)
        return best_match

    def _recording_matches_camera(self, recording: dict[str, object], camera: dict[str, object]) -> bool:
        camera_name = self._normalize_name(str(camera.get("name") or ""))
        camera_id = str(camera.get("id") or "")
        recording_bucket = self._normalize_name(str(recording.get("camera") or ""))
        filename = self._normalize_name(str(recording.get("filename") or ""))
        camera_id_prefix = camera_id[:8].lower()
        return (
            bool(camera_name) and recording_bucket == camera_name
            or bool(camera_id_prefix) and recording_bucket in {camera_id.lower(), camera_id_prefix}
            or bool(camera_name) and any(filename.startswith(f"{camera_name}{separator}") for separator in ("_", "-", "."))
        )

    def _normalize_name(self, value: str) -> str:
        return re.sub(r"[^a-z0-9_-]+", "_", value.strip().lower()).strip("_")

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    async def _get_stream_info(self, camera_name: str) -> dict[str, object] | None:
        method = getattr(self.adapter, "get_stream_info", None)
        if callable(method):
            result = await method(camera_name)
            return result if isinstance(result, dict) else None
        return None

    async def _capture_snapshot(self, camera_name: str) -> dict[str, object]:
        method = getattr(self.adapter, "capture_snapshot", None)
        if callable(method):
            result = await method(camera_name)
            return result if isinstance(result, dict) else {}
        return {"success": False, "message": "Snapshot capture is not available in the current adapter."}

    def _get_snapshot_storage_usage(self) -> dict[str, object]:
        method = getattr(self.adapter, "get_snapshot_storage_usage", None)
        if callable(method):
            result = method()
            return result if isinstance(result, dict) else {}
        return {}

    def _export_supported(self) -> bool:
        method = getattr(self.adapter, "is_export_supported", None)
        if callable(method):
            return bool(method())
        return False

    def _stream_ready(self, stream_info: dict[str, object] | None) -> bool:
        if stream_info is None:
            return False
        if "ready" in stream_info:
            return bool(stream_info.get("ready"))
        if "sourceReady" in stream_info:
            return bool(stream_info.get("sourceReady"))
        if "readyTime" in stream_info:
            return bool(stream_info.get("readyTime"))
        return False
