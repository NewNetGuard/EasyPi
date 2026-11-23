"""Cross-section reasoning for camera media, backups, and cloud storage."""

from __future__ import annotations

import asyncio
import re

from app.agent.adapters.backup import BackupAdapter
from app.agent.adapters.cameras import CamerasAdapter
from app.agent.adapters.cloud import CloudAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class CameraBackupCloudReasoningAgent:
    """Explain shared storage and media symptoms across cameras, backups, and cloud."""

    name = "camera_backup_cloud_reasoning_agent"
    _CAMERA_WORDS = ("camera", "cameras", "recording", "recordings", "snapshot", "stream", "clip", "media")
    _BACKUP_WORDS = ("backup", "backups", "restore", "archive")
    _CLOUD_WORDS = ("cloud", "picloud", "storage", "space", "full", "capacity", "telegram")
    _ROUTES = ("camera", "backup", "cloud", "dashboard")
    _STORAGE_ERROR_WORDS = ("space", "disk", "storage", "full", "capacity", "no space", "quota")

    def __init__(self, cameras: CamerasAdapter, backup: BackupAdapter, cloud: CloudAdapter) -> None:
        self.cameras = cameras
        self.backup = backup
        self.cloud = cloud

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        domain_hits = sum(
            1
            for keywords in (self._CAMERA_WORDS, self._BACKUP_WORDS, self._CLOUD_WORDS)
            if any(keyword in question or keyword in target for keyword in keywords)
        )

        score = 0
        if domain_hits >= 2:
            score += 160
        elif any(token in route for token in self._ROUTES) and domain_hits >= 1 and any(
            word in question for word in ("why", "broken", "failing", "issue", "problem", "full")
        ):
            score += 85

        if request.target:
            score += 10

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        cameras, backups = await asyncio.gather(
            self.cameras.list_cameras(),
            self.backup.list_backups(),
        )
        recordings = self.cameras.get_all_recordings()
        snapshots = self.cameras.list_snapshots()
        local_storage = self.cameras.get_storage_usage()
        cloud_stats = self.cloud.get_storage_stats()
        recent_cloud_files = self.cloud.get_recent_files(limit=5)

        if not any((cameras, backups, recordings, snapshots, local_storage, cloud_stats, recent_cloud_files)):
            return AgentResponse(
                category="service", target="media-storage", matched=True,
                title="Camera, backup, and cloud diagnostics",
                summary="Camera, backup, and cloud data are insufficient or unavailable.",
                confidence="low", section="dashboard", subsection="media-storage", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["All media-storage sources returned empty state."],
                recommendations=["Restore the source APIs before inferring storage consistency."],
            )

        target_camera = self._find_camera(str(request.target or request.question), cameras)
        offline_cameras = [camera for camera in cameras if str(camera.get("status") or "").lower() in {"offline", "error"}]
        failed_backup = next((item for item in backups if str(item.get("status") or "").lower() == "failed"), None)
        running_backup = next((item for item in backups if str(item.get("status") or "").lower() == "running"), None)
        cloud_percent = float(cloud_stats.get("percent") or 0)
        cloud_pressure = cloud_percent >= 90
        backup_storage_error = failed_backup is not None and self._contains_storage_error(str(failed_backup.get("error_message") or ""))
        camera_problem = target_camera is not None and str(target_camera.get("status") or "").lower() in {"offline", "error"}
        media_present = bool(recordings or snapshots or int(local_storage.get("file_count") or 0) > 0)

        facts = [
            AgentFact("Configured cameras", str(len(cameras))),
            AgentFact("Offline cameras", str(len(offline_cameras)), "warning" if offline_cameras else "info"),
            AgentFact("Saved recordings", str(len(recordings))),
            AgentFact("Snapshots", str(len(snapshots))),
            AgentFact("Local media files", str(local_storage.get("file_count") or 0)),
            AgentFact("Local media usage", str(local_storage.get("total_size_human") or "Unknown")),
            AgentFact("Cloud usage", f"{cloud_percent:.1f}%", "warning" if cloud_pressure else "info"),
            AgentFact("Recent cloud files", str(len(recent_cloud_files))),
            AgentFact("Failed backups", "1" if failed_backup else "0", "warning" if failed_backup else "info"),
        ]
        if target_camera is not None:
            facts.append(
                AgentFact(
                    "Target camera",
                    str(target_camera.get("name") or "Unknown"),
                    "critical" if camera_problem else "info",
                )
            )
        if failed_backup is not None:
            facts.append(AgentFact("Latest failed backup", str(failed_backup.get("name") or "Unknown"), "warning"))
            if failed_backup.get("error_message"):
                facts.append(AgentFact("Backup error", str(failed_backup.get("error_message")), "warning"))
        elif running_backup is not None:
            facts.append(AgentFact("Running backup", str(running_backup.get("name") or "Unknown")))

        base_reason = (
            "Current diagnostics compare local camera media state, system backup history, and cloud storage capacity."
        )

        if backup_storage_error and cloud_pressure and media_present:
            return AgentResponse(
                category="service",
                target="media-storage",
                matched=True,
                title="Camera, backup, and cloud diagnostics",
                summary="Storage pressure is showing up across camera media, backup history, and cloud capacity.",
                confidence="high",
                section="dashboard",
                subsection="media-storage",
                module=self.name,
                checks_run=["camera_inventory", "recording_storage", "backup_history", "cloud_storage_stats"],
                facts=facts,
                reason_chain=[
                    base_reason,
                    "The latest backup failure mentions a storage or capacity problem.",
                    "Cloud storage usage is already near the critical threshold.",
                    "Local camera media files are present, so media retention is adding more storage pressure.",
                ],
                recommendations=[
                    "Free storage space before retrying backup jobs.",
                    "Review camera retention and delete unneeded media if storage pressure remains high.",
                    "Treat cloud capacity as a separate ceiling until camera archive export exists explicitly.",
                ],
            )

        if camera_problem and failed_backup is None and not cloud_pressure:
            camera_name = str(target_camera.get("name") or "The target camera")
            return AgentResponse(
                category="service",
                target=camera_name,
                matched=True,
                title="Camera, backup, and cloud diagnostics",
                summary=f"{camera_name} has a camera-side problem, while backup and cloud signals currently look healthy.",
                confidence="high",
                section="dashboard",
                subsection="media-storage",
                module=self.name,
                checks_run=["camera_inventory", "recording_storage", "backup_history", "cloud_storage_stats"],
                facts=facts,
                reason_chain=[
                    base_reason,
                    "The target camera is marked offline or in error.",
                    "There is no matching failed system backup, and cloud storage is not under high pressure.",
                ],
                recommendations=[
                    "Fix camera reachability or stream credentials first.",
                    "Do not treat this as a cloud or backup-wide incident unless new failures appear there too.",
                ],
            )

        if failed_backup is not None and not backup_storage_error and not camera_problem and not cloud_pressure:
            return AgentResponse(
                category="service",
                target="system-backup",
                matched=True,
                title="Camera, backup, and cloud diagnostics",
                summary="The current problem looks isolated to System Backup rather than cameras or cloud storage.",
                confidence="high",
                section="dashboard",
                subsection="media-storage",
                module=self.name,
                checks_run=["camera_inventory", "recording_storage", "backup_history", "cloud_storage_stats"],
                facts=facts,
                reason_chain=[
                    base_reason,
                    "A backup failure is present.",
                    "The failure does not read like a storage-capacity error, and camera plus cloud signals stay stable.",
                ],
                recommendations=[
                    "Inspect the latest backup error directly in System Backup.",
                    "Only treat this as a shared storage problem if backup errors mention disk or capacity pressure.",
                ],
            )

        if cloud_pressure and failed_backup is None and not camera_problem:
            return AgentResponse(
                category="service",
                target="cloud-storage",
                matched=True,
                title="Camera, backup, and cloud diagnostics",
                summary="Cloud capacity is high, but current camera and backup signals do not confirm the same failure yet.",
                confidence="medium",
                section="dashboard",
                subsection="media-storage",
                module=self.name,
                checks_run=["camera_inventory", "recording_storage", "backup_history", "cloud_storage_stats"],
                facts=facts,
                reason_chain=[
                    base_reason,
                    "Cloud storage usage is near the critical threshold.",
                    "No failed system backup or camera-offline signal currently proves a shared storage incident.",
                ],
                recommendations=[
                    "Reduce cloud storage pressure before it turns into a wider storage incident.",
                    "If recordings or backups start failing next, compare the new error text for storage-related wording.",
                ],
            )

        return AgentResponse(
            category="service",
            target="media-storage",
            matched=True,
            title="Camera, backup, and cloud diagnostics",
            summary="Camera media, backup history, and cloud storage look internally consistent right now.",
            confidence="medium",
            section="dashboard",
            subsection="media-storage",
            module=self.name,
            checks_run=["camera_inventory", "recording_storage", "backup_history", "cloud_storage_stats"],
            facts=facts,
            reason_chain=[
                base_reason,
                "No shared media-storage incident was confirmed from the current local facts.",
            ],
            recommendations=[
                "Ask again with a camera name, backup name, or cloud symptom if you want a narrower explanation.",
            ],
        )

    def _find_camera(self, value: str, cameras: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
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

    def _contains_storage_error(self, value: str) -> bool:
        text = re.sub(r"\s+", " ", value.strip().lower())
        return any(token in text for token in self._STORAGE_ERROR_WORDS)
