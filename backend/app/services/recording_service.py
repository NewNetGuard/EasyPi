"""
Recording service for IP cameras using FFmpeg.

Manages ffmpeg processes for continuous recording of RTSP streams.
Supports:
- Continuous recording with segment rotation
- Automatic restart on failure
- Storage management
- Snapshot capture
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional
from config import ROOT_DIR
from app.core.safe_storage import (
    open_regular_beneath,
    rmdir_empty_beneath,
    unlink_regular_beneath,
)

logger = logging.getLogger("easypi")
RUNNER_PATH = str(ROOT_DIR / "scripts" / "runner")


@dataclass
class RecordingProcess:
    """Represents an active ffmpeg recording process."""
    camera_id: str
    camera_name: str
    rtsp_url: str
    output_dir: Path
    process: Optional[subprocess.Popen] = None
    started_at: Optional[datetime] = None
    segment_duration: int = 3600  # 1 hour segments
    restart_count: int = 0
    max_restarts: int = 5


class RecordingService:
    """Service for managing camera recordings via FFmpeg."""
    
    def __init__(self, recordings_base_path: str = None):
        if recordings_base_path is None:
            recordings_base_path = str(ROOT_DIR / "data" / "recordings")
        self.recordings_path = Path(recordings_base_path)
        self.recordings_path.mkdir(parents=True, exist_ok=True)
        self._processes: Dict[str, RecordingProcess] = {}
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        self._ffmpeg_checked = False
        self._loop_count = 0  # throttles the storage guard within the monitor loop

    def _safe_recording_file(self, candidate: Path, suffix: str) -> Optional[Path]:
        try:
            if candidate.is_symlink() or not candidate.is_file():
                return None
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(self.recordings_path.resolve(strict=True))
            if resolved.suffix.lower() != suffix:
                return None
            return resolved
        except (OSError, ValueError):
            return None

    def _safe_snapshot_file(self, candidate: Path) -> Optional[Path]:
        try:
            snapshot_root = self.get_snapshots_dir()
            if snapshot_root.is_symlink():
                return None
            if candidate.is_symlink() or not candidate.is_file():
                return None
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(snapshot_root.resolve(strict=True))
            if resolved.suffix.lower() not in {".jpg", ".jpeg", ".png"}:
                return None
            return resolved
        except (OSError, ValueError):
            return None

    def _unlink_recording_file(self, path: Path) -> os.stat_result:
        root = self.recordings_path.resolve(strict=True)
        relative = path.relative_to(root)
        return unlink_regular_beneath(root, relative, suffixes={".mp4"})
        
    @property
    def ffmpeg_available(self) -> bool:
        """Check if ffmpeg is installed."""
        return shutil.which("ffmpeg") is not None
    
    async def ensure_ffmpeg_installed(self) -> dict:
        """
        Check if ffmpeg is installed, attempt to install if not.
        
        Returns:
            dict with success status and message
        """
        if self.ffmpeg_available:
            return {"success": True, "message": "FFmpeg is already installed"}
        
        logger.info("FFmpeg not found; requesting the approved installation helper")
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                "sudo",
                "-n",
                RUNNER_PATH,
                "setup/install_ffmpeg.sh",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=620,
            )
            output = stdout.decode("utf-8", errors="replace")
            error_output = stderr.decode("utf-8", errors="replace")
            if process.returncode != 0:
                logger.error(
                    "Approved FFmpeg installer failed (rc=%s): %s",
                    process.returncode,
                    (error_output or output)[-4096:],
                )
                return {
                    "success": False,
                    "error": "FFmpeg installation failed; inspect the EasyPi service logs",
                }

            if self.ffmpeg_available:
                version_proc = await asyncio.create_subprocess_exec(
                    "ffmpeg",
                    "-version",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await version_proc.communicate()
                version_line = (
                    stdout.decode("utf-8", errors="replace").splitlines()[0]
                    if stdout
                    else "unknown"
                )
                logger.info("FFmpeg installed successfully: %s", version_line)
                return {
                    "success": True,
                    "message": "FFmpeg installed successfully",
                    "version": version_line,
                }
            return {
                "success": False,
                "error": "FFmpeg installer completed but the binary is unavailable",
            }
        except asyncio.TimeoutError:
            if process is not None and process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
            return {
                "success": False,
                "error": "FFmpeg installation timed out; inspect the EasyPi service logs",
            }
        except Exception as e:
            logger.error("Failed to install FFmpeg through the runner: %s", e)
            return {
                "success": False,
                "error": "FFmpeg installation could not be started",
            }

    
    def _get_camera_dir(self, camera_id: str, camera_name: str) -> Path:
        """Get recording directory for a camera."""
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in camera_name)
        camera_dir = self.recordings_path / f"{safe_name}_{camera_id[:8]}"
        camera_dir.mkdir(parents=True, exist_ok=True)
        return camera_dir
    
    def _build_ffmpeg_command(self, rec: RecordingProcess) -> list[str]:
        """Build ffmpeg command for recording."""
        date_str = datetime.now().strftime("%Y-%m-%d")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in rec.camera_name)
        safe_name = safe_name[:100] or "camera"
        output_pattern = rec.output_dir / date_str / f"{safe_name}_%Y%m%d_%H%M%S.mp4"
        
        # Ensure date directory exists
        (rec.output_dir / date_str).mkdir(parents=True, exist_ok=True)
        
        return [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "warning",
            # Input options
            "-rtsp_transport", "tcp",
            "-i", rec.rtsp_url,
            # Output options - segment muxer for continuous recording
            "-c:v", "copy",           # Copy video codec (no re-encoding)
            "-c:a", "aac",            # Re-encode audio to AAC for compatibility
            "-f", "segment",
            "-segment_time", str(rec.segment_duration),
            "-segment_format", "mp4",
            "-reset_timestamps", "1",
            "-strftime", "1",
            str(output_pattern),
        ]
    
    async def start_recording(self, camera_id: str, camera_name: str, rtsp_url: str) -> dict:
        """
        Start recording for a camera.
        
        Args:
            camera_id: Unique camera identifier
            camera_name: Human-readable camera name
            rtsp_url: Full RTSP URL with credentials
            
        Returns:
            dict with status and message
        """
        # Auto-install ffmpeg if not available (first time only)
        if not self.ffmpeg_available:
            if not self._ffmpeg_checked:
                self._ffmpeg_checked = True
                install_result = await self.ensure_ffmpeg_installed()
                if not install_result.get("success"):
                    return {
                        "success": False,
                        "error": install_result.get("error", "FFmpeg installation failed")
                    }
            else:
                return {
                    "success": False,
                    "error": "FFmpeg is not installed. Install with: sudo apt install ffmpeg"
                }
        
        # Check if already recording
        if camera_id in self._processes:
            existing = self._processes[camera_id]
            if existing.process and existing.process.poll() is None:
                return {
                    "success": True,
                    "message": "Recording already active",
                    "started_at": existing.started_at.isoformat() if existing.started_at else None
                }

        # Storage pre-write guard: never start a recording that pushes the disk
        # toward full. Free space first (ring buffer); refuse only if still critical.
        guard, min_free, _target, _ret = self._storage_cfg()
        if guard and self._free_pct() < min_free:
            await self.enforce_storage_limits()
            hard_floor = max(2.0, min_free / 2.0)
            if self._free_pct() < hard_floor:
                msg = f"Not enough free disk space to record ({self._free_pct():.1f}% free)"
                logger.error(f"Storage guard blocked recording for {camera_name}: {msg}")
                return {"success": False, "error": msg}

        # FFmpeg consumes go2rtc's loopback stream so camera credentials never
        # appear in a long-running process command line.
        from app.api.v1.endpoints.camera_helpers import get_go2rtc_rtsp_url

        rtsp_url = get_go2rtc_rtsp_url(camera_name, camera_id)

        # Create recording process
        output_dir = self._get_camera_dir(camera_id, camera_name)
        rec = RecordingProcess(
            camera_id=camera_id,
            camera_name=camera_name,
            rtsp_url=rtsp_url,
            output_dir=output_dir,
        )
        
        try:
            cmd = self._build_ffmpeg_command(rec)
            logger.info("Starting ffmpeg recording for %s", camera_name)
            
            rec.process = await asyncio.to_thread(
                subprocess.Popen,
                cmd,
                # A long-running recorder must never block on an undrained
                # pipe. Raw FFmpeg diagnostics may also contain the RTSP URL,
                # including camera credentials, so they are not persisted.
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # Detach from parent process
            )
            rec.started_at = datetime.now(timezone.utc)
            self._processes[camera_id] = rec
            
            # Give ffmpeg a moment to start and check for immediate errors
            await asyncio.sleep(1)
            
            if rec.process.poll() is not None:
                exit_code = rec.process.returncode
                logger.error(
                    "FFmpeg failed to start for %s (exit code: %s)",
                    camera_name,
                    exit_code,
                )
                del self._processes[camera_id]
                return {
                    "success": False,
                    "error": f"FFmpeg failed to start (exit code {exit_code})",
                }
            
            logger.info(f"Recording started for {camera_name} (PID: {rec.process.pid})")
            return {
                "success": True,
                "message": f"Recording started for {camera_name}",
                "started_at": rec.started_at.isoformat()
            }
            
        except Exception as exc:
            logger.error(
                "Failed to start recording for %s: %s",
                camera_name,
                type(exc).__name__,
            )
            return {
                "success": False,
                "error": "Recording process could not be started",
            }
    
    async def stop_recording(self, camera_id: str) -> dict:
        """
        Stop recording for a camera.
        
        Args:
            camera_id: Camera identifier
            
        Returns:
            dict with status and message
        """
        if camera_id not in self._processes:
            return {
                "success": True,
                "message": "Recording was not active"
            }
        
        rec = self._processes[camera_id]
        
        try:
            if rec.process and rec.process.poll() is None:
                # Send SIGTERM for graceful shutdown
                rec.process.terminate()
                
                # Wait up to 5 seconds for graceful exit
                try:
                    rec.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    # Force kill if still running
                    rec.process.kill()
                    rec.process.wait(timeout=2)
                
                logger.info(f"Recording stopped for {rec.camera_name}")
            
            del self._processes[camera_id]
            
            return {
                "success": True,
                "message": f"Recording stopped for {rec.camera_name}"
            }
            
        except Exception as exc:
            logger.error(
                "Error stopping recording for %s: %s",
                rec.camera_name,
                type(exc).__name__,
            )
            # Try to clean up anyway
            if camera_id in self._processes:
                del self._processes[camera_id]
            return {
                "success": False,
                "error": "Recording process could not be stopped",
            }
    
    async def get_recording_status(self, camera_id: str) -> dict:
        """Get recording status for a camera."""
        if camera_id not in self._processes:
            return {
                "recording": False,
                "status": "stopped"
            }
        
        rec = self._processes[camera_id]
        is_running = rec.process and rec.process.poll() is None
        
        return {
            "recording": is_running,
            "status": "recording" if is_running else "stopped",
            "started_at": rec.started_at.isoformat() if rec.started_at else None,
            "restart_count": rec.restart_count
        }
    
    async def capture_snapshot(self, camera_id: str, camera_name: str, rtsp_url: str) -> dict:
        """
        Capture a single snapshot from camera.
        
        Args:
            camera_id: Camera identifier
            camera_name: Camera name
            rtsp_url: RTSP URL
            
        Returns:
            dict with path to snapshot or error
        """
        if not self.ffmpeg_available:
            return {
                "success": False,
                "error": "FFmpeg is not installed"
            }
        
        snapshot_dir = self.recordings_path / "snapshots"
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in camera_name)
        snapshot_path = snapshot_dir / f"{safe_name}_{timestamp}.jpg"
        
        from app.api.v1.endpoints.camera_helpers import get_go2rtc_rtsp_url

        rtsp_url = get_go2rtc_rtsp_url(camera_name, camera_id)
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "error",
            "-rtsp_transport", "tcp",
            "-i", rtsp_url,
            "-frames:v", "1",
            "-q:v", "2",  # High quality JPEG
            "-y",  # Overwrite
            str(snapshot_path),
        ]
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            
            await asyncio.wait_for(process.communicate(), timeout=10)
            
            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"Snapshot failed (exit code {process.returncode})",
                }
            
            if snapshot_path.exists():
                return {
                    "success": True,
                    "filename": snapshot_path.name,
                    "size": snapshot_path.stat().st_size,
                    "timestamp": timestamp
                }
            else:
                return {
                    "success": False,
                    "error": "Snapshot file was not created"
                }
                
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": "Snapshot timed out (10s)"
            }
        except Exception as exc:
            logger.error(
                "Snapshot capture failed for %s: %s",
                camera_name,
                type(exc).__name__,
            )
            return {
                "success": False,
                "error": "Snapshot process could not be started",
            }
    
    def get_all_recordings(self) -> list[dict]:
        """Get list of all recording files."""
        recordings = []
        
        for camera_dir in self.recordings_path.iterdir():
            if (
                not camera_dir.is_symlink()
                and camera_dir.is_dir()
                and camera_dir.name != "snapshots"
            ):
                for date_dir in camera_dir.iterdir():
                    if not date_dir.is_symlink() and date_dir.is_dir():
                        for file in date_dir.glob("*.mp4"):
                            safe_file = self._safe_recording_file(file, ".mp4")
                            if safe_file is None:
                                continue
                            stat = safe_file.stat()
                            recordings.append({
                                "path": str(safe_file),
                                "camera": camera_dir.name,
                                "date": date_dir.name,
                                "filename": safe_file.name,
                                "size": stat.st_size,
                                "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                            })
        
        # Sort by creation time, newest first
        recordings.sort(key=lambda x: x["created_at"], reverse=True)
        return recordings
    
    def get_storage_usage(self) -> dict:
        """Get storage usage for recordings."""
        total_size = 0
        file_count = 0
        
        for file in self.recordings_path.rglob("*.mp4"):
            safe_file = self._safe_recording_file(file, ".mp4")
            if safe_file is not None:
                total_size += safe_file.stat().st_size
                file_count += 1
        
        for file in self.recordings_path.rglob("*.jpg"):
            safe_file = self._safe_recording_file(file, ".jpg")
            if safe_file is not None:
                total_size += safe_file.stat().st_size
                file_count += 1
        
        return {
            "total_size_bytes": total_size,
            "total_size_human": self._format_size(total_size),
            "file_count": file_count,
            "path": str(self.recordings_path)
        }
    
    def _format_size(self, size_bytes: int) -> str:
        """Format bytes to human readable string."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
    
    async def cleanup_old_recordings(self, max_age_days: int = 30) -> dict:
        """Delete recordings older than max_age_days."""
        cutoff = datetime.now() - timedelta(days=max_age_days)
        protected = self.protected_ids()
        deleted_count = 0
        deleted_size = 0

        for file in self.recordings_path.rglob("*.mp4"):
            safe_file = self._safe_recording_file(file, ".mp4")
            if safe_file is None or self._rec_id(safe_file) in protected:
                continue  # keep locked recordings regardless of age
            if datetime.fromtimestamp(safe_file.stat().st_mtime) < cutoff:
                try:
                    details = self._unlink_recording_file(safe_file)
                except OSError:
                    continue
                deleted_count += 1
                deleted_size += details.st_size
                logger.info(f"Deleted old recording: {safe_file}")
        
        # Remove empty directories
        self._remove_empty_dirs()
        
        return {
            "deleted_count": deleted_count,
            "deleted_size": self._format_size(deleted_size),
            "cutoff_date": cutoff.isoformat()
        }
    
    # --- protected ("kept") recordings ----------------------------------
    # A recording is identified by sha256(path)[:16] (same id the API uses). The
    # ids of recordings the user chose to keep are persisted in a small JSON file;
    # the storage guard and retention never delete a protected recording.
    def _rec_id(self, path) -> str:
        return hashlib.sha256(str(path).encode()).hexdigest()[:16]

    @property
    def _protected_file(self) -> Path:
        return self.recordings_path / ".protected.json"

    def protected_ids(self) -> set:
        try:
            data = json.loads(self._protected_file.read_text())
            return set(data) if isinstance(data, list) else set()
        except Exception:
            return set()

    def is_protected(self, recording_id: str) -> bool:
        return recording_id in self.protected_ids()

    def set_protected(self, recording_id: str, protected: bool) -> bool:
        ids = self.protected_ids()
        if protected:
            ids.add(recording_id)
        else:
            ids.discard(recording_id)
        try:
            self._protected_file.write_text(json.dumps(sorted(ids)))
            return True
        except Exception as e:
            logger.warning(f"Could not update protected recordings: {e}")
            return False

    def storage_status(self) -> dict:
        """Disk + recordings usage, and whether auto-cleanup is near (for the UI)."""
        try:
            u = shutil.disk_usage(self.recordings_path)
            total, free = u.total, u.free
        except Exception:
            total, free = 0, 0
        used = total - free
        used_pct = (used / total * 100.0) if total else 0.0
        free_pct = 100.0 - used_pct
        guard, min_free, _target, retention_days = self._storage_cfg()
        rec = self.get_storage_usage()
        return {
            "total_bytes": total,
            "free_bytes": free,
            "used_bytes": used,
            "used_pct": round(used_pct, 1),
            "free_pct": round(free_pct, 1),
            "min_free_pct": min_free,
            "retention_days": retention_days,
            "guard_enabled": guard,
            # warn once we are within ~5 points of the auto-clean floor
            "warning": bool(guard and free_pct <= (min_free + 5.0)),
            "recordings_bytes": rec.get("total_size_bytes", 0),
            "recordings_count": rec.get("file_count", 0),
            "protected_count": len(self.protected_ids()),
        }

    # --- storage guard (ring-buffer loop recording) ---------------------
    def _storage_cfg(self) -> tuple:
        """(guard_on, min_free_pct, target_free_pct, retention_days) from config."""
        try:
            from config import get_settings

            s = get_settings()
            return (
                bool(getattr(s, "RECORDINGS_STORAGE_GUARD", True)),
                float(getattr(s, "RECORDINGS_MIN_FREE_PCT", 10.0)),
                float(getattr(s, "RECORDINGS_TARGET_FREE_PCT", 20.0)),
                int(getattr(s, "RECORDINGS_RETENTION_DAYS", 30)),
            )
        except Exception:
            return True, 10.0, 20.0, 30

    def _free_pct(self) -> float:
        """Free space on the recordings filesystem, as a percentage."""
        try:
            u = shutil.disk_usage(self.recordings_path)
            return (u.free / u.total * 100.0) if u.total else 100.0
        except Exception:
            return 100.0

    def _oldest_recordings(self) -> list:
        """Deletable recording files (excludes protected/"kept"), oldest first."""
        protected = self.protected_ids()
        files = []
        for f in self.recordings_path.rglob("*.mp4"):
            sf = self._safe_recording_file(f, ".mp4")
            if sf is None or self._rec_id(sf) in protected:
                continue  # locked recordings are never auto-deleted
            try:
                files.append((sf.stat().st_mtime, sf))
            except OSError:
                continue
        files.sort(key=lambda t: t[0])
        return [f for _, f in files]

    def _remove_empty_dirs(self) -> None:
        for dir_path in sorted(self.recordings_path.rglob("*"), reverse=True):
            try:
                relative = dir_path.relative_to(self.recordings_path)
                rmdir_empty_beneath(self.recordings_path, relative)
            except OSError:
                continue

    def _record_storage_event(self, deleted: int, freed: int) -> None:
        """Best-effort activity event so an auto-cleanup is visible to the user."""
        try:
            from app.api.v1.endpoints.camera_operation_events import record_camera_event

            record_camera_event(
                action_id="camera.recordings.autoclean",
                title="Recordings auto-cleanup",
                subtitle="Storage guard",
                status="success",
                message=(
                    f"Freed {self._format_size(freed)} by deleting {deleted} oldest "
                    f"recording(s) to keep the disk healthy."
                ),
                started_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            pass

    def _record_storage_blocked_event(self) -> None:
        """Best-effort alert when the disk stays low because everything is locked."""
        try:
            from app.api.v1.endpoints.camera_operation_events import record_camera_event

            record_camera_event(
                action_id="camera.recordings.storage_blocked",
                title="Storage almost full",
                subtitle="Storage guard",
                status="failed",
                message=(
                    "The disk is nearly full and the remaining recordings are locked. "
                    "Download or unlock some recordings, or expand storage."
                ),
                started_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception:
            pass

    async def enforce_storage_limits(self) -> dict:
        """Keep the disk healthy (CCTV loop recording).

        1) delete recordings older than the retention window; 2) if free space is
        below the floor, delete the OLDEST recordings until it is back above the
        target. Recordings share the filesystem with the databases, so this stops
        the disk ever hitting 100% and destabilising the Pi. Safe to call often.
        """
        guard, min_free, target_free, retention_days = self._storage_cfg()
        if not guard:
            return {"skipped": True}

        deleted = 0
        freed = 0

        # 1) retention by age (best-effort)
        if retention_days and retention_days > 0:
            try:
                r = await self.cleanup_old_recordings(retention_days)
                deleted += int(r.get("deleted_count", 0))
            except Exception as e:
                logger.warning(f"Storage guard: retention cleanup error: {e}")

        # 2) free-space floor -> delete oldest first (ring buffer)
        if self._free_pct() < min_free:
            try:
                u = shutil.disk_usage(self.recordings_path)
                needed = int(u.total * (target_free / 100.0)) - u.free
            except Exception:
                needed = 0
            logger.warning(
                "Storage guard: free space %.1f%% below %.0f%% floor — freeing ~%.1f GB "
                "by deleting oldest recordings" % (self._free_pct(), min_free, max(0, needed) / 1e9)
            )
            for f in self._oldest_recordings():
                if freed >= needed:
                    break
                try:
                    details = self._unlink_recording_file(f)
                    deleted += 1
                    freed += details.st_size
                    logger.info(f"Storage guard deleted oldest recording: {f.name}")
                except OSError:
                    continue
            self._remove_empty_dirs()
            if freed:
                self._record_storage_event(deleted, freed)
                logger.warning(
                    "Storage guard: freed %s, disk now %.1f%% free"
                    % (self._format_size(freed), self._free_pct())
                )
            # Still low after cleanup -> the remaining recordings are locked/kept.
            if self._free_pct() < min_free:
                logger.error(
                    "Storage guard: only %.1f%% free after cleanup — remaining recordings "
                    "are locked. Unlock/download some or expand storage." % self._free_pct()
                )
                self._record_storage_blocked_event()

        return {"deleted_count": deleted, "freed_bytes": freed, "free_pct": round(self._free_pct(), 1)}

    async def start_monitor(self):
        """Start background task to monitor and restart failed recordings."""
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Recording monitor started")
    
    async def stop_monitor(self):
        """Stop monitoring and all recordings."""
        self._running = False
        
        # Stop all recordings
        for camera_id in list(self._processes.keys()):
            await self.stop_recording(camera_id)
        
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Recording monitor stopped")
    
    async def _monitor_loop(self):
        """Background loop to monitor recording processes."""
        while self._running:
            try:
                for camera_id, rec in list(self._processes.items()):
                    if rec.process and rec.process.poll() is not None:
                        # Process died
                        exit_code = rec.process.returncode
                        logger.warning(f"Recording died for {rec.camera_name} (exit code: {exit_code})")
                        
                        if rec.restart_count < rec.max_restarts:
                            # Attempt restart
                            rec.restart_count += 1
                            logger.info(f"Restarting recording for {rec.camera_name} (attempt {rec.restart_count})")
                            
                            cmd = self._build_ffmpeg_command(rec)
                            rec.process = await asyncio.to_thread(
                                subprocess.Popen,
                                cmd,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                start_new_session=True,
                            )
                        else:
                            logger.error(f"Max restarts exceeded for {rec.camera_name}, giving up")
                            del self._processes[camera_id]

                # Storage guard (ring buffer): keep the disk healthy every ~2 min,
                # and immediately on the first pass to catch an already-full disk.
                if self._loop_count % 4 == 0:
                    try:
                        await self.enforce_storage_limits()
                    except Exception as e:
                        logger.error(f"Storage guard error: {e}")
                self._loop_count += 1

                await asyncio.sleep(30)  # Check every 30 seconds

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in recording monitor: {e}")
                await asyncio.sleep(5)

    # =========================================================================
    # Snapshot Management
    # =========================================================================
    
    def get_snapshots_dir(self) -> Path:
        """Get the snapshots directory path."""
        return self.recordings_path / "snapshots"
    
    def list_snapshots(self, camera_name: Optional[str] = None) -> list[dict]:
        """
        List all snapshots.
        
        Args:
            camera_name: Optional filter by camera name
            
        Returns:
            List of snapshot info dictionaries
        """
        snapshots = []
        snapshot_dir = self.get_snapshots_dir()
        
        if not snapshot_dir.exists():
            return snapshots
        
        for file in snapshot_dir.iterdir():
            safe_file = self._safe_snapshot_file(file)
            if safe_file is not None:
                # Parse filename: camera_name_YYYYMMDD_HHMMSS.jpg
                filename = safe_file.stem
                parts = filename.rsplit('_', 2)
                
                if len(parts) >= 3:
                    cam_name = parts[0]
                    date_str = parts[1]
                    time_str = parts[2]
                else:
                    cam_name = filename
                    date_str = ""
                    time_str = ""
                
                # Filter by camera name if provided
                if camera_name and cam_name.lower() != camera_name.lower():
                    continue
                
                try:
                    stat = safe_file.stat()
                    created_at = datetime.fromtimestamp(stat.st_mtime).isoformat()
                except Exception:
                    created_at = ""
                
                snapshots.append({
                    "id": filename,
                    "camera_name": cam_name.replace('_', ' '),
                    "filename": safe_file.name,
                    "path": str(safe_file),
                    "size": safe_file.stat().st_size,
                    "created_at": created_at,
                    "date": date_str,
                    "time": time_str,
                })
        
        # Sort by creation time, newest first
        snapshots.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return snapshots
    
    def get_snapshot_by_filename(self, filename: str) -> Optional[Path]:
        """
        Get snapshot file path by filename.
        
        Args:
            filename: The snapshot filename (with or without extension)
            
        Returns:
            Path to the snapshot file if found, None otherwise
        """
        snapshot_dir = self.get_snapshots_dir()
        
        if not snapshot_dir.exists():
            return None

        if (
            not filename
            or "\x00" in filename
            or filename != Path(filename).name
            or filename in {".", ".."}
            or len(filename) > 255
        ):
            return None
        
        # Try exact match first
        exact_path = snapshot_dir / filename
        safe_exact = self._safe_snapshot_file(exact_path)
        if safe_exact is not None:
            return safe_exact
        
        # Try with common extensions
        for ext in ['.jpg', '.jpeg', '.png']:
            path = snapshot_dir / f"{filename}{ext}"
            safe_path = self._safe_snapshot_file(path)
            if safe_path is not None:
                return safe_path
        
        return None

    def _snapshot_candidate_names(self, filename: str) -> list[str]:
        if (
            not filename
            or "\x00" in filename
            or filename != Path(filename).name
            or filename in {".", ".."}
            or len(filename.encode("utf-8")) > 255
        ):
            return []
        names = [filename]
        if Path(filename).suffix.lower() not in {".jpg", ".jpeg", ".png"}:
            names.extend(f"{filename}{extension}" for extension in (".jpg", ".jpeg", ".png"))
        return names

    def open_snapshot_by_filename(self, filename: str) -> tuple[int, os.stat_result] | None:
        """Open a snapshot below a pinned snapshots directory."""
        root = self.get_snapshots_dir()
        for name in self._snapshot_candidate_names(filename):
            try:
                return open_regular_beneath(
                    root,
                    name,
                    suffixes={".jpg", ".jpeg", ".png"},
                )
            except OSError:
                continue
        return None
    
    def delete_snapshot(self, filename: str) -> dict:
        """
        Delete a specific snapshot.
        
        Args:
            filename: The snapshot filename
            
        Returns:
            dict with success status
        """
        root = self.get_snapshots_dir()
        for name in self._snapshot_candidate_names(filename):
            try:
                details = unlink_regular_beneath(
                    root,
                    name,
                    suffixes={".jpg", ".jpeg", ".png"},
                )
                return {"success": True, "freed_bytes": details.st_size}
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.warning("Snapshot deletion failed: %s", type(exc).__name__)
                return {"success": False, "error": "Snapshot could not be deleted"}
        return {"success": False, "error": "Snapshot not found"}
    
    def delete_snapshots_by_camera(self, camera_name: str) -> dict:
        """
        Delete all snapshots for a specific camera.
        
        Args:
            camera_name: The camera name
            
        Returns:
            dict with deletion results
        """
        snapshots = self.list_snapshots(camera_name=camera_name)
        deleted_count = 0
        freed_bytes = 0
        errors = []
        
        for snap in snapshots:
            result = self.delete_snapshot(snap["filename"])
            if result.get("success"):
                deleted_count += 1
                freed_bytes += result.get("freed_bytes", 0)
            else:
                errors.append(result.get("error"))
        
        return {
            "success": len(errors) == 0,
            "deleted_count": deleted_count,
            "freed_bytes": freed_bytes,
            "errors": errors if errors else None
        }
    
    def cleanup_old_snapshots(self, max_age_days: int = 7) -> dict:
        """
        Delete snapshots older than max_age_days.
        
        Args:
            max_age_days: Maximum age in days
            
        Returns:
            dict with cleanup results
        """
        snapshot_dir = self.get_snapshots_dir()
        
        if not snapshot_dir.exists():
            return {
                "success": True,
                "deleted_count": 0,
                "freed_bytes": 0,
                "message": "No snapshots directory"
            }
        
        cutoff = datetime.now() - timedelta(days=max_age_days)
        deleted_count = 0
        freed_bytes = 0
        
        for file in snapshot_dir.iterdir():
            safe_file = self._safe_snapshot_file(file)
            if safe_file is not None:
                try:
                    mtime = datetime.fromtimestamp(safe_file.stat().st_mtime)
                    if mtime < cutoff:
                        result = self.delete_snapshot(safe_file.name)
                        if result.get("success"):
                            deleted_count += 1
                            freed_bytes += result.get("freed_bytes", 0)
                except Exception as e:
                    logger.warning(f"Failed to delete old snapshot {safe_file}: {e}")
        
        return {
            "success": True,
            "deleted_count": deleted_count,
            "freed_bytes": freed_bytes,
            "message": f"Deleted {deleted_count} snapshots older than {max_age_days} days"
        }
    
    def get_snapshots_storage_info(self) -> dict:
        """
        Get storage information for snapshots.
        
        Returns:
            dict with storage stats
        """
        snapshot_dir = self.get_snapshots_dir()
        
        if not snapshot_dir.exists():
            return {
                "path": str(snapshot_dir),
                "exists": False,
                "total_size": 0,
                "file_count": 0
            }
        
        total_size = 0
        file_count = 0
        
        for file in snapshot_dir.iterdir():
            safe_file = self._safe_snapshot_file(file)
            if safe_file is not None:
                total_size += safe_file.stat().st_size
                file_count += 1
        
        return {
            "path": str(snapshot_dir),
            "exists": True,
            "total_size": total_size,
            "total_size_mb": round(total_size / (1024 * 1024), 2),
            "file_count": file_count
        }


# Global instance
recording_service = RecordingService()
