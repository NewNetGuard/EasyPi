"""
Snapshot capture service for IP cameras using FFmpeg.

Provides reliable RTSP snapshot capture with retry strategies
and configurable timeouts.
"""
import asyncio
import logging
import re
import shutil
from typing import Optional, Tuple

from app.core.config import settings

logger = logging.getLogger("easypi")

# JPEG magic bytes
JPEG_MAGIC = b'\xff\xd8'
RTSP_CREDENTIALS_RE = re.compile(r'(rtsp://[^:@/\s]+):([^@/\s]+)@', re.IGNORECASE)


class SnapshotService:
    """Service for capturing snapshots from RTSP cameras using FFmpeg."""
    
    def __init__(self):
        self.timeout_sec = getattr(settings, 'SNAPSHOT_TIMEOUT_SEC', 8)
        self.stimeout_usec = getattr(settings, 'SNAPSHOT_STIMEOUT_USEC', 5000000)
        self.retries = getattr(settings, 'SNAPSHOT_RETRIES', 2)
        self._ffmpeg_path: Optional[str] = None
        self._ffmpeg_checked = False
    
    def _check_ffmpeg_available(self) -> Tuple[bool, str]:
        """Check if ffmpeg is installed and available in PATH."""
        if self._ffmpeg_checked:
            if self._ffmpeg_path:
                return True, self._ffmpeg_path
            return False, "FFmpeg not found in PATH"
        
        self._ffmpeg_checked = True
        self._ffmpeg_path = shutil.which("ffmpeg")
        
        if self._ffmpeg_path:
            logger.info(f"FFmpeg found at: {self._ffmpeg_path}")
            return True, self._ffmpeg_path
        else:
            logger.error(
                "FFmpeg not found! Install it with: sudo apt-get install ffmpeg"
            )
            return False, "FFmpeg not found. Install with: sudo apt-get install ffmpeg"
    
    def _sanitize_rtsp_url_for_log(self, text: str) -> str:
        """Remove credentials from RTSP URLs in arbitrary text."""
        return RTSP_CREDENTIALS_RE.sub(r'\1:****@', text)

    def _format_ffmpeg_error(self, stderr_text: str) -> str:
        """Convert FFmpeg stderr to a user-friendly error message."""
        if not stderr_text:
            return "FFmpeg failed to read the stream."

        normalized = stderr_text.lower()

        if "invalid data found when processing input" in normalized:
            return "Invalid data from camera stream. Check RTSP URL, stream path, and codec."
        if "connection refused" in normalized:
            return "Connection refused by camera. Check IP address and port."
        if "i/o timeout" in normalized or "timed out" in normalized:
            return "Camera not responding (timeout). Check network connectivity and RTSP URL."
        if "unauthorized" in normalized or "401" in normalized:
            return "Authentication failed. Check RTSP username and password."
        if "forbidden" in normalized or "403" in normalized:
            return "Access denied by camera. Check RTSP permissions."
        if "not found" in normalized or "404" in normalized:
            return "Stream not found. Check RTSP path and channel."
        if "could not find codec parameters" in normalized:
            return "Unsupported stream or codec from camera."
        if "no route to host" in normalized or "network is unreachable" in normalized:
            return "Network unreachable. Check IP address and routing."
        if "server returned" in normalized:
            return "Camera returned an error while opening the stream."

        lines = [line.strip() for line in stderr_text.splitlines() if line.strip()]
        if not lines:
            return "FFmpeg failed to read the stream."
        return lines[-1][:200]

    async def _capture_with_params(
        self,
        rtsp_url: str,
        attempt: int,
        use_skip_frame: bool = False
    ) -> Tuple[bool, Optional[bytes], str]:
        """
        Capture snapshot with specific ffmpeg parameters.
        
        Args:
            rtsp_url: RTSP stream URL
            attempt: Attempt number (for logging)
            use_skip_frame: Whether to use -skip_frame nokey
            
        Returns:
            Tuple of (success, jpeg_bytes, error_message)
        """
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "error",
            "-rtsp_transport", "tcp",
            # Use -timeout instead of -stimeout for better compatibility
            # -timeout is in microseconds for older ffmpeg versions
            "-timeout", str(self.stimeout_usec),
        ]
        
        # Add skip_frame for second attempt
        if use_skip_frame:
            cmd.extend(["-skip_frame", "nokey"])
        
        # Add analyzeduration and probesize for faster startup
        cmd.extend([
            "-analyzeduration", "2000000",  # 2 seconds
            "-probesize", "2000000",  # 2MB
        ])
        
        cmd.extend([
            "-i", rtsp_url,
            "-frames:v", "1",
            "-q:v", "2",  # High quality JPEG
            "-f", "image2pipe",
            "-vcodec", "mjpeg",
            "pipe:1"
        ])
        
        safe_url = self._sanitize_rtsp_url_for_log(rtsp_url)
        logger.debug(
            f"Snapshot attempt {attempt}: skip_frame={use_skip_frame}, "
            f"timeout={self.timeout_sec}s, url={safe_url}"
        )
        
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.timeout_sec
                )
            except asyncio.TimeoutError:
                # Kill the process
                try:
                    process.kill()
                    await process.wait()
                except Exception as e:
                    logger.warning(f"Failed to kill ffmpeg process: {e}")
                
                error_msg = f"Timeout after {self.timeout_sec}s"
                logger.warning(
                    f"Snapshot attempt {attempt} timed out: {safe_url}"
                )
                return False, None, error_msg
            
            # Check exit code
            if process.returncode != 0:
                stderr_text = stderr.decode('utf-8', errors='replace').strip()[-500:] if stderr else ""
                safe_stderr = self._sanitize_rtsp_url_for_log(stderr_text)
                friendly_error = self._format_ffmpeg_error(safe_stderr)
                error_msg = f"FFmpeg exit code {process.returncode}: {friendly_error}"
                logger.warning(
                    f"Snapshot attempt {attempt} failed: {error_msg}, "
                    f"stderr: {safe_stderr}, url: {safe_url}"
                )
                return False, None, error_msg
            
            # Validate JPEG output
            if not stdout or len(stdout) < 100:
                error_msg = f"Empty or too small output ({len(stdout) if stdout else 0} bytes)"
                logger.warning(
                    f"Snapshot attempt {attempt} produced invalid output: "
                    f"{error_msg}, url: {safe_url}"
                )
                return False, None, error_msg
            
            # Check JPEG magic bytes
            if not stdout.startswith(JPEG_MAGIC):
                error_msg = f"Output doesn't start with JPEG magic bytes (got {stdout[:4].hex()})"
                logger.warning(
                    f"Snapshot attempt {attempt} invalid format: "
                    f"{error_msg}, url: {safe_url}"
                )
                return False, None, error_msg
            
            logger.info(
                f"Snapshot attempt {attempt} succeeded: "
                f"{len(stdout)} bytes, url: {safe_url}"
            )
            return True, stdout, ""
            
        except Exception as exc:
            error_msg = "Snapshot process could not be started"
            logger.error(
                "Snapshot attempt %s failed to start for %s: %s",
                attempt,
                safe_url,
                type(exc).__name__,
            )
            return False, None, error_msg
    
    async def capture_snapshot(self, rtsp_url: str) -> Tuple[bool, Optional[bytes], str]:
        """
        Capture a snapshot from RTSP stream with retry logic.
        
        Args:
            rtsp_url: RTSP stream URL (rtsp://user:pass@host:port/path)
            
        Returns:
            Tuple of (success, jpeg_bytes, error_message)
        """
        # Check if FFmpeg is available
        ffmpeg_available, ffmpeg_error = self._check_ffmpeg_available()
        if not ffmpeg_available:
            return False, None, ffmpeg_error
        
        last_error = "Unknown error"
        
        # Attempt 1: Standard parameters
        success, jpeg_bytes, error = await self._capture_with_params(
            rtsp_url, attempt=1, use_skip_frame=False
        )
        if success:
            return True, jpeg_bytes, ""
        
        last_error = error
        
        # Attempt 2: With skip_frame nokey (wait for keyframe)
        if self.retries >= 2:
            success, jpeg_bytes, error = await self._capture_with_params(
                rtsp_url, attempt=2, use_skip_frame=True
            )
            if success:
                return True, jpeg_bytes, ""
            
            last_error = error
        
        # All attempts failed
        safe_url = self._sanitize_rtsp_url_for_log(rtsp_url)
        logger.error(
            f"All snapshot attempts failed for {safe_url}: {last_error}"
        )
        return False, None, last_error


# Singleton instance
snapshot_service = SnapshotService()
