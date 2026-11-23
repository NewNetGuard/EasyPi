"""
MediaMTX client for camera stream management.

Provides snapshot capture via MediaMTX API and dynamic camera path management.
MediaMTX acts as RTSP proxy - single connection to camera, multiple consumers.
"""
import logging
from typing import Optional, Tuple
import httpx

from app.core.config import settings

logger = logging.getLogger("easypi")

# MediaMTX API base URL (running on same host)
MEDIAMTX_API_URL = getattr(settings, 'MEDIAMTX_API_URL', 'http://127.0.0.1:9997')
MEDIAMTX_WEBRTC_URL = getattr(settings, 'MEDIAMTX_WEBRTC_URL', 'http://127.0.0.1:8889')
MEDIAMTX_TIMEOUT = getattr(settings, 'MEDIAMTX_TIMEOUT', 10.0)


class MediaMTXClient:
    """Client for interacting with MediaMTX API."""
    
    def __init__(self):
        self.api_url = MEDIAMTX_API_URL
        self.webrtc_url = MEDIAMTX_WEBRTC_URL
        self.timeout = MEDIAMTX_TIMEOUT
    
    async def check_health(self) -> bool:
        """Check if MediaMTX is healthy."""
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(f"{self.api_url}/v3/paths/list")
                return resp.status_code == 200
        except Exception as e:
            logger.warning(f"MediaMTX health check failed: {e}")
            return False
    
    async def add_camera_path(
        self,
        camera_id: str,
        rtsp_url: str,
        on_demand: bool = True,
        close_after: str = "10s"
    ) -> Tuple[bool, str]:
        """
        Add or update a camera path in MediaMTX.
        
        Args:
            camera_id: Unique camera identifier (used as path name)
            rtsp_url: Full RTSP URL to the camera
            on_demand: Only connect when viewers present
            close_after: Disconnect after this time without viewers
            
        Returns:
            Tuple of (success, error_message)
        """
        path_config = {
            "source": rtsp_url,
            "sourceOnDemand": on_demand,
            "sourceOnDemandCloseAfter": close_after,
        }
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Try to add path first
                resp = await client.post(
                    f"{self.api_url}/v3/config/paths/add/{camera_id}",
                    json=path_config
                )
                
                if resp.status_code == 200:
                    logger.info(f"Added MediaMTX path for camera {camera_id}")
                    return True, ""
                
                # If path exists, update it
                if resp.status_code == 400 and "already exists" in resp.text.lower():
                    resp = await client.patch(
                        f"{self.api_url}/v3/config/paths/patch/{camera_id}",
                        json=path_config
                    )
                    if resp.status_code == 200:
                        logger.info(f"Updated MediaMTX path for camera {camera_id}")
                        return True, ""
                
                error = f"MediaMTX API error: {resp.status_code} - {resp.text}"
                logger.error(error)
                return False, error
                
        except Exception as e:
            error = f"Failed to add camera path: {str(e)}"
            logger.error(error)
            return False, error
    
    async def remove_camera_path(self, camera_id: str) -> Tuple[bool, str]:
        """
        Remove a camera path from MediaMTX.
        
        Args:
            camera_id: Camera identifier
            
        Returns:
            Tuple of (success, error_message)
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.delete(
                    f"{self.api_url}/v3/config/paths/delete/{camera_id}"
                )
                
                if resp.status_code == 200:
                    logger.info(f"Removed MediaMTX path for camera {camera_id}")
                    return True, ""
                
                # 404 is OK - path doesn't exist
                if resp.status_code == 404:
                    return True, ""
                
                error = f"MediaMTX API error: {resp.status_code} - {resp.text}"
                logger.error(error)
                return False, error
                
        except Exception as e:
            error = f"Failed to remove camera path: {str(e)}"
            logger.error(error)
            return False, error
    
    async def capture_snapshot(self, camera_id: str) -> Tuple[bool, Optional[bytes], str]:
        """
        Capture a snapshot from MediaMTX stream.
        
        MediaMTX provides a JPEG snapshot API at /api/frame.jpeg
        This uses the existing stream - no extra connection to camera!
        
        Args:
            camera_id: Camera identifier (path name in MediaMTX)
            
        Returns:
            Tuple of (success, jpeg_bytes, error_message)
        """
        # MediaMTX snapshot URL
        snapshot_url = f"{self.webrtc_url}/{camera_id}/frame.jpeg"
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(snapshot_url)
                
                if resp.status_code == 200:
                    jpeg_bytes = resp.content
                    
                    # Validate JPEG
                    if len(jpeg_bytes) < 100:
                        return False, None, f"Snapshot too small ({len(jpeg_bytes)} bytes)"
                    
                    if not jpeg_bytes.startswith(b'\xff\xd8'):
                        return False, None, "Invalid JPEG data"
                    
                    logger.debug(f"Snapshot captured via MediaMTX: {len(jpeg_bytes)} bytes")
                    return True, jpeg_bytes, ""
                
                # 404 - path not found or stream not ready
                if resp.status_code == 404:
                    return False, None, "Stream not available. Camera may be offline."
                
                # 503 - source not ready
                if resp.status_code == 503:
                    return False, None, "Stream not ready. Try again in a moment."
                
                error = f"MediaMTX snapshot error: {resp.status_code}"
                logger.warning(error)
                return False, None, error
                
        except httpx.TimeoutException:
            return False, None, f"Snapshot timeout ({self.timeout}s)"
        except Exception as e:
            error = f"Snapshot failed: {str(e)}"
            logger.error(error)
            return False, None, error
    
    async def get_stream_info(self, camera_id: str) -> Optional[dict]:
        """
        Get information about a stream.
        
        Args:
            camera_id: Camera identifier
            
        Returns:
            Stream info dict or None
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.api_url}/v3/paths/get/{camera_id}")
                
                if resp.status_code == 200:
                    return resp.json()
                
                return None
                
        except Exception as e:
            logger.warning(f"Failed to get stream info: {e}")
            return None
    
    async def list_paths(self) -> list[dict]:
        """
        List all configured paths.
        
        Returns:
            List of path configurations
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.get(f"{self.api_url}/v3/paths/list")
                
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("items", [])
                
                return []
                
        except Exception as e:
            logger.warning(f"Failed to list paths: {e}")
            return []


# Singleton instance
mediamtx_client = MediaMTXClient()
