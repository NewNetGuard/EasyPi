"""Camera discovery helpers and RTSP path detection."""
from __future__ import annotations

import asyncio
import logging
import os
from urllib.parse import quote

import httpx

from app.api.v1.endpoints.camera_helpers import (
    GO2RTC_DISABLED_SOURCE,
    GO2RTC_DISCOVERY_STREAM,
    check_camera_online,
)
from app.core.go2rtc_client import go2rtc_http_auth
from app.services.ptz.errors import PTZSecurityError
from app.services.ptz.ssrf import resolve_and_pin

_DISCOVERY_LOCK = asyncio.Lock()

CAMERA_BRANDS = {
    "hikvision": {
        "name": "Hikvision",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/Streaming/Channels/101",
            "/Streaming/Channels/102",
            "/h264/ch1/main/av_stream",
        ],
        "http_port": 80,
    },
    "dahua": {
        "name": "Dahua",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/cam/realmonitor?channel=1&subtype=1",
        ],
        "http_port": 80,
    },
    "amcrest": {
        "name": "Amcrest",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/cam/realmonitor?channel=1&subtype=1",
        ],
        "http_port": 80,
    },
    "reolink": {
        "name": "Reolink",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/h264Preview_01_main",
            "/h264Preview_01_sub",
            "/Preview_01_main",
        ],
        "http_port": 80,
    },
    "tapo": {
        "name": "TP-Link Tapo",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/stream1",
            "/stream2",
            "/live",
        ],
        "http_port": 80,
    },
    "ezviz": {
        "name": "EZVIZ",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/H264/ch1/main/av_stream",
            "/H264/ch1/sub/av_stream",
            "/live",
        ],
        "http_port": 80,
    },
    "uniview": {
        "name": "Uniview",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/media/video1",
            "/live/ch00_0",
            "/unicast/c1/s0/live",
        ],
        "http_port": 80,
    },
    "axis": {
        "name": "Axis",
        "default_port": 554,
        "default_username": "root",
        "rtsp_paths": [
            "/axis-media/media.amp",
            "/axis-media/media.amp?videocodec=h264",
        ],
        "http_port": 80,
    },
    "ubiquiti": {
        "name": "Ubiquiti UniFi",
        "default_port": 7447,
        "default_username": "ubnt",
        "rtsp_paths": [
            "/s0",
            "/s1",
            "/live",
        ],
        "http_port": 7080,
    },
    "foscam": {
        "name": "Foscam",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/videoMain",
            "/videoSub",
            "/h264_stream",
        ],
        "http_port": 88,
    },
    "imou": {
        "name": "IMOU (Dahua)",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/live",
        ],
        "http_port": 80,
    },
    "xiaomi": {
        "name": "Xiaomi/Imilab",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/live",
            "/hd",
            "/sd",
        ],
        "http_port": 80,
        "notes": "May require custom firmware for RTSP",
    },
    "eufy": {
        "name": "Eufy",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/live0",
            "/stream1",
        ],
        "http_port": 80,
        "notes": "Enable RTSP in Eufy app",
    },
    "annke": {
        "name": "Annke",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/Streaming/Channels/101",
            "/Streaming/Channels/102",
        ],
        "http_port": 80,
    },
    "vivotek": {
        "name": "Vivotek",
        "default_port": 554,
        "default_username": "root",
        "rtsp_paths": [
            "/live.sdp",
            "/video.mjpg",
            "/live1.sdp",
        ],
        "http_port": 80,
    },
    "sony": {
        "name": "Sony",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/media/video1",
            "/image1",
        ],
        "http_port": 80,
    },
    "generic": {
        "name": "Generic ONVIF",
        "default_port": 554,
        "default_username": "admin",
        "rtsp_paths": [
            "/ch0",
            "/stream1",
            "/live",
            "/0",
            "/1",
            "/video",
            "/media/video1",
        ],
        "http_port": 80,
    },
}

RTSP_PATHS_TO_TRY = [
    # Many lightweight/Thingino-style cameras use /ch0 and accept arbitrary
    # aliases as if they were valid. Try their canonical path before vendor
    # paths so discovery does not report a misleading Hikvision URL.
    "/ch0",
    "/Streaming/Channels/101",
    "/Streaming/Channels/102",
    "/Streaming/Channels/1",
    "/h264/ch1/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",
    "/cam/realmonitor?channel=1&subtype=1",
    "/h264Preview_01_main",
    "/h264Preview_01_sub",
    "/stream1",
    "/stream2",
    "/H264/ch1/main/av_stream",
    "/H264/ch1/sub/av_stream",
    "/media/video1",
    "/live/ch00_0",
    "/unicast/c1/s0/live",
    "/axis-media/media.amp",
    "/axis-media/media.amp?videocodec=h264",
    "/s0",
    "/s1",
    "/videoMain",
    "/videoSub",
    "/h264_stream",
    "/live.sdp",
    "/video.mjpg",
    "/image1",
    "/live",
    "/video",
    "/0",
    "/1",
]


def get_camera_brands_payload() -> dict:
    """Return sanitized brand metadata for the UI."""
    brands = {}
    for key, brand in CAMERA_BRANDS.items():
        brands[key] = {
            "name": brand["name"],
            "default_port": brand["default_port"],
            "default_username": brand["default_username"],
            "rtsp_paths": brand["rtsp_paths"],
            "notes": brand.get("notes"),
        }
    return {"brands": brands}


async def detect_camera_stream(
    *,
    ip: str,
    port: int,
    username: str,
    password: str,
    brand: str | None,
    logger: logging.Logger,
    preferred_path: str | None = None,
) -> dict:
    """Try common RTSP paths and return the first working one."""
    from app.services.snapshot_service import snapshot_service

    if len(username) > 100 or len(password) > 127:
        return {"success": False, "error": "Camera credentials are too long"}
    safe_username = quote(username, safe="")
    safe_password = quote(password, safe="")

    try:
        pinned_ip, pinned_port = resolve_and_pin(ip, port)
    except PTZSecurityError:
        return {
            "success": False,
            "error": "Only allowed local-network camera targets are supported",
        }
    host = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
    logger.info("Camera detection started for %s:%s", pinned_ip, pinned_port)

    if not check_camera_online(pinned_ip, pinned_port, timeout=3.0):
        return {
            "success": False,
            "error": "Camera is not reachable",
            "hint": "Check that the camera is powered on and connected to the network",
        }

    paths_to_try: list[str] = []
    detected_brand = None

    # Preserve an explicitly entered path when the camera accepts it. Some
    # cameras ignore the RTSP path entirely, so every candidate appears valid;
    # in that case choosing the first generic candidate would overwrite the
    # user's known-good path with an arbitrary alias.
    if preferred_path:
        paths_to_try.append(preferred_path)

    if brand and brand.lower() in CAMERA_BRANDS:
        brand_info = CAMERA_BRANDS[brand.lower()]
        paths_to_try.extend(brand_info["rtsp_paths"])
        detected_brand = brand_info["name"]
        logger.info("Using %s brand-specific paths first", detected_brand)

    for path in RTSP_PATHS_TO_TRY:
        if path not in paths_to_try:
            paths_to_try.append(path)

    attempts = 0
    max_attempts = 35
    go2rtc_url = os.getenv("EASYPI_GO2RTC_API_URL", "http://127.0.0.1:1984")
    local_stream = f"rtsp://127.0.0.1:8554/{GO2RTC_DISCOVERY_STREAM}"

    try:
        async with _DISCOVERY_LOCK:
            async with httpx.AsyncClient(timeout=10.0, auth=go2rtc_http_auth()) as client:
                try:
                    for path in paths_to_try:
                        if attempts >= max_attempts:
                            logger.warning(
                                "Max detection attempts (%s) reached for %s",
                                max_attempts,
                                ip,
                            )
                            break

                        attempts += 1
                        if safe_password:
                            rtsp_url = (
                                f"rtsp://{safe_username}:{safe_password}@"
                                f"{host}:{pinned_port}{path}#transport=tcp"
                            )
                        else:
                            rtsp_url = f"rtsp://{host}:{pinned_port}{path}#transport=tcp"

                        response = await client.patch(
                            f"{go2rtc_url}/api/streams",
                            params={"name": GO2RTC_DISCOVERY_STREAM, "src": rtsp_url},
                        )
                        if not 200 <= response.status_code < 300:
                            continue

                        logger.debug(
                            "Trying RTSP path [%s/%s]: %s",
                            attempts,
                            len(paths_to_try),
                            path,
                        )
                        success, _jpeg_bytes, _error = (
                            await snapshot_service.capture_snapshot(local_stream)
                        )
                        if success:
                            logger.info("Found working RTSP path for %s: %s", ip, path)
                            return {
                                "success": True,
                                "rtspPath": path,
                                "port": port,
                                "brand": detected_brand,
                                "message": f"Found working stream at {path}",
                                "attempts": attempts,
                            }
                finally:
                    # Overwrite the temporary source so camera credentials do
                    # not remain in go2rtc memory after discovery.
                    try:
                        await client.patch(
                            f"{go2rtc_url}/api/streams",
                            params={
                                "name": GO2RTC_DISCOVERY_STREAM,
                                "src": GO2RTC_DISABLED_SOURCE,
                            },
                        )
                    except httpx.RequestError:
                        pass
    except (httpx.RequestError, RuntimeError):
        return {
            "success": False,
            "error": "Camera streaming service is unavailable",
            "attempts": attempts,
        }

    logger.info("Camera detection failed for %s after %s attempts", ip, attempts)
    return {
        "success": False,
        "error": "Could not find working RTSP stream",
        "hint": "Check camera credentials or consult camera manual for RTSP URL",
        "attempts": attempts,
        "suggestions": [
            "Verify username and password are correct",
            "Check if RTSP is enabled in camera settings",
            "Try specifying the camera brand for better detection",
            "Consult camera documentation for correct RTSP path",
        ],
    }
