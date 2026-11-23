from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Optional
from urllib.parse import quote

import websockets
from fastapi import Query, WebSocket
from starlette import status

from app.api.v1.endpoints.auth import verify_ws_token
from app.api.v1.endpoints.camera_helpers import normalize_stream_name
from app.core.go2rtc_client import go2rtc_authorization_header
from app.db.session import get_db
from app.api.websocket.ws_auth import (
    revalidate_session_periodically,
    websocket_session_is_valid,
)
from app.models.camera import Camera

logger = logging.getLogger(__name__)
_MSE_CODECS_RE = re.compile(r"^[A-Za-z0-9.,_-]{0,1024}$")


def _validated_mse_request(message: str) -> str:
    """Accept only the single read-only MSE subscription command."""
    if len(message) > 2048:
        raise ValueError("camera request is too large")
    try:
        payload = json.loads(message)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid camera request") from exc
    if not isinstance(payload, dict) or set(payload) - {"type", "value"}:
        raise ValueError("invalid camera request")
    codecs = payload.get("value", "")
    if payload.get("type") != "mse" or not isinstance(codecs, str):
        raise ValueError("unsupported camera transport")
    if not _MSE_CODECS_RE.fullmatch(codecs):
        raise ValueError("invalid camera codecs")
    return json.dumps({"type": "mse", "value": codecs}, separators=(",", ":"))


async def camera_live_websocket(
    websocket: WebSocket,
    camera_id: str,
    ws_token: Optional[str] = Query(None),
) -> None:
    """Proxy MSE media so revocation closes the server-side media consumer."""
    user_id: Optional[int] = None
    session_jti: Optional[str] = None

    if ws_token:
        claims = verify_ws_token(ws_token)
        if not claims:
            logger.warning(
                "Camera live WS rejected - invalid ws_token from %s",
                websocket.client,
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user_id = claims.user_id
        session_jti = claims.session_jti
    else:
        logger.warning(
            "Camera live WS rejected - no token from %s",
            websocket.client,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # The one-shot token may have been issued before logout, account deletion or
    # deactivation. Validate its bound login session before touching go2rtc.
    if not websocket_session_is_valid(
        user_id=user_id,
        session_jti=session_jti,
    ):
        logger.warning("Camera live WS rejected - revoked session for user %s", user_id)
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    db = next(get_db())
    try:
        camera = db.get(Camera, camera_id)
    finally:
        db.close()

    if camera is None:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    stream_name = normalize_stream_name(camera.name, camera.id)
    
    # MSE media travels through this upstream WebSocket. go2rtc binds its MSE
    # consumer to the WebSocket transport and removes it when we close upstream.
    go2rtc_base = os.getenv("EASYPI_GO2RTC_WS_URL", "ws://127.0.0.1:1984/api/ws")
    if not go2rtc_base.endswith("/api/ws"):
        go2rtc_base = f"{go2rtc_base.rstrip('/')}/api/ws"
    cache_buster = f"{int(asyncio.get_running_loop().time() * 1000)}"
    upstream_url = f"{go2rtc_base}?src={quote(stream_name, safe='')}&_={cache_buster}"

    try:
        authorization = go2rtc_authorization_header()
        upstream = await websockets.connect(
            upstream_url,
            additional_headers=(
                {"Authorization": authorization} if authorization else None
            ),
            ping_interval=20,
            ping_timeout=20,
            max_size=8 * 1024 * 1024,
        )
    except Exception as exc:
        await websocket.accept()
        await websocket.send_json(
            {"type": "error", "message": "LIVE_STREAM_UNAVAILABLE"}
        )
        await websocket.close(code=status.WS_1011_INTERNAL_ERROR)
        logger.error(
            "Camera live upstream connection failed for %s: %s",
            camera_id,
            type(exc).__name__,
        )
        return

    await websocket.accept()
    logger.info("Camera live WS connected for user %s, camera %s", user_id, camera_id)

    async def client_to_upstream() -> None:
        subscribed = False
        try:
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    break
                text = message.get("text")
                if subscribed or text is None:
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break
                await upstream.send(_validated_mse_request(text))
                subscribed = True
        except Exception:
            logger.debug("Camera live client->upstream closed for %s", camera_id)

    async def upstream_to_client() -> None:
        try:
            async for message in upstream:
                if isinstance(message, bytes):
                    await websocket.send_bytes(message)
                else:
                    await websocket.send_text(message)
        except Exception:
            logger.debug("Camera live upstream->client closed for %s", camera_id)

    tasks = [
        asyncio.create_task(client_to_upstream()),
        asyncio.create_task(upstream_to_client()),
        # Tear the stream down if the session is revoked / user deactivated mid-view.
        asyncio.create_task(
            revalidate_session_periodically(
                websocket,
                user_id=user_id,
                session_jti=session_jti,
                interval_sec=5.0,
            )
        ),
    ]
    _, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    try:
        await upstream.close()
    except Exception:
        pass
    # Only close if not already closed
    try:
        if websocket.client_state.name != "DISCONNECTED":
            await websocket.close()
    except Exception:
        pass


__all__ = ["camera_live_websocket"]
