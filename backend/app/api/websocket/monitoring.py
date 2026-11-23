from __future__ import annotations

import asyncio
import json
import logging
from typing import Dict, Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from starlette import status

from app.api.websocket.manager import ConnectionManager
from app.core.system_monitor import SystemMonitor

router = APIRouter()
manager = ConnectionManager()
monitor = SystemMonitor()
logger = logging.getLogger(__name__)


@router.websocket("/ws/monitoring")
async def monitoring_websocket(
    websocket: WebSocket,
    ws_token: Optional[str] = Query(None),
) -> None:
    """
    WebSocket endpoint for system monitoring data.
    
    SECURITY: Requires a short-lived token from /auth/ws-token.
    """
    from app.api.v1.endpoints.auth import verify_ws_token
    
    user_id: Optional[int] = None
    session_jti: Optional[str] = None

    # Try ws_token first (new cookie-based flow)
    if ws_token:
        claims = verify_ws_token(ws_token)
        if not claims:
            logger.warning(
                "Monitoring WS connection rejected - invalid ws_token from %s",
                websocket.client,
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user_id = claims.user_id
        session_jti = claims.session_jti
    else:
        # No authentication provided
        logger.warning(
            "Monitoring WS connection rejected - no token from %s",
            websocket.client,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Authentication successful - proceed with connection
    connection_id = await manager.connect(websocket)
    logger.info(f"Monitoring WebSocket connected for user {user_id}")

    from app.api.websocket.ws_auth import revalidate_session_periodically
    _revalidator = asyncio.create_task(
        revalidate_session_periodically(
            websocket,
            user_id=user_id,
            session_jti=session_jti,
        )
    )
    try:
        while True:
            # Off-load to a thread: snapshot() must not block the event loop,
            # otherwise every connected dashboard stalls the whole backend.
            snapshot = await asyncio.to_thread(monitor.snapshot)
            data = _serialize_snapshot(snapshot)
            await manager.send(connection_id, data)
            await asyncio.sleep(1.0)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        _revalidator.cancel()
        await manager.disconnect(connection_id)


def _serialize_snapshot(snapshot: Dict[str, object]) -> str:
    def default_serializer(obj):
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return str(obj)

    return json.dumps(snapshot, default=default_serializer)


__all__ = ["router", "monitoring_websocket"]
