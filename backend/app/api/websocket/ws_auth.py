"""Live-connection auth revalidation for WebSockets.

WebSocket auth is only checked at the handshake, so a long-lived stream (camera,
monitoring, terminal) would otherwise survive a logout / session revocation / user
deactivation until the client disconnects. This runs alongside the stream and tears the
socket down when the session is no longer valid.
"""
from __future__ import annotations

import asyncio
import logging
from app.utils.time import utc_now

from starlette import status

logger = logging.getLogger(__name__)

# Re-check this often. Short enough that a revoked session is torn down promptly, long
# enough to be negligible load on the DB / event loop.
DEFAULT_REVALIDATE_INTERVAL_SEC = 120.0


def websocket_session_is_valid(
    *,
    user_id: int,
    session_jti: str,
    require_admin: bool = False,
) -> bool:
    """Validate the session-bound identity carried by a consumed WS token."""
    from app.db.session import SessionLocal
    from app.models.session import UserSession
    from app.models.user import User

    if not session_jti:
        return False
    try:
        with SessionLocal() as db:
            user = db.get(User, int(user_id))
            if not user or not user.is_active or (require_admin and user.role != "admin"):
                return False
            session = db.query(UserSession).filter(
                UserSession.token_jti == session_jti,
                UserSession.user_id == int(user_id),
                UserSession.is_active.is_(True),
            ).one_or_none()
            return bool(session and session.expires_at >= utc_now())
    except Exception:
        return False


async def revalidate_session_periodically(
    websocket,
    *,
    token: str | None = None,
    user_id=None,
    session_jti: str | None = None,
    require_admin: bool = False,
    interval_sec: float = DEFAULT_REVALIDATE_INTERVAL_SEC,
) -> None:
    """Close the socket if auth becomes invalid mid-connection.

    Pass `token` for JWT-authenticated sockets (catches session revocation, expiry and
    user deactivation via decode_access_token). For sockets authenticated by a consumed
    one-shot token, pass `user_id` and its `session_jti` to re-check both the user
    and the login session that issued it.
    """
    from app.db.session import get_db
    from app.core.security import decode_access_token

    while True:
        await asyncio.sleep(interval_sec)

        # Self-terminate once the socket is gone (normal disconnect), so this task can never
        # leak even if the caller's cancel() is skipped on an exception path.
        try:
            if (getattr(websocket.client_state, "name", "") == "DISCONNECTED"
                    or getattr(websocket.application_state, "name", "") == "DISCONNECTED"):
                return
        except Exception:
            pass

        still_valid = True
        if token:
            try:
                db = next(get_db())
                try:
                    decode_access_token(token, db=db)  # raises if revoked/expired/inactive
                finally:
                    db.close()
            except Exception:
                still_valid = False
        elif user_id is not None:
            still_valid = await asyncio.to_thread(
                websocket_session_is_valid,
                user_id=int(user_id),
                session_jti=session_jti or "",
                require_admin=require_admin,
            )

        if not still_valid:
            logger.info("WS torn down mid-connection: session revoked / user no longer authorized")
            try:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            except Exception:
                pass
            return
