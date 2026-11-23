"""Task logs WebSocket handler for real-time log streaming."""
import asyncio
import logging
from pathlib import Path
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect
from starlette import status

from app.api.v1.endpoints.tasks import active_tasks
from app.db.session import SessionLocal
from app.models.user import User

logger = logging.getLogger(__name__)


async def task_logs(
    websocket: WebSocket,
    task_id: str,
    ws_token: Optional[str] = None,
) -> None:
    """Stream task logs in real-time via WebSocket.
    
    Connects to a running task and streams its log output as it's written.
    
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
                "Task logs WS connection rejected - invalid ws_token from %s",
                websocket.client,
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return
        user_id = claims.user_id
        session_jti = claims.session_jti
    else:
        # No authentication provided
        logger.warning(
            "Task logs WS connection rejected - no token from %s",
            websocket.client,
        )
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    try:
        authenticated_user_id = int(user_id)
    except (TypeError, ValueError):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    with SessionLocal() as db:
        user = db.get(User, authenticated_user_id)
        if not user or not user.is_active or user.role != "admin":
            logger.warning(
                "Task logs WS connection rejected - admin access required for user %s",
                authenticated_user_id,
            )
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

    user_id = authenticated_user_id

    # Authentication and authorization succeeded - proceed with connection
    await websocket.accept()
    logger.info(f"Task logs WebSocket connected for user {user_id}, task {task_id}")

    from app.api.websocket.ws_auth import revalidate_session_periodically
    _revalidator = asyncio.create_task(
        revalidate_session_periodically(
            websocket,
            user_id=user_id,
            session_jti=session_jti,
            require_admin=True,
        )
    )
    try:
        # Check if task exists
        if task_id not in active_tasks:
            await websocket.send_json({"error": "Task not found", "task_id": task_id})
            await websocket.close()
            return
        
        task = active_tasks[task_id]
        log_file = Path(task["log_file"])
        
        # Send initial task metadata
        await websocket.send_json({
            "type": "metadata",
            "task_id": task_id,
            "script": task["script"],
            "action": task["action"],
            "status": task["status"],
        })
        
        # Wait for log file to be created
        for _ in range(50):  # Wait up to 5 seconds
            if log_file.exists():
                break
            await asyncio.sleep(0.1)
        
        if not log_file.exists():
            await websocket.send_json({"error": "Log file not found"})
            await websocket.close()
            return
        
        # Stream log file content
        sent_bytes = 0
        
        while True:
            try:
                # Read new content
                with open(log_file, "r") as f:
                    f.seek(sent_bytes)
                    new_content = f.read()
                    
                    if new_content:
                        # Send new log lines
                        for line in new_content.splitlines(keepends=True):
                            await websocket.send_json({
                                "type": "log",
                                "data": line,
                            })
                        sent_bytes += len(new_content.encode())
                
                # Check if task is finished
                task_status = task["status"]
                if task_status in ["success", "failed", "error"]:
                    # Send final status
                    await websocket.send_json({
                        "type": "status",
                        "status": task_status,
                        "exit_code": task.get("exit_code"),
                    })
                    break
                
                # Wait before checking for more content
                await asyncio.sleep(0.1)
                
            except WebSocketDisconnect:
                logger.info(f"Client disconnected from task {task_id}")
                break
            except Exception as e:
                logger.error(f"Error streaming logs for task {task_id}: {e}")
                await websocket.send_json({"error": str(e)})
                break
        
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for task {task_id}")
    except Exception as e:
        logger.exception(f"WebSocket error for task {task_id}: {e}")
    finally:
        _revalidator.cancel()
        try:
            await websocket.close()
        except Exception:
            pass
