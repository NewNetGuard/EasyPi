"""
AI Assistant API Endpoints

Endpoints for AI chat, installation, and management.
All endpoints require admin authentication.
"""

import asyncio
import logging
import time
from collections import defaultdict
from threading import Lock
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session
from typing import List

from app.api.deps import require_admin
from app.core.rate_limit import get_client_ip
from app.db.session import get_db
from app.models.user import User
from app.services.ai_diagnostic_service import AIDiagnosticService
from app.services.ai_service import AIService
from app.services.operation_event_service import OperationEventService
from app.schemas.ai import (
    ChatRequest,
    ChatResponse,
    AIInstallStatus,
    ConversationMessage,
    InstallRequest,
    AIModelInfo,
    AISettingsUpdate,
    DiagnosticExplainRequest,
    DiagnosticExplainResponse,
    DiagnosticActionRequest,
    DiagnosticActionResponse,
    DiagnosticProbeRequest,
    DiagnosticProbeResponse,
)

router = APIRouter(tags=["ai"])
ai_service = AIService()
diagnostic_service = AIDiagnosticService()
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()


class RateLimiter:
    """Simple in-memory rate limiter for agent-heavy endpoints."""

    def __init__(self, calls: int, period: int) -> None:
        self.calls = calls
        self.period = period
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def is_allowed(self, key: str) -> bool:
        now = time.time()
        with self._lock:
            self._requests[key] = [item for item in self._requests[key] if now - item < self.period]
            if len(self._requests[key]) >= self.calls:
                return False
            self._requests[key].append(now)
            return True


_diagnostic_read_limiter = RateLimiter(calls=90, period=60)
_diagnostic_write_limiter = RateLimiter(calls=30, period=60)


def _client_key(request: Request) -> str:
    return get_client_ip(request)


def enforce_diagnostic_read_rate_limit(request: Request) -> None:
    client_key = _client_key(request)
    if not _diagnostic_read_limiter.is_allowed(client_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for diagnostic requests.",
            headers={"Retry-After": "60"},
        )


def enforce_diagnostic_write_rate_limit(request: Request) -> None:
    client_key = _client_key(request)
    if not _diagnostic_write_limiter.is_allowed(client_key):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded for diagnostic actions.",
            headers={"Retry-After": "60"},
        )


def _record_ai_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/ai",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record AI event %s: %s", action_id, exc)


@router.get("/status", response_model=AIInstallStatus)
async def get_ai_status(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Get AI installation status"""
    await ai_service.check_health(db)
    return await ai_service.get_status(db)


@router.get("/health")
async def check_ai_health(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Check if Ollama is running"""
    is_healthy = await ai_service.check_health(db)
    return {"healthy": is_healthy}


@router.get("/ollama/status")
async def get_ollama_status(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Get Ollama runtime status"""
    return await ai_service.get_ollama_status(db)


@router.post("/ollama/ensure")
async def ensure_ollama(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Install/start Ollama if needed (streaming logs). Requires admin."""

    async def generate():
        async for log_line in ai_service.ensure_ollama(db):
            yield log_line

    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/ollama/start")
async def start_ollama(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Start Ollama service."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await ai_service.start_ollama(db)
    _record_ai_event(
        action_id="ai.ollama.start",
        title="Start Ollama runtime",
        subtitle="AI Chat · Local model runtime",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", "Ollama start completed"),
        started_at=started_at,
    )
    return result


@router.post("/ollama/stop")
async def stop_ollama(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Stop Ollama service."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await ai_service.stop_ollama(db)
    _record_ai_event(
        action_id="ai.ollama.stop",
        title="Stop Ollama runtime",
        subtitle="AI Chat · Local model runtime",
        status="success" if result.get("success", False) else "failed",
        message=result.get("message", "Ollama stop completed"),
        started_at=started_at,
    )
    return result


@router.post("/install")
async def install_ai(
    payload: InstallRequest | None = None,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Install Ollama and model (streaming logs). Requires admin."""

    model_name = payload.model_name if payload else None
    temperature = payload.temperature if payload else None
    system_prompt = payload.system_prompt if payload else None

    async def generate():
        async for log_line in ai_service.install(
            db=db,
            model_name=model_name,
            temperature=temperature,
            system_prompt=system_prompt,
        ):
            yield log_line
    
    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/models", response_model=List[AIModelInfo])
async def list_available_models(_admin: User = Depends(require_admin)):
    """List curated Ollama models available inside EasyPi."""
    return ai_service.get_available_models()


@router.get("/models/installed")
async def list_installed_models(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """List models currently installed in Ollama."""
    models = await ai_service.get_installed_models(db)
    return {"models": models}


@router.put("/config", response_model=AIInstallStatus)
async def update_ai_config(
    payload: AISettingsUpdate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Update AI assistant configuration (model, temperature, prompt)."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await ai_service.update_config(db, payload)
    _record_ai_event(
        action_id="ai.config.update",
        title="Update AI settings",
        subtitle="AI Chat · Assistant configuration",
        status="success",
        message=result.message if hasattr(result, "message") else "AI settings updated",
        started_at=started_at,
    )
    return result


@router.post("/ask", response_model=ChatResponse)
async def ask_ai(
    request: ChatRequest,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Ask AI a question"""
    ready, reason = await ai_service.ensure_model_ready(db)
    if not ready:
        raise HTTPException(status_code=503, detail=reason)
    
    try:
        return await ai_service.chat(
            message=request.message,
            session_id=request.session_id,
            db=db,
            temperature_override=request.temperature
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/diagnostics/explain", response_model=DiagnosticExplainResponse)
async def explain_diagnostic(
    request: DiagnosticExplainRequest,
    _rate_limit: None = Depends(enforce_diagnostic_read_rate_limit),
    admin: User = Depends(require_admin)
):
    """Explain a local diagnostic question using deterministic local facts."""
    try:
        return await diagnostic_service.explain(
            question=request.question,
            target_type=request.target_type,
            target=request.target,
            route=request.route,
            tab=request.tab,
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            actor_user_id=getattr(admin, "id", None),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Agent diagnostic explain failed")
        raise HTTPException(status_code=500, detail="Agent diagnostics failed.")


@router.post("/diagnostics/action", response_model=DiagnosticActionResponse)
async def execute_diagnostic_action(
    request: DiagnosticActionRequest,
    _rate_limit: None = Depends(enforce_diagnostic_write_rate_limit),
    admin: User = Depends(require_admin)
):
    """Execute an allowlisted agent action and optionally return refreshed diagnostics."""
    try:
        return await diagnostic_service.execute_action(
            action_id=request.action_id,
            parameters=request.parameters,
            confirmation_token=request.confirmation_token,
            question=request.question,
            target_type=request.target_type,
            target=request.target,
            route=request.route,
            tab=request.tab,
            entity_type=request.entity_type,
            entity_id=request.entity_id,
            actor_user_id=getattr(admin, "id", None),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Agent diagnostic action failed")
        raise HTTPException(status_code=500, detail="Agent action failed.")


@router.post("/diagnostics/probe", response_model=DiagnosticProbeResponse)
async def run_diagnostic_probe(
    request: DiagnosticProbeRequest,
    _rate_limit: None = Depends(enforce_diagnostic_read_rate_limit),
    admin: User = Depends(require_admin),
):
    """Run an explicitly requested, allowlisted diagnostic probe."""
    try:
        return await diagnostic_service.run_probe(
            request.probe_id,
            parameters=request.parameters,
            actor_user_id=getattr(admin, "id", None),
        )
    except HTTPException:
        raise
    except Exception:
        logger.exception("Agent diagnostic probe failed")
        raise HTTPException(status_code=500, detail="Agent probe failed.")


@router.post("/chat/stream")
async def chat_stream(
    request: ChatRequest,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Chat with AI (streaming response)"""
    ready, reason = await ai_service.ensure_model_ready(db)
    if not ready:
        raise HTTPException(status_code=503, detail=reason)
    
    keepalive_token = "[[KEEPALIVE]]"
    keepalive_interval = 15.0

    async def generate():
        queue: asyncio.Queue[str] = asyncio.Queue()
        done = asyncio.Event()
        error_holder: dict[str, Exception | None] = {"error": None}

        async def pump() -> None:
            try:
                async for chunk in ai_service.chat_stream(
                    message=request.message,
                    session_id=request.session_id,
                    db=db,
                    temperature_override=request.temperature
                ):
                    await queue.put(chunk)
            except Exception as exc:
                error_holder["error"] = exc
            finally:
                done.set()

        task = asyncio.create_task(pump())
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(queue.get(), timeout=keepalive_interval)
                except asyncio.TimeoutError:
                    if done.is_set() and queue.empty():
                        break
                    yield keepalive_token
                    continue

                if chunk:
                    yield chunk
                if done.is_set() and queue.empty():
                    break

            if error_holder["error"] is not None:
                yield f"\n[Error: {error_holder['error']}]"
        finally:
            if not task.done():
                task.cancel()
    
    return StreamingResponse(
        generate(),
        media_type="text/plain",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/history/{session_id}", response_model=List[ConversationMessage])
async def get_conversation_history(
    session_id: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Get conversation history"""
    return await run_in_threadpool(ai_service.get_conversation_history, session_id, db, limit)


@router.delete("/history/{session_id}")
async def clear_conversation_history(
    session_id: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Clear conversation history for a session"""
    deleted_count = await run_in_threadpool(ai_service.clear_conversation_history, session_id, db)
    return {"deleted": deleted_count, "session_id": session_id}


@router.delete("/history")
async def clear_all_history(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Clear all conversation history"""
    deleted_count = await run_in_threadpool(ai_service.clear_all_history, db)
    return {"deleted": deleted_count}


@router.get("/sessions")
async def get_all_sessions(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Get all chat sessions with last message preview"""
    return await run_in_threadpool(ai_service.get_all_sessions, db)


@router.delete("/uninstall")
async def uninstall_ai(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Uninstall Ollama and remove all data (streaming logs). Requires admin."""
    async def generate():
        async for log_line in ai_service.uninstall(db):
            yield log_line
    
    return StreamingResponse(
        generate(),
        media_type="text/plain"
    )


@router.delete("/model")
async def delete_model(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Delete only the AI model (keep Ollama installed). Requires admin."""
    async def generate():
        async for log_line in ai_service.delete_model(db):
            yield log_line
    
    return StreamingResponse(
        generate(),
        media_type="text/plain"
    )


@router.post("/install/cancel")
async def cancel_install(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Cancel ongoing installation and clean up downloaded files. Requires admin."""
    result = await ai_service.cancel_install(db)
    return result


__all__ = ["router"]
