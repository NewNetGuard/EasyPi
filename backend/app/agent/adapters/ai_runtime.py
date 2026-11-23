"""AI runtime fact adapter."""

from __future__ import annotations

from typing import Any, Callable

from app.db.session import SessionLocal
from app.services.ai_service import AIService


class AIRuntimeAdapter:
    """Expose read-only Ollama and AI runtime state."""

    def __init__(
        self,
        service: Any | None = None,
        *,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.service = service or AIService()
        self.session_factory = session_factory or SessionLocal

    async def get_install_status(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            status = await self.service.get_status(db)
            if hasattr(status, "model_dump"):
                return status.model_dump(mode="json")
            return dict(status)
        finally:
            db.close()

    async def get_ollama_status(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            status = await self.service.get_ollama_status(db)
            return status if isinstance(status, dict) else {}
        finally:
            db.close()

    async def get_installed_models(self) -> list[str]:
        db = self.session_factory()
        try:
            models = await self.service.get_installed_models(db)
            return [str(model) for model in models if model]
        finally:
            db.close()

    def get_available_models(self) -> list[dict[str, Any]]:
        models = self.service.get_available_models()
        normalized: list[dict[str, Any]] = []
        for model in models:
            if hasattr(model, "model_dump"):
                normalized.append(model.model_dump(mode="json"))
            elif isinstance(model, dict):
                normalized.append(dict(model))
        return normalized

    def get_sessions(self) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            sessions = self.service.get_all_sessions(db)
            return [session for session in sessions if isinstance(session, dict)]
        finally:
            db.close()

    def get_session_history(self, session_id: str, limit: int = 20) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            messages = self.service.get_conversation_history(session_id, db, limit=limit)
            history: list[dict[str, Any]] = []
            for message in messages:
                history.append(
                    {
                        "id": getattr(message, "id", None),
                        "role": getattr(message, "role", None),
                        "content": getattr(message, "content", None),
                        "created_at": getattr(message, "created_at", None).isoformat()
                        if getattr(message, "created_at", None)
                        else None,
                        "model": getattr(message, "model", None),
                    }
                )
            return history
        finally:
            db.close()

    async def start_ollama(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.start_ollama(db)
            return dict(result) if isinstance(result, dict) else {"success": False, "message": "Unexpected Ollama start result"}
        finally:
            db.close()

    async def stop_ollama(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.stop_ollama(db)
            return dict(result) if isinstance(result, dict) else {"success": False, "message": "Unexpected Ollama stop result"}
        finally:
            db.close()
