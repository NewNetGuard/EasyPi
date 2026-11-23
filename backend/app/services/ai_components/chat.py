"""AIChatMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.ai_components.context import (
    AIConfig,
    AIConversation,
    AIInstallStatus,
    AIModelInfo,
    AISettingsUpdate,
    AsyncGenerator,
    ChatResponse,
    List,
    Optional,
    Path,
    Session,
    asyncio,
    create_install_job,
    get_installer_log_path,
    get_settings,
    httpx,
    json,
    logger,
    logging,
    os,
    re,
    read_installer_log,
    run_in_threadpool,
    start_install_job,
    subprocess,
    text,
    utc_now,
    uuid,
)
from app.services.ai_components.knowledge import build_easypi_system_prompt
from app.services.ai_components.retrieval import retrieve_easypi_knowledge


class AIChatMixin:
    async def chat(
        self,
        message: str,
        session_id: Optional[str],
        db: Session,
        temperature_override: Optional[float] = None,
    ) -> ChatResponse:
        """Send message to AI and get a full response."""
        config = await run_in_threadpool(self._ensure_config, db)
        model_name = self._validate_model_name(config.model_name)
        ollama_url = self._normalize_ollama_url(
            config.ollama_url or self.ollama_url or "http://127.0.0.1:11434"
        )
        temperature = self._clamp_temperature(
            temperature_override
            if temperature_override is not None
            else config.temperature
        )
        if not session_id:
            session_id = str(uuid.uuid4())

        user_msg = AIConversation(
            session_id=session_id, role="user", content=message, model=model_name
        )

        def _store_user_msg():
            db.add(user_msg)
            db.commit()

        await run_in_threadpool(_store_user_msg)

        def _load_history():
            return (
                db.query(AIConversation)
                .filter(AIConversation.session_id == session_id)
                .order_by(AIConversation.created_at.desc())
                .limit(10)
                .all()
            )

        history = await run_in_threadpool(_load_history)

        knowledge_query = "\n".join(
            item.content
            for item in reversed(history)
            if item.role == "user" and item.content
        )[-2_000:]
        retrieved_knowledge = await run_in_threadpool(
            retrieve_easypi_knowledge,
            knowledge_query,
        )
        system_prompt = build_easypi_system_prompt(
            config.system_prompt,
            self.DEFAULT_SYSTEM_PROMPT,
            retrieved_knowledge,
        )

        messages = [{"role": "system", "content": system_prompt}]
        for msg in reversed(history):
            messages.append({"role": msg.role, "content": msg.content})

        try:
            async with httpx.AsyncClient(timeout=self._ollama_timeout()) as client:
                response = await client.post(
                    f"{ollama_url}/api/chat",
                    json={
                        "model": model_name,
                        "messages": messages,
                        "stream": False,
                        "options": {"temperature": temperature},
                    },
                )
                response.raise_for_status()
                data = response.json()
                ai_response = data.get("message", {}).get("content", "")

                ai_msg = AIConversation(
                    session_id=session_id,
                    role="assistant",
                    content=ai_response,
                    model=model_name,
                )

                def _store_ai_msg():
                    db.add(ai_msg)
                    db.commit()

                await run_in_threadpool(_store_ai_msg)

                return ChatResponse(
                    response=ai_response, session_id=session_id, model=model_name
                )
        except httpx.HTTPError as exc:
            logger.error("Ollama API error: %s", exc)
            raise

    async def chat_stream(
        self,
        message: str,
        session_id: Optional[str],
        db: Session,
        temperature_override: Optional[float] = None,
    ) -> AsyncGenerator[str, None]:
        """Send message to AI and stream the response chunk-by-chunk."""
        config = await run_in_threadpool(self._ensure_config, db)
        model_name = self._validate_model_name(config.model_name)
        ollama_url = self._normalize_ollama_url(
            config.ollama_url or self.ollama_url or "http://127.0.0.1:11434"
        )
        temperature = self._clamp_temperature(
            temperature_override
            if temperature_override is not None
            else config.temperature
        )
        if not session_id:
            session_id = str(uuid.uuid4())

        user_msg = AIConversation(
            session_id=session_id, role="user", content=message, model=model_name
        )

        def _store_user_msg():
            db.add(user_msg)
            db.commit()

        await run_in_threadpool(_store_user_msg)

        def _load_history():
            return (
                db.query(AIConversation)
                .filter(AIConversation.session_id == session_id)
                .order_by(AIConversation.created_at.desc())
                .limit(10)
                .all()
            )

        history = await run_in_threadpool(_load_history)

        knowledge_query = "\n".join(
            item.content
            for item in reversed(history)
            if item.role == "user" and item.content
        )[-2_000:]
        retrieved_knowledge = await run_in_threadpool(
            retrieve_easypi_knowledge,
            knowledge_query,
        )
        system_prompt = build_easypi_system_prompt(
            config.system_prompt,
            self.DEFAULT_SYSTEM_PROMPT,
            retrieved_knowledge,
        )

        messages = [{"role": "system", "content": system_prompt}]
        for msg in reversed(history):
            messages.append({"role": msg.role, "content": msg.content})

        full_response = ""
        try:
            async with httpx.AsyncClient(timeout=self._ollama_timeout()) as client:
                async with client.stream(
                    "POST",
                    f"{ollama_url}/api/chat",
                    json={
                        "model": model_name,
                        "messages": messages,
                        "stream": True,
                        "options": {"temperature": temperature},
                    },
                ) as response:
                    if response.status_code != 200:
                        body = await response.aread()
                        message = f"HTTP {response.status_code}"
                        if body:
                            try:
                                payload = json.loads(body.decode("utf-8"))
                                message = (
                                    payload.get("error")
                                    or payload.get("detail")
                                    or message
                                )
                            except json.JSONDecodeError:
                                message = (
                                    body.decode("utf-8", errors="replace").strip()
                                    or message
                                )
                        logger.error("Ollama chat stream failed: %s", message)
                        raise RuntimeError(message)
                    async for line in response.aiter_lines():
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        error_message = data.get("error") or data.get("detail")
                        if error_message:
                            logger.error("Ollama stream error: %s", error_message)
                            raise RuntimeError(error_message)
                        message_block = data.get("message", {})
                        content = message_block.get("content")
                        if content:
                            full_response += content
                            yield content

            if full_response:
                ai_msg = AIConversation(
                    session_id=session_id,
                    role="assistant",
                    content=full_response,
                    model=model_name,
                )

                def _store_ai_msg():
                    db.add(ai_msg)
                    db.commit()

                await run_in_threadpool(_store_ai_msg)
        except Exception as exc:
            logger.error("Chat stream error: %s", exc)
            raise

    # --------------------------------------------------------------------- #
    # History helpers
    # --------------------------------------------------------------------- #
    def get_conversation_history(self, session_id: str, db: Session, limit: int = 50):
        """Get conversation history for a session."""
        return (
            db.query(AIConversation)
            .filter(AIConversation.session_id == session_id)
            .order_by(AIConversation.created_at.asc())
            .limit(limit)
            .all()
        )

    def clear_conversation_history(self, session_id: str, db: Session) -> int:
        """Clear conversation history for a specific session."""
        deleted = (
            db.query(AIConversation)
            .filter(AIConversation.session_id == session_id)
            .delete()
        )
        db.commit()
        logger.info("Cleared %d messages for session %s", deleted, session_id)
        return deleted

    def clear_all_history(self, db: Session) -> int:
        """Clear all conversation history."""
        deleted = db.query(AIConversation).delete()
        db.commit()
        logger.info("Cleared all %d messages", deleted)
        return deleted

    def get_all_sessions(self, db: Session) -> List[dict]:
        """Get all chat sessions with metadata."""
        from sqlalchemy import func, desc

        # Get unique sessions with their last message time and message count
        sessions_query = (
            db.query(
                AIConversation.session_id,
                func.count(AIConversation.id).label("message_count"),
                func.max(AIConversation.created_at).label("last_message_at"),
                func.min(AIConversation.created_at).label("created_at"),
            )
            .group_by(AIConversation.session_id)
            .order_by(desc("last_message_at"))
            .all()
        )

        sessions = []
        for session in sessions_query:
            # Get first user message as title
            first_msg = (
                db.query(AIConversation)
                .filter(
                    AIConversation.session_id == session.session_id,
                    AIConversation.role == "user",
                )
                .order_by(AIConversation.created_at.asc())
                .first()
            )

            last_msg = (
                db.query(AIConversation)
                .filter(AIConversation.session_id == session.session_id)
                .order_by(AIConversation.created_at.desc())
                .first()
            )

            title = (
                first_msg.content[:50] + "..."
                if first_msg and len(first_msg.content) > 50
                else (first_msg.content if first_msg else "New chat")
            )
            model_name = None
            if last_msg and last_msg.model:
                model_name = last_msg.model
            elif first_msg and first_msg.model:
                model_name = first_msg.model

            sessions.append(
                {
                    "session_id": session.session_id,
                    "title": title,
                    "message_count": session.message_count,
                    "created_at": session.created_at.isoformat()
                    if session.created_at
                    else None,
                    "last_message_at": session.last_message_at.isoformat()
                    if session.last_message_at
                    else None,
                    "model": model_name,
                }
            )

        return sessions
