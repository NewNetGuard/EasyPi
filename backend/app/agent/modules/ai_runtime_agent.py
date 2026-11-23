"""AI runtime diagnostics module."""

from __future__ import annotations

from app.agent.adapters.ai_runtime import AIRuntimeAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class AIRuntimeAgent:
    """Explain Ollama, model, and AI runtime state."""

    name = "ai_runtime_agent"
    _KEYWORDS = (
        "ollama",
        "chat session",
        "ai chat",
        "local ai",
        "assistant model",
        "installed models",
        "install ai",
        "installation",
        "history",
        "stream",
        "streaming",
        "uninstall ai",
        "ai inference",
        "model inference",
        "ollama inference",
    )
    _ROUTES = ("ai", "claude")

    def __init__(self, adapter: AIRuntimeAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 110
        if any(token in route for token in self._ROUTES):
            score += 40
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        tab = str(request.tab or "").strip().lower()
        question = " ".join(part for part in (request.question.lower(), tab) if part)
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        target_raw = str(request.target or "").strip()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        install_status = await self.adapter.get_install_status()
        ollama_status = await self.adapter.get_ollama_status()
        installed_models = await self.adapter.get_installed_models()
        sessions = self.adapter.get_sessions()
        available_models = self.adapter.get_available_models()
        wants_history = "history" in question or "session" in question
        selected_session = self._find_session(target_raw or request.question, sessions) if wants_history else None
        session_history = self.adapter.get_session_history(str(selected_session.get("session_id")), limit=10) if selected_session else []

        if not install_status and not ollama_status and not installed_models and not available_models:
            return AgentResponse(
                category="service",
                target="ai-runtime",
                matched=True,
                title="AI runtime diagnostics",
                summary="AI runtime data are unavailable, so Ollama installation and health are unknown.",
                confidence="low",
                section="ai",
                subsection="runtime",
                module=self.name,
                checks_run=[],
                facts=[AgentFact("Runtime data", "Unavailable", "warning")],
                reason_chain=["All AI runtime sources returned empty payloads."],
                recommendations=["Check the AI runtime backend and retry."],
            )

        facts = [
            AgentFact("Configured model", str(install_status.get("model_name") or "Unknown")),
            AgentFact("Install status", str(install_status.get("status") or "unknown")),
            AgentFact("Ollama installed", self._yes_no(bool(ollama_status.get("installed")))),
            AgentFact("Ollama healthy", self._yes_no(bool(ollama_status.get("healthy"))), "info" if ollama_status.get("healthy") else "warning"),
            AgentFact("Installed models", str(len(installed_models))),
            AgentFact("Chat sessions", str(len(sessions))),
            AgentFact("Available curated models", str(len(available_models))),
        ]
        if selected_session is not None:
            facts.append(AgentFact("Selected session", str(selected_session.get("title") or selected_session.get("session_id") or "Unknown")))
            facts.append(AgentFact("Session messages", str(selected_session.get("message_count") or 0)))
        if session_history:
            facts.append(AgentFact("History preview size", str(len(session_history))))

        install_state = str(install_status.get("status") or "unknown").strip().lower()

        runtime_healthy = bool(ollama_status.get("installed")) and bool(ollama_status.get("healthy")) and bool(ollama_status.get("service_active"))

        if install_state == "error" and runtime_healthy and installed_models:
            summary = "AI install metadata is stale or conflicting: it reports an error while the live Ollama runtime is healthy with an installed model."
            confidence = "low"
            reason_chain = [
                "The saved install record reports an error.",
                "Live Ollama health and model inventory independently show a working runtime.",
            ]
            recommendations = ["Refresh or reconcile the saved install-state record without disrupting the healthy runtime."]
        elif install_state == "installing":
            summary = "AI runtime installation is currently in progress."
            confidence = "high"
            reason_chain = [
                "The AI runtime install state was queried.",
                "The current install status is marked as installing.",
            ]
            recommendations = [
                "Wait for the installation job to complete before opening a new chat session.",
            ]
        elif install_state == "uninstalling":
            summary = "AI runtime is currently uninstalling."
            confidence = "high"
            reason_chain = [
                "The AI runtime install state was queried.",
                "The current install status is marked as uninstalling.",
            ]
            recommendations = [
                "Wait for the uninstall job to finish before reinstalling or opening AI Chat again.",
            ]
        elif install_state == "error":
            summary = "The AI Chat (Ollama) install did not complete. Note that AI Chat is optional and heavy on a Raspberry Pi."
            confidence = "high"
            reason_chain = [
                "The AI runtime install state was queried.",
                "The current install status is marked as error.",
            ]
            recommendations = [
                "Check the AI install panel/logs if you want to retry — a failed model pull is usually out of disk space or RAM.",
                "AI Chat is optional; EasyPi's built-in agent already answers about your system instantly, with no model needed.",
            ]
        elif "uninstall" in question and bool(ollama_status.get("installed")):
            summary = "AI runtime is still installed locally, so uninstall has not completed yet."
            confidence = "high"
            reason_chain = [
                "The AI runtime status was queried.",
                "Ollama still reports itself as installed on this EasyPi instance.",
            ]
            recommendations = [
                "Run the uninstall flow to remove the local AI runtime if that is still intended.",
            ]
        elif not bool(ollama_status.get("installed")):
            summary = "The local AI Chat (Ollama) is not installed — this is optional, and language models are heavy on a Raspberry Pi."
            confidence = "high"
            reason_chain = [
                "The AI runtime status was queried.",
                "Ollama is not installed locally.",
            ]
            recommendations = [
                "AI Chat is optional: on a Pi a small model is weak and a capable one is too heavy/slow.",
                "You do not need it for diagnostics — EasyPi's built-in agent already answers about your system instantly and accurately.",
                "If you still want it, install Ollama and pull a small model (or point it at a stronger machine's Ollama).",
            ]
        elif "stream" in question or "streaming" in question:
            if not bool(ollama_status.get("service_active")) or not bool(ollama_status.get("healthy")):
                summary = "AI chat streaming cannot work reliably because the Ollama runtime is not healthy."
                confidence = "high"
                reason_chain = [
                    "The AI runtime status was queried.",
                    "The local Ollama service is not healthy or not active.",
                    "Streaming depends on a healthy local runtime.",
                ]
                recommendations = [
                    "Start Ollama and verify health before retrying chat streaming.",
                ]
            elif not installed_models:
                summary = "AI chat streaming is unavailable because no local model is installed."
                confidence = "high"
                reason_chain = [
                    "The AI runtime status was queried.",
                    "No installed local model is available for streaming responses.",
                ]
                recommendations = [
                    "Install a local model before retrying chat streaming.",
                ]
            else:
                summary = "The local AI runtime is healthy, and no streaming-specific failure is visible from current backend facts."
                confidence = "medium"
                reason_chain = [
                    "The AI runtime status was queried.",
                    "Ollama is healthy and a local model is installed.",
                    "No dedicated streaming failure state is stored in the current backend surface.",
                ]
                recommendations = [
                    "If streaming still fails in the UI, inspect the browser network stream and the backend AI logs.",
                ]
        elif not bool(ollama_status.get("service_active")) or not bool(ollama_status.get("healthy")):
            summary = "AI runtime is installed, but Ollama is not healthy right now."
            confidence = "high"
            reason_chain = [
                "The AI runtime status was queried.",
                "Ollama is installed but the runtime is not healthy or not active.",
            ]
            recommendations = [
                "Check Ollama status and start the service if it is stopped.",
                "Inspect the AI install panel for service or model errors.",
            ]
        elif not installed_models:
            summary = "Ollama is healthy, but no models are currently installed."
            confidence = "high"
            reason_chain = [
                "The AI runtime status was queried.",
                "Ollama is reachable, but the installed model list is empty.",
            ]
            recommendations = [
                "Install at least one model before opening a new chat session.",
            ]
        elif wants_history and selected_session is not None and session_history:
            message_count = int(selected_session.get("message_count") or 0)
            if message_count > len(session_history):
                summary = "AI chat history preview is incomplete: only an oldest subset is available, so the latest message cannot be determined."
                confidence = "low"
            else:
                latest_message = session_history[-1]
                facts.append(AgentFact("Latest role", str(latest_message.get("role") or "Unknown")))
                summary = "AI chat history is available for the selected session."
                confidence = "high"
            reason_chain = [
                "Chat sessions were queried from the local database.",
                "A matching session was found and recent history entries were loaded successfully.",
            ]
            recommendations = [
                "Open the matching chat session in AI Chat if you want the full conversation history.",
            ]
        elif wants_history and not sessions:
            summary = "AI runtime is healthy, but no chat sessions have been recorded yet."
            confidence = "medium"
            reason_chain = [
                "The AI runtime status was queried.",
                "No chat session records were found in the local database.",
            ]
            recommendations = [
                "Open AI Chat and start a new session to populate history.",
            ]
        elif wants_history:
            summary = "AI chat sessions are stored locally and at least one session is available."
            confidence = "high"
            reason_chain = [
                "Chat sessions were queried from the local database.",
                "At least one stored session exists for AI Chat history.",
            ]
            recommendations = [
                "Include a session title or identifier in your question for a more specific history diagnosis.",
            ]
        else:
            summary = "AI runtime looks healthy and ready for local chat."
            confidence = "medium"
            reason_chain = [
                "The AI runtime status was queried.",
                "Ollama is healthy and installed model data is available.",
            ]
            recommendations = [
                "If a specific prompt still fails, inspect model selection, system prompt, and session history.",
            ]

        return AgentResponse(
            category="service",
            target="ai-runtime",
            matched=True,
            title="AI runtime diagnostics",
            summary=summary,
            confidence=confidence,
            section="ai",
            subsection=tab if tab in {"chat", "models"} else "runtime",
            module=self.name,
            checks_run=["ai_install_status", "ollama_status", "installed_models", "ai_sessions"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _find_session(self, value: str, sessions: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        best_match = None
        best_length = 0
        for session in sessions:
            session_id = str(session.get("session_id") or "").strip().lower()
            title = str(session.get("title") or "").strip().lower()
            if normalized in {session_id, title}:
                return session
            if title and title in normalized and len(title) > best_length:
                best_match = session
                best_length = len(title)
        return best_match
