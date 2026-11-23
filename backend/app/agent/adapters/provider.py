"""AI provider adapter for provider and Claude-style diagnostics."""

from __future__ import annotations

from typing import Any

from app.agent.adapters.ai_runtime import AIRuntimeAdapter


class ProviderAdapter:
    """Expose the currently configured AI provider surface."""

    def __init__(self, runtime: AIRuntimeAdapter | None = None) -> None:
        self.runtime = runtime or AIRuntimeAdapter()

    async def get_provider_state(self) -> dict[str, Any]:
        install_status = await self.runtime.get_install_status()
        ollama_status = await self.runtime.get_ollama_status()
        sessions = self.runtime.get_sessions()
        return {
            "provider": "ollama-local",
            "external_provider_configured": False,
            "api_key_configured": False,
            "provider_auth_state": "not_configured",
            "provider_message": "No external provider integration is configured in the current backend.",
            "quota_tracking_available": False,
            "quota_state": "unsupported",
            "request_logs_available": False,
            "redaction_pipeline_available": False,
            "redaction_mode": "local-only",
            "selected_model": install_status.get("model_name"),
            "install_status": install_status.get("status"),
            "ollama_url": install_status.get("ollama_url"),
            "ollama_installed": bool(ollama_status.get("installed")),
            "ollama_healthy": bool(ollama_status.get("healthy")),
            "session_count": len(sessions),
        }
