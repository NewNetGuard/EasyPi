"""AI provider diagnostics module."""

from __future__ import annotations

from app.agent.adapters.provider import ProviderAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class ClaudeProviderAgent:
    """Explain provider-selection and external AI provider questions."""

    name = "claude_provider_agent"
    _KEYWORDS = (
        "claude",
        "provider",
        "external ai",
        "cloud ai",
        "api key",
        "anthropic",
        "openai",
        "gemini",
        "redacted",
        "redaction",
        "blocked request",
    )
    _ROUTES = ("claude", "ai")

    def __init__(self, adapter: ProviderAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()

        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 150
        if "claude" in route:
            score += 80
        elif "ai" in route and any(keyword in question for keyword in ("provider", "api key", "external", "claude")):
            score += 40
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        question = request.question.lower()
        state = await self.adapter.get_provider_state()
        provider_name = str(state.get("provider") or "unknown")
        external_provider = bool(state.get("external_provider_configured"))
        api_key_configured = bool(state.get("api_key_configured"))
        auth_state = str(state.get("provider_auth_state") or "unknown")
        facts = [
            AgentFact("Configured provider", provider_name),
            AgentFact("External provider configured", self._yes_no(external_provider)),
            AgentFact("API key configured", self._yes_no(api_key_configured)),
            AgentFact("Provider auth state", auth_state),
            AgentFact("Selected model", str(state.get("selected_model") or "Unknown")),
            AgentFact("Install status", str(state.get("install_status") or "unknown")),
            AgentFact("Ollama installed", self._yes_no(bool(state.get("ollama_installed")))),
            AgentFact(
                "Ollama healthy",
                self._yes_no(bool(state.get("ollama_healthy"))),
                "info" if bool(state.get("ollama_healthy")) else "warning",
            ),
        ]
        ollama_url = state.get("ollama_url")
        if ollama_url:
            facts.append(AgentFact("Ollama URL", str(ollama_url)))
        facts.append(
            AgentFact(
                "Provider request logs",
                self._yes_no(bool(state.get("request_logs_available"))),
                "info" if bool(state.get("request_logs_available")) else "warning",
            )
        )
        facts.append(
            AgentFact(
                "Redaction pipeline",
                str(state.get("redaction_mode") or "Unknown"),
                "info" if bool(state.get("redaction_pipeline_available")) else "warning",
            )
        )
        facts.append(
            AgentFact(
                "Quota tracking",
                str(state.get("quota_state") or "Unknown"),
                "info" if bool(state.get("quota_tracking_available")) else "warning",
            )
        )
        if state.get("provider_message"):
            facts.append(AgentFact("Provider detail", str(state.get("provider_message"))))

        if not external_provider:
            if "api key" in question or "auth" in question or "rejected" in question:
                summary = "No external provider API key is configured because this EasyPi build is currently using the local Ollama runtime only."
                confidence = "high"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "No external provider configuration or API credential is stored in the current backend state.",
                    "Provider-auth questions cannot succeed while EasyPi remains in local-only Ollama mode.",
                ]
                recommendations = [
                    "Use the local Ollama runtime for AI Chat unless a future external provider backend is added.",
                ]
            elif "quota" in question or "rate limit" in question or "limit" in question:
                summary = "No external provider quota state is available because EasyPi is currently using the local Ollama runtime only."
                confidence = "high"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "No external provider backend or quota telemetry is configured in the current runtime surface.",
                ]
                recommendations = [
                    "Treat provider-quota questions as unsupported until an external provider backend exists.",
                ]
            elif "redact" in question or "redaction" in question or "blocked request" in question:
                summary = "No cloud-provider redaction pipeline is active because EasyPi is currently using the local Ollama runtime only."
                confidence = "high"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "The current provider surface is local-only and does not expose an external redaction pipeline.",
                ]
                recommendations = [
                    "Handle privacy filtering locally before adding any future cloud-provider integration.",
                ]
            elif "which provider" in question or "provider" in question:
                summary = "EasyPi is currently using the local Ollama runtime as its active AI provider."
                confidence = "high"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "No external provider configuration is present, so the active surface remains local Ollama.",
                ]
                recommendations = [
                    "Open AI Chat or AI Runtime diagnostics if the local provider still does not answer.",
                ]
            else:
                summary = (
                    "This EasyPi build is currently configured for local Ollama only. "
                    "No external Claude-style provider or API key is configured."
                )
                confidence = "high"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "No external provider configuration or API credential is stored in the current backend state.",
                    "EasyPi is currently using the local Ollama runtime as its AI provider surface.",
                ]
                recommendations = [
                    "Use AI Chat with the local Ollama runtime unless an external provider integration is added later.",
                    "Treat provider-specific errors as unsupported until an external provider backend exists.",
                ]
        else:
            if "api key" in question or "auth" in question or "rejected" in question:
                summary = "An external AI provider is configured, but its authentication state is not healthy."
                confidence = "high" if auth_state not in {"ok", "ready"} else "medium"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "An external provider configuration is present.",
                    "The provider authentication state indicates that credentials should be verified.",
                ]
                recommendations = [
                    "Verify the external provider API key and provider-specific request logs next.",
                ]
            elif "redact" in question or "redaction" in question or "blocked request" in question:
                summary = "An external AI provider is configured, so request filtering should be verified in the provider redaction pipeline."
                confidence = "medium"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "An external provider configuration is present.",
                    "Redaction and blocked-request questions depend on provider-side filtering and request logs.",
                ]
                recommendations = [
                    "Inspect provider request logs and local redaction settings before retrying the blocked request.",
                ]
            else:
                summary = "An external AI provider is configured in addition to the local runtime."
                confidence = "medium"
                reason_chain = [
                    "The local AI provider state was inspected.",
                    "An external provider configuration is present.",
                ]
                recommendations = [
                    "Verify the external provider credentials and provider-specific request logs next.",
                ]

        return AgentResponse(
            category="service",
            target="ai-provider",
            matched=True,
            title="AI provider diagnostics",
            summary=summary,
            confidence=confidence,
            section="ai",
            subsection="provider",
            module=self.name,
            checks_run=["provider_state"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
