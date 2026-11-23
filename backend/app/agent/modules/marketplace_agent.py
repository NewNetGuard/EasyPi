"""Read-only explanation of the current Marketplace preview."""

from __future__ import annotations

from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class MarketplaceAgent:
    """Describe the honest, non-installing Marketplace preview state."""

    name = "marketplace_agent"
    _KEYWORDS = (
        "marketplace",
        "plugin",
        "package catalog",
        "package registry",
        "install package",
    )

    def score(self, request: AgentRequest) -> int:
        route = (request.route or "").strip().strip("/").lower()
        text = f"{request.question} {request.target or ''}".lower()
        score = 0
        if route.split("/", 1)[0] == "marketplace":
            score += 140
        if any(keyword in text for keyword in self._KEYWORDS):
            score += 100
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        return AgentResponse(
            category="service",
            target="marketplace",
            matched=True,
            title="Marketplace preview status",
            summary=(
                "Marketplace apps are currently a read-only preview with no live app registry; app install, update, and uninstall are disabled. "
                "Separately, reviewed system services such as WireGuard may still be installed through the allowlisted Services workflow."
            ),
            confidence="high",
            section="marketplace",
            subsection="preview",
            module=self.name,
            checks_run=["marketplace_release_state"],
            facts=[
                AgentFact("Release state", "Preview"),
                AgentFact("Live registry", "Not available", "warning"),
                AgentFact("Marketplace app installs", "Not available", "warning"),
                AgentFact("Available interaction", "Search and category filters"),
            ],
            reason_chain=[
                "The current Marketplace release state is defined as a curated preview.",
                "A trusted registry, package signatures, background jobs, action previews, and rollback are required before installation can be enabled safely.",
            ],
            recommendations=[
                "Use search and category filters to explore the planned package ideas.",
                "Do not expect preview cards to install software in the current release.",
            ],
        )
