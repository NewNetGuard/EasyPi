"""Help and support diagnostics module."""

from __future__ import annotations

from app.agent.adapters.help import HelpAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class HelpAgent:
    """Suggest the best help topic, guide, or error explanation."""

    name = "help_agent"
    _KEYWORDS = (
        "help",
        "support",
        "guide",
        "faq",
        "documentation",
        "docs",
        "error code",
        "read next",
        "what next",
        "where next",
        "where should i start",
    )
    _ROUTES = ("help",)

    def __init__(self, adapter: HelpAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        raw_question = request.question
        question = raw_question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        error_match = self.adapter.find_error_code(raw_question, request.target)
        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 110
        if ("meaning" in question or " mean" in question or question.endswith("mean?")) and (
            error_match is not None or "error" in question or "code" in question or "err_" in question
        ):
            score += 80
        if "how to" in question or "how do i" in question:
            score += 90
        if error_match is not None:
            score += 130
        if any(token in route for token in self._ROUTES):
            score += 40
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question
        route = request.route or ""
        normalized_question = question.lower()
        if self.score(request) <= 0:
            return None

        error = self.adapter.find_error_code(question, request.target)
        if error is not None:
            return self._error_response(error)

        route_topic_getter = getattr(self.adapter, "get_topic_by_route", None)
        route_topic = route_topic_getter(route) if callable(route_topic_getter) else None
        topic = self.adapter.find_topic(question, route)
        guide = self.adapter.find_guide(question, route, topic.get("guideId") if topic else None)
        related_topics_getter = getattr(self.adapter, "get_related_topics", None)
        related_topics = related_topics_getter(route, limit=3) if callable(related_topics_getter) else []
        if any(
            token in normalized_question
            for token in ("what should i read next", "what next", "where next", "where should i start")
        ) and route_topic is not None:
            return self._route_guidance_response(route_topic, guide or self.adapter.find_guide("", route, route_topic.get("guideId")), related_topics)
        if topic is not None:
            return self._topic_response(topic, guide, related_topics)
        if guide is not None:
            return self._guide_response(guide)
        if route_topic is not None:
            return self._route_guidance_response(
                route_topic,
                self.adapter.find_guide("", route, route_topic.get("guideId")),
                related_topics,
            )

        topics = self.adapter.get_context_topics()
        fallback_suggestions = related_topics
        facts = [AgentFact("Known topics", str(len(topics)))]
        if route:
            facts.append(AgentFact("Current route", route))
        if fallback_suggestions:
            facts.append(
                AgentFact(
                    "Suggested topics",
                    ", ".join(str(item.get("title") or "Unknown") for item in fallback_suggestions),
                )
            )
        return AgentResponse(
            category="service",
            target="help",
            matched=True,
            title="Help Center overview",
            summary="Help Center is available, but the question did not match a specific topic yet.",
            confidence="low",
            section="help",
            subsection="support",
            module=self.name,
            checks_run=["help_topics"],
            facts=facts,
            reason_chain=[
                "The local help catalog was queried.",
                "No direct topic, guide, or troubleshooting reference matched the current question.",
            ],
            recommendations=[
                "Mention the feature name, route, or exact Help reference for a better match.",
            ],
        )

    def _topic_response(
        self,
        topic: dict[str, str],
        guide: dict[str, str] | None,
        related_topics: list[dict[str, str]] | None = None,
    ) -> AgentResponse:
        facts = [
            AgentFact("Topic", str(topic.get("title") or "Unknown")),
            AgentFact("Route", str(topic.get("route") or "Unknown")),
        ]
        if guide is not None:
            facts.append(AgentFact("Suggested guide", str(guide.get("title") or guide.get("id") or "Unknown")))
        if related_topics:
            facts.append(
                AgentFact(
                    "Related topics",
                    ", ".join(str(item.get("title") or "Unknown") for item in related_topics[:3]),
                )
            )

        recommendations = [
            "Open Help & Support for the full guide and related FAQs.",
        ]
        if topic.get("route"):
            recommendations.append(f"Open the related section at {topic['route']}.")
        if guide is not None:
            recommendations.append(f"Read the guide '{guide.get('title')}' next.")

        return AgentResponse(
            category="service",
            target=str(topic.get("route") or "help"),
            matched=True,
            title="Help topic match",
            summary=str(topic.get("summary") or "A matching help topic was found."),
            confidence="high" if guide is not None else "medium",
            section="help",
            subsection="support",
            module=self.name,
            checks_run=["help_topics", "help_guides"],
            facts=facts,
            reason_chain=[
                "The local help catalog was queried.",
                "A route or keyword match was found in the Help Center topics.",
            ],
            recommendations=recommendations,
        )

    def _route_guidance_response(
        self,
        topic: dict[str, str],
        guide: dict[str, str] | None,
        related_topics: list[dict[str, str]],
    ) -> AgentResponse:
        facts = [
            AgentFact("Current route", str(topic.get("route") or "Unknown")),
            AgentFact("Primary topic", str(topic.get("title") or "Unknown")),
        ]
        if guide is not None:
            facts.append(AgentFact("Recommended guide", str(guide.get("title") or guide.get("id") or "Unknown")))
        if related_topics:
            facts.append(
                AgentFact(
                    "Next topics",
                    ", ".join(str(item.get("title") or "Unknown") for item in related_topics[:3]),
                )
            )

        recommendations = ["Open Help & Support for the route-specific guide."]
        if guide is not None:
            recommendations.append(f"Start with '{guide.get('title')}'.")
        for item in related_topics[:2]:
            recommendations.append(f"Read '{item.get('title')}' next if that area is still unclear.")

        return AgentResponse(
            category="service",
            target=str(topic.get("route") or "help"),
            matched=True,
            title="Help route guidance",
            summary=f"The best place to start is '{topic.get('title')}' in Help & Support.",
            confidence="high" if guide is not None else "medium",
            section="help",
            subsection="guides",
            module=self.name,
            checks_run=["help_topics", "help_guides"],
            facts=facts,
            reason_chain=[
                "The current route was matched against local Help Center topics.",
                "The agent selected the closest help topic and guide for the active section.",
            ],
            recommendations=recommendations,
        )

    def _guide_response(self, guide: dict[str, str]) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=str(guide.get("id") or "guide"),
            matched=True,
            title="Help guide match",
            summary=f"The best matching guide is '{guide.get('title')}'.",
            confidence="medium",
            section="help",
            subsection="guides",
            module=self.name,
            checks_run=["help_guides"],
            facts=[
                AgentFact("Guide", str(guide.get("title") or "Unknown")),
                AgentFact("Section", str(guide.get("sectionId") or "Unknown")),
            ],
            reason_chain=[
                "The local help guide index was queried.",
                "The question matched a guide title or section.",
            ],
            recommendations=[
                "Open Help & Support and search for the guide title to view the full steps.",
            ],
        )

    def _error_response(self, error: dict[str, str | int]) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=str(error.get("code") or "error"),
            matched=True,
            title=f"Help for {error.get('code')}",
            summary=str(error.get("meaning") or error.get("message") or "Help reference found."),
            confidence="high",
            section="help",
            subsection="errors",
            module=self.name,
            checks_run=["help_error_codes"],
            facts=[
                AgentFact("Help reference", str(error.get("code") or "Unknown")),
                AgentFact("HTTP status", str(error.get("status") or "Unknown")),
                AgentFact("Message", str(error.get("message") or "Unknown")),
            ],
            reason_chain=[
                "The local Help Center error catalog was queried.",
                "A matching troubleshooting reference was found.",
            ],
            recommendations=[
                "Open Help & Support for the full fix list tied to this reference.",
            ],
        )
