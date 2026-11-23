"""Help catalog fact adapter."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import re

from app.core.paths import get_easypi_root


class HelpAdapter:
    """Expose read-only help catalog data from the frontend source."""

    _FALLBACK_TOPICS = [
        {
            "id": "setup-overview",
            "route": "/setup",
            "title": "Setup & Permissions",
            "summary": "Configure backend access, permissions, and DNS for EasyPi.",
            "guideId": "guide-setup",
        },
        {
            "id": "dashboard-overview",
            "route": "/dashboard",
            "title": "Dashboard",
            "summary": "Monitor Pi resources, services, and alerts.",
            "guideId": "guide-monitoring",
        },
        {
            "id": "system-security-overview",
            "route": "/security",
            "title": "System Security",
            "summary": "Run security scans and apply hardening fixes.",
            "guideId": "guide-system-security",
        },
        {
            "id": "ai-overview",
            "route": "/ai",
            "title": "AI Chat",
            "summary": "Manage Ollama, models, and local AI sessions.",
            "guideId": "guide-ai",
        },
    ]
    _FALLBACK_GUIDES = [
        {"id": "guide-setup", "title": "How to complete setup", "sectionId": "setup"},
        {"id": "guide-system-security", "title": "How to run a security scan", "sectionId": "system-security"},
        {"id": "guide-ai", "title": "How to work with the AI assistant", "sectionId": "ai"},
        {"id": "guide-monitoring", "title": "How to monitor resources in real time", "sectionId": "monitoring"},
    ]
    _FALLBACK_ERRORS = [
        {
            "code": "ERR_PERMISSION_DENIED",
            "status": 403,
            "message": "Permission denied - sudo required",
            "meaning": "Operation requires sudo permissions or EasyPi group membership.",
        },
        {
            "code": "ERR_BACKUP_NOT_FOUND",
            "status": 404,
            "message": "Backup not found",
            "meaning": "The requested backup archive is missing or was removed.",
        },
    ]

    def __init__(self, source_path: str | Path | None = None) -> None:
        self.source_path = Path(source_path) if source_path else self._resolve_default_path()

    def find_topic(self, question: str, route: str | None = None) -> dict[str, str] | None:
        normalized_route = self._normalize_route(route)
        topics = self.get_context_topics()
        if normalized_route:
            for topic in topics:
                if self._normalize_route(topic.get("route")) == normalized_route:
                    return topic

        lowered = f"{question} {normalized_route}".strip().lower()
        best_match = None
        best_score = 0
        for topic in topics:
            score = 0
            title = str(topic.get("title") or "").lower()
            summary = str(topic.get("summary") or "").lower()
            route_value = self._normalize_route(topic.get("route"))
            if title and title in lowered:
                score += 120
            meaningful_tokens = {token for token in re.findall(r"[a-z0-9_-]+", lowered) if len(token) >= 4}
            if summary and any(token in summary for token in meaningful_tokens):
                score += 40
            if route_value and route_value.strip("/") and route_value.strip("/") in lowered:
                score += 80
            if score > best_score:
                best_match = topic
                best_score = score
        return best_match

    def find_guide(self, question: str, route: str | None = None, guide_id: str | None = None) -> dict[str, str] | None:
        guides = self.get_guides()
        if guide_id:
            for guide in guides:
                if guide.get("id") == guide_id:
                    return guide

        topic = self.find_topic(question, route)
        if topic and topic.get("guideId"):
            for guide in guides:
                if guide.get("id") == topic["guideId"]:
                    return guide

        lowered = question.lower()
        best_match = None
        best_score = 0
        for guide in guides:
            score = 0
            title = str(guide.get("title") or "").lower()
            section_id = str(guide.get("sectionId") or "").lower()
            if title and title in lowered:
                score += 120
            elif title and any(token in title for token in re.findall(r"[a-z0-9_-]+", lowered) if len(token) >= 4):
                score += 50
            if section_id and section_id in lowered:
                score += 40
            if score > best_score:
                best_match = guide
                best_score = score
        return best_match

    def find_error_code(self, question: str, target: str | None = None) -> dict[str, str | int] | None:
        code = self._extract_error_code(f"{question} {target or ''}")
        if not code:
            return None
        for entry in self.get_error_codes():
            if str(entry.get("code") or "").upper() == code:
                return entry
        return None

    def get_context_topics(self) -> list[dict[str, str]]:
        catalog = self._load_catalog()
        return list(catalog["topics"])

    def get_guides(self) -> list[dict[str, str]]:
        catalog = self._load_catalog()
        return list(catalog["guides"])

    def get_error_codes(self) -> list[dict[str, str | int]]:
        catalog = self._load_catalog()
        return list(catalog["errors"])

    def get_topic_by_route(self, route: str | None) -> dict[str, str] | None:
        normalized_route = self._normalize_route(route)
        if not normalized_route:
            return None
        for topic in self.get_context_topics():
            if self._normalize_route(topic.get("route")) == normalized_route:
                return topic
        return None

    def get_related_topics(self, route: str | None, *, limit: int = 3) -> list[dict[str, str]]:
        normalized_route = self._normalize_route(route)
        topics = self.get_context_topics()
        if not normalized_route:
            return [topic for topic in topics if topic.get("route") != "*"][:limit]

        exact_topic = self.get_topic_by_route(normalized_route)
        related: list[dict[str, str]] = []
        for topic in topics:
            topic_route = self._normalize_route(topic.get("route"))
            if topic_route == "*" or topic_route == normalized_route:
                continue
            if exact_topic is not None:
                exact_title = str(exact_topic.get("title") or "").lower()
                title = str(topic.get("title") or "").lower()
                if exact_title and any(token in title for token in exact_title.split()):
                    related.append(topic)
                    continue
            related.append(topic)
        return related[:limit]

    def _normalize_route(self, route: str | None) -> str:
        value = str(route or "").strip()
        if not value:
            return ""
        if not value.startswith("/"):
            value = f"/{value}"
        return value.lower()

    def _extract_error_code(self, value: str) -> str | None:
        match = re.search(r"\bERR_[A-Z0-9_]+\b", value or "", re.IGNORECASE)
        if not match:
            return None
        return match.group(0).upper()

    def _resolve_default_path(self) -> Path:
        candidates = [
            get_easypi_root() / "frontend" / "src" / "data" / "helpContent.ts",
            Path(__file__).resolve().parents[4] / "frontend" / "src" / "data" / "helpContent.ts",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[0]

    @lru_cache(maxsize=1)
    def _load_catalog(self) -> dict[str, list[dict[str, str | int]]]:
        if self.source_path.exists():
            try:
                text = self.source_path.read_text(encoding="utf-8", errors="replace")
                topics = self._parse_context_topics(text)
                guides = self._parse_guides(text)
                errors = self._parse_error_codes(text)
                if topics or guides or errors:
                    return {
                        "topics": topics or list(self._FALLBACK_TOPICS),
                        "guides": guides or list(self._FALLBACK_GUIDES),
                        "errors": errors or list(self._FALLBACK_ERRORS),
                    }
            except Exception:
                pass
        return {
            "topics": list(self._FALLBACK_TOPICS),
            "guides": list(self._FALLBACK_GUIDES),
            "errors": list(self._FALLBACK_ERRORS),
        }

    def _parse_context_topics(self, text: str) -> list[dict[str, str]]:
        block = self._extract_array_block(text, "export const contextHelpTopics")
        if not block:
            return []
        pattern = re.compile(
            r"\{\s*id:\s*'(?P<id>[^']+)'\s*,\s*route:\s*'(?P<route>[^']+)'\s*,\s*title:\s*'(?P<title>[^']+)'\s*,\s*summary:\s*'(?P<summary>[^']+)'\s*(?:,\s*guideId:\s*'(?P<guide>[^']+)')?\s*\}",
            re.S,
        )
        topics: list[dict[str, str]] = []
        for match in pattern.finditer(block):
            topics.append(
                {
                    "id": match.group("id"),
                    "route": match.group("route"),
                    "title": match.group("title"),
                    "summary": match.group("summary"),
                    "guideId": match.group("guide") or "",
                }
            )
        return topics

    def _parse_guides(self, text: str) -> list[dict[str, str]]:
        block = self._extract_array_block(text, "export const guides")
        if not block:
            return []
        pattern = re.compile(
            r"\{\s*id:\s*'(?P<id>[^']+)'\s*,\s*title:\s*'(?P<title>[^']+)'\s*,\s*sectionId:\s*'(?P<section>[^']+)'",
            re.S,
        )
        guides: list[dict[str, str]] = []
        for match in pattern.finditer(block):
            guides.append(
                {
                    "id": match.group("id"),
                    "title": match.group("title"),
                    "sectionId": match.group("section"),
                }
            )
        return guides

    def _parse_error_codes(self, text: str) -> list[dict[str, str | int]]:
        block = self._extract_array_block(text, "export const errorCodes")
        if not block:
            return []
        pattern = re.compile(
            r"\{\s*code:\s*'(?P<code>[^']+)'\s*,\s*status:\s*(?P<status>\d+)\s*,\s*message:\s*'(?P<message>[^']+)'\s*,\s*meaning:\s*'(?P<meaning>[^']+)'",
            re.S,
        )
        errors: list[dict[str, str | int]] = []
        for match in pattern.finditer(block):
            errors.append(
                {
                    "code": match.group("code"),
                    "status": int(match.group("status")),
                    "message": match.group("message"),
                    "meaning": match.group("meaning"),
                }
            )
        return errors

    def _extract_array_block(self, text: str, marker: str) -> str:
        start = text.find(marker)
        if start == -1:
            return ""
        open_bracket = text.find("[", start)
        if open_bracket == -1:
            return ""
        depth = 0
        for index in range(open_bracket, len(text)):
            char = text[index]
            if char == "[":
                depth += 1
            elif char == "]":
                depth -= 1
                if depth == 0:
                    return text[open_bracket + 1:index]
        return ""
