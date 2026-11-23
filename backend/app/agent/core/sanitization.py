"""Input normalization and validation helpers for the EasyPi agent."""

from __future__ import annotations

import math
import re
from typing import Any

from app.agent.core.contracts import AgentRequest

ACTION_ID_RE = re.compile(r"^[a-z][a-z0-9._-]{2,99}$")
ROUTE_RE = re.compile(r"^[a-z0-9][a-z0-9/_-]{0,254}$")
TAB_RE = re.compile(r"^[a-z0-9][a-z0-9:_./ -]{0,99}$")
ENTITY_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9:_./ -]{0,99}$")
PARAM_KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
WHITESPACE_RE = re.compile(r"\s+")


def normalize_free_text(value: Any, *, max_length: int) -> str:
    """Normalize broad user text without allowing control characters."""

    text = str(value or "")
    text = CONTROL_CHARS_RE.sub(" ", text)
    text = WHITESPACE_RE.sub(" ", text).strip()
    if max_length > 0:
        text = text[:max_length].strip()
    return text


def normalize_optional_text(value: Any, *, max_length: int) -> str | None:
    """Normalize optional user text."""

    text = normalize_free_text(value, max_length=max_length)
    return text or None


def normalize_route(value: Any) -> str | None:
    """Normalize a frontend route hint into a stable slug-like form."""

    route = str(value or "").strip().strip("/").lower()
    if not route:
        return None
    route = CONTROL_CHARS_RE.sub("", route)
    route = re.sub(r"/{2,}", "/", route)
    return route or None


def validate_route(value: Any) -> str | None:
    """Validate and normalize a route-like value."""

    normalized = normalize_route(value)
    if normalized is None:
        return None
    if not ROUTE_RE.fullmatch(normalized):
        raise ValueError("Route contains unsupported characters")
    return normalized


def validate_tab(value: Any) -> str | None:
    """Validate and normalize a tab hint."""

    normalized = normalize_optional_text(value, max_length=100)
    if normalized is None:
        return None
    normalized = normalized.lower()
    if not TAB_RE.fullmatch(normalized):
        raise ValueError("Tab contains unsupported characters")
    return normalized


def validate_entity_type(value: Any) -> str | None:
    """Validate and normalize an entity type hint."""

    normalized = normalize_optional_text(value, max_length=100)
    if normalized is None:
        return None
    normalized = normalized.lower()
    if not ENTITY_TYPE_RE.fullmatch(normalized):
        raise ValueError("Entity type contains unsupported characters")
    return normalized


def validate_action_id(value: Any) -> str:
    """Validate and normalize a registered agent action identifier."""

    normalized = normalize_optional_text(value, max_length=100)
    if normalized is None:
        raise ValueError("Action id is required")
    normalized = normalized.lower()
    if not ACTION_ID_RE.fullmatch(normalized):
        raise ValueError("Action id contains unsupported characters")
    return normalized


def sanitize_action_parameters(
    parameters: dict[str, Any] | None,
    *,
    max_keys: int = 8,
    max_string_length: int = 255,
) -> dict[str, str | int | float | bool | None]:
    """Keep only simple, bounded action parameters."""

    if parameters is None:
        return {}
    if not isinstance(parameters, dict):
        raise ValueError("Action parameters must be an object")
    if len(parameters) > max_keys:
        raise ValueError("Too many action parameters were provided")

    sanitized: dict[str, str | int | float | bool | None] = {}
    for key, raw_value in parameters.items():
        key_text = normalize_optional_text(key, max_length=64)
        if key_text is None or not PARAM_KEY_RE.fullmatch(key_text.lower()):
            raise ValueError("Action parameter keys contain unsupported characters")
        key_text = key_text.lower()

        if raw_value is None or isinstance(raw_value, bool):
            sanitized[key_text] = raw_value
            continue
        if isinstance(raw_value, int) and not isinstance(raw_value, bool):
            sanitized[key_text] = raw_value
            continue
        if isinstance(raw_value, float):
            if not math.isfinite(raw_value):
                raise ValueError("Numeric action parameters must be finite")
            sanitized[key_text] = raw_value
            continue
        if isinstance(raw_value, str):
            sanitized[key_text] = normalize_free_text(raw_value, max_length=max_string_length)
            continue
        raise ValueError("Action parameters only support primitive JSON values")

    return sanitized


def normalize_agent_request(request: AgentRequest) -> AgentRequest:
    """Normalize an AgentRequest before routing or execution."""

    try:
        route = validate_route(request.route)
    except ValueError:
        route = None
    try:
        tab = validate_tab(request.tab)
    except ValueError:
        tab = None
    try:
        entity_type = validate_entity_type(request.entity_type)
    except ValueError:
        entity_type = None

    return AgentRequest(
        question=normalize_free_text(request.question, max_length=500),
        target_type=request.target_type,
        target=normalize_optional_text(request.target, max_length=255),
        route=route,
        tab=tab,
        entity_type=entity_type,
        entity_id=normalize_optional_text(request.entity_id, max_length=255),
        actor_user_id=request.actor_user_id if isinstance(request.actor_user_id, int) and request.actor_user_id > 0 else None,
    )


__all__ = [
    "normalize_agent_request",
    "normalize_free_text",
    "normalize_optional_text",
    "normalize_route",
    "sanitize_action_parameters",
    "validate_action_id",
    "validate_entity_type",
    "validate_route",
    "validate_tab",
]
