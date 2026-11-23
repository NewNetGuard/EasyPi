"""Allowlisted read-only probes for the EasyPi agent."""

from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from collections.abc import Awaitable, Callable
from typing import Any

ProbeHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | None] | dict[str, Any] | None]


@dataclass(slots=True)
class ProbeDefinition:
    handler: ProbeHandler
    allowed_keys: set[str] = field(default_factory=set)
    required_keys: set[str] = field(default_factory=set)


class AgentProbeRegistry:
    """Store and execute allowlisted read-only probes."""

    def __init__(self) -> None:
        self._handlers: dict[str, ProbeDefinition] = {}

    def register(
        self,
        probe_id: str,
        handler: ProbeHandler,
        *,
        allowed_keys: set[str] | None = None,
        required_keys: set[str] | None = None,
    ) -> None:
        allowed = set(allowed_keys or set())
        required = set(required_keys or set())
        if not required.issubset(allowed):
            raise ValueError("Required probe parameters must also be allowlisted")
        self._handlers[probe_id] = ProbeDefinition(handler, allowed, required)

    def list_probe_ids(self) -> list[str]:
        return sorted(self._handlers)

    async def run(self, probe_id: str, parameters: dict[str, Any] | None = None) -> dict[str, Any]:
        definition = self._handlers.get(probe_id)
        if definition is None:
            return {
                "success": False,
                "probe_id": probe_id,
                "source_status": "unavailable",
                "message": "This read-only agent probe is not registered.",
            }

        supplied = dict(parameters or {})
        unexpected = sorted(set(supplied) - definition.allowed_keys)
        if unexpected:
            return {
                "success": False,
                "probe_id": probe_id,
                "source_status": "unavailable",
                "message": f"Unsupported probe parameters: {', '.join(unexpected)}.",
            }
        missing = sorted(definition.required_keys - set(supplied))
        if missing:
            return {
                "success": False,
                "probe_id": probe_id,
                "source_status": "unavailable",
                "message": f"Missing required probe parameters: {', '.join(missing)}.",
            }
        try:
            result = definition.handler(supplied)
            if inspect.isawaitable(result):
                result = await result
            if result is None or (isinstance(result, dict) and not result):
                return {
                    "success": False,
                    "probe_id": probe_id,
                    "source_status": "unavailable",
                    "message": "The probe source returned no diagnostic evidence.",
                }
            if not isinstance(result, dict):
                return {
                    "success": False,
                    "probe_id": probe_id,
                    "source_status": "unavailable",
                    "message": "The probe source returned an unsupported evidence payload.",
                }
            payload = dict(result)
        except Exception as exc:
            return {
                "success": False,
                "probe_id": probe_id,
                "source_status": "unavailable",
                "message": f"Probe source failed with {type(exc).__name__}: {exc}",
            }
        raw_success = payload.get("success")
        if not isinstance(raw_success, bool):
            return {
                "success": False,
                "probe_id": probe_id,
                "source_status": "unavailable",
                "message": "The probe source did not explicitly confirm its result.",
            }
        explicit_error = payload.get("error")
        explicit_error_message = payload.get("error_message")
        explicit_errors = payload.get("errors")
        empty_error_values = (None, "", False, [], {})
        has_explicit_error = any(
            value not in empty_error_values
            for value in (explicit_error, explicit_error_message, explicit_errors)
        )
        raw_state = str(payload.get("status") or "").strip().lower()
        conflicting_failure_state = raw_state in {
            "error",
            "failed",
            "failure",
            "unhealthy",
            "unavailable",
            "timeout",
            "timed_out",
        }
        if raw_success and (has_explicit_error or conflicting_failure_state):
            detail = (
                explicit_error
                or explicit_error_message
                or explicit_errors
                or payload.get("message")
                or raw_state
            )
            payload["success"] = False
            payload["probe_id"] = probe_id
            payload["source_status"] = "conflict"
            payload["message"] = f"The probe source returned conflicting success and failure evidence: {detail}"
            return payload
        allowed_statuses = {"ok", "partial", "unavailable", "stale", "conflict"}
        source_status = str(payload.get("source_status") or ("ok" if raw_success else "unavailable"))
        if source_status not in allowed_statuses:
            payload["success"] = False
            source_status = "unavailable"
            payload["message"] = "The probe source returned an invalid source status."
        elif source_status != "ok":
            payload["success"] = False
        elif not raw_success:
            source_status = "partial"
        payload["probe_id"] = probe_id
        payload["source_status"] = source_status
        return payload
