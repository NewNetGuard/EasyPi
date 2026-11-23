"""Helpers for building and normalizing agent responses."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.agent.core.confidence import normalize_confidence
from app.agent.core.contracts import (
    AgentAction,
    AgentFact,
    AgentResponse,
    CategoryType,
    ConfidenceLevel,
    SourceStatus,
)


def build_response(
    *,
    category: CategoryType,
    target: str,
    matched: bool,
    title: str,
    summary: str,
    confidence: str | ConfidenceLevel,
    section: str | None = None,
    subsection: str | None = None,
    module: str | None = None,
    source_status: SourceStatus = "ok",
    source_errors: list[str] | None = None,
    checks_run: list[str] | None = None,
    facts: list[AgentFact] | None = None,
    recommendations: list[str] | None = None,
    reason_chain: list[str] | None = None,
    actions: list[AgentAction] | None = None,
) -> AgentResponse:
    """Build a normalized agent response."""

    response = AgentResponse(
        category=category,
        target=str(target or "").strip(),
        matched=matched,
        title=str(title or "").strip(),
        summary=str(summary or "").strip(),
        confidence=normalize_confidence(confidence),
        section=section,
        subsection=subsection,
        module=module,
        source_status=source_status,
        source_errors=list(source_errors or []),
        checks_run=list(checks_run or []),
        facts=list(facts or []),
        recommendations=list(recommendations or []),
        reason_chain=list(reason_chain or []),
        actions=list(actions or []),
    )
    return finalize_response(response)


def finalize_response(response: AgentResponse) -> AgentResponse:
    """Normalize a module response before it leaves the agent pipeline."""

    response.confidence = normalize_confidence(response.confidence)
    response.checks_run = _dedupe_strings(response.checks_run)
    response.recommendations = _dedupe_strings(response.recommendations)
    response.reason_chain = _dedupe_strings(response.reason_chain)
    response.facts = _dedupe_facts(response.facts)
    response.actions = _dedupe_actions(response.actions)
    _apply_freshness_policy(response)
    _apply_source_status(response)
    if response.source_status != "ok":
        response.actions = []
    if response.source_status in {"stale", "conflict", "unavailable"}:
        safe_recommendations = {
            "stale": "Refresh the underlying source before making a current-state decision.",
            "conflict": "Resolve the conflicting sources and refresh diagnostics before changing system state.",
            "unavailable": "Restore the unavailable diagnostic source and retry before changing system state.",
        }
        response.recommendations = [safe_recommendations[response.source_status]]
        response.reason_chain = [
            f"Recommendations and actions were withheld because source_status={response.source_status}."
        ]
    return response


def _apply_source_status(response: AgentResponse) -> None:
    """Expose provenance quality instead of forcing clients to infer it from prose."""

    response.source_errors = _dedupe_strings(response.source_errors)
    # Probe payload fields are structured evidence whose names may legitimately
    # contain words such as ``conflicts`` (for example, ``conflicts: []``).
    # Their adapter-provided ``source_status`` is authoritative; treating field
    # names as prose creates false conflicts for otherwise healthy probes.  The
    # probe summary and reason chain remain part of the inference blob, so an
    # actual conflict reported in human-readable evidence is still detected.
    inference_facts = [
        fact
        for fact in response.facts
        if not str(fact.label or "").strip().lower().startswith("probe ")
    ]
    blob = " ".join(
        [response.summary, *response.reason_chain]
        + [f"{fact.label} {fact.value}" for fact in inference_facts]
    ).lower()
    fact_errors = [
        str(fact.value)
        for fact in response.facts
        if "source failure" in str(fact.label or "").lower()
    ]
    response.source_errors = _dedupe_strings([*response.source_errors, *fact_errors])
    if "data freshness stale" in blob or "timestamp is stale" in blob:
        response.source_status = "stale"
    elif any(token in blob for token in ("conflict", "conflicting", "inconsistent", "out of sync", "contradict")):
        response.source_status = "conflict"
    elif response.source_errors and response.source_status == "ok":
        response.source_status = "partial" if response.checks_run else "unavailable"
    elif response.source_status == "ok" and response.confidence == "low" and any(token in blob for token in ("unavailable", "insufficient", "unknown", "not returned")):
        response.source_status = "unavailable"


_FRESHNESS_LABEL_TOKENS = (
    "last seen",
    "latest time",
    "last updated",
    "feed last updated",
    "deployment date",
    "last scan",
    "latest handshake",
    "collected at",
    "last lan scan",
)


def _apply_freshness_policy(response: AgentResponse) -> None:
    """Prevent historical timestamps from being presented as current truth."""

    now = datetime.now(timezone.utc)
    stale_fact: AgentFact | None = None
    stale_at: datetime | None = None
    future_fact: AgentFact | None = None
    future_at: datetime | None = None
    for fact in response.facts:
        label = str(fact.label or "").strip().lower()
        status_values = {
            str(item.value or "").strip().lower()
            for item in response.facts
            if str(item.label or "").strip().lower() == "status"
            or str(item.label or "").strip().lower().endswith(" status")
        }
        active_record_timestamp = "created at" in label and bool(
            status_values & {"running", "pending", "queued", "in_progress", "in progress"}
        )
        if not active_record_timestamp and not any(token in label for token in _FRESHNESS_LABEL_TOKENS):
            continue
        parsed = _parse_timestamp(str(fact.value or ""))
        if parsed is not None and parsed > now + timedelta(minutes=5):
            future_fact = fact
            future_at = parsed
            break
        if parsed is not None and parsed < now - timedelta(days=7):
            stale_fact = fact
            stale_at = parsed
            break

    if future_fact is not None and future_at is not None:
        response.title = "Invalid diagnostic timestamp"
        response.summary = (
            f"The available {str(future_fact.label or 'data').strip().lower()} timestamp "
            f"is in the future ({future_at.isoformat()}), so the current state cannot be confirmed."
        )
        response.confidence = "low"
        response.source_status = "conflict"
        response.actions = []
        response.facts.append(AgentFact("Data freshness", "Invalid future timestamp", "warning"))
        response.source_errors.append("A source timestamp is unexpectedly in the future.")
        response.recommendations.append("Correct the source clock and refresh the diagnostic data.")
        response.reason_chain.append("Future-dated evidence was not accepted as current state.")
        return

    if stale_fact is None or stale_at is None:
        return

    label = str(stale_fact.label or "data").strip()
    if "expiry" in label.lower():
        for fact in response.facts:
            if str(fact.label or "").strip().lower() == "active share links":
                fact.value = "0"
        response.summary = "The available share entry has expired; there are no verified active share links."
    else:
        response.title = "Historical diagnostic data"
        response.summary = (
            f"The available {label.lower()} timestamp is stale ({stale_at.date().isoformat()}), "
            "so the current state cannot be confirmed."
        )
    response.confidence = "low"
    response.actions = []
    response.facts.append(AgentFact("Data freshness", "Stale", "warning"))
    response.recommendations.append("Refresh the underlying source before making a current-state decision.")
    response.reason_chain.append("Historical data was not treated as evidence of the current runtime state.")


def _parse_timestamp(value: str) -> datetime | None:
    normalized = str(value or "").strip()
    if not normalized or normalized.lower() in {"unknown", "none", "never"}:
        return None
    candidates = [normalized]
    if normalized.endswith("Z"):
        candidates.insert(0, normalized[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            parsed = None
        if parsed is not None:
            return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)
    for fmt in ("%d.%m.%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(normalized, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    unique: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
    return unique


def _dedupe_facts(values: list[AgentFact]) -> list[AgentFact]:
    seen: set[tuple[str, str, str]] = set()
    unique: list[AgentFact] = []
    for fact in values:
        key = (
            str(fact.label or "").strip(),
            str(fact.value or "").strip(),
            str(fact.severity or "info").strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(fact)
    return unique


def _dedupe_actions(values: list[AgentAction]) -> list[AgentAction]:
    seen: set[tuple[str, tuple[tuple[str, object], ...]]] = set()
    unique: list[AgentAction] = []
    for action in values:
        key = (
            str(action.action_id or "").strip(),
            tuple(sorted(dict(action.parameters).items())),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(action)
    return unique
