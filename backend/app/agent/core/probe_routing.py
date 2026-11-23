"""Route explicit natural-language diagnostics to read-only production probes."""

from __future__ import annotations

import json
import re
from typing import Any, TypeAlias

from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse, SourceStatus

ProbeSelection: TypeAlias = tuple[str, dict[str, Any]]
ProbeSelections: TypeAlias = ProbeSelection | list[ProbeSelection] | None

_PROBE_PHRASES = (
    "database health",
    "redis health",
    "dependency health",
    "dependencies health",
    "camera discovery",
    "discover camera",
    "find camera",
    "onvif discovery",
    "camera ptz",
    "ptz health",
    "pan tilt zoom",
    "camera live",
    "live view",
    "webrtc",
    "mjpeg",
    "dns profile",
    "profile binding",
    "dynamic dns profile",
    "dns rewrite",
    "rewrite manager",
    "prism",
    "dpi pipeline",
    "threat journal",
    "journal ingestion",
    "auth journal",
    "tailscale route",
    "route approval",
    "admin approval",
    "tailscale funnel",
    "funnel status",
    "notification delivery",
    "smtp delivery",
    "push delivery",
    "telegram delivery",
    "cloud metadata",
    "thumbnail",
    "cloud preview",
    "file outcome",
    "file operation",
    "file mutation",
    "terminal live",
    "pty",
    "terminal websocket",
    "auth workflow",
    "login workflow",
    "refresh token",
    "csrf failure",
    "account recovery",
    "wireguard qr",
    "wireguard artifact",
    "wireguard config integrity",
    "marketplace runtime",
    "marketplace install",
    "marketplace service",
    "ai inference",
    "model inference",
    "ollama inference",
    "backup integrity",
    "archive integrity",
    "restore integrity",
    "personal dns tenancy",
    "personal dns deployment",
    "device admission",
    "unknown device admission",
    "heuristic alert",
    "heuristics alert",
    "netprotection component",
    "guard component",
    "dns listener",
    "fail-safe worker",
    "task runtime",
    "task status",
    "service runtime",
    "service status",
)
_NEXT_PROBE_BOUNDARY = re.compile(
    r"\s+(?:and|then)\s+(?=(?:check\s+)?(?:"
    + "|".join(re.escape(phrase) for phrase in sorted(_PROBE_PHRASES, key=len, reverse=True))
    + r")\b)",
    flags=re.IGNORECASE,
)


def select_probe(request: AgentRequest) -> ProbeSelections:
    """Select every explicitly requested probe, preserving question order."""

    original_text = " ; ".join(
        value
        for value in (
            str(request.question or "").strip(),
            str(request.route or "").strip(),
            str(request.tab or "").strip(),
            str(request.entity_type or "").strip(),
        )
        if value
    )
    target = str(request.entity_id or request.target or "").strip()
    matches: list[tuple[int, ProbeSelection]] = []

    def target_after(end_position: int) -> str:
        """Extract the target local to one phrase occurrence."""

        suffix = original_text[end_position:]
        match = re.match(
            r"^(?:\s+[A-Za-z-]+){0,2}\s+for\s+(.+)$",
            suffix,
            flags=re.IGNORECASE,
        )
        if not match:
            return ""
        candidate = match.group(1).split(";", 1)[0].strip()
        boundary = _NEXT_PROBE_BOUNDARY.search(candidate)
        if boundary:
            candidate = candidate[: boundary.start()].strip()
        candidate = candidate.rstrip(",;!?").strip()
        if len(candidate) >= 2 and candidate[0] == candidate[-1] and candidate[0] in {'"', "'"}:
            candidate = candidate[1:-1].strip()
        return candidate[:256]

    def add(
        probe_id: str,
        phrases: tuple[str, ...],
        *,
        parameter_key: str | None = None,
        fixed_parameters: dict[str, Any] | None = None,
        require_target: bool = False,
    ) -> None:
        for phrase in phrases:
            for occurrence in re.finditer(re.escape(phrase), original_text, flags=re.IGNORECASE):
                parameters = dict(fixed_parameters or {})
                local_target = target_after(occurrence.end()) or target
                if parameter_key and local_target:
                    parameters[parameter_key] = local_target
                if require_target and not local_target:
                    continue
                matches.append((occurrence.start(), (probe_id, parameters)))

    add("health.dependencies", ("database health", "redis health", "dependency health", "dependencies health"))
    add(
        "camera.discovery",
        ("camera discovery", "discover camera", "find camera", "onvif discovery"),
        parameter_key="target",
    )
    add(
        "camera.ptz",
        ("camera ptz", "ptz health", "pan tilt zoom"),
        parameter_key="camera_id",
        require_target=True,
    )
    add(
        "camera.live",
        ("camera live", "live view", "webrtc", "mjpeg"),
        parameter_key="camera_id",
        require_target=True,
    )
    add("dns.profiles", ("dns profile", "profile binding", "dynamic dns profile"), parameter_key="target")
    add("dns.rewrites", ("dns rewrite", "rewrite manager"), parameter_key="target")
    add("prism.pipeline", ("prism", "dpi pipeline"))
    add("threat_monitor.journal", ("threat journal", "journal ingestion", "auth journal"))
    add("tailscale.routes", ("tailscale route", "route approval", "admin approval"), parameter_key="target")
    add("tailscale.funnel", ("tailscale funnel", "funnel status"))
    add(
        "notifications.delivery",
        ("notification delivery", "smtp delivery", "push delivery", "telegram delivery"),
        parameter_key="target",
    )
    add("cloud.metadata", ("cloud metadata", "thumbnail", "cloud preview"), parameter_key="entity_id")
    add("files.outcome", ("file outcome", "file operation", "file mutation"), parameter_key="target")
    add("terminal.live", ("terminal live", "pty", "terminal websocket"), parameter_key="target")
    add(
        "auth.workflow",
        ("auth workflow", "login workflow", "refresh token", "csrf failure", "account recovery"),
        parameter_key="target",
    )
    add(
        "wireguard.artifacts",
        ("wireguard qr", "wireguard artifact", "wireguard config integrity"),
        parameter_key="entity_id",
    )
    add(
        "marketplace.runtime",
        ("marketplace runtime", "marketplace install", "marketplace service"),
        parameter_key="target",
    )
    add("ai.inference", ("ai inference", "model inference", "ollama inference"))
    add(
        "backup.integrity",
        ("backup integrity", "archive integrity", "restore integrity"),
        parameter_key="snapshot_id",
        require_target=True,
    )
    if request.actor_user_id:
        add(
            "personal_dns.tenancy",
            ("personal dns tenancy", "personal dns deployment"),
            fixed_parameters={"actor_user_id": request.actor_user_id},
        )
    add("devices.admission", ("device admission", "unknown device admission"), parameter_key="device_id")
    add("heuristics.alerts", ("heuristic alert", "heuristics alert"))
    add("netprotection.components", ("netprotection component", "guard component", "dns listener", "fail-safe worker"))
    add("tasks.runtime", ("task runtime", "task status"), parameter_key="task_id")
    add(
        "services.runtime",
        ("service runtime", "service status"),
        parameter_key="service_name",
        require_target=True,
    )

    ordered: list[ProbeSelection] = []
    seen: set[tuple[str, str]] = set()
    for _position, selection in sorted(matches, key=lambda item: item[0]):
        identity = (selection[0], json.dumps(selection[1], sort_keys=True, default=str))
        if identity not in seen:
            seen.add(identity)
            ordered.append(selection)
    if not ordered:
        return None
    return ordered[0] if len(ordered) == 1 else ordered


def normalize_probe_selections(selected: ProbeSelections) -> list[ProbeSelection]:
    if selected is None:
        return []
    if isinstance(selected, list):
        return selected
    return [selected]


def build_probe_response(
    request: AgentRequest,
    results: list[tuple[str, dict[str, Any]]],
) -> AgentResponse:
    """Build a probe-primary response without unrelated module conclusions."""

    allowed_statuses: set[SourceStatus] = {"ok", "partial", "unavailable", "stale", "conflict"}
    rank = {"ok": 0, "partial": 1, "stale": 2, "unavailable": 3, "conflict": 4}
    statuses: list[SourceStatus] = []
    facts: list[AgentFact] = []
    messages: list[str] = []
    errors: list[str] = []

    for probe_id, payload in results:
        raw_status = str(payload.get("source_status") or ("ok" if payload.get("success") else "unavailable"))
        status: SourceStatus = raw_status if raw_status in allowed_statuses else "unavailable"  # type: ignore[assignment]
        if not bool(payload.get("success")) and status == "ok":
            status = "partial"
        message = str(payload.get("message") or "Probe returned no diagnostic message.").strip()
        statuses.append(status)
        messages.append(f"{probe_id}: {message}" if len(results) > 1 else message)
        facts.extend(
            [
                AgentFact("Diagnostic probe", probe_id),
                AgentFact("Probe result", "Healthy" if payload.get("success") else "Not healthy", "info" if status == "ok" else "warning"),
                AgentFact("Probe evidence", message[:500], "info" if status == "ok" else "warning"),
            ]
        )
        for key, value in payload.items():
            if key in {"success", "source_status", "message", "probe_id"} or value is None:
                continue
            rendered = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)
            facts.append(AgentFact(f"Probe {key.replace('_', ' ')}", rendered[:500]))
        if status != "ok":
            errors.append(f"{probe_id}: {message}")

    overall = max(statuses, key=lambda value: rank[value]) if statuses else "unavailable"
    all_healthy = bool(results) and all(
        status == "ok" and bool(payload.get("success"))
        for status, (_probe_id, payload) in zip(statuses, results, strict=True)
    )
    title = f"{results[0][0]} diagnostic" if len(results) == 1 else "Targeted diagnostic probes"
    category = "device" if results and results[0][0].startswith("camera.") else "service"
    return AgentResponse(
        category=category,
        target=request.target or request.entity_id or (results[0][0] if len(results) == 1 else "diagnostics"),
        matched=True,
        title=title,
        summary=" ".join(messages),
        confidence="high" if all_healthy else ("medium" if overall == "partial" else "low"),
        section=request.route,
        subsection=request.tab,
        module="diagnostic_probes",
        source_status=overall,
        source_errors=errors,
        checks_run=[f"probe:{probe_id}" for probe_id, _payload in results],
        facts=facts,
        recommendations=[] if all_healthy else ["Resolve or refresh the targeted probe evidence before changing system state."],
        reason_chain=[
            f"The production read-only probe '{probe_id}' returned source_status={status}."
            for status, (probe_id, _payload) in zip(statuses, results, strict=True)
        ],
        actions=[],
    )


def merge_probe_result(response: AgentResponse, probe_id: str, payload: dict[str, Any]) -> AgentResponse:
    """Compatibility wrapper: an explicit probe replaces module conclusions."""

    request = AgentRequest(question=probe_id, route=response.section, tab=response.subsection, target=response.target)
    return build_probe_response(request, [(probe_id, payload)])
