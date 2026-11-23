"""Fallback responses for unsupported agent requests."""

from __future__ import annotations

from app.agent.core.context import build_agent_context
from app.agent.core.contracts import AgentContext, AgentFact, AgentRequest, AgentResponse
from app.agent.core.response_builder import build_response

_ROUTE_GUIDANCE: dict[str, tuple[str, list[str]]] = {
    "dashboard": (
        "The dashboard question does not map cleanly to a supported card or cross-section incident yet.",
        [
            "Ask about a specific dashboard card such as monitoring, Guard Security, backup, cameras, VPN, or remote access.",
            "Mention whether you want the main incident, a red card, or a specific widget explanation.",
        ],
    ),
    "guard-security": (
        "The Guard Security question needs a more specific device, domain, rule, or policy target.",
        [
            "Mention the affected device, blocked domain, profile, schedule, rewrite, or query-log entry.",
            "Ask whether the issue is about Shadow Mode, upstream DNS, lists, or parental controls.",
        ],
    ),
    "ip-cameras": (
        "The camera question needs a camera name or a more specific media workflow.",
        [
            "Mention the camera name and whether the problem is live view, recording, snapshot, export, or storage.",
            "Include whether the stream is offline, black, not ready, or missing media files.",
        ],
    ),
    "cloud": (
        "The cloud question needs a narrower storage or Telegram context.",
        [
            "Ask about storage pressure, shares, trash, duplicates, previews, or Telegram uploads.",
            "Include the affected file, share link, or upload workflow if one exists.",
        ],
    ),
    "settings": (
        "The Settings question needs the active tab or account detail to narrow the diagnosis.",
        [
            "Ask about Settings > General, Notifications, Security, or User specifically.",
            "Include the affected username or whether the issue is 2FA, push, quiet hours, email, avatar, or API token.",
        ],
    ),
    "setup": (
        "The Setup question needs a more specific setup workflow.",
        [
            "Ask about permissions, relogin, system DNS, timezone, restart flow, or update capability.",
            "Mention whether the issue is incomplete setup, missing DNS pinning, or restart/update access.",
        ],
    ),
    "personal-dns": (
        "The Personal DNS question needs a narrower deployment or reachability target.",
        [
            "Mention the VPS IP or domain and whether the problem is certificate, upstream DNS, firewall, cleanup, DoH, or DoT.",
            "Ask whether the admin panel, DNS port, or public resolver reachability is the failing part.",
        ],
    ),
    "remote-access": (
        "The Remote Access question needs a more specific Tailscale context.",
        [
            "Ask about login state, a peer, subnet router, Funnel, advertised routes, or LAN reachability.",
            "Include the affected peer name or say whether the problem is on the dashboard or inside Remote Access.",
        ],
    ),
    "network-activity": (
        "The Network Activity question needs a specific device or traffic symptom.",
        [
            "Mention the device name or IP and whether the problem is top talker, top domain, blocked domains, or empty live graphs.",
            "Ask whether you want overall activity, per-device traffic, or blocked-domain reasoning.",
        ],
    ),
    "network-toolkit": (
        "The Network Toolkit question needs a more specific tool scope.",
        [
            "Ask about LAN scan, port alerts, speed test, traffic graph, connections, ARP, or gateway mode.",
            "Include the host, port, or connection you want explained.",
        ],
    ),
    "security": (
        "The Security question needs a specific scan finding or remediation target.",
        [
            "Mention the finding, safe fix, reboot requirement, audit log event, firewall, SSH password auth, or filesystem issue.",
            "Ask whether you want the top finding, a specific fix, or audit-log reasoning.",
        ],
    ),
    "system-backup": (
        "The backup question needs a specific job or backup workflow target.",
        [
            "Mention the backup name and whether the problem is create, restore, download, delete, cancel, or a missing archive file.",
            "Ask whether the issue is a failed job, a blocked restore, or a missing backup artifact.",
        ],
    ),
    "users": (
        "The Users question needs a username or account-security target.",
        [
            "Mention the username and whether the problem is login, role, sessions, 2FA, backup codes, avatar, or API token.",
            "Ask whether the issue is account state, auth flow, or user-management permissions.",
        ],
    ),
    "vpn": (
        "The VPN question needs a peer or WireGuard workflow target.",
        [
            "Mention the peer name and whether the problem is handshake, endpoint, QR, config export, install status, or runtime state.",
            "Ask whether the issue is server status or a single client peer.",
        ],
    ),
    "file-manager": (
        "The File Manager question needs a path or file operation target.",
        [
            "Mention the file path and whether the issue is upload, download, edit, preview, delete, or disk access.",
            "Ask whether the failure is permission-related or storage-related.",
        ],
    ),
    "terminal": (
        "The Terminal question needs a session or command context.",
        [
            "Mention whether the issue is session start, command execution, permission denial, or an unexpected disconnect.",
            "Include the failing command or whether the terminal session closed immediately.",
        ],
    ),
    "help": (
        "The Help question needs an error code, guide topic, or current page context.",
        [
            "Mention the error code or ask for the next guide for the current section.",
            "Ask whether you want a guide, FAQ, or error-code meaning.",
        ],
    ),
    "ai-chat": (
        "The AI question needs a narrower runtime or provider target.",
        [
            "Ask whether the issue is Ollama runtime, model install, chat history, streaming, or provider authentication.",
            "Mention if the problem is local AI runtime or cloud provider usage.",
        ],
    ),
}


def build_unsupported_response(
    request: AgentRequest,
    context: AgentContext | None = None,
) -> AgentResponse:
    """Return a deterministic fallback when no module can answer yet."""

    context = context or build_agent_context(request)
    target = (context.target or context.question).strip()
    route_family = _route_family(context.route_lower)
    route_summary, route_recommendations = _ROUTE_GUIDANCE.get(
        route_family,
        (
            "The agent does not have enough local facts or a matching EasyPi domain for this exact question yet.",
            [
                "Try asking about a device, domain, service, camera, backup, or user issue.",
                "Include the affected object name, such as a device IP, camera name, backup name, or domain.",
            ],
        ),
    )

    recommendations = list(route_recommendations)
    if context.entity_type_lower:
        recommendations.insert(
            0,
            f"Include the exact {context.entity_type_lower} identifier or name in the question if you want object-level diagnostics.",
        )
    if context.tab_lower:
        recommendations.insert(
            0,
            f"Keep the question scoped to the active '{context.tab_lower}' tab so the agent can match the right EasyPi sub-domain.",
        )

    return build_response(
        category="unknown",
        target=target,
        matched=False,
        title="Not enough local diagnostic context",
        summary=route_summary,
        confidence="low",
        module="agent_gateway",
        section=route_family or "unknown",
        subsection=context.tab_lower or context.entity_type_lower or "unsupported",
        checks_run=["router_match"],
        recommendations=recommendations,
        reason_chain=[
            "The request context was normalized from the current route, tab, target, and entity hints.",
            "No agent module returned a strong enough domain match for this exact question.",
            "The agent is refusing to guess because local facts are missing or the question is still too broad.",
        ],
        facts=[
            AgentFact("Route", context.route or "Unknown"),
            AgentFact("Tab", context.tab or "None"),
            AgentFact("Entity type", context.entity_type or "None"),
        ],
    )


def _route_family(route: str) -> str:
    value = str(route or "").strip().strip("/").lower()
    if not value:
        return ""
    return value.split("/", 1)[0]
