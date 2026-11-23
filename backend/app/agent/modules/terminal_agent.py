"""Terminal agent module."""

from __future__ import annotations

from app.agent.adapters.terminal import TerminalAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class TerminalAgent:
    """Explain terminal access and audit state."""

    name = "terminal_agent"
    _KEYWORDS = (
        "terminal",
        "shell",
        "console",
        "websocket",
        "ws token",
        "command line",
        "pty",
        "access denied",
        "command failed",
        "session closed",
        "exit code",
        "blocked ip",
    )
    _ROUTES = ("terminal",)

    def __init__(self, adapter: TerminalAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 100
        if any(token in route for token in self._ROUTES):
            score += 50
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        limits = self.adapter.get_security_limits()
        sessions = await self.adapter.get_recent_sessions(limit=10)
        commands = await self.adapter.get_recent_commands(limit=10)

        if not limits:
            return AgentResponse(
                category="service",
                target="terminal",
                matched=True,
                title="Terminal diagnostics",
                summary="Terminal runtime and security-limit data are unavailable, so PTY availability is unknown.",
                confidence="low",
                section="terminal",
                subsection="security",
                module=self.name,
                checks_run=["terminal_sessions", "terminal_commands"],
                facts=[AgentFact("Runtime data", "Unavailable", "warning")],
                reason_chain=["The terminal security source returned no authoritative payload."],
                recommendations=["Check the terminal backend runtime before retrying."],
            )

        facts = [
            AgentFact("PTY support", self._yes_no(bool(limits.get("has_pty"))), "info" if limits.get("has_pty") else "critical"),
            AgentFact("Active sessions", str(limits.get("active_sessions") or 0)),
            AgentFact("Max per user", str(limits.get("max_per_user") or 0)),
            AgentFact("Max total", str(limits.get("max_total") or 0)),
            AgentFact("WS token lifetime", f"{limits.get('ws_token_lifetime') or 0}s"),
            AgentFact("Blocked IPs", str(limits.get("blocked_ips") or 0)),
        ]
        blocked_ip_list = limits.get("blocked_ip_list") or []
        if blocked_ip_list:
            facts.append(AgentFact("Blocked IP list", ", ".join(str(ip) for ip in blocked_ip_list)))
        if sessions:
            latest = sessions[0]
            facts.append(AgentFact("Latest session user", str(latest.get("username") or "Unknown")))
            facts.append(AgentFact("Latest session start", str(latest.get("started_at") or "Unknown")))
            facts.append(AgentFact("Latest session end", str(latest.get("ended_at") or "Open")))
        if commands:
            facts.append(AgentFact("Recent commands", str(len(commands))))
        failed_command = next((command for command in commands if self._is_failed_exit(command.get("exit_code"))), None)
        if failed_command is not None:
            facts.append(AgentFact("Latest failed command", str(failed_command.get("command") or "Unknown"), "warning"))
            facts.append(AgentFact("Exit code", str(failed_command.get("exit_code") or "Unknown"), "warning"))

        limits_uninitialized = any(
            int(limits.get(key) or 0) <= 0
            for key in ("max_per_user", "max_total", "ws_token_lifetime")
        )
        source_status = "ok"
        if limits_uninitialized:
            summary = "Terminal security limits are uninitialized or unavailable, so live PTY readiness cannot be confirmed."
            confidence = "low"
            source_status = "partial"
            reason_chain = ["Zero or missing terminal limits were not treated as a healthy runtime configuration."]
            recommendations = ["Load valid terminal session and token limits before opening a live PTY."]
        elif not limits.get("has_pty"):
            summary = "Terminal PTY support is not available on this platform."
            confidence = "high"
            reason_chain = [
                "The terminal runtime reports that PTY support is unavailable.",
            ]
            recommendations = [
                "Terminal features require a Unix-like environment with PTY support.",
            ]
        elif int(limits.get("max_total") or 0) > 0 and int(limits.get("active_sessions") or 0) >= int(limits.get("max_total") or 0):
            summary = "Terminal access is at the global session limit."
            confidence = "high"
            reason_chain = [
                "Terminal security limits were inspected.",
                "The current number of active terminal sessions has reached the global limit.",
            ]
            recommendations = [
                "Close an existing terminal session before opening another one.",
            ]
        elif blocked_ip_list:
            summary = "Terminal access is currently denied for at least one blocked client IP."
            confidence = "high"
            reason_chain = [
                "Terminal security limits were inspected.",
                "The terminal security manager currently holds blocked client IP entries.",
            ]
            recommendations = [
                "Retry terminal access from an allowed private or Tailscale address.",
                "Clear the blocked IP only after confirming the failed attempts were legitimate.",
            ]
        elif failed_command is not None:
            exit_value = failed_command.get("exit_code")
            if isinstance(exit_value, str) and not exit_value.lstrip("-+").isdigit():
                summary = f"The latest recorded terminal command ended with signal or status {exit_value}; no numeric exit code is available."
            else:
                summary = "The latest recorded terminal command failed with a non-zero exit code."
            confidence = "high"
            reason_chain = [
                "Recent terminal audit commands were inspected.",
                "At least one recent command recorded a non-zero exit code.",
            ]
            recommendations = [
                "Inspect the terminal output for the recorded command and rerun it manually if needed.",
            ]
        elif ("closed" in question or "disconnect" in question or "ended" in question) and sessions and sessions[0].get("ended_at"):
            summary = "The latest terminal session was already closed on the backend side."
            confidence = "high"
            reason_chain = [
                "Recent terminal audit sessions were inspected.",
                "The latest recorded session has an end timestamp, so it is no longer active.",
            ]
            recommendations = [
                "Open a new terminal session if you need an interactive shell again.",
            ]
        elif "token" in question or "websocket" in question:
            summary = "Terminal access depends on a short-lived WebSocket token and local security checks."
            confidence = "high"
            reason_chain = [
                "Terminal security settings were inspected.",
                "WebSocket token lifetime and session limits are enforced before PTY startup.",
            ]
            recommendations = [
                "Open the terminal immediately after requesting the terminal WebSocket token.",
                "Ensure the request comes from an allowed private or Tailscale address.",
            ]
        elif not sessions:
            summary = "No terminal sessions have been recorded yet."
            confidence = "medium"
            reason_chain = [
                "Terminal audit tables were queried.",
                "No previous terminal sessions were found.",
            ]
            recommendations = [
                "Open the Terminal page to start the first audited session.",
            ]
        else:
            summary = "Terminal security and audit state look healthy."
            confidence = "medium"
            reason_chain = [
                "Terminal security settings and recent audit records were inspected.",
            ]
            recommendations = [
                "If terminal startup still fails, inspect browser headers, session limits, and IP restrictions.",
            ]

        return AgentResponse(
            category="service",
            target="terminal",
            matched=True,
            title="Terminal diagnostics",
            summary=summary,
            confidence=confidence,
            section="terminal",
            subsection="security",
            module=self.name,
            source_status=source_status,
            checks_run=["terminal_security", "terminal_sessions", "terminal_commands"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _is_failed_exit(self, value: object) -> bool:
        if value is None or value == "":
            return False
        try:
            return int(value) != 0
        except (TypeError, ValueError):
            return True
