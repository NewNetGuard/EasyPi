"""Action planning and execution for the EasyPi agent."""

from __future__ import annotations

import inspect
import secrets
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any

from app.agent.core.contracts import AgentAction, AgentActionResult, AgentRequest, AgentResponse
from app.agent.core.sanitization import sanitize_action_parameters, validate_action_id

ActionHandler = Callable[[dict[str, Any]], Awaitable[dict[str, Any] | AgentActionResult | None] | dict[str, Any] | AgentActionResult | None]

_BASE_SUCCESS_STATUSES = frozenset({"success", "succeeded", "ok", "completed", "complete"})
_ACTION_SUCCESS_STATUSES: dict[str, frozenset[str]] = {
    "backup.create_full": frozenset({"started"}),
    "backup.cancel_latest_running": frozenset({"cancelled", "canceled"}),
    "threat_monitor.start": frozenset({"started", "already_running"}),
    "threat_monitor.stop": frozenset({"stopped", "already_stopped"}),
    "netprotection.start_service": frozenset({"started", "already_running"}),
    "netprotection.stop_service": frozenset({"stopped", "already_stopped"}),
    "netprotection.restart_service": frozenset({"restarted", "started"}),
    "remote_access.start_tailscale": frozenset({"started", "already_running"}),
    "remote_access.stop_tailscale": frozenset({"stopped", "already_stopped"}),
    "camera.start_recording": frozenset({"started", "already_running"}),
    "camera.stop_recording": frozenset({"stopped", "already_stopped"}),
    "setup.restart_services": frozenset({"restarted", "started"}),
    "security.start_outdated_packages_fix": frozenset({"started"}),
    "wireguard.restart_service": frozenset({"restarted", "started"}),
    "ai.start_ollama": frozenset({"started", "already_running"}),
    "ai.stop_ollama": frozenset({"stopped", "already_stopped"}),
    "cloud.start_telegram_bot": frozenset({"started", "already_running"}),
    "cloud.stop_telegram_bot": frozenset({"stopped", "already_stopped"}),
}


@dataclass(slots=True)
class AgentActionSpec:
    """Registered action handler plus its accepted parameter contract."""

    handler: ActionHandler
    allowed_keys: frozenset[str] | None
    required_keys: frozenset[str]
    successful_statuses: frozenset[str]


class AgentActionRegistry:
    """Store and execute allowlisted agent actions."""

    def __init__(self) -> None:
        self._handlers: dict[str, AgentActionSpec] = {}
        self._confirmations: dict[str, tuple[str, dict[str, Any], int | None, float]] = {}

    def issue_confirmation(
        self,
        action_id: str,
        parameters: dict[str, Any] | None = None,
        *,
        actor_user_id: int | None = None,
        ttl_seconds: int = 300,
    ) -> str:
        """Issue a short-lived, single-use token bound to an action payload."""

        normalized_action_id = validate_action_id(action_id)
        safe_parameters = sanitize_action_parameters(parameters)
        token = secrets.token_urlsafe(32)
        self._confirmations[token] = (
            normalized_action_id,
            dict(safe_parameters),
            actor_user_id,
            time.monotonic() + max(30, min(int(ttl_seconds), 900)),
        )
        self._prune_confirmations()
        return token

    def register(
        self,
        action_id: str,
        handler: ActionHandler,
        *,
        allowed_keys: set[str] | frozenset[str] | None = None,
        required_keys: set[str] | frozenset[str] | None = None,
        successful_statuses: set[str] | frozenset[str] | None = None,
    ) -> None:
        normalized_action_id = validate_action_id(action_id)
        normalized_allowed = None
        if allowed_keys is not None:
            normalized_allowed = frozenset(str(key).strip().lower() for key in allowed_keys)
        normalized_required = frozenset(str(key).strip().lower() for key in (required_keys or set()))
        if normalized_allowed is not None and not normalized_required.issubset(normalized_allowed):
            raise ValueError("Required action keys must be a subset of allowed keys")
        self._handlers[normalized_action_id] = AgentActionSpec(
            handler=handler,
            allowed_keys=normalized_allowed,
            required_keys=normalized_required,
            successful_statuses=(
                _BASE_SUCCESS_STATUSES
                | (
                    frozenset(str(status).strip().lower() for status in successful_statuses)
                    if successful_statuses is not None
                    else _ACTION_SUCCESS_STATUSES.get(normalized_action_id, frozenset())
                )
            ),
        )

    async def execute(
        self,
        action_id: str,
        parameters: dict[str, Any] | None = None,
        *,
        confirmation_token: str | None = None,
        actor_user_id: int | None = None,
    ) -> AgentActionResult:
        try:
            normalized_action_id = validate_action_id(action_id)
        except ValueError as exc:
            return AgentActionResult(
                action_id=str(action_id or "").strip(),
                success=False,
                message=str(exc),
            )
        spec = self._handlers.get(normalized_action_id)
        if spec is None:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message="This agent action is not registered.",
            )

        try:
            safe_parameters = sanitize_action_parameters(parameters)
        except ValueError as exc:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message=str(exc),
            )
        unexpected = []
        if spec.allowed_keys is not None:
            unexpected = sorted(set(safe_parameters) - set(spec.allowed_keys))
        if unexpected:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message=f"Unsupported parameters were provided for this action: {', '.join(unexpected)}.",
            )
        missing = sorted(set(spec.required_keys) - set(safe_parameters))
        if missing:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message=f"Missing required parameters for this action: {', '.join(missing)}.",
            )

        if not self._consume_confirmation(
            confirmation_token,
            action_id=normalized_action_id,
            parameters=safe_parameters,
            actor_user_id=actor_user_id,
        ):
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message="Explicit server-side confirmation is required for this agent action.",
            )

        try:
            result = spec.handler(dict(safe_parameters))
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message=f"The action failed: {type(exc).__name__}: {exc}",
            )
        if isinstance(result, AgentActionResult):
            return AgentActionResult(
                action_id=normalized_action_id,
                success=bool(result.success),
                message=str(result.message or ("Action completed." if result.success else "The action failed.")),
                data=dict(result.data),
                follow_up=result.follow_up,
            )
        if result is None:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message="The action handler did not confirm completion.",
            )

        if hasattr(result, "model_dump"):
            payload = dict(result.model_dump(mode="json"))
        elif isinstance(result, Mapping):
            payload = dict(result)
        else:
            return AgentActionResult(
                action_id=normalized_action_id,
                success=False,
                message="The action handler returned an unsupported result and did not confirm completion.",
            )

        raw_success = payload.pop("success", None)
        raw_message = payload.pop("message", None)
        status = str(payload.get("status") or "").strip().lower()
        error_values = (
            payload.get("error"),
            payload.get("error_message"),
            payload.get("errors"),
        )
        error_parts: list[str] = []
        for value in error_values:
            if value in (None, "", False, [], {}):
                continue
            if isinstance(value, (list, tuple, set)):
                error_parts.extend(str(item).strip() for item in value if str(item).strip())
            else:
                rendered = str(value).strip()
                if rendered:
                    error_parts.append(rendered)
        error = "; ".join(error_parts)
        successful_statuses = spec.successful_statuses
        failed_statuses = {"error", "failed", "failure", "cancelled", "canceled", "timeout"}

        # Completion is fail-closed. A handler must explicitly report a boolean
        # success or a recognized terminal status; errors and disagreements win.
        if isinstance(raw_success, bool):
            success = raw_success
        elif status in successful_statuses:
            success = True
        else:
            success = False
        if error or (status in failed_statuses and status not in successful_statuses):
            success = False
        if isinstance(raw_success, bool) and status:
            if (raw_success and status not in successful_statuses) or (not raw_success and status in successful_statuses):
                success = False

        if not success and error:
            message = error
        elif raw_message is not None and str(raw_message).strip():
            message = str(raw_message).strip()
        elif success:
            message = "Action completed successfully."
        else:
            message = "The action handler did not confirm successful completion."
        return AgentActionResult(
            action_id=normalized_action_id,
            success=success,
            message=message,
            data=payload,
        )

    def _consume_confirmation(
        self,
        token: str | None,
        *,
        action_id: str,
        parameters: dict[str, Any],
        actor_user_id: int | None,
    ) -> bool:
        self._prune_confirmations()
        normalized_token = str(token or "").strip()
        if not normalized_token:
            return False
        issued = self._confirmations.pop(normalized_token, None)
        if issued is None:
            return False
        issued_action_id, issued_parameters, issued_actor_user_id, expires_at = issued
        return (
            expires_at >= time.monotonic()
            and secrets.compare_digest(issued_action_id, action_id)
            and issued_parameters == parameters
            and issued_actor_user_id == actor_user_id
        )

    def _prune_confirmations(self) -> None:
        now = time.monotonic()
        expired = [token for token, (_, _, _, expires_at) in self._confirmations.items() if expires_at < now]
        for token in expired:
            self._confirmations.pop(token, None)


class AgentActionPlanner:
    """Attach concrete remediation actions to deterministic agent responses."""

    def suggest(self, request: AgentRequest, response: AgentResponse) -> list[AgentAction]:
        actions: list[AgentAction] = []
        module = str(response.module or "")
        summary = response.summary.lower()
        target = str(response.target or "")

        if module == "netprotection_agent":
            client_ip = self._fact_value(response, "IP")
            if "fail-closed quarantine" in summary and client_ip:
                actions.append(
                    AgentAction(
                        action_id="netprotection.restore_internet",
                        label="Restore Internet",
                        description="Remove the current fail-closed quarantine for this device.",
                        style="primary",
                        confirmation_text=f"Restore internet for {target}?",
                        parameters={"client_ip": client_ip, "client_name": target},
                    )
                )
            if response.category == "domain" and "blocked recent requests for" in summary and target:
                actions.append(
                    AgentAction(
                        action_id="netprotection.allow_domain",
                        label=f"Allow {target}",
                        description=f"Add {target} to the Guard Security allowlist so EasyPi stops blocking it.",
                        style="primary",
                        confirmation_text=f"Add {target} to the allowlist so EasyPi stops blocking it?",
                        parameters={"domain": target},
                    )
                )
            if response.category == "domain" and target and "blocked recent requests for" not in summary:
                actions.append(
                    AgentAction(
                        action_id="netprotection.block_domain",
                        label=f"Block {target}",
                        description=f"Add {target} to the Guard Security blocklist so EasyPi stops resolving it.",
                        style="danger",
                        confirmation_text=f"Add {target} to the blocklist so EasyPi blocks it?",
                        parameters={"domain": target},
                    )
                )
            if "protection is disabled" in summary:
                actions.append(
                    AgentAction(
                        action_id="netprotection.enable_protection",
                        label="Enable Protection",
                        description="Turn NetProtection filtering back on so DNS queries are filtered again.",
                        style="primary",
                        confirmation_text="Enable NetProtection filtering now?",
                    )
                )

        if module == "system_services_agent":
            service_name = str(response.target or "").lower()
            if service_name == "netprotection" and "not running locally" in summary:
                actions.append(
                    AgentAction(
                        action_id="netprotection.start_service",
                        label="Start NetProtection",
                        description="Start the local NetProtection service.",
                        style="primary",
                        confirmation_text="Start the NetProtection service?",
                    )
                )
            elif service_name == "netprotection" and any(token in summary for token in ("degraded", "failed", "unhealthy")):
                actions.append(
                    AgentAction(
                        action_id="netprotection.restart_service",
                        label="Restart NetProtection",
                        description="Restart the local NetProtection service.",
                        style="secondary",
                        confirmation_text="Restart the NetProtection service now?",
                    )
                )
            if service_name == "threat-monitoring":
                if "currently disabled" in summary:
                    actions.append(
                        AgentAction(
                            action_id="threat_monitor.start",
                            label="Start Threat Monitoring",
                            description="Enable the local threat monitoring service.",
                            style="primary",
                            confirmation_text="Start threat monitoring?",
                        )
                    )

        if module == "remote_access_agent":
            if "installed but not running" in summary:
                actions.append(
                    AgentAction(
                        action_id="remote_access.start_tailscale",
                        label="Start Tailscale",
                        description="Start the Tailscale connection on this EasyPi instance.",
                        style="primary",
                        confirmation_text="Start Tailscale now?",
                    )
                )

        if module == "wireguard_agent" and (
            "installed but not running" in summary or "no configured peer has a recent handshake" in summary
        ):
            actions.append(
                AgentAction(
                    action_id="wireguard.restart_service",
                    label="Restart WireGuard",
                    description="Restart the local WireGuard service.",
                    style="primary",
                    confirmation_text="Restart WireGuard now?",
                )
            )

        if module == "backup_agent":
            if "currently running" in summary:
                actions.append(
                    AgentAction(
                        action_id="backup.cancel_latest_running",
                        label="Cancel Backup",
                        description="Cancel the most recent running backup job.",
                        style="danger",
                        confirmation_text="Cancel the current backup job?",
                    )
                )
            if any(token in summary for token in ("failed backup", "no backup history yet", "no backups yet", "no completed backup is available")):
                actions.append(
                    AgentAction(
                        action_id="backup.create_full",
                        label="Create Full Backup",
                        description="Start a new full system backup.",
                        style="primary",
                        confirmation_text="Create a new full backup now?",
                    )
                )

        if module == "cameras_agent":
            if "offline" not in summary:
                if "actively recording" in summary:
                    actions.append(
                        AgentAction(
                            action_id="camera.stop_recording",
                            label="Stop Recording",
                            description="Stop the active recording job for this camera.",
                            style="secondary",
                            confirmation_text=f"Stop recording for {target}?",
                            parameters={"camera_name": target},
                        )
                    )
                if "not recording" in summary or "no recordings found" in summary:
                    actions.append(
                        AgentAction(
                            action_id="camera.start_recording",
                            label="Start Recording",
                            description="Start a recording job for this camera.",
                            style="primary",
                            confirmation_text=f"Start recording for {target}?",
                            parameters={"camera_name": target},
                        )
                    )

        is_permissions_response = (
            target == "setup-permissions"
            or str(response.subsection or "").lower() == "permissions"
            or "setup permissions are incomplete" in summary
        )
        if module == "setup_agent" and is_permissions_response:
            current_user = self._fact_value(response, "Current user")
            group_exists = (self._fact_value(response, "EasyPi group exists") or "").lower()
            in_group = (self._fact_value(response, "User in EasyPi group") or "").lower()
            sudo_configured = (self._fact_value(response, "Sudo configured") or "").lower()
            needs_relogin = (self._fact_value(response, "Needs relogin") or "").lower()

            if needs_relogin == "yes":
                actions.append(
                    AgentAction(
                        action_id="setup.restart_services",
                        label="Restart EasyPi Services",
                        description="Restart core EasyPi services to activate the updated group membership.",
                        style="secondary",
                        confirmation_text="Restart EasyPi services now?",
                    )
                )
            elif sudo_configured == "yes" and "no" in {group_exists, in_group}:
                actions.append(
                    AgentAction(
                        action_id="setup.permissions_setup",
                        label="Run Permissions Setup",
                        description="Create or repair the EasyPi group and sudo configuration.",
                        style="primary",
                        confirmation_text="Run EasyPi permissions setup now?",
                        parameters={"username": current_user} if current_user and current_user != "Unknown" else {},
                    )
                )

        if module == "security_agent":
            issue_id = str(response.target or "")
            issue_actions = {
                "firewall_inactive": (
                    "security.fix_firewall",
                    "Apply Firewall Fix",
                    "Apply the firewall remediation from System Security.",
                ),
                "password_auth_enabled": (
                    "security.fix_password_auth",
                    "Disable Password Auth",
                    "Apply the SSH password-auth remediation.",
                ),
                "filesystem_readonly": (
                    "security.fix_filesystem_readonly",
                    "Repair Read-Only Filesystem",
                    "Run the filesystem remediation from System Security.",
                ),
            }
            if issue_id in issue_actions:
                action_id, label, description = issue_actions[issue_id]
                actions.append(
                    AgentAction(
                        action_id=action_id,
                        label=label,
                        description=description,
                        style="primary",
                        confirmation_text=f"{label} now?",
                    )
                )
            if response.target == "security-update-job" and "no package update job is currently running" in summary:
                actions.append(
                    AgentAction(
                        action_id="security.start_outdated_packages_fix",
                        label="Start Package Update Fix",
                        description="Start the outdated packages remediation job.",
                        style="primary",
                        confirmation_text="Start the package update remediation now?",
                    )
                )

        if module == "users_auth_agent":
            username = target
            if response.subsection == "sessions" or "session" in request.question.lower():
                actions.append(
                    AgentAction(
                        action_id="users.revoke_sessions",
                        label="Revoke Sessions",
                        description="Revoke all active sessions for this user.",
                        style="danger",
                        confirmation_text=f"Revoke all active sessions for {username}?",
                        parameters={"username": username},
                    )
                )

        if module == "ai_runtime_agent" and "not healthy right now" in summary:
            actions.append(
                AgentAction(
                    action_id="ai.start_ollama",
                    label="Start Ollama",
                    description="Start the local Ollama runtime.",
                    style="primary",
                    confirmation_text="Start Ollama now?",
                )
            )

        if module == "cloud_agent" and response.target == "cloud-telegram" and "not connected" in summary:
            actions.append(
                AgentAction(
                    action_id="cloud.start_telegram_bot",
                    label="Start Telegram Bot",
                    description="Start the local Cloud Telegram bot process.",
                    style="primary",
                    confirmation_text="Start the Cloud Telegram bot now?",
                )
            )

        if module == "network_toolkit_agent" and response.target == "gateway-mode" and "disabled or incomplete" in summary:
            actions.append(
                AgentAction(
                    action_id="network_toolkit.fix_gateway_mode",
                    label="Fix Gateway Mode",
                    description="Run the built-in gateway repair routine.",
                    style="primary",
                    confirmation_text="Run gateway mode repair now?",
                )
            )

        return self._dedupe(actions)

    def _fact_value(self, response: AgentResponse, label: str) -> str | None:
        expected = label.strip().lower()
        for fact in response.facts:
            if fact.label.strip().lower() == expected:
                value = str(fact.value or "").strip()
                return value or None
        return None

    def _dedupe(self, actions: list[AgentAction]) -> list[AgentAction]:
        unique: list[AgentAction] = []
        seen: set[tuple[str, tuple[tuple[str, object], ...]]] = set()
        for action in actions:
            key = (action.action_id, tuple(sorted(action.parameters.items())))
            if key in seen:
                continue
            seen.add(key)
            unique.append(action)
        return unique
