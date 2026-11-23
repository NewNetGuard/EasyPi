"""Settings diagnostics module."""

from __future__ import annotations

from app.agent.adapters.settings import SettingsAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class SettingsAgent:
    """Explain the Settings page tabs using local backend facts."""

    name = "settings_agent"
    _GENERAL_KEYWORDS = (
        "settings",
        "timezone",
        "time zone",
        "theme",
        "accent",
        "appearance",
        "font",
        "language",
    )
    _NOTIFICATION_KEYWORDS = (
        "notification",
        "notifications",
        "push",
        "smtp",
        "email alert",
        "email notification",
        "digest",
        "quiet hours",
    )
    _SECURITY_KEYWORDS = (
        "2fa",
        "two-factor",
        "backup code",
        "backup codes",
        "password change",
        "session list",
        "sessions",
        "api token",
        "security settings",
    )
    _USER_KEYWORDS = (
        "profile",
        "avatar",
        "api token",
        "user settings",
        "profile picture",
    )
    _ROUTES = ("settings",)

    def __init__(self, adapter: SettingsAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        tab = (request.tab or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(token in route for token in self._ROUTES):
            score += 80

        if tab == "general" and self._matches(question, target, self._GENERAL_KEYWORDS):
            score += 70
        if tab == "notifications" and self._matches(question, target, self._NOTIFICATION_KEYWORDS):
            score += 70
        if tab == "security" and self._matches(question, target, self._SECURITY_KEYWORDS):
            score += 70
        if tab == "user" and self._matches(question, target, self._USER_KEYWORDS):
            score += 70

        if self._matches(question, target, self._GENERAL_KEYWORDS):
            score += 45
        if self._matches(question, target, self._NOTIFICATION_KEYWORDS):
            score += 55
        if self._matches(question, target, self._SECURITY_KEYWORDS):
            score += 55
        if self._matches(question, target, self._USER_KEYWORDS):
            score += 55

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        tab = (request.tab or "").lower()
        target = str(request.target or "").strip()

        if not any(token in route for token in self._ROUTES) and self.score(request) <= 0:
            return None

        username_hint = target or request.entity_id

        if tab == "notifications" or self._matches(question, target.lower(), self._NOTIFICATION_KEYWORDS):
            return await self._notifications_response(username_hint=username_hint, question=question)
        if tab == "security" or self._matches(question, target.lower(), self._SECURITY_KEYWORDS):
            return await self._security_response(username_hint=username_hint, question=question)
        if tab == "user" or self._matches(question, target.lower(), self._USER_KEYWORDS):
            return await self._user_response(username_hint=username_hint, question=question)
        if tab == "general" or self._matches(question, target.lower(), self._GENERAL_KEYWORDS):
            return await self._general_response(question=question)
        if any(token in route for token in self._ROUTES):
            return await self._overview_response(username_hint=username_hint)
        return None

    async def _general_response(self, *, question: str) -> AgentResponse:
        state = await self.adapter.get_general_state()
        if not state.get("timezone"):
            return self._unavailable_response("settings-general", "Settings General diagnostics", "General settings")
        timezone_value = str(state.get("timezone"))
        facts = [
            AgentFact("Timezone", timezone_value),
            AgentFact("Theme storage", "Browser local storage"),
            AgentFact("Language storage", "Browser local storage"),
            AgentFact("Development mode", self._yes_no(bool(state.get("is_development")))),
        ]

        if any(keyword in question for keyword in ("theme", "accent", "appearance", "font", "language")):
            summary = (
                "Theme, accent, font, and language selections in Settings > General are UI-side preferences. "
                "Only timezone is applied on the backend."
            )
            reason_chain = [
                "The current timezone was read from the backend system settings.",
                "Theme and language options are stored in the browser, not in backend system config.",
            ]
        else:
            summary = f"EasyPi is currently configured for timezone '{timezone_value}'."
            reason_chain = [
                "The current timezone was read from the backend system settings.",
            ]

        return AgentResponse(
            category="service",
            target="settings-general",
            matched=True,
            title="Settings General diagnostics",
            summary=summary,
            confidence="high",
            section="settings",
            subsection="general",
            module=self.name,
            checks_run=["settings_general"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Use Settings > General to change timezone on the backend.",
                "Remember that theme, accent, font, and language preferences are browser-local UI settings.",
            ],
        )

    async def _notifications_response(self, *, username_hint: str | None, question: str) -> AgentResponse:
        try:
            state = await self.adapter.get_notification_state(username_hint=username_hint)
        except Exception as exc:
            response = self._unavailable_response("settings-notifications", "Settings Notifications diagnostics", "Notification settings")
            response.source_status = "unavailable"
            response.source_errors = [f"{type(exc).__name__}: {exc}"]
            response.facts = [AgentFact("Source failure", f"{type(exc).__name__}: {exc}", "warning")]
            return response
        if not self._matches_user_hint(state, username_hint):
            return self._unavailable_response(
                "settings-notifications",
                "Settings Notifications diagnostics",
                f"Requested user {username_hint or 'notifications'}",
            )
        facts = [
            AgentFact("User", str(state.get("username") or "Unknown")),
            AgentFact("Email service configured", self._yes_no(bool(state.get("smtp_configured")))),
            AgentFact("SMTP host", str(state.get("smtp_host") or "Not configured")),
            AgentFact("Notifications enabled", self._yes_no(bool(state.get("notifications_enabled")))),
            AgentFact("Notification email", str(state.get("notification_email") or "Not configured")),
            AgentFact("Quiet hours", self._yes_no(bool(state.get("quiet_hours_enabled")))),
            AgentFact("Digest mode", self._yes_no(bool(state.get("digest_mode")))),
            AgentFact("Hourly usage", f"{int(state.get('hourly_usage') or 0)}/{int(state.get('max_emails_per_hour') or 0)}"),
            AgentFact("Daily usage", f"{int(state.get('daily_usage') or 0)}/{int(state.get('max_emails_per_day') or 0)}"),
            AgentFact("Push configured", self._yes_no(bool(state.get("push_configured")))),
            AgentFact(
                "User push subscriptions",
                str(state.get("user_push_subscriptions") or 0),
                "warning" if not int(state.get("user_push_subscriptions") or 0) else "info",
            ),
            AgentFact("Total push subscriptions", str(state.get("total_push_subscriptions") or 0)),
        ]
        if bool(state.get("quiet_hours_enabled")):
            facts.append(
                AgentFact(
                    "Quiet hours window",
                    f"{int(state.get('quiet_hours_start') or 0):02d}:00-{int(state.get('quiet_hours_end') or 0):02d}:00",
                )
            )
        if bool(state.get("digest_mode")):
            facts.append(AgentFact("Digest interval", f"{int(state.get('digest_interval_hours') or 0)} hours"))

        limits_uninitialized = (
            int(state.get("max_emails_per_hour") or 0) <= 0
            or int(state.get("max_emails_per_day") or 0) <= 0
        )

        if limits_uninitialized and not any(token in question for token in ("push", "email", "smtp")):
            summary = "Notification rate-limit state is uninitialized or unavailable, so delivery health cannot be confirmed."
            confidence = "low"
            reason_chain = [
                "Notification usage counters were returned with a zero or missing limit.",
                "The 0/0 values were not treated as a healthy configured rate limit.",
            ]
        elif "push" in question and not bool(state.get("push_configured")):
            summary = "Push notifications are not configured on the EasyPi server."
            confidence = "high"
            reason_chain = [
                "The push notification service configuration was inspected.",
                "No VAPID keys are configured for browser push notifications.",
            ]
        elif "push" in question and not int(state.get("user_push_subscriptions") or 0):
            summary = "Push notifications are available, but this user has no active browser subscription."
            confidence = "high"
            reason_chain = [
                "The push notification service is configured.",
                "No active browser subscription was found for the selected user.",
            ]
        elif ("email" in question or "smtp" in question) and not bool(state.get("smtp_configured")):
            summary = "Email notifications are not configured on the EasyPi server."
            confidence = "high"
            reason_chain = [
                "The notification email service configuration was inspected.",
                "SMTP credentials are not configured locally.",
            ]
        elif ("email" in question or "notification email" in question) and not bool(state.get("notification_email")):
            summary = "Email delivery is enabled in Settings, but the selected user has no notification email configured."
            confidence = "high"
            reason_chain = [
                "The notification preferences were inspected for the selected user.",
                "No notification email address is stored for this account.",
            ]
        elif ("quiet hours" in question or "silent" in question or "night" in question) and bool(state.get("quiet_hours_enabled")):
            summary = "Notifications can be intentionally delayed because quiet hours are enabled for this user."
            confidence = "high"
            reason_chain = [
                "The notification preferences were inspected for the selected user.",
                "Quiet hours are enabled, so non-critical alerts are suppressed in the configured time window.",
            ]
        elif "digest" in question and bool(state.get("digest_mode")):
            summary = "Notifications are currently batched into digest mode instead of being delivered immediately."
            confidence = "high"
            reason_chain = [
                "The notification preferences were inspected for the selected user.",
                "Digest mode is enabled, so alerts are grouped and sent later.",
            ]
        elif (
            "rate limit" in question
            or "not arriving" in question
            or "too many" in question
        ) and (
            int(state.get("max_emails_per_hour") or 0) > 0
            and int(state.get("hourly_usage") or 0) >= int(state.get("max_emails_per_hour") or 0)
            or int(state.get("max_emails_per_day") or 0) > 0
            and int(state.get("daily_usage") or 0) >= int(state.get("max_emails_per_day") or 0)
        ):
            summary = "Notifications are currently hitting the configured email rate limits."
            confidence = "high"
            reason_chain = [
                "The notification preferences were inspected for the selected user.",
                "Current email usage reached the configured hourly or daily notification limit.",
            ]
        elif not bool(state.get("notifications_enabled")):
            summary = "Notification delivery is configured, but notifications are disabled for the selected user."
            confidence = "high"
            reason_chain = [
                "The notification preferences were inspected for the selected user.",
                "User-level notifications are currently disabled.",
            ]
        else:
            summary = "Notification settings look healthy."
            confidence = "medium"
            reason_chain = [
                "Email and push notification settings were inspected.",
                "No obvious notification misconfiguration was found.",
            ]

        return AgentResponse(
            category="service",
            target="settings-notifications",
            matched=True,
            title="Settings Notifications diagnostics",
            summary=summary,
            confidence=confidence,
            section="settings",
            subsection="notifications",
            module=self.name,
            source_status="partial" if limits_uninitialized else "ok",
            checks_run=["settings_notifications"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Enable browser notifications in Settings > Notifications and subscribe from the current browser.",
                "Configure SMTP if email alerts should be delivered outside the browser.",
            ],
        )

    async def _security_response(self, *, username_hint: str | None, question: str) -> AgentResponse:
        state = await self.adapter.get_security_state(username_hint=username_hint)
        if not state or not self._matches_user_hint(state, username_hint):
            return self._unavailable_response("settings-security", "Settings Security diagnostics", "Security settings")
        facts = [
            AgentFact("User", str(state.get("username") or "Unknown")),
            AgentFact(
                "Account active",
                self._yes_no(bool(state.get("account_active"))),
                "critical" if not bool(state.get("account_active")) else "info",
            ),
            AgentFact(
                "2FA enabled",
                self._yes_no(bool(state.get("totp_enabled"))),
                "warning" if not bool(state.get("totp_enabled")) else "info",
            ),
            AgentFact("Backup codes remaining", str(state.get("backup_codes_remaining") or 0)),
            AgentFact(
                "Active sessions",
                str(state.get("active_sessions") or 0),
                "warning" if not int(state.get("active_sessions") or 0) else "info",
            ),
            AgentFact("API token configured", self._yes_no(bool(state.get("api_token_configured")))),
        ]
        if state.get("last_login"):
            facts.append(AgentFact("Last login", str(state.get("last_login"))))
        if state.get("last_login_ip"):
            facts.append(AgentFact("Last login IP", str(state.get("last_login_ip"))))

        if not bool(state.get("account_active")):
            summary = "The selected account is disabled in Settings > Security context."
            confidence = "high"
            reason_chain = [
                "The current account state was inspected.",
                "The account is marked as inactive.",
            ]
        elif "2fa" in question or "two-factor" in question:
            if bool(state.get("totp_enabled")):
                summary = "Two-factor authentication is enabled for this account."
                confidence = "high"
                reason_chain = [
                    "The current account security settings were inspected.",
                    "Two-factor authentication is enabled for this account.",
                ]
            else:
                summary = "Two-factor authentication is not enabled for this account."
                confidence = "high"
                reason_chain = [
                    "The current account security settings were inspected.",
                    "Two-factor authentication is currently disabled.",
                ]
        elif "session" in question and not int(state.get("active_sessions") or 0):
            summary = "No active sessions are currently recorded for this account."
            confidence = "high"
            reason_chain = [
                "The current account security settings were inspected.",
                "No active sessions were found for the selected user.",
            ]
        elif "backup code" in question and not int(state.get("backup_codes_remaining") or 0):
            summary = "This account has no backup codes remaining."
            confidence = "high"
            reason_chain = [
                "The current account security settings were inspected.",
                "No unused backup codes are recorded for this account.",
            ]
        elif "backup code" in question:
            summary = "Backup codes are available for this account."
            confidence = "high"
            reason_chain = [
                "The current account security settings were inspected.",
                "Unused backup codes are still recorded for this account.",
            ]
        elif "api token" in question and not bool(state.get("api_token_configured")):
            summary = "No API token is configured yet."
            confidence = "high"
            reason_chain = [
                "The global API token state was inspected.",
                "No API token file is currently stored.",
            ]
        else:
            summary = "Settings > Security currently looks healthy for this account."
            confidence = "medium"
            reason_chain = [
                "The current account security settings were inspected.",
                "No obvious issue was found in 2FA, sessions, or API token state.",
            ]

        return AgentResponse(
            category="service",
            target="settings-security",
            matched=True,
            title="Settings Security diagnostics",
            summary=summary,
            confidence=confidence,
            section="settings",
            subsection="security",
            module=self.name,
            checks_run=["settings_security"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Enable 2FA if the account should require stronger login protection.",
                "Review active sessions and revoke stale sessions if the account was used on multiple devices.",
            ],
        )

    async def _user_response(self, *, username_hint: str | None, question: str) -> AgentResponse:
        state = await self.adapter.get_user_state(username_hint=username_hint)
        if not state or not self._matches_user_hint(state, username_hint):
            return self._unavailable_response(
                "settings-user",
                "Settings User diagnostics",
                f"Requested user {username_hint or 'profile'}",
            )
        facts = [
            AgentFact("User", str(state.get("username") or "Unknown")),
            AgentFact("Role", str(state.get("role") or "Unknown")),
            AgentFact("Email", str(state.get("email") or "Not configured")),
            AgentFact(
                "Avatar configured",
                self._yes_no(bool(state.get("avatar_configured"))),
                "warning" if not bool(state.get("avatar_configured")) else "info",
            ),
            AgentFact("API token configured", self._yes_no(bool(state.get("api_token_configured")))),
        ]
        if state.get("last_login"):
            facts.append(AgentFact("Last login", str(state.get("last_login"))))
        if state.get("last_login_ip"):
            facts.append(AgentFact("Last login IP", str(state.get("last_login_ip"))))

        if "avatar" in question and not bool(state.get("avatar_configured")):
            summary = "No custom avatar is currently stored for this user."
            confidence = "high"
            reason_chain = [
                "The selected user profile was inspected.",
                "No stored avatar file was found for this account.",
            ]
        elif "api token" in question and not bool(state.get("api_token_configured")):
            summary = "No API token is configured yet for the User settings workflow."
            confidence = "high"
            reason_chain = [
                "The global API token state was inspected.",
                "No token file is currently stored on disk.",
            ]
        elif "email" in question and not bool(state.get("email")):
            summary = "No email address is currently stored for this user profile."
            confidence = "high"
            reason_chain = [
                "The selected user profile was inspected.",
                "The email field is currently empty for this account.",
            ]
        else:
            summary = "Settings > User profile data was collected successfully."
            confidence = "medium"
            reason_chain = [
                "The selected user profile was inspected.",
                "Basic profile metadata is available locally.",
            ]

        return AgentResponse(
            category="service",
            target="settings-user",
            matched=True,
            title="Settings User diagnostics",
            summary=summary,
            confidence=confidence,
            section="settings",
            subsection="user",
            module=self.name,
            checks_run=["settings_user"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Upload a custom avatar if the profile should show a non-default image.",
                "Generate an API token only if an external integration really needs it.",
            ],
        )

    async def _overview_response(self, *, username_hint: str | None) -> AgentResponse:
        overview = await self.adapter.get_overview(username_hint=username_hint)
        if not overview:
            return self._unavailable_response("settings", "Settings overview diagnostics", "Settings")
        general = overview.get("general") or {}
        notifications = overview.get("notifications") or {}
        security = overview.get("security") or {}
        user = overview.get("user") or {}
        if username_hint and not all(
            self._matches_user_hint(state, username_hint)
            for state in (notifications, security, user)
        ):
            return self._unavailable_response(
                "settings",
                "Settings overview diagnostics",
                f"Requested user {username_hint}",
            )

        return AgentResponse(
            category="service",
            target="settings",
            matched=True,
            title="Settings overview diagnostics",
            summary="Settings state was collected across General, Notifications, Security, and User tabs.",
            confidence="medium",
            section="settings",
            subsection="overview",
            module=self.name,
            checks_run=["settings_general", "settings_notifications", "settings_security", "settings_user"],
            facts=[
                AgentFact("Timezone", str(general.get("timezone") or "Unknown")),
                AgentFact("Notifications enabled", self._yes_no(bool(notifications.get("notifications_enabled")))),
                AgentFact("Push configured", self._yes_no(bool(notifications.get("push_configured")))),
                AgentFact("2FA enabled", self._yes_no(bool(security.get("totp_enabled")))),
                AgentFact("Avatar configured", self._yes_no(bool(user.get("avatar_configured")))),
            ],
            reason_chain=[
                "Settings data was collected across all major Settings tabs.",
            ],
            recommendations=[
                "Ask about the active Settings tab for a more specific explanation.",
            ],
        )

    def _matches(self, question: str, target: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword in question or keyword in target for keyword in keywords)

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    @staticmethod
    def _matches_user_hint(state: dict[str, object], username_hint: str | None) -> bool:
        normalized = str(username_hint or "").strip().casefold()
        if not normalized:
            return True
        return normalized in {
            str(state.get("username") or "").strip().casefold(),
            str(state.get("user_id") or "").strip().casefold(),
        }

    def _unavailable_response(self, target: str, title: str, source: str) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=target,
            matched=True,
            title=title,
            summary=f"{source} data are unavailable or do not match the request, so the current state is unknown.",
            confidence="low",
            section="settings",
            subsection="overview",
            module=self.name,
            source_status="unavailable",
            checks_run=[],
            facts=[AgentFact("Source data", "Unavailable", "warning")],
            reason_chain=["No authoritative matching settings payload was returned."],
            recommendations=["Retry with an existing user or after checking the Settings backend source."],
        )
