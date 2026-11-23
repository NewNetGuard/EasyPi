"""Cross-section reasoning for Users, Security, and Settings."""

from __future__ import annotations

from app.agent.adapters.security import SecurityAdapter
from app.agent.adapters.settings import SettingsAdapter
from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class UsersSecuritySettingsReasoningAgent:
    """Explain whether account issues come from user state, settings, or wider security findings."""

    name = "users_security_settings_reasoning_agent"
    _USER_WORDS = ("user", "users", "account", "login", "auth", "session", "2fa", "two-factor")
    _SETTINGS_WORDS = ("settings", "profile", "avatar", "api token", "security settings")
    _SECURITY_WORDS = ("security", "scan", "policy", "hardening", "firewall")

    def __init__(
        self,
        users_auth: UsersAuthAdapter,
        settings: SettingsAdapter,
        security: SecurityAdapter,
    ) -> None:
        self.users_auth = users_auth
        self.settings = settings
        self.security = security

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        target = (request.target or "").lower()
        route = (request.route or "").lower()
        haystack = f"{question} {target} {route}"
        hits = sum(
            1
            for keywords in (self._USER_WORDS, self._SETTINGS_WORDS, self._SECURITY_WORDS)
            if any(keyword in haystack for keyword in keywords)
        )
        return 155 if hits >= 2 else 0

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        users = await self.users_auth.list_users()
        sessions = await self.users_auth.list_sessions()
        target_user = self._find_user(str(request.target or request.question), users)
        if target_user is None:
            requested_target = str(request.target or request.entity_id or "Unknown").strip() or "Unknown"
            return AgentResponse(
                category="service",
                target="users-security-settings",
                matched=True,
                title="Cross-section diagnostics for Users, Security, and Settings",
                summary="No matching user was found, so no other user's Settings or Security data were used.",
                confidence="low",
                section="settings",
                subsection="cross-section",
                module=self.name,
                source_status="unavailable",
                checks_run=["users"],
                facts=[AgentFact("Requested user", requested_target, "warning")],
                reason_chain=["The user lookup returned no exact matching account."],
                recommendations=["Provide an existing exact username or user ID and retry."],
            )
        username_hint = str(target_user.get("username") or "") if target_user else None
        settings_security = await self.settings.get_security_state(username_hint=username_hint)
        latest_scan = self.security.get_latest_scan() or {}

        user_sessions = self._user_sessions(target_user, sessions)
        expired_sessions = [session for session in user_sessions if bool(session.get("expired"))]
        revoked_sessions = [session for session in user_sessions if bool(session.get("revoked"))]
        critical_findings = list(latest_scan.get("critical") or [])

        facts = [
            AgentFact("Target user", str(username_hint or "Unknown")),
            AgentFact(
                "Account active",
                self._yes_no(bool(settings_security.get("account_active"))),
                "critical" if not bool(settings_security.get("account_active")) else "info",
            ),
            AgentFact(
                "2FA enabled",
                self._yes_no(bool(settings_security.get("totp_enabled"))),
                "warning" if not bool(settings_security.get("totp_enabled")) else "info",
            ),
            AgentFact("Known sessions", str(len(user_sessions))),
            AgentFact("Expired sessions", str(len(expired_sessions)), "warning" if expired_sessions else "info"),
            AgentFact("Revoked sessions", str(len(revoked_sessions)), "warning" if revoked_sessions else "info"),
            AgentFact(
                "Critical security findings",
                str(len(critical_findings)),
                "critical" if critical_findings else "info",
            ),
        ]

        if target_user is None:
            summary = "No matching user was found, so the account issue cannot be correlated with Settings or Security yet."
            confidence = "low"
            reason_chain = [
                "The local user database was inspected.",
                "No matching user record was found for the current question.",
            ]
            recommendations = [
                "Include the username or user ID when asking about a login or account issue.",
            ]
        elif not bool(settings_security.get("account_active")):
            summary = f"User '{username_hint}' cannot log in because the account is disabled, not because of a broader system security finding."
            confidence = "high"
            reason_chain = [
                "Users and Settings state were inspected for the target account.",
                "The account is marked inactive in local user state.",
            ]
            recommendations = [
                "Re-enable the account before debugging broader Security or Settings issues.",
            ]
        elif bool(settings_security.get("totp_enabled")) and any(
            token in request.question.lower() for token in ("login", "2fa", "two-factor", "auth")
        ):
            summary = f"User '{username_hint}' is gated by Settings > Security because 2FA is enabled for this account."
            confidence = "high"
            reason_chain = [
                "Users and Settings state were inspected for the target account.",
                "Two-factor authentication is enabled for this account.",
            ]
            recommendations = [
                "Use a valid 2FA or backup code before treating this as a wider Security incident.",
            ]
        elif expired_sessions or revoked_sessions:
            summary = f"Session state explains the current auth problem for '{username_hint}' more directly than a broader Security finding."
            confidence = "high"
            reason_chain = [
                "Users and Settings state were inspected for the target account.",
                "Expired or revoked sessions were found for this account.",
            ]
            recommendations = [
                "Revoke stale sessions or log in again before debugging wider Security findings.",
            ]
        elif critical_findings:
            summary = "The account state looks mostly healthy, but System Security still reports critical findings."
            confidence = "medium"
            reason_chain = [
                "Users and Settings state did not show a direct local account block.",
                "System Security still reports critical findings that may affect trust in the overall system state.",
            ]
            recommendations = [
                "Review critical Security findings next, because the account itself does not show a direct local block.",
            ]
        else:
            summary = "Users, Settings, and Security look internally consistent for this account right now."
            confidence = "medium"
            reason_chain = [
                "Users, Settings, and Security were inspected together for the target account.",
                "No shared root cause was detected.",
            ]
            recommendations = [
                "Ask a narrower question about the user account, session, or security finding if one area still looks wrong.",
            ]

        section, subsection = self._resolve_location(request)

        return AgentResponse(
            category="service",
            target=username_hint or "users-security-settings",
            matched=True,
            title="Cross-section diagnostics for Users, Security, and Settings",
            summary=summary,
            confidence=confidence,
            section=section,
            subsection=subsection,
            module=self.name,
            checks_run=["users", "sessions", "settings_security", "latest_security_scan"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _resolve_location(self, request: AgentRequest) -> tuple[str, str]:
        route = (request.route or "").strip().lower()
        if "settings" in route:
            return ("settings", "cross-section")
        if "users" in route:
            return ("users", "cross-section")
        if "security" in route:
            return ("security", "cross-section")
        return ("dashboard", "cross-section")

    def _find_user(self, value: str, users: list[dict[str, object]]) -> dict[str, object] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        best_match = None
        best_length = 0
        for user in users:
            username = str(user.get("username") or "").strip().lower()
            user_id = str(user.get("id") or "").strip().lower()
            if normalized in {username, user_id}:
                return user
            if username and username in normalized and len(username) > best_length:
                best_match = user
                best_length = len(username)
        return best_match

    def _user_sessions(
        self,
        user: dict[str, object] | None,
        sessions: list[dict[str, object]],
    ) -> list[dict[str, object]]:
        if user is None:
            return []
        user_id = str(user.get("id") or "")
        username = str(user.get("username") or "").strip().lower()
        matches: list[dict[str, object]] = []
        for session in sessions:
            session_user_id = str(session.get("user_id") or "")
            session_username = str(session.get("username") or "").strip().lower()
            if user_id and session_user_id == user_id:
                matches.append(session)
                continue
            if username and session_username == username:
                matches.append(session)
        return matches

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
