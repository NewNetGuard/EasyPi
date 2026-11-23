"""Users and auth agent module."""

from __future__ import annotations

from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class UsersAuthAgent:
    """Explain user accounts, authentication, and registration state."""

    name = "users_auth_agent"
    _KEYWORDS = (
        "user",
        "users",
        "login",
        "log in",
        "auth",
        "2fa",
        "two-factor",
        "session",
        "register",
        "registration",
        "account",
        "role",
        "avatar",
        "api token",
        "token invalid",
        "backup code",
        "backup codes",
    )
    _ROUTES = ("users",)

    def __init__(self, adapter: UsersAuthAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 100

        if any(token in route for token in self._ROUTES):
            score += 25

        if request.target:
            score += 10

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = str(request.target or "").strip()
        if not any(keyword in question or keyword in target.lower() for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        if "register" in question or "registration" in question or "setup token" in question:
            return await self._registration_response()

        users = await self.adapter.list_users()
        if not users:
            return await self._registration_response()

        user = self._find_user(target or request.question, users)
        if user is None:
            if target:
                return self._missing_user_response(target, users)
            return self._overview_response(users)

        return await self._user_response(user, question)

    async def _registration_response(self) -> AgentResponse:
        state = await self.adapter.get_registration_state()
        if not state:
            return AgentResponse(
                category="service",
                target="registration",
                matched=True,
                title="Registration diagnostics",
                summary="Registration state is unavailable, so first-user registration cannot be confirmed.",
                confidence="low",
                section="users",
                subsection="registration",
                module=self.name,
                checks_run=[],
                facts=[AgentFact("Registration state", "Unknown", "warning")],
                reason_chain=["The registration source returned no authoritative payload."],
                recommendations=["Check the authentication backend and retry."],
            )
        registration_allowed = bool(state.get("registration_allowed"))
        user_count = int(state.get("user_count") or 0)
        source_status = "ok"
        if not registration_allowed and user_count == 0:
            summary = "Registration state is internally inconsistent: no users exist, but first-user registration is disabled."
            confidence = "low"
            source_status = "conflict"
            reason_chain = [
                "The registration source reports zero users.",
                "The same source reports that first-user registration is disabled, so neither side was treated as authoritative.",
            ]
        elif registration_allowed:
            summary = "First-user registration is currently allowed and requires the setup token."
            confidence = "high"
            reason_chain = [
                "The user database was checked.",
                "No existing users were found, so initial registration remains open.",
            ]
        else:
            summary = "Public registration is disabled because EasyPi already has existing users."
            confidence = "high"
            reason_chain = [
                "The user database was checked.",
                "At least one existing user already exists, so public registration is disabled.",
            ]

        return AgentResponse(
            category="service",
            target="registration",
            matched=True,
            title="Registration diagnostics",
            summary=summary,
            confidence=confidence,
            section="users",
            subsection="registration",
            module=self.name,
            source_status=source_status,
            checks_run=["registration_state"],
            facts=[
                AgentFact("Users", str(user_count)),
                AgentFact("Registration allowed", self._yes_no(registration_allowed)),
                AgentFact("Setup token required", self._yes_no(bool(state.get("requires_setup_token")))),
            ],
            reason_chain=reason_chain,
            recommendations=[
                "Use the setup token only for the first admin registration.",
                "Create additional users through the Users page after the first account exists.",
            ],
        )

    async def _user_response(self, user: dict[str, object], question: str) -> AgentResponse:
        username = str(user.get("username") or "Unknown user")
        active = bool(user.get("is_active"))
        totp_enabled = bool(user.get("totp_enabled"))
        active_sessions = int(user.get("active_sessions") or 0)
        declared_active_sessions = active_sessions
        avatar_configured = self._has_avatar(user)
        api_token_configured = self._has_api_token()
        facts = [
            AgentFact("User", username),
            AgentFact("Role", str(user.get("role") or "Unknown")),
            AgentFact("Active", self._yes_no(active), "info" if active else "critical"),
            AgentFact("2FA enabled", self._yes_no(totp_enabled), "info" if totp_enabled else "warning"),
            AgentFact("Active sessions", str(active_sessions)),
            AgentFact("Avatar configured", self._yes_no(avatar_configured), "warning" if not avatar_configured else "info"),
            AgentFact("API token configured", self._yes_no(api_token_configured), "warning" if not api_token_configured else "info"),
            AgentFact("Last login", str(user.get("last_login") or "Never")),
        ]
        if user.get("last_login_ip"):
            facts.append(AgentFact("Last login IP", str(user.get("last_login_ip"))))
        user_sessions = []
        if any(token in question for token in ("session", "token", "logged out", "csrf", "delete user", "delete account", "remove user")):
            sessions = await self.adapter.list_sessions()
            user_sessions = [
                session for session in sessions if str(session.get("username") or "").strip().lower() == username.lower()
            ]
            facts.append(AgentFact("Recorded sessions", str(len(user_sessions))))
            revoked = sum(1 for session in user_sessions if bool(session.get("revoked")))
            expired = sum(1 for session in user_sessions if bool(session.get("expired")))
            facts.append(AgentFact("Revoked sessions", str(revoked), "warning" if revoked else "info"))
            facts.append(AgentFact("Expired sessions", str(expired), "warning" if expired else "info"))
            active_sessions = sum(
                1
                for session in user_sessions
                if bool(session.get("is_active", True))
                and not bool(session.get("revoked"))
                and not bool(session.get("expired"))
            )
            facts.append(AgentFact("Verified live sessions", str(active_sessions)))

        session_question = any(
            token in question
            for token in ("session", "token", "logged out", "csrf", "delete user", "delete account", "remove user")
        )
        session_conflict = session_question and declared_active_sessions > 0 and not user_sessions
        source_status = "ok"
        if session_conflict:
            summary = f"Session state for user '{username}' is inconsistent and cannot confirm why the token is invalid."
            confidence = "low"
            source_status = "conflict"
            reason_chain = [
                f"The user record reports {declared_active_sessions} active session(s).",
                "The authoritative session list returned no matching records, so the account was not reported healthy.",
            ]
            recommendations = ["Refresh or repair the session store before revoking or trusting session state."]
        elif not active:
            summary = f"User '{username}' cannot log in because the account is disabled."
            confidence = "high"
            reason_chain = [
                "The user account was found in the database.",
                "The account is marked as inactive.",
            ]
            recommendations = [
                "Re-enable the account from the Users page if login should be allowed.",
            ]
        elif any(token in question for token in ("delete user", "delete account", "remove user")):
            if str(user.get("role") or "").lower() == "admin":
                summary = f"Deletion safety for admin user '{username}' cannot be confirmed from session state alone."
                confidence = "low"
                source_status = "partial"
                reason_chain = [
                    "The target account has the admin role.",
                    "Session state does not prove that another active administrator can recover or manage EasyPi.",
                ]
                recommendations = [
                    "Verify another active administrator exists, revoke remaining sessions, and preserve recovery access before deleting this account.",
                ]
            elif active_sessions:
                summary = f"User '{username}' still has active sessions, so delete or deprovision work should start by revoking sessions."
                confidence = "high"
                reason_chain = [
                    "The user account was found in the database.",
                    "The account still has active local sessions.",
                ]
                recommendations = [
                    "Revoke active sessions first, then delete the account if it is no longer needed.",
                ]
            else:
                summary = f"User '{username}' has no active sessions, so the account can be removed more safely."
                confidence = "medium"
                reason_chain = [
                    "The user account was found in the database.",
                    "No active sessions remain for this account.",
                ]
                recommendations = [
                    "Delete the account only if you no longer need its access history or role assignments.",
                ]
        elif "role" in question:
            summary = f"User '{username}' currently has role '{user.get('role') or 'unknown'}'."
            confidence = "high"
            reason_chain = [
                "The user account was found in the database.",
                "The current role is stored in the local user record.",
            ]
            recommendations = [
                "Change the role only if this user should gain or lose admin permissions.",
            ]
        elif "avatar" in question:
            if avatar_configured:
                summary = f"User '{username}' already has a stored custom avatar."
            else:
                summary = f"User '{username}' does not have a custom avatar stored yet."
            confidence = "high"
            reason_chain = [
                "The user account was found in the database.",
                "Avatar storage was checked for the selected user.",
            ]
            recommendations = [
                "Upload or replace the avatar from the user profile page if a custom image is needed.",
            ]
        elif "api token" in question:
            if api_token_configured:
                summary = "A global EasyPi API token is currently configured."
            else:
                summary = "No EasyPi API token is currently configured."
            confidence = "high"
            reason_chain = [
                "The local API token storage was checked.",
                "The agent confirmed whether an API token file currently exists.",
            ]
            recommendations = [
                "Generate an API token only if an external integration actually needs backend access.",
            ]
        elif "backup code" in question:
            backup_codes_remaining = int(user.get("backup_codes_remaining") or 0)
            if backup_codes_remaining > 0:
                summary = f"User '{username}' still has backup codes available for two-factor recovery."
                confidence = "high"
                reason_chain = [
                    "The user account was found in the database.",
                    "The stored security metadata still shows unused backup codes.",
                ]
            else:
                summary = f"User '{username}' has no backup codes remaining for two-factor recovery."
                confidence = "high"
                reason_chain = [
                    "The user account was found in the database.",
                    "No unused backup codes remain in the stored security metadata.",
                ]
            recommendations = [
                "Regenerate backup codes after confirming the current TOTP device is available.",
            ]
        elif any(token in question for token in ("token invalid", "session", "logged out", "csrf")) and user_sessions:
            revoked = sum(1 for session in user_sessions if bool(session.get("revoked")))
            expired = sum(1 for session in user_sessions if bool(session.get("expired")))
            if revoked or expired:
                summary = f"User '{username}' has revoked or expired sessions that can explain token or login state issues."
                confidence = "high"
                reason_chain = [
                    "The user account was found in the database.",
                    "Recent user sessions were inspected for revoked and expired state.",
                    "At least one stored session is no longer valid.",
                ]
            else:
                summary = f"User '{username}' has active local sessions, so token failure is not obvious from stored session state alone."
                confidence = "medium"
                reason_chain = [
                    "The user account was found in the database.",
                    "Recent user sessions were inspected and remain active locally.",
                ]
            recommendations = [
                "Revoke stale sessions and retry login if session integrity looks suspicious.",
                "If browser login still fails, inspect cookies, CSRF flow, and 2FA state next.",
            ]
        elif totp_enabled and any(token in question for token in ("login", "auth", "2fa", "two-factor")):
            summary = f"User '{username}' must provide a two-factor authentication code during login."
            confidence = "high"
            reason_chain = [
                "The user account was found in the database.",
                "Two-factor authentication is enabled for this account.",
            ]
            recommendations = [
                "Use a valid TOTP code or a backup code during login.",
            ]
        elif user.get("last_login") in (None, "", "Never"):
            summary = f"User '{username}' exists but has never logged in."
            confidence = "high"
            reason_chain = [
                "The user account was found in the database.",
                "No previous login timestamp is stored for this account.",
            ]
            recommendations = [
                "Verify the username and password if the user expected to have logged in already.",
            ]
        else:
            summary = f"User '{username}' is active and the account state looks healthy."
            confidence = "medium"
            reason_chain = [
                "The user account was found in the database.",
                "The account is active and has valid local metadata.",
            ]
            recommendations = [
                "If login still fails, check password correctness, cookies, CSRF, and browser state.",
            ]

        subsection = "sessions" if "session" in question else "accounts"
        return AgentResponse(
            category="service",
            target=username,
            matched=True,
            title=f"User diagnostics for {username}",
            summary=summary,
            confidence=confidence,
            section="users",
            subsection=subsection,
            module=self.name,
            source_status=source_status,
            checks_run=["users", "sessions"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _overview_response(self, users: list[dict[str, object]]) -> AgentResponse:
        total = len(users)
        active_users = sum(1 for user in users if bool(user.get("is_active")))
        admins = sum(1 for user in users if str(user.get("role")) == "admin")
        with_2fa = sum(1 for user in users if bool(user.get("totp_enabled")))
        active_without_2fa = sum(
            1 for user in users if bool(user.get("is_active")) and not bool(user.get("totp_enabled"))
        )
        single_admin = admins <= 1
        weak_2fa = active_without_2fa > 0

        recommendations = []
        if single_admin:
            recommendations.append(
                "Only one admin exists — if you lose that account you cannot recover EasyPi. Add a second admin as a backup."
            )
        if weak_2fa:
            recommendations.append(
                "Enable two-factor authentication (TOTP), especially on admin accounts, to protect against password theft."
            )
        if not recommendations:
            recommendations.append(
                "Accounts look well-protected. Include a username in your question for a per-account diagnosis."
            )

        if single_admin and weak_2fa:
            summary = f"{total} account(s): a single admin and {active_without_2fa} active account(s) without 2FA — both are recovery/security risks worth fixing."
        elif single_admin:
            summary = f"{total} account(s) with only one admin — add a second admin so you are not locked out if that account is lost."
        elif weak_2fa:
            summary = f"{total} account(s): {active_without_2fa} active account(s) have no two-factor authentication enabled."
        else:
            summary = f"{total} account(s): {admins} admins, and all active users have 2FA — account security looks solid."

        return AgentResponse(
            category="service",
            target="users",
            matched=True,
            title="Users and auth overview",
            summary=summary,
            confidence="high",
            section="users",
            subsection="accounts",
            module=self.name,
            checks_run=["users", "sessions"],
            facts=[
                AgentFact("Users", str(total)),
                AgentFact("Active users", str(active_users)),
                AgentFact("Admins", str(admins), "warning" if single_admin else "info"),
                AgentFact("Users with 2FA", f"{with_2fa}/{total}", "warning" if weak_2fa else "info"),
            ],
            reason_chain=[
                "The local user database and active session counts were inspected.",
                f"{admins} admin account(s) and {with_2fa} of {total} accounts with 2FA were found.",
            ],
            recommendations=recommendations,
        )

    def _missing_user_response(self, target: str, users: list[dict[str, object]]) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=str(target),
            matched=True,
            title="User not found",
            summary=f"EasyPi could not find a local user matching '{target}'.",
            confidence="high",
            section="users",
            subsection="accounts",
            module=self.name,
            checks_run=["users"],
            facts=[
                AgentFact("Requested user", str(target)),
                AgentFact("Known users", str(len(users))),
            ],
            reason_chain=[
                "The local user database was queried.",
                "No username or user ID matched the requested account.",
            ],
            recommendations=[
                "Check the exact username spelling or create the user from the Users page if the account does not exist yet.",
            ],
        )

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

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _has_avatar(self, user: dict[str, object]) -> bool:
        method = getattr(self.adapter, "has_avatar", None)
        if not callable(method):
            return bool(user.get("avatar_configured"))
        try:
            return bool(method(int(user.get("id") or 0)))
        except Exception:
            return bool(user.get("avatar_configured"))

    def _has_api_token(self) -> bool:
        method = getattr(self.adapter, "has_api_token", None)
        if not callable(method):
            return False
        try:
            return bool(method())
        except Exception:
            return False
