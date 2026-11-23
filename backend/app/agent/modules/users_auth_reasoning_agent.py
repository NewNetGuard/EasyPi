"""Cross-section reasoning for users and authentication."""

from __future__ import annotations

from app.agent.adapters.users_auth import UsersAuthAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class UsersAuthReasoningAgent:
    """Explain login and account problems that span users, sessions, and registration."""

    name = "users_auth_reasoning_agent"
    _LOGIN_WORDS = (
        "login",
        "log in",
        "sign in",
        "auth",
        "authentication",
        "password",
        "recovery",
    )
    _SESSION_WORDS = ("session", "sessions", "logged out", "logout", "revoked", "expired", "cookie", "token")
    _REGISTRATION_WORDS = ("register", "registration", "setup token", "first user")
    _TWO_FACTOR_WORDS = ("2fa", "two-factor", "two factor", "totp", "backup code")
    _LOCKOUT_WORDS = ("locked out", "nobody", "everyone", "all users", "all accounts", "cannot access", "can't access")
    _ROUTES = ("users", "settings", "security")

    def __init__(self, adapter: UsersAuthAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()

        buckets = 0
        if self._matches_any(question, target, self._LOGIN_WORDS):
            buckets += 1
        if self._matches_any(question, target, self._SESSION_WORDS):
            buckets += 1
        if self._matches_any(question, target, self._REGISTRATION_WORDS):
            buckets += 1
        if self._matches_any(question, target, self._TWO_FACTOR_WORDS):
            buckets += 1

        score = 0
        if buckets >= 2:
            score += 155
        elif self._matches_any(question, target, self._LOCKOUT_WORDS) and buckets >= 1:
            score += 145
        elif any(token in route for token in self._ROUTES) and buckets >= 1 and any(
            word in question for word in ("why", "broken", "problem", "issue", "cannot", "can't", "failed")
        ):
            score += 90

        if request.target:
            score += 10

        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        if self.score(request) <= 0:
            return None

        question = request.question.lower()
        users = await self.adapter.list_users()
        sessions = await self.adapter.list_sessions()
        registration = await self.adapter.get_registration_state()

        if not users and not sessions and not registration:
            return AgentResponse(
                category="service", target="users-auth", matched=True,
                title="Users and authentication diagnostics",
                summary="User, registration, and session source data are unavailable.",
                confidence="low", section="users", subsection="cross-section", module=self.name,
                checks_run=[], facts=[AgentFact("Source data", "Unavailable", "warning")],
                reason_chain=["All authentication sources returned empty state."],
                recommendations=["Restore the authentication data sources before evaluating account consistency."],
            )

        user = self._find_user(str(request.target or request.question), users)
        scoped_sessions = sessions
        if user is not None:
            scoped_sessions = [session for session in sessions if int(session.get("user_id") or -1) == int(user.get("id") or -2)]

        active_users = [item for item in users if bool(item.get("is_active"))]
        active_admins = [item for item in active_users if str(item.get("role") or "").lower() == "admin"]
        active_sessions = [item for item in scoped_sessions if self._is_live_session(item)]
        revoked_sessions = [item for item in scoped_sessions if bool(item.get("revoked"))]
        expired_sessions = [item for item in scoped_sessions if bool(item.get("expired"))]
        disabled_users = [item for item in users if not bool(item.get("is_active"))]

        facts = [
            AgentFact("Users", str(len(users))),
            AgentFact("Active users", str(len(active_users)), "warning" if not active_users and users else "info"),
            AgentFact("Active admins", str(len(active_admins)), "warning" if not active_admins and users else "info"),
            AgentFact("Registration allowed", self._yes_no(bool(registration.get("registration_allowed")))),
            AgentFact("Live sessions", str(len(active_sessions))),
            AgentFact("Revoked sessions", str(len(revoked_sessions)), "warning" if revoked_sessions else "info"),
            AgentFact("Expired sessions", str(len(expired_sessions)), "warning" if expired_sessions else "info"),
        ]

        if user is not None:
            facts.extend(
                [
                    AgentFact("User", str(user.get("username") or "Unknown")),
                    AgentFact("Role", str(user.get("role") or "Unknown")),
                    AgentFact("User active", self._yes_no(bool(user.get("is_active"))), "info" if user.get("is_active") else "critical"),
                    AgentFact("User 2FA", self._yes_no(bool(user.get("totp_enabled"))), "info" if user.get("totp_enabled") else "warning"),
                ]
            )

        if not users and bool(registration.get("registration_allowed")):
            return AgentResponse(
                category="service",
                target="users-auth",
                matched=True,
                title="Users and authentication diagnostics",
                summary="EasyPi has no user accounts yet, so first-user registration is the current entry point.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The local user database was inspected.",
                    "No user records were found, so login cannot succeed until the first account is created.",
                ],
                recommendations=[
                    "Complete the first admin registration with the setup token.",
                    "Do not expect normal login to work until at least one user exists.",
                ],
            )

        if users and not active_admins:
            return AgentResponse(
                category="service",
                target="users-auth",
                matched=True,
                title="Users and authentication diagnostics",
                summary="EasyPi currently has no active admin account, which can leave the system effectively locked out.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The local user database was inspected.",
                    "No active admin account was found among existing users.",
                ],
                recommendations=[
                    "Re-enable an admin account or use the recovery path before making more auth changes.",
                    "Avoid disabling the last admin account on the system.",
                ],
            )

        if users and len(disabled_users) == len(users):
            return AgentResponse(
                category="service",
                target="users-auth",
                matched=True,
                title="Users and authentication diagnostics",
                summary="All local user accounts are disabled, so nobody can authenticate normally.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The local user database was inspected.",
                    "Every stored account is marked as inactive.",
                ],
                recommendations=[
                    "Re-enable at least one admin account or use recovery access.",
                ],
            )

        if user is not None and not bool(user.get("is_active")):
            return AgentResponse(
                category="service",
                target=str(user.get("username") or "user"),
                matched=True,
                title="User access diagnostics",
                summary=f"User '{user.get('username')}' cannot authenticate because the account is disabled.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The requested user account was found in the local database.",
                    "That account is marked as inactive, so login is blocked before password or 2FA checks.",
                ],
                recommendations=[
                    "Re-enable the user in the Users page if access should be restored.",
                ],
            )

        if self._matches_any(question, "", self._SESSION_WORDS) and scoped_sessions and not active_sessions:
            if revoked_sessions:
                summary = "The stored authentication sessions for this scope are revoked or inactive."
                reason = "Every session in scope is revoked or inactive."
            else:
                summary = "The stored authentication sessions for this scope are expired or inactive."
                reason = "No live session remains in scope."
            return AgentResponse(
                category="service",
                target=str(user.get("username") if user is not None else "users-auth"),
                matched=True,
                title="Session diagnostics",
                summary=summary,
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The local session store was inspected.",
                    reason,
                ],
                recommendations=[
                    "Sign in again to create a fresh session.",
                    "If sessions were revoked intentionally, verify account and password state before retrying.",
                ],
            )

        if user is not None and self._matches_any(question, "", self._TWO_FACTOR_WORDS + self._LOGIN_WORDS) and bool(user.get("totp_enabled")):
            return AgentResponse(
                category="service",
                target=str(user.get("username") or "user"),
                matched=True,
                title="User access diagnostics",
                summary=f"User '{user.get('username')}' still needs a valid two-factor code to finish authentication.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The requested user account was found in the local database.",
                    "Two-factor authentication is enabled for this account.",
                ],
                recommendations=[
                    "Use a valid TOTP code or a backup code during login.",
                ],
            )

        if self._matches_any(question, "", self._REGISTRATION_WORDS) and not bool(registration.get("registration_allowed")):
            return AgentResponse(
                category="service",
                target="registration",
                matched=True,
                title="Registration diagnostics",
                summary="Public registration is closed because EasyPi already has existing user accounts.",
                confidence="high",
                section="users",
                subsection="cross-section",
                module=self.name,
                checks_run=["users", "user_sessions", "registration_state"],
                facts=facts,
                reason_chain=[
                    "The local registration state was inspected.",
                    "EasyPi already has one or more user accounts, so public first-user registration is disabled.",
                ],
                recommendations=[
                    "Create additional users from the Users page instead of using the public registration flow.",
                ],
            )

        return AgentResponse(
            category="service",
            target=str(user.get("username") if user is not None else "users-auth"),
            matched=True,
            title="Users and authentication diagnostics",
            summary="Users, registration, and session state look internally consistent right now.",
            confidence="medium",
            section="users",
            subsection="cross-section",
            module=self.name,
            checks_run=["users", "user_sessions", "registration_state"],
            facts=facts,
            reason_chain=[
                "The local user database, registration state, and stored sessions were inspected together.",
                "No system-wide authentication contradiction was detected in the current data.",
            ],
            recommendations=[
                "If a single user still cannot sign in, ask again with the username for a narrower diagnosis.",
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

    def _matches_any(self, question: str, target: str, keywords: tuple[str, ...]) -> bool:
        return any(keyword in question or keyword in target for keyword in keywords)

    def _is_live_session(self, session: dict[str, object]) -> bool:
        return bool(session.get("is_active")) and not bool(session.get("revoked")) and not bool(session.get("expired"))

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
