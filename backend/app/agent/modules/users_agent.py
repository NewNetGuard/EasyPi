"""Canonical users agent module."""

from app.agent.modules.users_auth_agent import UsersAuthAgent


class UsersAgent(UsersAuthAgent):
    """Compatibility wrapper that exposes the canonical users agent name."""

    name = "users_agent"
