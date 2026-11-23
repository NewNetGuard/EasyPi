"""Users adapter aliases for agent modules."""

from __future__ import annotations

from typing import Any

from app.agent.adapters.users_auth import UsersAuthAdapter


class UsersAdapter(UsersAuthAdapter):
    """Expose user and session state under the canonical users adapter name."""

    async def get_user(self, value: str) -> dict[str, Any] | None:
        normalized = str(value or "").strip().lower()
        if not normalized:
            return None
        for user in await self.list_users():
            username = str(user.get("username") or "").strip().lower()
            user_id = str(user.get("id") or "").strip().lower()
            if normalized in {username, user_id}:
                return user
        return None

    def has_avatar(self, user_id: int) -> bool:
        try:
            from app.api.v1.endpoints.auth import get_avatar_path

            return get_avatar_path(int(user_id)).exists()
        except Exception:
            return False

    def has_api_token(self) -> bool:
        try:
            from app.api.v1.endpoints.auth import API_TOKEN_PATH

            return API_TOKEN_PATH.exists()
        except Exception:
            return False
