"""Settings fact adapter for agent modules."""

from __future__ import annotations

import json
from typing import Any, Callable

from sqlalchemy import func, select

from app.api.endpoints.system import get_timezone as get_timezone_state
from app.core.paths import get_user_data_dir
from app.db.session import SessionLocal
from app.models.session import UserSession
from app.models.user import User
from app.services.email_service import NotificationPreferences, email_service
from app.services.push_notification_service import get_push_service

USER_DATA_DIR = get_user_data_dir()
API_TOKEN_PATH = USER_DATA_DIR / "api_token.txt"


class SettingsAdapter:
    """Expose Settings page state without requiring the UI."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.session_factory = session_factory or SessionLocal

    async def get_general_state(self) -> dict[str, Any]:
        timezone_info = await get_timezone_state()
        if not isinstance(timezone_info, dict):
            timezone_info = {}
        return {
            "timezone": str(timezone_info.get("timezone") or "UTC"),
            "is_development": bool(timezone_info.get("is_development")),
            "theme_scope": "browser-local",
            "language_scope": "browser-local",
            "language_status": "english-default",
        }

    async def get_notification_state(self, *, username_hint: str | None = None) -> dict[str, Any]:
        user = self._get_user_context(username_hint)
        prefs = email_service.get_preferences(str(user["id"])) if user else NotificationPreferences()
        push_service = get_push_service()
        user_push_subscriptions = push_service.get_subscriptions(user_id=user["id"]) if user else []
        usage_email = prefs.email or ""
        usage = email_service.rate_limiter.get_counts(usage_email) if usage_email else {"hourly": 0, "daily": 0}

        return {
            "user_id": user["id"] if user else None,
            "username": user["username"] if user else None,
            "smtp_configured": email_service.is_enabled,
            "smtp_host": email_service.config.host or None,
            "smtp_username": email_service.config.username or None,
            "notifications_enabled": bool(prefs.enabled),
            "notification_email": prefs.email or None,
            "quiet_hours_enabled": bool(prefs.quiet_hours_enabled),
            "quiet_hours_start": int(prefs.quiet_hours_start),
            "quiet_hours_end": int(prefs.quiet_hours_end),
            "digest_mode": bool(prefs.digest_mode),
            "digest_interval_hours": int(prefs.digest_interval_hours),
            "max_emails_per_hour": int(prefs.max_emails_per_hour),
            "max_emails_per_day": int(prefs.max_emails_per_day),
            "min_priority": getattr(prefs.min_priority, "value", str(prefs.min_priority)),
            "alert_types_count": len(prefs.alert_types),
            "hourly_usage": int(usage.get("hourly") or 0),
            "daily_usage": int(usage.get("daily") or 0),
            "push_configured": bool(push_service.is_configured),
            "user_push_subscriptions": len(user_push_subscriptions),
            "total_push_subscriptions": int(push_service.get_subscription_count()),
            "push_history_entries": len(push_service.get_history(limit=10)),
        }

    async def get_security_state(self, *, username_hint: str | None = None) -> dict[str, Any]:
        user = self._get_user_context(username_hint)
        if user is None:
            return {
                "user_id": None,
                "username": None,
                "account_active": False,
                "totp_enabled": False,
                "backup_codes_remaining": 0,
                "active_sessions": 0,
                "api_token_configured": API_TOKEN_PATH.exists(),
            }

        return {
            "user_id": user["id"],
            "username": user["username"],
            "account_active": bool(user["is_active"]),
            "totp_enabled": bool(user["totp_enabled"]),
            "backup_codes_remaining": int(user["backup_codes_remaining"]),
            "active_sessions": int(user["active_sessions"]),
            "last_login": user["last_login"],
            "last_login_ip": user["last_login_ip"],
            "api_token_configured": API_TOKEN_PATH.exists(),
        }

    async def get_user_state(self, *, username_hint: str | None = None) -> dict[str, Any]:
        user = self._get_user_context(username_hint)
        if user is None:
            return {
                "user_id": None,
                "username": None,
                "role": None,
                "email": None,
                "avatar_configured": False,
                "api_token_configured": API_TOKEN_PATH.exists(),
                "last_login": None,
                "last_login_ip": None,
            }

        avatar_path = USER_DATA_DIR / f"avatar_{user['id']}.png"
        return {
            "user_id": user["id"],
            "username": user["username"],
            "role": user["role"],
            "email": user["email"],
            "avatar_configured": avatar_path.exists(),
            "api_token_configured": API_TOKEN_PATH.exists(),
            "last_login": user["last_login"],
            "last_login_ip": user["last_login_ip"],
        }

    async def get_overview(self, *, username_hint: str | None = None) -> dict[str, Any]:
        general = await self.get_general_state()
        notifications = await self.get_notification_state(username_hint=username_hint)
        security = await self.get_security_state(username_hint=username_hint)
        user = await self.get_user_state(username_hint=username_hint)
        return {
            "general": general,
            "notifications": notifications,
            "security": security,
            "user": user,
        }

    def _get_user_context(self, username_hint: str | None = None) -> dict[str, Any] | None:
        db = self.session_factory()
        try:
            target = str(username_hint or "").strip().lower()
            query = select(User).order_by(User.id.asc())
            users = db.execute(query).scalars().all()
            if not users:
                return None

            selected = users[0] if not target else None
            if target:
                for user in users:
                    username = str(user.username or "").strip().lower()
                    user_id = str(user.id)
                    if target in {username, user_id}:
                        selected = user
                        break
            if selected is None:
                return None

            active_sessions = (
                db.execute(
                    select(func.count(UserSession.id)).where(
                        UserSession.user_id == selected.id,
                        UserSession.is_active.is_(True),
                    )
                ).scalar()
                or 0
            )
            backup_codes_remaining = 0
            if selected.backup_codes:
                try:
                    backup_codes_remaining = len(json.loads(selected.backup_codes))
                except Exception:
                    backup_codes_remaining = 0

            return {
                "id": selected.id,
                "username": selected.username,
                "role": selected.role,
                "email": selected.email,
                "is_active": selected.is_active,
                "totp_enabled": selected.totp_enabled,
                "backup_codes_remaining": backup_codes_remaining,
                "active_sessions": int(active_sessions),
                "last_login": selected.last_login.isoformat() if selected.last_login else None,
                "last_login_ip": selected.last_login_ip,
            }
        finally:
            db.close()
