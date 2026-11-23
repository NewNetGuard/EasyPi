"""Users and auth fact adapter for agent modules."""

from __future__ import annotations

from app.utils.time import utc_now
from typing import Any, Callable

from sqlalchemy import func, select

from app.db.session import SessionLocal
from app.models.session import UserSession
from app.models.user import User


class UsersAuthAdapter:
    """Expose read-only user and authentication state."""

    def __init__(self, *, session_factory: Callable[[], Any] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    async def list_users(self) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
            results: list[dict[str, Any]] = []
            for user in users:
                active_sessions = (
                    db.execute(
                        select(func.count(UserSession.id)).where(
                            UserSession.user_id == user.id,
                            UserSession.is_active.is_(True),
                        )
                    ).scalar()
                    or 0
                )
                backup_codes_remaining = 0
                if user.backup_codes:
                    try:
                        import json

                        backup_codes_remaining = len(json.loads(user.backup_codes))
                    except Exception:
                        backup_codes_remaining = 0
                results.append(
                    {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": user.role,
                        "is_active": user.is_active,
                        "created_at": user.created_at.isoformat() if user.created_at else None,
                        "last_login": user.last_login.isoformat() if user.last_login else None,
                        "last_login_ip": user.last_login_ip,
                        "totp_enabled": bool(user.totp_enabled),
                        "active_sessions": int(active_sessions),
                        "backup_codes_remaining": int(backup_codes_remaining),
                    }
                )
            return results
        finally:
            db.close()

    async def get_registration_state(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            user_count = db.query(User).count()
            return {
                "user_count": user_count,
                "registration_allowed": user_count == 0,
                "requires_setup_token": user_count == 0,
            }
        finally:
            db.close()

    async def list_sessions(self) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            now = utc_now()
            rows = db.execute(
                select(UserSession, User.username, User.role)
                .join(User, User.id == UserSession.user_id)
                .order_by(UserSession.last_active.desc(), UserSession.created_at.desc())
            ).all()
            sessions: list[dict[str, Any]] = []
            for session, username, role in rows:
                payload = session.to_response()
                payload.update(
                    {
                        "username": username,
                        "role": role,
                        "session_id": session.id,
                        "user_id": session.user_id,
                        "revoked": session.revoked_at is not None,
                        "revoked_at": session.revoked_at.isoformat() if session.revoked_at else None,
                        "expired": bool(session.expires_at and session.expires_at < now),
                        "token_jti": session.token_jti,
                    }
                )
                sessions.append(payload)
            return sessions
        finally:
            db.close()

    async def revoke_sessions(self, username: str) -> dict[str, Any]:
        db = self.session_factory()
        try:
            user = db.execute(select(User).where(func.lower(User.username) == str(username or "").strip().lower())).scalar_one_or_none()
            if user is None:
                return {"success": False, "message": f'User "{username}" was not found.'}
            result = db.execute(
                UserSession.__table__.update()
                .where(UserSession.user_id == user.id)
                .where(UserSession.is_active.is_(True))
                .values(is_active=False)
            )
            db.commit()
            return {"success": True, "message": f"Revoked {result.rowcount} sessions for {user.username}", "count": result.rowcount}
        finally:
            db.close()

    async def disable_2fa(self, username: str) -> dict[str, Any]:
        db = self.session_factory()
        try:
            user = db.execute(select(User).where(func.lower(User.username) == str(username or "").strip().lower())).scalar_one_or_none()
            if user is None:
                return {"success": False, "message": f'User "{username}" was not found.'}
            user.totp_enabled = False
            user.totp_secret = None
            user.backup_codes = None
            db.commit()
            return {"success": True, "message": f"2FA disabled for {user.username}"}
        finally:
            db.close()

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
