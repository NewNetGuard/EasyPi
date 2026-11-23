"""Terminal fact adapter."""

from __future__ import annotations

from typing import Any, Callable

from sqlalchemy import desc

from app.api.websocket.terminal import HAS_PTY
from app.core.terminal_security import (
    MAX_TERMINAL_SESSIONS_PER_USER,
    MAX_TOTAL_TERMINAL_SESSIONS,
    WS_TOKEN_LIFETIME,
    terminal_security,
)
from app.db.session import SessionLocal
from app.models.terminal import TerminalCommand, TerminalSession


class TerminalAdapter:
    """Expose read-only terminal audit and security state."""

    def __init__(self, *, session_factory: Callable[[], Any] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    async def get_recent_sessions(self, *, limit: int = 10) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            sessions = (
                db.query(TerminalSession)
                .order_by(desc(TerminalSession.started_at))
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": session.id,
                    "user_id": session.user_id,
                    "username": session.username,
                    "started_at": session.started_at.isoformat() if session.started_at else None,
                    "ended_at": session.ended_at.isoformat() if session.ended_at else None,
                    "ip_address": session.ip_address,
                }
                for session in sessions
            ]
        finally:
            db.close()

    async def get_recent_commands(self, *, limit: int = 10) -> list[dict[str, Any]]:
        db = self.session_factory()
        try:
            commands = (
                db.query(TerminalCommand)
                .order_by(desc(TerminalCommand.executed_at))
                .limit(limit)
                .all()
            )
            return [
                {
                    "id": command.id,
                    "session_id": command.session_id,
                    "command": command.command,
                    "executed_at": command.executed_at.isoformat() if command.executed_at else None,
                    "exit_code": command.exit_code,
                    "output_length": command.output_length,
                }
                for command in commands
            ]
        finally:
            db.close()

    def get_security_limits(self) -> dict[str, Any]:
        stats = terminal_security.get_stats()
        return {
            "has_pty": HAS_PTY,
            "max_per_user": MAX_TERMINAL_SESSIONS_PER_USER,
            "max_total": MAX_TOTAL_TERMINAL_SESSIONS,
            "ws_token_lifetime": WS_TOKEN_LIFETIME,
            "active_sessions": stats.get("active_sessions", 0),
            "blocked_ips": len(stats.get("blocked_ips", [])),
            "blocked_ip_list": list(stats.get("blocked_ips", [])),
        }
