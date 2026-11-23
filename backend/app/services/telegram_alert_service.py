"""
Telegram alert channel.

A lightweight, standalone way to push watchdog/security alerts to a phone via a
Telegram bot — no app to install beyond Telegram itself. Config (bot token +
chat id + enabled) is persisted in the NetProtection data dir. Used by the
proactive watchdog to fan alerts out alongside web push.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)

CONFIG_FILE = "telegram_alerts.json"


class TelegramAlertService:
    def __init__(self) -> None:
        self._path: Optional[Path] = None
        self._token: Optional[str] = None
        self._chat_id: Optional[str] = None
        self._enabled: bool = False

    def load(self, data_dir: str) -> None:
        self._path = Path(data_dir) / CONFIG_FILE
        try:
            if self._path.exists():
                d = json.loads(self._path.read_text())
                self._token = d.get("bot_token") or None
                self._chat_id = str(d.get("chat_id")) if d.get("chat_id") else None
                self._enabled = bool(d.get("enabled"))
        except Exception as e:
            logger.debug(f"telegram config load failed: {e}")

    def _ensure_path(self) -> None:
        # Self-heal if startup init never ran: resolve the data dir lazily so a
        # config write never silently no-ops (which would lose the token).
        if self._path is not None:
            return
        try:
            from app.core.paths import get_netprotection_data_dir
            self.load(str(get_netprotection_data_dir()))
        except Exception as e:
            logger.debug(f"telegram lazy path resolve failed: {e}")

    def _save(self) -> None:
        try:
            if self._path:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                self._path.write_text(json.dumps({
                    "bot_token": self._token, "chat_id": self._chat_id, "enabled": self._enabled,
                }))
                try:
                    self._path.chmod(0o600)  # bot token is a secret
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"telegram config save failed: {e}")

    def set_config(self, *, bot_token: Optional[str] = None, chat_id: Optional[str] = None,
                   enabled: Optional[bool] = None) -> None:
        # A blank token on update means "keep the existing one" (so toggling enabled
        # doesn't require re-entering the secret).
        self._ensure_path()
        if bot_token:
            self._token = bot_token.strip()
        if chat_id is not None:
            self._chat_id = str(chat_id).strip() or None
        if enabled is not None:
            self._enabled = bool(enabled)
        self._save()

    @property
    def is_configured(self) -> bool:
        return bool(self._enabled and self._token and self._chat_id)

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self._enabled,
            "configured": bool(self._token and self._chat_id),
            "has_token": bool(self._token),
            "chat_id": self._chat_id,
        }

    async def send(self, text: str) -> Dict[str, Any]:
        if not (self._token and self._chat_id):
            return {"ok": False, "error": "not configured"}
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.post(url, json={
                    "chat_id": self._chat_id, "text": text,
                    "parse_mode": "HTML", "disable_web_page_preview": True,
                })
            ok = r.status_code == 200
            return {"ok": ok, "status": r.status_code, "detail": ("" if ok else r.text[:200])}
        except Exception as e:
            return {"ok": False, "error": str(e)[:200]}


_service: Optional[TelegramAlertService] = None


def get_telegram_alerts() -> TelegramAlertService:
    global _service
    if _service is None:
        _service = TelegramAlertService()
    return _service
