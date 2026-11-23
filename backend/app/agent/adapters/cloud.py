"""PiCloud fact adapter."""

from __future__ import annotations

from typing import Any


class CloudAdapter:
    """Expose cloud storage state from the canonical PiCloud service."""

    def __init__(self, service: Any | None = None) -> None:
        if service is None:
            from app.services.picloud_service import pi_cloud_service

            service = pi_cloud_service
        self.service = service

    def _call(self, method: str, *args: Any) -> Any:
        try:
            return getattr(self.service, method)(*args)
        except Exception:
            return None

    def get_storage_stats(self) -> dict[str, Any]:
        return self._normalize_object(self._call("storage_stats"))

    def get_recent_files(self, limit: int = 10) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("recent_files", limit))

    def list_shares(self) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("list_shares"))

    def list_trash(self) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("list_trash"))

    def find_duplicates(self) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("find_duplicates"))

    def get_activity(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("get_activity", limit))

    def get_telegram_status(self) -> dict[str, Any]:
        return self._normalize_object(self._call("get_telegram_status"))

    def get_telegram_uploads(self, limit: int = 20) -> list[dict[str, Any]]:
        return self._normalize_list(self._call("get_telegram_uploads", limit))

    def start_telegram_bot(self) -> dict[str, Any]:
        try:
            result = self.service.start_telegram_bot()
            if isinstance(result, dict):
                return dict(result)
            if result is None:
                # The production service has a synchronous void command. When
                # it exposes status, verify the postcondition; small compatible
                # service implementations without a status method still use
                # normal return as their documented completion contract.
                get_status = getattr(self.service, "get_telegram_status", None)
                if callable(get_status):
                    status = self._normalize_object(get_status())
                    enabled = bool(status.get("enabled"))
                    return {
                        "success": enabled,
                        "message": (
                            "The Telegram bot was started."
                            if enabled
                            else str(status.get("message") or "Telegram bot start postcondition was not confirmed.")
                        ),
                        "status": status,
                    }
                return {"success": True, "message": "The Telegram bot start command completed."}
            return {"success": False, "message": "The Telegram service did not confirm that the bot started."}
        except Exception as exc:
            return {"success": False, "message": f"Telegram bot could not be started: {exc}"}

    def stop_telegram_bot(self) -> dict[str, Any]:
        try:
            result = self.service.stop_telegram_bot()
            if isinstance(result, dict):
                return dict(result)
            # PiCloud defines stop_telegram_bot as a synchronous void command:
            # returning normally means the stop event was handled and state was
            # persisted.  The generic action registry remains fail-closed for
            # unknown None-returning handlers.
            if result is None:
                get_status = getattr(self.service, "get_telegram_status", None)
                if callable(get_status):
                    status = self._normalize_object(get_status())
                    if not status:
                        return {
                            "success": False,
                            "message": "The Telegram bot stop postcondition could not be read.",
                        }
                    stopped = not bool(status.get("enabled")) and not bool(
                        status.get("is_running", status.get("isRunning", False))
                    )
                    return {
                        "success": stopped,
                        "message": (
                            "The Telegram bot was stopped."
                            if stopped
                            else str(
                                status.get("message")
                                or "Telegram bot stop postcondition was not confirmed."
                            )
                        ),
                        "status": status,
                    }
                return {"success": True, "message": "The Telegram bot was stopped."}
            return {"success": False, "message": "The Telegram service returned an unsupported stop result."}
        except Exception as exc:
            return {"success": False, "message": f"Telegram bot could not be stopped: {exc}"}

    def _normalize_list(self, value: Any) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for item in value or []:
            payload = self._normalize_object(item)
            if payload:
                normalized.append(payload)
        return normalized

    def _normalize_object(self, value: Any) -> dict[str, Any]:
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json", by_alias=False)
        if isinstance(value, dict):
            return dict(value)
        return {}
