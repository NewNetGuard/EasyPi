"""
Push Notification Service for Web Push API
Enables browser push notifications for system alerts, updates, and events
"""

import json
import logging
import os
import re
import stat
import threading
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from typing import Optional, Dict, Any, Iterator, List
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlsplit
from app.utils.time import utc_now
import asyncio

logger = logging.getLogger(__name__)

# Try to import pywebpush, but make it optional
try:
    import requests
    from pywebpush import webpush
    WEBPUSH_AVAILABLE = True
except ImportError:
    WEBPUSH_AVAILABLE = False
    logger.warning("pywebpush not installed. Push notifications will be simulated.")


_DEFAULT_ALLOWED_PUSH_HOSTS = {
    "fcm.googleapis.com",
    "push.services.mozilla.com",
    "updates.push.services.mozilla.com",
    "web.push.apple.com",
    ".notify.windows.com",
}
_PUSH_REQUEST_TIMEOUT_SECONDS = 10
_MAX_SUBSCRIPTIONS_FILE_BYTES = 2 * 1024 * 1024
_MAX_SUBSCRIPTIONS = 1000
_MAX_SUBSCRIPTIONS_PER_USER = 10
_PUSH_KEY_RE = re.compile(r"^[A-Za-z0-9_+/-]+={0,2}$")


class PushSubscriptionConflictError(ValueError):
    """An existing push endpoint belongs to a different user."""


class PushSubscriptionLimitError(ValueError):
    """A user or the installation reached its bounded subscription limit."""


def _subscription_locked(method):
    """Run one synchronous subscription-state operation atomically."""
    @wraps(method)
    def locked(service, *args, **kwargs):
        with service._subscription_lock:
            return method(service, *args, **kwargs)

    return locked


def _write_new_private_file(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            fd = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o600)
    finally:
        if fd >= 0:
            os.close(fd)


def _read_bounded_regular_file(path: Path, max_bytes: int) -> bytes:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_size > max_bytes
    ):
        raise ValueError("unsafe push state file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
            or info.st_size > max_bytes
        ):
            raise ValueError("unsafe push state file")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        raise ValueError("push state file is too large")
    return data


def _replace_private_file(path: Path, content: bytes) -> None:
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    _write_new_private_file(temporary, content)
    try:
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def validate_push_keys(keys: Dict[str, str]) -> Dict[str, str]:
    """Validate the two bounded URL-safe key values required by Web Push."""
    if not isinstance(keys, dict) or set(keys) != {"p256dh", "auth"}:
        raise ValueError("Push keys must contain p256dh and auth")
    normalized: Dict[str, str] = {}
    for name in ("p256dh", "auth"):
        value = keys.get(name)
        if (
            not isinstance(value, str)
            or not 16 <= len(value) <= 256
            or not _PUSH_KEY_RE.fullmatch(value)
        ):
            raise ValueError("Invalid push subscription key")
        normalized[name] = value
    return normalized


def _allowed_push_hosts() -> set[str]:
    """Return built-in providers plus deployment-approved exact host patterns."""
    configured = {
        value.strip().lower().rstrip(".")
        for value in os.getenv("EASYPI_WEBPUSH_ALLOWED_HOSTS", "").split(",")
        if value.strip()
    }
    return _DEFAULT_ALLOWED_PUSH_HOSTS | configured


def validate_push_endpoint(endpoint: str) -> str:
    """Accept only HTTPS endpoints belonging to an approved push provider."""
    value = (endpoint or "").strip()
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid push endpoint") from exc

    if parsed.scheme.lower() != "https" or not host:
        raise ValueError("Push endpoint must use HTTPS")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Invalid push endpoint")
    if port not in (None, 443):
        raise ValueError("Push endpoint must use the standard HTTPS port")

    allowed = any(
        host == pattern or (pattern.startswith(".") and host.endswith(pattern))
        for pattern in _allowed_push_hosts()
    )
    if not allowed:
        raise ValueError("Push endpoint provider is not allowed")
    return value


if WEBPUSH_AVAILABLE:
    class _NoRedirectSession(requests.Session):
        """Requests session that cannot follow a push provider redirect."""

        def request(self, method, url, **kwargs):
            kwargs["allow_redirects"] = False
            return super().request(method, url, **kwargs)


@dataclass
class PushSubscription:
    """Represents a browser push subscription"""
    endpoint: str
    keys: Dict[str, str]
    user_id: Optional[int] = None
    created_at: datetime = field(default_factory=utc_now)
    last_used: Optional[datetime] = None
    user_agent: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint": self.endpoint,
            "keys": self.keys,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_used": self.last_used.isoformat() if self.last_used else None,
            "user_agent": self.user_agent
        }


@dataclass 
class NotificationPayload:
    """Push notification payload"""
    title: str
    body: str
    icon: Optional[str] = "/icons/icon-192x192.png"
    badge: Optional[str] = "/icons/badge-72x72.png"
    tag: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    actions: Optional[List[Dict[str, str]]] = None
    require_interaction: bool = False
    silent: bool = False
    timestamp: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        payload = {
            "title": self.title,
            "body": self.body,
        }
        if self.icon:
            payload["icon"] = self.icon
        if self.badge:
            payload["badge"] = self.badge
        if self.tag:
            payload["tag"] = self.tag
        if self.data:
            payload["data"] = self.data
        if self.actions:
            payload["actions"] = self.actions
        if self.require_interaction:
            payload["requireInteraction"] = True
        if self.silent:
            payload["silent"] = True
        if self.timestamp:
            payload["timestamp"] = self.timestamp
        return payload


class PushNotificationService:
    """
    Service for managing web push notifications.
    
    Uses VAPID (Voluntary Application Server Identification) for authentication.
    Stores subscriptions in memory (can be extended to use database).
    """
    
    def __init__(self):
        self._subscription_lock = threading.RLock()
        self._subscriptions: Dict[str, PushSubscription] = {}
        self._vapid_private_key: Optional[str] = None
        self._vapid_public_key: Optional[str] = None
        self._vapid_claims: Dict[str, str] = {}
        self._notification_history: List[Dict[str, Any]] = []
        self._max_history = 100
        self._subs_path: Optional[Path] = None

    def ensure_configured(self, data_dir: str, email: str = "admin@easypi.local") -> None:
        """Load-or-generate VAPID keys (persisted in data_dir) and configure the
        service; also load persisted subscriptions. Idempotent, so it can be called
        at every startup. Without this, push is disabled (VAPID unconfigured)."""
        self._vapid_private_key = None
        self._vapid_public_key = None
        self._vapid_claims = {}
        self._subs_path = None
        self._subscriptions = {}
        try:
            d = Path(data_dir)
            d.mkdir(parents=True, exist_ok=True)
            pem_path = d / "vapid_private.pem"
            meta_path = d / "vapid.json"
            pem_present = pem_path.exists() or pem_path.is_symlink()
            meta_present = meta_path.exists() or meta_path.is_symlink()
            if pem_present and meta_present:
                pem_info = pem_path.lstat()
                meta_info = meta_path.lstat()
                if (
                    not stat.S_ISREG(pem_info.st_mode)
                    or stat.S_ISLNK(pem_info.st_mode)
                    or pem_info.st_size > 16 * 1024
                    or not stat.S_ISREG(meta_info.st_mode)
                    or stat.S_ISLNK(meta_info.st_mode)
                    or meta_info.st_size > 16 * 1024
                ):
                    raise ValueError("unsafe VAPID key files")
                os.chmod(pem_path, 0o600)
                os.chmod(meta_path, 0o600)
                meta = json.loads(_read_bounded_regular_file(meta_path, 16 * 1024).decode("utf-8"))
                public_key = meta.get("public_key")
                vapid_email = meta.get("email", email)
                if (
                    not isinstance(public_key, str)
                    or not 32 <= len(public_key) <= 256
                    or not _PUSH_KEY_RE.fullmatch(public_key)
                    or not isinstance(vapid_email, str)
                    or not 3 <= len(vapid_email) <= 320
                    or any(character in vapid_email for character in "\r\n\x00")
                ):
                    raise ValueError("invalid VAPID metadata")
                self.configure(str(pem_path), public_key, vapid_email)
            else:
                if pem_present or meta_present:
                    raise ValueError("incomplete VAPID keypair")
                import base64
                from py_vapid import Vapid01
                from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
                v = Vapid01()
                v.generate_keys()
                raw = v.public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
                app_key = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
                _write_new_private_file(pem_path, v.private_pem())
                try:
                    _write_new_private_file(
                        meta_path,
                        json.dumps({"public_key": app_key, "email": email}).encode("utf-8"),
                    )
                except Exception:
                    pem_path.unlink(missing_ok=True)
                    raise
                self.configure(str(pem_path), app_key, email)
                logger.info("Generated new VAPID keypair for web push")
            self._subs_path = d / "push_subscriptions.json"
            self._load_subscriptions()
        except Exception as exc:
            logger.warning("Push VAPID provisioning failed: %s", type(exc).__name__)

    def _load_subscriptions(self) -> None:
        loaded: Dict[str, PushSubscription] = {}
        try:
            if self._subs_path and self._subs_path.exists():
                raw = json.loads(
                    _read_bounded_regular_file(
                        self._subs_path,
                        _MAX_SUBSCRIPTIONS_FILE_BYTES,
                    ).decode("utf-8")
                )
                if not isinstance(raw, list) or len(raw) > _MAX_SUBSCRIPTIONS:
                    raise ValueError("invalid push subscriptions payload")
                os.chmod(self._subs_path, 0o600)
                for s in raw:
                    try:
                        endpoint = validate_push_endpoint(s["endpoint"])
                        keys = validate_push_keys(s["keys"])
                        user_id = s.get("user_id")
                        if user_id is not None and (not isinstance(user_id, int) or user_id < 1):
                            raise ValueError("invalid push subscription owner")
                        user_agent = s.get("user_agent")
                        if user_agent is not None and (
                            not isinstance(user_agent, str) or len(user_agent) > 500
                        ):
                            raise ValueError("invalid push subscription metadata")
                    except (AttributeError, KeyError, TypeError, ValueError):
                        logger.warning("Ignored a stored push subscription with an unsafe endpoint")
                        continue
                    loaded[endpoint] = PushSubscription(
                        endpoint=endpoint,
                        keys=keys,
                        user_id=user_id,
                        user_agent=user_agent,
                    )
                self._subscriptions = loaded
                logger.info("Loaded %s push subscription(s)", len(self._subscriptions))
        except Exception as e:
            self._subscriptions = {}
            logger.warning("Could not load push subscriptions: %s", type(e).__name__)

    def _save_subscriptions(self) -> None:
        try:
            if self._subs_path:
                content = json.dumps([
                    {"endpoint": s.endpoint, "keys": s.keys, "user_id": s.user_id, "user_agent": s.user_agent}
                    for s in self._subscriptions.values()
                ]).encode("utf-8")
                if len(content) > _MAX_SUBSCRIPTIONS_FILE_BYTES:
                    raise ValueError("push subscriptions payload is too large")
                _replace_private_file(self._subs_path, content)
        except Exception as exc:
            logger.warning("Could not save push subscriptions: %s", type(exc).__name__)
            raise RuntimeError("Could not persist push subscriptions") from exc

    def configure(
        self,
        vapid_private_key: str,
        vapid_public_key: str,
        vapid_email: str
    ) -> None:
        """Configure VAPID credentials for push notifications"""
        self._vapid_private_key = vapid_private_key
        self._vapid_public_key = vapid_public_key
        self._vapid_claims = {
            "sub": f"mailto:{vapid_email}"
        }
        logger.info("Push notification service configured")
        
    @property
    def is_configured(self) -> bool:
        """Check if VAPID credentials are configured"""
        return bool(self._vapid_private_key and self._vapid_public_key)
    
    @property
    def public_key(self) -> Optional[str]:
        """Get the VAPID public key for client subscription"""
        return self._vapid_public_key

    @contextmanager
    def user_subscription_guard(self, user_id: int) -> Iterator[None]:
        """Serialize account state changes with push subscription registration."""
        if not isinstance(user_id, int) or user_id < 1:
            raise ValueError("Invalid push subscription owner")
        with self._subscription_lock:
            yield
    
    @_subscription_locked
    def add_subscription(
        self,
        endpoint: str,
        keys: Dict[str, str],
        user_id: Optional[int] = None,
        user_agent: Optional[str] = None
    ) -> PushSubscription:
        """Register a new push subscription"""
        endpoint = validate_push_endpoint(endpoint)
        keys = validate_push_keys(keys)
        existing = self._subscriptions.get(endpoint)
        if existing is not None and existing.user_id != user_id:
            raise PushSubscriptionConflictError("Push subscription is already registered")
        if existing is None:
            if len(self._subscriptions) >= _MAX_SUBSCRIPTIONS:
                raise PushSubscriptionLimitError("Push subscription limit reached")
            if user_id is not None and len(self.get_subscriptions(user_id=user_id)) >= _MAX_SUBSCRIPTIONS_PER_USER:
                raise PushSubscriptionLimitError("Push subscription limit reached for this user")
        subscription = PushSubscription(
            endpoint=endpoint,
            keys=keys,
            user_id=user_id,
            user_agent=user_agent
        )
        self._subscriptions[endpoint] = subscription
        try:
            self._save_subscriptions()
        except Exception:
            if existing is None:
                self._subscriptions.pop(endpoint, None)
            else:
                self._subscriptions[endpoint] = existing
            raise
        logger.info("Added push subscription for user %s", user_id)
        return subscription
    
    @_subscription_locked
    def remove_subscription(
        self, endpoint: str, user_id: Optional[int] = None
    ) -> bool:
        """Remove a subscription, optionally requiring its owning user."""
        subscription = self._subscriptions.get(endpoint)
        if subscription is not None and (
            user_id is None or subscription.user_id == user_id
        ):
            del self._subscriptions[endpoint]
            try:
                self._save_subscriptions()
            except Exception:
                self._subscriptions[endpoint] = subscription
                raise
            logger.info("Removed push subscription")
            return True
        return False

    @_subscription_locked
    def remove_user_subscriptions(self, user_id: int) -> int:
        """Revoke and persist every push subscription owned by one user."""
        removed = {
            endpoint: subscription
            for endpoint, subscription in self._subscriptions.items()
            if subscription.user_id == user_id
        }
        if not removed:
            return 0
        for endpoint in removed:
            del self._subscriptions[endpoint]
        try:
            self._save_subscriptions()
        except Exception:
            self._subscriptions.update(removed)
            raise
        logger.info("Removed %s push subscription(s) for user %s", len(removed), user_id)
        return len(removed)
    
    @_subscription_locked
    def get_subscriptions(
        self,
        user_id: Optional[int] = None
    ) -> List[PushSubscription]:
        """Get all subscriptions, optionally filtered by user"""
        if user_id is not None:
            return [
                sub for sub in self._subscriptions.values()
                if sub.user_id == user_id
            ]
        return list(self._subscriptions.values())
    
    @_subscription_locked
    def get_subscription_count(self) -> int:
        """Get total number of active subscriptions"""
        return len(self._subscriptions)

    @_subscription_locked
    def _is_current_subscription(self, subscription: PushSubscription) -> bool:
        """Return whether this exact subscription is still eligible for delivery."""
        return self._subscriptions.get(subscription.endpoint) is subscription
    
    async def send_notification(
        self,
        payload: NotificationPayload,
        user_id: Optional[int] = None,
        endpoint: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send push notification to subscribed browsers.
        
        Args:
            payload: Notification content
            user_id: Send to specific user's devices (optional)
            endpoint: Send to specific subscription (optional)
            
        Returns:
            Dict with success/failure counts
        """
        if not self.is_configured:
            logger.warning("Push notifications not configured")
            return {"success": 0, "failed": 0, "error": "Not configured"}
        
        # Determine target subscriptions
        subscriptions = self.get_subscriptions()
        if endpoint:
            targets = [item for item in subscriptions if item.endpoint == endpoint]
        elif user_id is not None:
            targets = [item for item in subscriptions if item.user_id == user_id]
        else:
            targets = subscriptions
        
        if not targets:
            return {"success": 0, "failed": 0, "error": "No subscriptions found"}
        
        results = {"success": 0, "failed": 0, "errors": []}
        payload_json = json.dumps(payload.to_dict())
        
        for subscription in targets:
            if not self._is_current_subscription(subscription):
                continue
            try:
                await self._send_to_subscription(subscription, payload_json)
                subscription.last_used = utc_now()
                results["success"] += 1
            except Exception as e:
                logger.error(f"Failed to send push to {subscription.endpoint[:50]}: {e}")
                results["failed"] += 1
                results["errors"].append("Push delivery failed")
                
                # Remove invalid subscriptions
                if "expired" in str(e).lower() or "unsubscribed" in str(e).lower():
                    try:
                        self.remove_subscription(subscription.endpoint)
                    except RuntimeError:
                        logger.warning("Could not persist removal of an expired push subscription")
        
        # Store in history
        self._add_to_history(payload, results)
        
        return results
    
    async def _send_to_subscription(
        self,
        subscription: PushSubscription,
        payload_json: str
    ) -> None:
        """Send notification to a single subscription"""
        validate_push_endpoint(subscription.endpoint)
        if not WEBPUSH_AVAILABLE:
            # Simulate sending in development
            logger.info("[SIMULATED] Push delivery")
            await asyncio.sleep(0.1)
            return
        
        subscription_info = {
            "endpoint": subscription.endpoint,
            "keys": subscription.keys
        }
        
        # Run in thread pool to avoid blocking
        loop = asyncio.get_event_loop()
        def _deliver() -> None:
            with _NoRedirectSession() as session:
                webpush(
                    subscription_info=subscription_info,
                    data=payload_json,
                    vapid_private_key=self._vapid_private_key,
                    vapid_claims=self._vapid_claims,
                    requests_session=session,
                    timeout=_PUSH_REQUEST_TIMEOUT_SECONDS,
                )

        await loop.run_in_executor(None, _deliver)
    
    def _add_to_history(
        self,
        payload: NotificationPayload,
        results: Dict[str, Any]
    ) -> None:
        """Add notification to history"""
        entry = {
            "timestamp": utc_now().isoformat(),
            "title": payload.title,
            "body": payload.body,
            "success": results["success"],
            "failed": results["failed"]
        }
        self._notification_history.append(entry)
        
        # Trim history
        if len(self._notification_history) > self._max_history:
            self._notification_history = self._notification_history[-self._max_history:]
    
    def get_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get notification history"""
        return self._notification_history[-limit:]
    
    # Convenience methods for common notification types
    
    async def notify_system_alert(
        self,
        title: str,
        message: str,
        severity: str = "info",
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Send a system alert notification"""
        icon_map = {
            "info": "/icons/info.png",
            "warning": "/icons/warning.png", 
            "error": "/icons/error.png",
            "success": "/icons/success.png"
        }
        
        payload = NotificationPayload(
            title=title,
            body=message,
            icon=icon_map.get(severity, icon_map["info"]),
            tag=f"system-alert-{severity}",
            data={"type": "system_alert", "severity": severity},
            require_interaction=severity in ["warning", "error"]
        )
        return await self.send_notification(payload, user_id=user_id)
    
    async def notify_service_status(
        self,
        service_name: str,
        status: str,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Notify about service status change"""
        status_messages = {
            "started": f"🟢 {service_name} has started",
            "stopped": f"🔴 {service_name} has stopped",
            "error": f"⚠️ {service_name} encountered an error",
            "restarted": f"🔄 {service_name} has restarted"
        }
        
        payload = NotificationPayload(
            title="Service Status",
            body=status_messages.get(status, f"{service_name}: {status}"),
            tag=f"service-{service_name}",
            data={"type": "service_status", "service": service_name, "status": status}
        )
        return await self.send_notification(payload, user_id=user_id)
    
    async def notify_backup_complete(
        self,
        backup_name: str,
        success: bool,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Notify about backup completion"""
        if success:
            title = "Backup Complete ✅"
            body = f"Backup '{backup_name}' completed successfully"
        else:
            title = "Backup Failed ❌"
            body = f"Backup '{backup_name}' failed"
        
        payload = NotificationPayload(
            title=title,
            body=body,
            tag="backup-status",
            data={"type": "backup", "name": backup_name, "success": success},
            require_interaction=not success
        )
        return await self.send_notification(payload, user_id=user_id)
    
    async def notify_security_event(
        self,
        event_type: str,
        description: str,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Notify about security events"""
        payload = NotificationPayload(
            title="🔒 Security Alert",
            body=description,
            tag=f"security-{event_type}",
            data={"type": "security", "event": event_type},
            require_interaction=True
        )
        return await self.send_notification(payload, user_id=user_id)
    
    async def notify_update_available(
        self,
        version: str,
        user_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Notify about available updates"""
        payload = NotificationPayload(
            title="Update Available 🆕",
            body=f"EasyPi version {version} is available",
            tag="update-available",
            data={"type": "update", "version": version},
            actions=[
                {"action": "update", "title": "Update Now"},
                {"action": "later", "title": "Later"}
            ]
        )
        return await self.send_notification(payload, user_id=user_id)


# Global service instance
push_service = PushNotificationService()


def get_push_service() -> PushNotificationService:
    """Get the push notification service instance"""
    return push_service
