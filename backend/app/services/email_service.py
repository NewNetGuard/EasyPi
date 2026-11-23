"""
Email Notification Service.

Provides email notifications for security alerts, system events, and user notifications.
Supports SMTP with TLS/SSL, templated emails, and rate limiting.
"""

import asyncio
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from app.utils.time import utc_now
from enum import Enum
from typing import Optional, List, Dict, Any
from pathlib import Path
import json
import os
import re
import stat
import uuid
from collections import defaultdict
import threading
from html import escape

from app.core.encryption import decrypt_password, encrypt_password, is_encrypted

logger = logging.getLogger(__name__)

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9-]{1,78}$")
_MAX_DIGEST_ALERTS_PER_USER = 500
_MAX_NOTIFICATION_CONFIG_BYTES = 1024 * 1024


def _html(value: Any) -> str:
    return escape(str(value), quote=True)


def _header_value(value: Any, *, max_length: int = 998) -> str:
    normalized = str(value)
    if not normalized or len(normalized) > max_length:
        raise ValueError("Invalid email header value")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError("Invalid email header value")
    return normalized


def _read_bounded_json(path: Path) -> Any:
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_size > _MAX_NOTIFICATION_CONFIG_BYTES
    ):
        raise ValueError("unsafe notification configuration file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino)
            or info.st_size > _MAX_NOTIFICATION_CONFIG_BYTES
        ):
            raise ValueError("unsafe notification configuration file")
        chunks: list[bytes] = []
        remaining = _MAX_NOTIFICATION_CONFIG_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) > _MAX_NOTIFICATION_CONFIG_BYTES:
        raise ValueError("notification configuration file is too large")
    return json.loads(data.decode("utf-8"))


def _write_private_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    if len(encoded) > _MAX_NOTIFICATION_CONFIG_BYTES:
        raise ValueError("notification configuration payload is too large")
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            handle.write(encoded.decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _dashboard_url() -> str:
    """Return the configured dashboard URL escaped for an HTML attribute."""
    from config import get_settings

    return escape(get_settings().DASHBOARD_URL, quote=True)


class EmailPriority(str, Enum):
    """Email priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of alerts that can trigger email notifications."""
    SECURITY_BREACH = "security_breach"
    LOGIN_FAILED = "login_failed"
    LOGIN_SUCCESS = "login_success"
    BRUTE_FORCE = "brute_force"
    SYSTEM_ERROR = "system_error"
    SERVICE_DOWN = "service_down"
    SERVICE_RESTORED = "service_restored"
    BACKUP_COMPLETED = "backup_completed"
    BACKUP_FAILED = "backup_failed"
    DISK_SPACE_LOW = "disk_space_low"
    HIGH_CPU_USAGE = "high_cpu_usage"
    HIGH_MEMORY_USAGE = "high_memory_usage"
    SSL_EXPIRING = "ssl_expiring"
    NEW_DEVICE_LOGIN = "new_device_login"
    PASSWORD_CHANGED = "password_changed"
    TWO_FACTOR_DISABLED = "two_factor_disabled"
    FIREWALL_RULE_CHANGED = "firewall_rule_changed"
    VPN_CONNECTION = "vpn_connection"
    CAMERA_MOTION = "camera_motion"
    CUSTOM = "custom"


@dataclass
class SMTPConfig:
    """SMTP server configuration."""
    host: str = "smtp.gmail.com"
    port: int = 587
    username: str = ""
    password: str = ""
    use_tls: bool = True
    use_ssl: bool = False
    timeout: int = 30
    from_email: str = ""
    from_name: str = "EasyPi Notifications"
    
    @classmethod
    def from_env(cls) -> "SMTPConfig":
        """Load configuration from environment variables."""
        return cls(
            host=os.getenv("SMTP_HOST", "smtp.gmail.com"),
            port=int(os.getenv("SMTP_PORT", "587")),
            username=os.getenv("SMTP_USERNAME", ""),
            password=os.getenv("SMTP_PASSWORD", ""),
            use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
            use_ssl=os.getenv("SMTP_USE_SSL", "false").lower() == "true",
            timeout=int(os.getenv("SMTP_TIMEOUT", "30")),
            from_email=os.getenv("SMTP_FROM_EMAIL", ""),
            from_name=os.getenv("SMTP_FROM_NAME", "EasyPi Notifications"),
        )


@dataclass
class NotificationPreferences:
    """User notification preferences."""
    enabled: bool = True
    email: str = ""
    
    # Which alert types to receive
    alert_types: List[AlertType] = field(default_factory=lambda: list(AlertType))
    
    # Minimum priority to receive
    min_priority: EmailPriority = EmailPriority.NORMAL
    
    # Rate limiting
    max_emails_per_hour: int = 10
    max_emails_per_day: int = 50
    
    # Digest mode (batch notifications)
    digest_mode: bool = False
    digest_interval_hours: int = 24
    
    # Quiet hours (no notifications)
    quiet_hours_enabled: bool = False
    quiet_hours_start: int = 22  # 10 PM
    quiet_hours_end: int = 8     # 8 AM


@dataclass
class EmailMessage:
    """Email message structure."""
    to: List[str]
    subject: str
    body_text: str
    body_html: Optional[str] = None
    priority: EmailPriority = EmailPriority.NORMAL
    alert_type: Optional[AlertType] = None
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    reply_to: Optional[str] = None
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)


class RateLimiter:
    """Rate limiter for email notifications."""
    
    def __init__(self):
        self._hourly_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._daily_counts: Dict[str, List[datetime]] = defaultdict(list)
        self._lock = threading.Lock()
    
    def check_and_increment(
        self, 
        email: str, 
        max_hourly: int, 
        max_daily: int
    ) -> tuple[bool, str]:
        """
        Check if email can be sent and increment counters.
        Returns (allowed, reason).
        """
        now = utc_now()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        with self._lock:
            # Clean old entries
            self._hourly_counts[email] = [
                t for t in self._hourly_counts[email] if t > hour_ago
            ]
            self._daily_counts[email] = [
                t for t in self._daily_counts[email] if t > day_ago
            ]
            
            # Check limits
            hourly_count = len(self._hourly_counts[email])
            daily_count = len(self._daily_counts[email])
            
            if hourly_count >= max_hourly:
                return False, f"Hourly limit reached ({max_hourly}/hour)"
            
            if daily_count >= max_daily:
                return False, f"Daily limit reached ({max_daily}/day)"
            
            # Increment counters
            self._hourly_counts[email].append(now)
            self._daily_counts[email].append(now)
            
            return True, ""
    
    def get_counts(self, email: str) -> Dict[str, int]:
        """Get current counts for an email."""
        now = utc_now()
        hour_ago = now - timedelta(hours=1)
        day_ago = now - timedelta(days=1)
        
        with self._lock:
            hourly = len([t for t in self._hourly_counts[email] if t > hour_ago])
            daily = len([t for t in self._daily_counts[email] if t > day_ago])
            
            return {"hourly": hourly, "daily": daily}


class EmailTemplates:
    """Email templates for various notification types."""
    
    @staticmethod
    def get_base_html_template() -> str:
        """Get base HTML email template."""
        # Note: CSS braces must be doubled to escape them for .format()
        return """
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background-color: #f5f5f5; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: #ffffff; }}
        .header {{ background-color: {header_color}; color: white; padding: 20px; text-align: center; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 30px; }}
        .alert-box {{ background-color: {alert_bg}; border-left: 4px solid {alert_border}; padding: 15px; margin: 20px 0; }}
        .details {{ background-color: #f9f9f9; padding: 15px; border-radius: 4px; margin: 20px 0; }}
        .details table {{ width: 100%; border-collapse: collapse; }}
        .details td {{ padding: 8px 0; border-bottom: 1px solid #eee; }}
        .details td:first-child {{ font-weight: bold; width: 40%; color: #666; }}
        .footer {{ background-color: #f5f5f5; padding: 20px; text-align: center; font-size: 12px; color: #666; }}
        .button {{ display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; margin: 10px 0; }}
        .priority-critical {{ color: #dc3545; font-weight: bold; }}
        .priority-high {{ color: #fd7e14; font-weight: bold; }}
        .priority-normal {{ color: #28a745; }}
        .priority-low {{ color: #6c757d; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥧 EasyPi</h1>
            <p>{header_subtitle}</p>
        </div>
        <div class="content">
            {content}
        </div>
        <div class="footer">
            <p>This is an automated message from EasyPi.</p>
            <p>Sent at {timestamp}</p>
            <p><a href="{dashboard_url}">Open Dashboard</a></p>
        </div>
    </div>
</body>
</html>
"""
    
    @staticmethod
    def security_alert(
        alert_type: str,
        title: str,
        description: str,
        details: Dict[str, Any],
        priority: EmailPriority,
        timestamp: datetime
    ) -> tuple[str, str]:
        """Generate security alert email."""
        # Priority colors
        priority_colors = {
            EmailPriority.CRITICAL: ("#dc3545", "#fff5f5", "#dc3545"),
            EmailPriority.HIGH: ("#fd7e14", "#fff8f0", "#fd7e14"),
            EmailPriority.NORMAL: ("#28a745", "#f0fff4", "#28a745"),
            EmailPriority.LOW: ("#6c757d", "#f8f9fa", "#6c757d"),
        }
        
        header_color, alert_bg, alert_border = priority_colors.get(
            priority, priority_colors[EmailPriority.NORMAL]
        )
        
        # Build details table
        details_html = ""
        if details:
            rows = "".join(
                f"<tr><td>{_html(k)}</td><td>{_html(v)}</td></tr>"
                for k, v in details.items()
            )
            details_html = f"""
            <div class="details">
                <table>{rows}</table>
            </div>
            """
        
        # Plain text version
        text_content = f"""
{title}

{description}

Details:
{chr(10).join(f'  {k}: {v}' for k, v in details.items())}

Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
Priority: {priority.value.upper()}

---
This is an automated message from EasyPi.
"""
        
        # HTML content
        html_content = f"""
            <h2>{_html(title)}</h2>
            <div class="alert-box">
                <p><strong>Priority:</strong> <span class="priority-{priority.value}">{priority.value.upper()}</span></p>
                <p>{_html(description)}</p>
            </div>
            {details_html}
            <p><a href="{{dashboard_url}}" class="button">View Dashboard</a></p>
        """
        
        html_template = EmailTemplates.get_base_html_template()
        html_body = html_template.format(
            header_color=header_color,
            header_subtitle=f"Security Alert: {_html(alert_type)}",
            alert_bg=alert_bg,
            alert_border=alert_border,
            content=html_content,
            timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            dashboard_url=_dashboard_url()
        )
        
        return text_content, html_body
    
    @staticmethod
    def system_notification(
        title: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        timestamp: Optional[datetime] = None
    ) -> tuple[str, str]:
        """Generate system notification email."""
        timestamp = timestamp or utc_now()
        
        details_text = ""
        details_html = ""
        if details:
            details_text = "\n".join(f"  {k}: {v}" for k, v in details.items())
            rows = "".join(
                f"<tr><td>{_html(k)}</td><td>{_html(v)}</td></tr>"
                for k, v in details.items()
            )
            details_html = f'<div class="details"><table>{rows}</table></div>'
        
        text_content = f"""
{title}

{message}

{f"Details:{chr(10)}{details_text}" if details_text else ""}

Timestamp: {timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

---
This is an automated message from EasyPi.
"""
        
        html_content = f"""
            <h2>{_html(title)}</h2>
            <p>{_html(message)}</p>
            {details_html}
        """
        
        html_template = EmailTemplates.get_base_html_template()
        html_body = html_template.format(
            header_color="#007bff",
            header_subtitle="System Notification",
            alert_bg="#e7f3ff",
            alert_border="#007bff",
            content=html_content,
            timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            dashboard_url=_dashboard_url()
        )
        
        return text_content, html_body
    
    @staticmethod
    def digest_email(
        alerts: List[Dict[str, Any]],
        period: str,
        timestamp: datetime
    ) -> tuple[str, str]:
        """Generate digest email with multiple alerts."""
        alert_count = len(alerts)
        
        # Group by priority
        by_priority: Dict[str, List] = defaultdict(list)
        for alert in alerts:
            by_priority[alert.get("priority", "normal")].append(alert)
        
        # Plain text
        text_lines = [f"EasyPi Alert Digest - {period}", "", f"Total alerts: {alert_count}", ""]
        
        for priority in ["critical", "high", "normal", "low"]:
            if by_priority[priority]:
                text_lines.append(f"\n{priority.upper()} Priority ({len(by_priority[priority])}):")
                for alert in by_priority[priority]:
                    text_lines.append(f"  - {alert.get('title', 'Unknown')}: {alert.get('message', '')}")
        
        text_content = "\n".join(text_lines)
        
        # HTML
        alerts_html = ""
        for priority in ["critical", "high", "normal", "low"]:
            if by_priority[priority]:
                alerts_html += f'<h3 class="priority-{priority}">{priority.upper()} ({len(by_priority[priority])})</h3><ul>'
                for alert in by_priority[priority]:
                    alerts_html += (
                        f"<li><strong>{_html(alert.get('title', 'Unknown'))}</strong>: "
                        f"{_html(alert.get('message', ''))}</li>"
                    )
                alerts_html += "</ul>"
        
        html_content = f"""
            <h2>Alert Digest - {period}</h2>
            <p>You have <strong>{alert_count}</strong> alerts in the past {period}.</p>
            {alerts_html}
            <p><a href="{{dashboard_url}}" class="button">View All Alerts</a></p>
        """
        
        html_template = EmailTemplates.get_base_html_template()
        html_body = html_template.format(
            header_color="#6c757d",
            header_subtitle=f"Alert Digest - {period}",
            alert_bg="#f8f9fa",
            alert_border="#6c757d",
            content=html_content,
            timestamp=timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
            dashboard_url=_dashboard_url()
        )
        
        return text_content, html_body


class EmailNotificationService:
    """
    Email notification service with SMTP support.
    
    Features:
    - Async email sending
    - Rate limiting per user
    - Priority-based filtering
    - Quiet hours support
    - Digest mode for batching
    - HTML and plain text emails
    - Attachments support
    """
    
    def __init__(self, config: Optional[SMTPConfig] = None):
        self.config = config if config is not None else self._load_smtp_config()
        self.rate_limiter = RateLimiter()
        self._digest_queue: Dict[str, List[Dict]] = defaultdict(list)
        self._preferences: Dict[str, NotificationPreferences] = self._load_preferences()
        self._enabled = bool(self.config.username and self.config.password)
        
        if not self._enabled:
            logger.warning("Email notifications disabled: SMTP credentials not configured")
    
    @property
    def is_enabled(self) -> bool:
        """Check if email service is enabled."""
        return self._enabled
    
    # ------------------------------------------------------------------ persistence
    def _smtp_file(self) -> Path:
        from app.core.paths import get_data_dir

        return get_data_dir() / "smtp_config.json"

    @staticmethod
    def _smtp_to_dict(config: SMTPConfig) -> Dict[str, Any]:
        return {
            "version": 1,
            "host": config.host,
            "port": config.port,
            "username": config.username,
            "password": encrypt_password(config.password),
            "use_tls": config.use_tls,
            "use_ssl": config.use_ssl,
            "timeout": config.timeout,
            "from_email": config.from_email,
            "from_name": config.from_name,
        }

    def _load_smtp_config(self) -> SMTPConfig:
        """Load the encrypted UI configuration, falling back to environment."""
        path = self._smtp_file()
        if not path.exists():
            return SMTPConfig.from_env()
        try:
            raw = _read_bounded_json(path)
            if not isinstance(raw, dict) or raw.get("version") != 1:
                raise ValueError("unsupported SMTP configuration format")
            os.chmod(path, 0o600)
            stored_password = str(raw.get("password", ""))
            password = decrypt_password(stored_password)
            if stored_password and is_encrypted(stored_password) and not password:
                raise ValueError("SMTP password could not be decrypted")
            return SMTPConfig(
                host=str(raw["host"]),
                port=int(raw["port"]),
                username=str(raw["username"]),
                password=password,
                use_tls=bool(raw.get("use_tls", True)),
                use_ssl=bool(raw.get("use_ssl", False)),
                timeout=int(raw.get("timeout", 30)),
                from_email=str(raw.get("from_email", "")),
                from_name=str(raw.get("from_name", "EasyPi Notifications")),
            )
        except Exception as exc:
            logger.error("Could not load persisted SMTP configuration: %s", exc)
            return SMTPConfig.from_env()

    def save_smtp_config(self, config: SMTPConfig) -> None:
        """Persist SMTP settings atomically with the password encrypted."""
        path = self._smtp_file()
        try:
            _write_private_json(path, self._smtp_to_dict(config))
        except Exception as exc:
            raise RuntimeError("Could not persist SMTP configuration") from exc

    def apply_smtp_config(self, config: SMTPConfig) -> None:
        """Persist a tested configuration, then make it active."""
        self.save_smtp_config(config)
        self.config = config
        self._enabled = bool(config.username and config.password)

    def _prefs_file(self) -> Path:
        from app.core.paths import get_data_dir
        return get_data_dir() / "notification_prefs.json"

    @staticmethod
    def _prefs_to_dict(p: "NotificationPreferences") -> Dict[str, Any]:
        return {
            "enabled": p.enabled,
            "email": p.email,
            "alert_types": [t.value for t in p.alert_types],
            "min_priority": p.min_priority.value,
            "max_emails_per_hour": p.max_emails_per_hour,
            "max_emails_per_day": p.max_emails_per_day,
            "digest_mode": p.digest_mode,
            "digest_interval_hours": p.digest_interval_hours,
            "quiet_hours_enabled": p.quiet_hours_enabled,
            "quiet_hours_start": p.quiet_hours_start,
            "quiet_hours_end": p.quiet_hours_end,
        }

    @staticmethod
    def _prefs_from_dict(d: Dict[str, Any]) -> "NotificationPreferences":
        alert_types = []
        for v in (d.get("alert_types") or []):
            try:
                alert_types.append(AlertType(v))
            except ValueError:
                continue
        if not alert_types:
            alert_types = list(AlertType)
        try:
            min_priority = EmailPriority(d.get("min_priority", "normal"))
        except ValueError:
            min_priority = EmailPriority.NORMAL
        email = str(d.get("email", "") or "")
        if len(email) > 320 or any(character in email for character in "\r\n\x00"):
            email = ""
        return NotificationPreferences(
            enabled=bool(d.get("enabled", True)),
            email=email,
            alert_types=alert_types,
            min_priority=min_priority,
            max_emails_per_hour=max(1, min(100, int(d.get("max_emails_per_hour", 10)))),
            max_emails_per_day=max(1, min(500, int(d.get("max_emails_per_day", 50)))),
            digest_mode=bool(d.get("digest_mode", False)),
            digest_interval_hours=max(1, min(168, int(d.get("digest_interval_hours", 24)))),
            quiet_hours_enabled=bool(d.get("quiet_hours_enabled", False)),
            quiet_hours_start=max(0, min(23, int(d.get("quiet_hours_start", 22)))),
            quiet_hours_end=max(0, min(23, int(d.get("quiet_hours_end", 8)))),
        )

    def _load_preferences(self) -> Dict[str, "NotificationPreferences"]:
        """Load persisted notification preferences from disk."""
        try:
            path = self._prefs_file()
            if not path.exists():
                return {}
            raw = _read_bounded_json(path)
            if not isinstance(raw, dict):
                raise ValueError("invalid notification preferences payload")
            os.chmod(path, 0o600)
            out: Dict[str, NotificationPreferences] = {}
            for uid, d in (raw or {}).items():
                if isinstance(d, dict):
                    out[str(uid)] = self._prefs_from_dict(d)
            return out
        except Exception as e:
            logger.warning(f"Could not load notification preferences: {e}")
            return {}

    def _save_preferences(self) -> None:
        """Persist notification preferences to disk (atomic)."""
        path = self._prefs_file()
        try:
            data = {uid: self._prefs_to_dict(p) for uid, p in self._preferences.items()}
            _write_private_json(path, data)
        except Exception as exc:
            raise RuntimeError("Could not persist notification preferences") from exc

    def set_preferences(self, user_id: str, preferences: NotificationPreferences) -> None:
        """Set notification preferences for a user (persisted to disk)."""
        previous = self._preferences.get(user_id)
        self._preferences[user_id] = preferences
        try:
            self._save_preferences()
        except Exception:
            if previous is None:
                self._preferences.pop(user_id, None)
            else:
                self._preferences[user_id] = previous
            raise
    
    def get_preferences(self, user_id: str) -> NotificationPreferences:
        """Get notification preferences for a user."""
        return self._preferences.get(user_id, NotificationPreferences())
    
    def _is_quiet_hours(self, prefs: NotificationPreferences) -> bool:
        """Check if current time is within quiet hours."""
        if not prefs.quiet_hours_enabled:
            return False
        
        current_hour = datetime.now().hour
        start = prefs.quiet_hours_start
        end = prefs.quiet_hours_end
        
        if start < end:
            return start <= current_hour < end
        else:  # Spans midnight
            return current_hour >= start or current_hour < end
    
    def _should_send(
        self, 
        prefs: NotificationPreferences,
        alert_type: AlertType,
        priority: EmailPriority
    ) -> tuple[bool, str]:
        """Check if notification should be sent based on preferences."""
        if not prefs.enabled:
            return False, "Notifications disabled"
        
        if not prefs.email:
            return False, "No email configured"
        
        if alert_type not in prefs.alert_types:
            return False, f"Alert type {alert_type.value} not subscribed"
        
        # Priority check
        priority_order = [EmailPriority.LOW, EmailPriority.NORMAL, EmailPriority.HIGH, EmailPriority.CRITICAL]
        if priority_order.index(priority) < priority_order.index(prefs.min_priority):
            return False, f"Priority {priority.value} below minimum {prefs.min_priority.value}"
        
        # Quiet hours (except critical)
        if priority != EmailPriority.CRITICAL and self._is_quiet_hours(prefs):
            return False, "Quiet hours active"
        
        # Rate limiting
        allowed, reason = self.rate_limiter.check_and_increment(
            prefs.email,
            prefs.max_emails_per_hour,
            prefs.max_emails_per_day
        )
        if not allowed:
            return False, reason
        
        return True, ""
    
    def _create_mime_message(self, message: EmailMessage) -> MIMEMultipart:
        """Create MIME message from EmailMessage."""
        msg = MIMEMultipart("alternative")
        from_address = _header_value(self.config.from_email or self.config.username, max_length=320)
        from_name = _header_value(self.config.from_name, max_length=100)
        recipients = [_header_value(address, max_length=320) for address in message.to]
        msg["Subject"] = _header_value(message.subject)
        msg["From"] = f"{from_name} <{from_address}>"
        msg["To"] = ", ".join(recipients)
        
        if message.cc:
            msg["Cc"] = ", ".join(
                _header_value(address, max_length=320) for address in message.cc
            )
        
        if message.reply_to:
            msg["Reply-To"] = _header_value(message.reply_to, max_length=320)
        
        # Priority headers
        if message.priority == EmailPriority.CRITICAL:
            msg["X-Priority"] = "1"
            msg["Importance"] = "high"
        elif message.priority == EmailPriority.HIGH:
            msg["X-Priority"] = "2"
            msg["Importance"] = "high"
        elif message.priority == EmailPriority.LOW:
            msg["X-Priority"] = "5"
            msg["Importance"] = "low"
        
        # Custom headers
        for key, value in message.headers.items():
            if not _HEADER_NAME_RE.fullmatch(str(key)):
                raise ValueError("Invalid email header name")
            msg[str(key)] = _header_value(value)
        
        # Add text body
        msg.attach(MIMEText(message.body_text, "plain", "utf-8"))
        
        # Add HTML body if available
        if message.body_html:
            msg.attach(MIMEText(message.body_html, "html", "utf-8"))
        
        # Add attachments
        for attachment in message.attachments:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(attachment["content"])
            encoders.encode_base64(part)
            filename = Path(str(attachment["filename"])).name
            filename = _header_value(filename, max_length=255)
            part.add_header(
                "Content-Disposition",
                "attachment",
                filename=filename,
            )
            msg.attach(part)
        
        return msg
    
    def _send_sync(self, message: EmailMessage) -> bool:
        """Send email synchronously."""
        if not self._enabled:
            logger.debug("Email not sent: service disabled")
            return False
        
        try:
            msg = self._create_mime_message(message)
            
            all_recipients = message.to + message.cc + message.bcc
            
            if self.config.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config.host, 
                    self.config.port, 
                    context=context,
                    timeout=self.config.timeout
                ) as server:
                    server.login(self.config.username, self.config.password)
                    server.send_message(msg, to_addrs=all_recipients)
            else:
                with smtplib.SMTP(
                    self.config.host, 
                    self.config.port,
                    timeout=self.config.timeout
                ) as server:
                    if self.config.use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                    server.login(self.config.username, self.config.password)
                    server.send_message(msg, to_addrs=all_recipients)
            
            logger.info("Email sent successfully to %s recipient(s)", len(message.to))
            return True
            
        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP authentication failed")
            return False
        except smtplib.SMTPException as exc:
            logger.error("SMTP error: %s", type(exc).__name__)
            return False
        except Exception as exc:
            logger.error("Failed to send email: %s", type(exc).__name__)
            return False
    
    async def send_async(self, message: EmailMessage) -> bool:
        """Send email asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._send_sync, message)
    
    def send(self, message: EmailMessage) -> bool:
        """Send email (sync wrapper)."""
        return self._send_sync(message)
    
    async def send_alert(
        self,
        user_id: str,
        alert_type: AlertType,
        title: str,
        description: str,
        details: Optional[Dict[str, Any]] = None,
        priority: EmailPriority = EmailPriority.NORMAL,
    ) -> bool:
        """
        Send an alert notification to a user.
        
        Respects user preferences, rate limits, and quiet hours.
        """
        prefs = self.get_preferences(user_id)
        
        # Check if should send
        should_send, reason = self._should_send(prefs, alert_type, priority)
        if not should_send:
            logger.debug(f"Alert not sent to {user_id}: {reason}")
            
            # Add to digest queue if in digest mode
            if prefs.digest_mode and "limit" not in reason.lower():
                queue = self._digest_queue[user_id]
                queue.append({
                    "type": alert_type.value,
                    "title": title,
                    "message": description,
                    "priority": priority.value,
                    "timestamp": utc_now().isoformat(),
                    "details": details or {}
                })
                if len(queue) > _MAX_DIGEST_ALERTS_PER_USER:
                    del queue[:-_MAX_DIGEST_ALERTS_PER_USER]
            
            return False
        
        # Generate email content
        text_body, html_body = EmailTemplates.security_alert(
            alert_type=alert_type.value,
            title=title,
            description=description,
            details=details or {},
            priority=priority,
            timestamp=utc_now()
        )
        
        # Create message
        message = EmailMessage(
            to=[prefs.email],
            subject=f"[EasyPi {priority.value.upper()}] {title}",
            body_text=text_body,
            body_html=html_body,
            priority=priority,
            alert_type=alert_type
        )
        
        return await self.send_async(message)
    
    async def send_system_notification(
        self,
        to_emails: List[str],
        title: str,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> bool:
        """Send a system notification (no user preferences check)."""
        text_body, html_body = EmailTemplates.system_notification(
            title=title,
            message=message,
            details=details
        )
        
        email = EmailMessage(
            to=to_emails,
            subject=f"[EasyPi] {title}",
            body_text=text_body,
            body_html=html_body,
            priority=EmailPriority.NORMAL
        )
        
        return await self.send_async(email)
    
    async def send_digest(self, user_id: str) -> bool:
        """Send queued alerts as a digest email."""
        prefs = self.get_preferences(user_id)
        alerts = self._digest_queue.get(user_id, [])
        
        if not alerts:
            return True  # Nothing to send
        
        if not prefs.email:
            return False
        
        text_body, html_body = EmailTemplates.digest_email(
            alerts=alerts,
            period=f"{prefs.digest_interval_hours} hours",
            timestamp=utc_now()
        )
        
        message = EmailMessage(
            to=[prefs.email],
            subject=f"[EasyPi] Alert Digest - {len(alerts)} alerts",
            body_text=text_body,
            body_html=html_body,
            priority=EmailPriority.NORMAL
        )
        
        success = await self.send_async(message)
        
        if success:
            self._digest_queue[user_id] = []
        
        return success
    
    def test_connection(self) -> tuple[bool, str]:
        """Test SMTP connection."""
        if not self._enabled:
            return False, "SMTP credentials not configured"
        
        try:
            if self.config.use_ssl:
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(
                    self.config.host,
                    self.config.port,
                    context=context,
                    timeout=self.config.timeout
                ) as server:
                    server.login(self.config.username, self.config.password)
            else:
                with smtplib.SMTP(
                    self.config.host,
                    self.config.port,
                    timeout=self.config.timeout
                ) as server:
                    if self.config.use_tls:
                        context = ssl.create_default_context()
                        server.starttls(context=context)
                    server.login(self.config.username, self.config.password)
            
            return True, "Connection successful"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Authentication failed"
        except smtplib.SMTPConnectError:
            return False, "Could not connect to SMTP server"
        except Exception:
            return False, "SMTP connection failed"


# Global service instance
email_service = EmailNotificationService()


# Convenience functions
async def send_security_alert(
    user_id: str,
    alert_type: AlertType,
    title: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    priority: EmailPriority = EmailPriority.HIGH
) -> bool:
    """Send a security alert email."""
    return await email_service.send_alert(
        user_id=user_id,
        alert_type=alert_type,
        title=title,
        description=description,
        details=details,
        priority=priority
    )


async def broadcast_security_alert(
    alert_type: AlertType,
    title: str,
    description: str,
    details: Optional[Dict[str, Any]] = None,
    priority: EmailPriority = EmailPriority.HIGH,
) -> int:
    """
    Dispatch a security alert to every user who has configured notification
    preferences. Each user's own preferences (enabled / subscribed alert types /
    quiet hours / rate limits) are respected by send_alert. Returns the number
    of recipients an email was actually sent to. Safe no-op when SMTP is not
    configured or nobody has set preferences.
    """
    sent = 0
    for user_id in list(email_service._preferences.keys()):
        try:
            if await email_service.send_alert(
                user_id=user_id,
                alert_type=alert_type,
                title=title,
                description=description,
                details=details,
                priority=priority,
            ):
                sent += 1
        except Exception:
            continue
    return sent


async def send_login_alert(
    user_id: str,
    email: str,
    ip_address: str,
    user_agent: str,
    success: bool,
    new_device: bool = False
) -> bool:
    """Send login notification."""
    # Set temporary preferences if not set
    prefs = email_service.get_preferences(user_id)
    if not prefs.email:
        prefs.email = email
        email_service.set_preferences(user_id, prefs)
    
    if success:
        if new_device:
            return await email_service.send_alert(
                user_id=user_id,
                alert_type=AlertType.NEW_DEVICE_LOGIN,
                title="New Device Login Detected",
                description="A login from a new device was detected on your account.",
                details={
                    "IP Address": ip_address,
                    "Device": user_agent,
                    "Time": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
                },
                priority=EmailPriority.HIGH
            )
        else:
            return await email_service.send_alert(
                user_id=user_id,
                alert_type=AlertType.LOGIN_SUCCESS,
                title="Successful Login",
                description="Your account was accessed.",
                details={
                    "IP Address": ip_address,
                    "Time": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
                },
                priority=EmailPriority.LOW
            )
    else:
        return await email_service.send_alert(
            user_id=user_id,
            alert_type=AlertType.LOGIN_FAILED,
            title="Failed Login Attempt",
            description="Someone tried to log into your account with an incorrect password.",
            details={
                "IP Address": ip_address,
                "Device": user_agent,
                "Time": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
            },
            priority=EmailPriority.NORMAL
        )
