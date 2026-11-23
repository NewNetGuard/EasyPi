"""
Email Notifications API endpoints.

Provides endpoints for:
- Configuring SMTP settings
- Managing notification preferences
- Testing email delivery
- Sending test notifications
"""

import asyncio
import logging
import json
import re
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.utils.time import utc_now

from app.api.deps import get_db, get_current_user, require_admin as get_current_admin_user
from app.models.user import User
from app.services.operation_event_service import OperationEventService
from app.services.email_service import (
    email_service,
    EmailNotificationService,
    SMTPConfig,
    NotificationPreferences,
    AlertType,
    EmailPriority,
    EmailMessage,
    EmailTemplates,
    send_security_alert,
)


router = APIRouter(prefix="/notifications", tags=["Notifications"])
operation_event_service = OperationEventService()
logger = logging.getLogger(__name__)


def _record_notification_event(
    *,
    action_id: str,
    title: str,
    subtitle: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle=subtitle,
            route="/notifications",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record notification operation %s: %s", action_id, exc)


# ============== Request/Response Models ==============

# Security patterns
HOSTNAME_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$')
SAFE_TEXT_PATTERN = re.compile(r'^[^<>"\x00-\x1f]*$')  # No HTML tags or control chars
ALERT_TYPE_PATTERN = re.compile(r'^[a-z_]{2,30}$')
PRIORITY_VALUES = ['low', 'normal', 'high', 'critical']


class SMTPConfigRequest(BaseModel):
    """SMTP configuration request."""
    host: str = Field(..., min_length=1, max_length=255, description="SMTP server hostname")
    port: int = Field(587, ge=1, le=65535, description="SMTP server port")
    username: str = Field(..., min_length=1, max_length=255, description="SMTP username/email")
    password: Optional[str] = Field(
        None,
        min_length=1,
        max_length=500,
        description="SMTP password or app password; omit to keep the saved password",
    )
    use_tls: bool = Field(True, description="Use STARTTLS")
    use_ssl: bool = Field(False, description="Use SSL/TLS")
    from_email: Optional[EmailStr] = Field(None, description="From email address (defaults to username)")
    from_name: str = Field("EasyPi Notifications", max_length=100, description="From display name")
    
    @field_validator('host')
    @classmethod
    def validate_host(cls, v: str) -> str:
        v = v.strip().lower()
        if not HOSTNAME_PATTERN.match(v):
            raise ValueError('Invalid hostname format')
        return v
    
    @field_validator('from_name')
    @classmethod
    def validate_from_name(cls, v: str) -> str:
        v = v.strip()
        if not SAFE_TEXT_PATTERN.match(v):
            raise ValueError('From name contains invalid characters')
        return v

    @model_validator(mode="after")
    def validate_transport(self) -> "SMTPConfigRequest":
        if self.use_tls and self.use_ssl:
            raise ValueError("STARTTLS and implicit SSL cannot both be enabled")
        return self


class SMTPConfigResponse(BaseModel):
    """SMTP configuration response (without password)."""
    host: str
    port: int
    username: str
    use_tls: bool
    use_ssl: bool
    from_email: Optional[str]
    from_name: str
    is_configured: bool


class NotificationPreferencesRequest(BaseModel):
    """Notification preferences request."""
    enabled: bool = Field(True, description="Enable email notifications")
    email: Optional[EmailStr] = Field(None, description="Email address for notifications")
    alert_types: List[str] = Field(
        default_factory=lambda: [t.value for t in AlertType],
        description="Alert types to receive"
    )
    min_priority: str = Field("normal", description="Minimum priority level")
    max_emails_per_hour: int = Field(10, ge=1, le=100, description="Max emails per hour")
    max_emails_per_day: int = Field(50, ge=1, le=500, description="Max emails per day")
    digest_mode: bool = Field(False, description="Batch notifications into digest")
    digest_interval_hours: int = Field(24, ge=1, le=168, description="Digest interval in hours")
    quiet_hours_enabled: bool = Field(False, description="Enable quiet hours")
    quiet_hours_start: int = Field(22, ge=0, le=23, description="Quiet hours start (0-23)")
    quiet_hours_end: int = Field(8, ge=0, le=23, description="Quiet hours end (0-23)")

    @field_validator("alert_types")
    @classmethod
    def validate_alert_types(cls, values: List[str]) -> List[str]:
        allowed = {alert_type.value for alert_type in AlertType}
        if not values or any(value not in allowed for value in values):
            raise ValueError("One or more alert types are invalid")
        return list(dict.fromkeys(values))

    @field_validator("min_priority")
    @classmethod
    def validate_min_priority(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in PRIORITY_VALUES:
            raise ValueError("Invalid minimum priority")
        return normalized


class NotificationPreferencesResponse(BaseModel):
    """Notification preferences response."""
    enabled: bool
    email: Optional[str]
    alert_types: List[str]
    min_priority: str
    max_emails_per_hour: int
    max_emails_per_day: int
    digest_mode: bool
    digest_interval_hours: int
    quiet_hours_enabled: bool
    quiet_hours_start: int
    quiet_hours_end: int
    current_usage: Dict[str, int]


class TestEmailRequest(BaseModel):
    """Test email request."""
    to_email: EmailStr = Field(..., description="Recipient email address")
    subject: Optional[str] = Field("EasyPi Test Email", max_length=200, description="Email subject")

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        normalized = value.strip()
        if not normalized or any(character in normalized for character in "\r\n\x00"):
            raise ValueError("Invalid email subject")
        return normalized


class SendAlertRequest(BaseModel):
    """Send alert request."""
    alert_type: str = Field(..., min_length=2, max_length=30, description="Type of alert")
    title: str = Field(..., min_length=1, max_length=200, description="Alert title")
    description: str = Field(..., min_length=1, max_length=2000, description="Alert description")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")
    priority: str = Field("normal", description="Alert priority")
    
    @field_validator('alert_type')
    @classmethod
    def validate_alert_type(cls, v: str) -> str:
        v = v.strip().lower()
        if not ALERT_TYPE_PATTERN.match(v):
            raise ValueError('Alert type must be lowercase letters and underscores only (2-30 chars)')
        return v
    
    @field_validator('title', 'description')
    @classmethod
    def validate_text_fields(cls, v: str) -> str:
        v = v.strip()
        if not SAFE_TEXT_PATTERN.match(v):
            raise ValueError('Text contains invalid characters (HTML tags or control characters not allowed)')
        return v
    
    @field_validator('priority')
    @classmethod
    def validate_priority(cls, v: str) -> str:
        v = v.strip().lower()
        if v not in PRIORITY_VALUES:
            raise ValueError(f'Priority must be one of: {PRIORITY_VALUES}')
        return v

    @field_validator("details")
    @classmethod
    def validate_details(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is not None and len(json.dumps(value, ensure_ascii=False)) > 16_384:
            raise ValueError("Alert details are too large")
        return value


class StatusResponse(BaseModel):
    """Status response."""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None


# ============== Admin Endpoints ==============

@router.get("/smtp/config", response_model=SMTPConfigResponse)
async def get_smtp_config(
    current_user: User = Depends(get_current_admin_user)
) -> SMTPConfigResponse:
    """
    Get current SMTP configuration (admin only).
    
    Password is not returned for security.
    """
    config = email_service.config
    return SMTPConfigResponse(
        host=config.host,
        port=config.port,
        username=config.username,
        use_tls=config.use_tls,
        use_ssl=config.use_ssl,
        from_email=config.from_email,
        from_name=config.from_name,
        is_configured=email_service.is_enabled
    )


@router.put("/smtp/config", response_model=StatusResponse)
async def update_smtp_config(
    request: SMTPConfigRequest,
    current_user: User = Depends(get_current_admin_user)
) -> StatusResponse:
    """
    Update SMTP configuration (admin only).
    
    Changes take effect immediately.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        password = request.password or email_service.config.password
        if not password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="SMTP password is required for initial configuration",
            )
        new_config = SMTPConfig(
            host=request.host,
            port=request.port,
            username=request.username,
            password=password,
            use_tls=request.use_tls,
            use_ssl=request.use_ssl,
            from_email=request.from_email or request.username,
            from_name=request.from_name
        )
        
        # Test connection before saving
        temp_service = EmailNotificationService(new_config)
        success, message = await asyncio.to_thread(temp_service.test_connection)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to connect to SMTP server: {message}"
            )
        
        # Persist first so a reported success always survives a restart.
        email_service.apply_smtp_config(new_config)

        _record_notification_event(
            action_id="notifications.smtp.config",
            title="Update SMTP configuration",
            subtitle=subtitle,
            status="success",
            message="SMTP configuration updated successfully",
            started_at=started_at,
        )
        return StatusResponse(
            success=True,
            message="SMTP configuration updated successfully"
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.smtp.config",
            title="Update SMTP configuration",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise
    except Exception as exc:
        logger.exception("Failed to persist SMTP configuration")
        _record_notification_event(
            action_id="notifications.smtp.config",
            title="Update SMTP configuration",
            subtitle=subtitle,
            status="failed",
            message="SMTP configuration could not be saved",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SMTP configuration could not be saved",
        ) from exc


@router.post("/smtp/test", response_model=StatusResponse)
async def test_smtp_connection(
    current_user: User = Depends(get_current_admin_user)
) -> StatusResponse:
    """
    Test SMTP connection (admin only).
    
    Verifies that the current SMTP configuration can connect and authenticate.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    success, message = await asyncio.to_thread(email_service.test_connection)
    _record_notification_event(
        action_id="notifications.smtp.test",
        title="Test SMTP connection",
        subtitle=subtitle,
        status="success" if success else "failed",
        message=message,
        started_at=started_at,
    )
    return StatusResponse(
        success=success,
        message=message
    )


@router.post("/test-email", response_model=StatusResponse)
async def send_test_email(
    request: TestEmailRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user)
) -> StatusResponse:
    """
    Send a test email (admin only).
    
    Useful for verifying email delivery is working correctly.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        if not email_service.is_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email service is not configured"
            )
        
        text_body, html_body = EmailTemplates.system_notification(
            title="Test Email",
            message="This is a test email from EasyPi. If you received this, email notifications are working correctly!",
            details={
                "Sent by": current_user.username,
                "Server time": utc_now().strftime("%Y-%m-%d %H:%M:%S UTC")
            }
        )
        
        message = EmailMessage(
            to=[request.to_email],
            subject=request.subject or "EasyPi Test Email",
            body_text=text_body,
            body_html=html_body,
            priority=EmailPriority.NORMAL
        )
        
        # Send in background
        async def send_email():
            await email_service.send_async(message)
        
        background_tasks.add_task(send_email)
        _record_notification_event(
            action_id="notifications.email.test",
            title="Send test email",
            subtitle=subtitle,
            status="success",
            message="Test email queued for delivery",
            started_at=started_at,
        )
        return StatusResponse(
            success=True,
            message="Test email queued for delivery"
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.email.test",
            title="Send test email",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


# ============== User Preference Endpoints ==============

@router.get("/preferences", response_model=NotificationPreferencesResponse)
async def get_notification_preferences(
    current_user: User = Depends(get_current_user)
) -> NotificationPreferencesResponse:
    """
    Get current user's notification preferences.
    """
    prefs = email_service.get_preferences(str(current_user.id))
    usage = email_service.rate_limiter.get_counts(prefs.email or "")
    
    return NotificationPreferencesResponse(
        enabled=prefs.enabled,
        email=prefs.email or None,
        alert_types=[t.value for t in prefs.alert_types],
        min_priority=prefs.min_priority.value,
        max_emails_per_hour=prefs.max_emails_per_hour,
        max_emails_per_day=prefs.max_emails_per_day,
        digest_mode=prefs.digest_mode,
        digest_interval_hours=prefs.digest_interval_hours,
        quiet_hours_enabled=prefs.quiet_hours_enabled,
        quiet_hours_start=prefs.quiet_hours_start,
        quiet_hours_end=prefs.quiet_hours_end,
        current_usage=usage
    )


@router.put("/preferences", response_model=NotificationPreferencesResponse)
async def update_notification_preferences(
    request: NotificationPreferencesRequest,
    current_user: User = Depends(get_current_user)
) -> NotificationPreferencesResponse:
    """
    Update current user's notification preferences.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    # Parse alert types
    alert_types = []
    for t in request.alert_types:
        try:
            alert_types.append(AlertType(t))
        except ValueError:
            pass  # Ignore invalid alert types
    
    if not alert_types:
        alert_types = list(AlertType)
    
    # Parse priority
    try:
        min_priority = EmailPriority(request.min_priority)
    except ValueError:
        min_priority = EmailPriority.NORMAL
    
    prefs = NotificationPreferences(
        enabled=request.enabled,
        email=request.email or "",
        alert_types=alert_types,
        min_priority=min_priority,
        max_emails_per_hour=request.max_emails_per_hour,
        max_emails_per_day=request.max_emails_per_day,
        digest_mode=request.digest_mode,
        digest_interval_hours=request.digest_interval_hours,
        quiet_hours_enabled=request.quiet_hours_enabled,
        quiet_hours_start=request.quiet_hours_start,
        quiet_hours_end=request.quiet_hours_end
    )
    
    try:
        email_service.set_preferences(str(current_user.id), prefs)
    except Exception as exc:
        logger.exception("Failed to persist notification preferences")
        _record_notification_event(
            action_id="notifications.preferences.update",
            title="Update notification preferences",
            subtitle=subtitle,
            status="failed",
            message="Notification preferences could not be saved",
            started_at=started_at,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Notification preferences could not be saved",
        ) from exc
    
    usage = email_service.rate_limiter.get_counts(prefs.email)
    _record_notification_event(
        action_id="notifications.preferences.update",
        title="Update notification preferences",
        subtitle=subtitle,
        status="success",
        message="Notification preferences updated",
        started_at=started_at,
    )
    return NotificationPreferencesResponse(
        enabled=prefs.enabled,
        email=prefs.email or None,
        alert_types=[t.value for t in prefs.alert_types],
        min_priority=prefs.min_priority.value,
        max_emails_per_hour=prefs.max_emails_per_hour,
        max_emails_per_day=prefs.max_emails_per_day,
        digest_mode=prefs.digest_mode,
        digest_interval_hours=prefs.digest_interval_hours,
        quiet_hours_enabled=prefs.quiet_hours_enabled,
        quiet_hours_start=prefs.quiet_hours_start,
        quiet_hours_end=prefs.quiet_hours_end,
        current_usage=usage
    )


# ============== Alert Endpoints ==============

@router.get("/alert-types")
async def get_alert_types(
    current_user: User = Depends(get_current_user)
) -> Dict[str, List[Dict[str, str]]]:
    """
    Get available alert types.
    """
    return {
        "alert_types": [
            {"value": t.value, "label": t.value.replace("_", " ").title()}
            for t in AlertType
        ],
        "priorities": [
            {"value": p.value, "label": p.value.title()}
            for p in EmailPriority
        ]
    }


@router.post("/send-alert", response_model=StatusResponse)
async def send_alert(
    request: SendAlertRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user)
) -> StatusResponse:
    """
    Send an alert notification (admin only).
    
    Useful for testing or manual alerts.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        if not email_service.is_enabled:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email service is not configured"
            )
        
        try:
            alert_type = AlertType(request.alert_type)
        except ValueError:
            alert_type = AlertType.CUSTOM
        
        try:
            priority = EmailPriority(request.priority)
        except ValueError:
            priority = EmailPriority.NORMAL
        
        async def send_alert_task():
            await send_security_alert(
                user_id=str(current_user.id),
                alert_type=alert_type,
                title=request.title,
                description=request.description,
                details=request.details,
                priority=priority
            )
        
        background_tasks.add_task(send_alert_task)
        _record_notification_event(
            action_id="notifications.alert.send",
            title="Send alert notification",
            subtitle=subtitle,
            status="success",
            message="Alert notification queued for delivery",
            started_at=started_at,
        )
        return StatusResponse(
            success=True,
            message="Alert notification queued for delivery"
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.alert.send",
            title="Send alert notification",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.post("/send-digest", response_model=StatusResponse)
async def send_digest(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
) -> StatusResponse:
    """
    Send queued digest notifications.
    
    Forces immediate delivery of any queued digest alerts.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    async def send_digest_task():
        await email_service.send_digest(str(current_user.id))
    
    background_tasks.add_task(send_digest_task)
    _record_notification_event(
        action_id="notifications.digest.send",
        title="Send notification digest",
        subtitle=subtitle,
        status="success",
        message="Digest queued for delivery",
        started_at=started_at,
    )
    return StatusResponse(
        success=True,
        message="Digest queued for delivery"
    )


@router.get("/status", response_model=StatusResponse)
async def get_notification_status(
    current_user: User = Depends(get_current_user)
) -> StatusResponse:
    """
    Get email notification service status.
    """
    prefs = email_service.get_preferences(str(current_user.id))
    usage = email_service.rate_limiter.get_counts(prefs.email or "")
    
    return StatusResponse(
        success=email_service.is_enabled,
        message="Email service is configured" if email_service.is_enabled else "Email service not configured",
        details={
            "enabled": email_service.is_enabled,
            "user_notifications_enabled": prefs.enabled,
            "user_email_configured": bool(prefs.email),
            "emails_sent_this_hour": usage.get("hourly", 0),
            "emails_sent_today": usage.get("daily", 0),
            "hourly_limit": prefs.max_emails_per_hour,
            "daily_limit": prefs.max_emails_per_day
        }
    )


# ============== Push Notifications Endpoints ==============

from app.services.push_notification_service import (  # noqa: E402
    get_push_service,
    NotificationPayload,
    validate_push_endpoint,
    validate_push_keys,
    PushSubscriptionConflictError,
    PushSubscriptionLimitError,
)


class PushSubscriptionRequest(BaseModel):
    """Request to subscribe to push notifications"""
    endpoint: str = Field(..., max_length=2000, description="Push subscription endpoint URL")
    keys: Dict[str, str] = Field(..., description="Subscription keys (p256dh and auth)")
    user_agent: Optional[str] = Field(None, max_length=500, description="User agent string")
    
    @field_validator('endpoint')
    @classmethod
    def validate_endpoint(cls, v: str) -> str:
        return validate_push_endpoint(v)

    @field_validator("keys")
    @classmethod
    def validate_keys(cls, value: Dict[str, str]) -> Dict[str, str]:
        return validate_push_keys(value)


class PushNotificationRequest(BaseModel):
    """Request to send a push notification"""
    title: str = Field(..., min_length=1, max_length=200, description="Notification title")
    body: str = Field(..., min_length=1, max_length=1000, description="Notification body")
    icon: Optional[str] = Field(None, max_length=500, description="Icon URL")
    tag: Optional[str] = Field(None, max_length=100, description="Notification tag for grouping")
    data: Optional[Dict[str, Any]] = Field(None, description="Custom data payload")
    require_interaction: bool = Field(False, description="Require user interaction")
    user_id: Optional[int] = Field(None, ge=1, description="Target specific user (admin only)")
    
    @field_validator('title', 'body')
    @classmethod
    def validate_notification_text(cls, v: str) -> str:
        v = v.strip()
        if not SAFE_TEXT_PATTERN.match(v):
            raise ValueError('Text contains invalid characters')
        return v
    
    @field_validator('tag')
    @classmethod
    def validate_tag(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if not re.match(r'^[a-zA-Z0-9_\-]{1,100}$', v):
            raise ValueError('Tag must contain only alphanumeric characters, dashes, and underscores')
        return v

    @field_validator("icon")
    @classmethod
    def validate_icon(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        if (
            not re.fullmatch(r"/[A-Za-z0-9_./-]{1,499}", value)
            or ".." in value.split("/")
            or value.startswith("//")
        ):
            raise ValueError("Icon must be a local absolute path")
        return value

    @field_validator("data")
    @classmethod
    def validate_data(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is not None and len(json.dumps(value, ensure_ascii=False)) > 8_192:
            raise ValueError("Push notification data is too large")
        return value


class PushStatusResponse(BaseModel):
    """Push notification status response"""
    configured: bool
    public_key: Optional[str]
    subscriptions_count: int
    user_subscribed: bool


def _revalidate_push_user_session(
    request: Request,
    db: Session,
    expected_user_id: int,
    expected_username: str,
    expected_created_at: datetime,
) -> User:
    """Recheck the login session and immutable account identity after a wait."""
    live_user = get_current_user(request, None, db)
    if (
        live_user.id != expected_user_id
        or live_user.username != expected_username
        or live_user.created_at != expected_created_at
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated account has changed",
        )
    return live_user


@router.get("/push/vapid-key")
async def get_vapid_public_key(
    current_user: User = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    Get VAPID public key for push subscription.
    
    The client uses this key to subscribe to push notifications.
    """
    push_service = get_push_service()
    
    return {
        "public_key": push_service.public_key,
        "configured": push_service.is_configured
    }


@router.post("/push/subscribe")
async def subscribe_to_push(
    request: PushSubscriptionRequest,
    http_request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> StatusResponse:
    """
    Subscribe browser to push notifications.
    
    Called by the frontend after getting permission and creating a subscription.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        push_service = get_push_service()
        
        if not push_service.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Push notifications not configured"
            )
        
        try:
            user_id = current_user.id
            account_identity = (current_user.username, current_user.created_at)
            with push_service.user_subscription_guard(user_id):
                # Authentication may have completed before an administrator revoked
                # the account. Start a fresh read transaction while holding the same
                # guard used by deactivation/deletion, then persist the subscription.
                db.rollback()
                _revalidate_push_user_session(
                    http_request,
                    db,
                    user_id,
                    *account_identity,
                )
                subscription = push_service.add_subscription(
                    endpoint=request.endpoint,
                    keys=request.keys,
                    user_id=user_id,
                    user_agent=request.user_agent
                )
        except PushSubscriptionConflictError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Push subscription is already registered",
            ) from exc
        except PushSubscriptionLimitError as exc:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Push subscription limit reached",
            ) from exc
        _record_notification_event(
            action_id="notifications.push.subscribe",
            title="Subscribe to push notifications",
            subtitle=subtitle,
            status="success",
            message="Browser subscribed to push notifications",
            started_at=started_at,
        )
        return StatusResponse(
            success=True,
            message="Successfully subscribed to push notifications",
            details={
                "created_at": subscription.created_at.isoformat()
            }
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.push.subscribe",
            title="Subscribe to push notifications",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.post("/push/unsubscribe")
async def unsubscribe_from_push(
    request: PushSubscriptionRequest,
    current_user: User = Depends(get_current_user)
) -> StatusResponse:
    """
    Unsubscribe browser from push notifications.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    push_service = get_push_service()
    
    removed = push_service.remove_subscription(
        request.endpoint, user_id=current_user.id
    )
    _record_notification_event(
        action_id="notifications.push.unsubscribe",
        title="Unsubscribe from push notifications",
        subtitle=subtitle,
        status="success" if removed else "failed",
        message="Successfully unsubscribed" if removed else "Subscription not found",
        started_at=started_at,
    )
    return StatusResponse(
        success=removed,
        message="Successfully unsubscribed" if removed else "Subscription not found"
    )


@router.get("/push/status", response_model=PushStatusResponse)
async def get_push_status(
    current_user: User = Depends(get_current_user)
) -> PushStatusResponse:
    """
    Get push notification status for current user.
    """
    push_service = get_push_service()
    
    user_subscriptions = push_service.get_subscriptions(user_id=current_user.id)
    
    return PushStatusResponse(
        configured=push_service.is_configured,
        public_key=push_service.public_key,
        subscriptions_count=len(user_subscriptions),
        user_subscribed=len(user_subscriptions) > 0
    )


@router.post("/push/send")
async def send_push_notification(
    request: PushNotificationRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_admin_user)
) -> StatusResponse:
    """
    Send push notification (admin only).
    
    Can send to all users or a specific user.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        push_service = get_push_service()
        
        if not push_service.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Push notifications not configured"
            )
        
        payload = NotificationPayload(
            title=request.title,
            body=request.body,
            icon=request.icon,
            tag=request.tag,
            data=request.data,
            require_interaction=request.require_interaction
        )
        
        result = await push_service.send_notification(
            payload=payload,
            user_id=request.user_id
        )
        success = result["success"] > 0
        _record_notification_event(
            action_id="notifications.push.send",
            title="Send push notification",
            subtitle=subtitle,
            status="success" if success else "failed",
            message=f"Sent to {result['success']} devices, {result['failed']} failed",
            started_at=started_at,
        )
        return StatusResponse(
            success=success,
            message=f"Sent to {result['success']} devices, {result['failed']} failed",
            details=result
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.push.send",
            title="Send push notification",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.post("/push/test")
async def send_test_push(
    current_user: User = Depends(get_current_user)
) -> StatusResponse:
    """
    Send a test push notification to current user.
    """
    started_at = datetime.now(timezone.utc).isoformat()
    subtitle = f"Notifications - {current_user.username}"
    try:
        push_service = get_push_service()
        
        if not push_service.is_configured:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Push notifications not configured"
            )
        
        user_subs = push_service.get_subscriptions(user_id=current_user.id)
        
        if not user_subs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No push subscriptions found for this user"
            )
        
        result = await push_service.notify_system_alert(
            title="Test Notification",
            message="Push notifications are working correctly!",
            severity="success",
            user_id=current_user.id
        )
        
        success = result["success"] > 0
        _record_notification_event(
            action_id="notifications.push.test",
            title="Send test push notification",
            subtitle=subtitle,
            status="success" if success else "failed",
            message="Test notification sent" if success else "No push notifications were delivered",
            started_at=started_at,
        )
        return StatusResponse(
            success=success,
            message="Test notification sent",
            details=result
        )
    except HTTPException as exc:
        _record_notification_event(
            action_id="notifications.push.test",
            title="Send test push notification",
            subtitle=subtitle,
            status="failed",
            message=str(exc.detail),
            started_at=started_at,
        )
        raise


@router.get("/push/history")
async def get_push_history(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_admin_user)
) -> Dict[str, Any]:
    """
    Get push notification history (admin only).
    """
    push_service = get_push_service()
    
    return {
        "history": push_service.get_history(limit=limit),
        "total_subscriptions": push_service.get_subscription_count()
    }
