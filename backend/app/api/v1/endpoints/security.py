"""
Security API Endpoints

Endpoints for security scanning, fixes, and firewall management.
All endpoints require admin authentication.
"""

import logging
import re
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.db.session import get_db
from app.models.user import User
from app.services.security_service import SecurityService
from app.services.firewall_service import FirewallService
from app.services.threat_service import threat_service
from app.services.audit_log_service import audit_log_service
from app.services.operation_event_service import OperationEventService
from app.schemas.security import (
    SecurityScanResponse,
    FixResponse,
    FixJobStartResponse,
    FixJobStatusResponse,
    PasswordChangeRequest,
    FirewallRuleCreate,
    FirewallRuleResponse
)


class AuditLogEntry(BaseModel):
    """Single audit log entry"""
    timestamp: str
    type: str  # success, warning, info, error
    title: str
    details: str
    source: str  # ssh, sudo, system, etc.


class AuditLogsResponse(BaseModel):
    """Audit logs response"""
    logs: List[AuditLogEntry]
    total: int


router = APIRouter(tags=["security"])
security_service = SecurityService()
firewall_service = FirewallService()
operation_event_service = OperationEventService()
logger = logging.getLogger(__name__)


def _record_security_event(
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
            route="/security",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record security event %s: %s", action_id, exc)


# ===== SECURITY SCAN =====

@router.get("/scan", response_model=SecurityScanResponse)
async def run_security_scan(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Run comprehensive security scan"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await security_service.run_security_scan(db)
        operation_event_service.record_event(
            action_id="security.scan",
            status="success",
            title="Run security scan",
            subtitle="Security · System hardening",
            route="/security",
            message=(
                f"Critical: {len(result.critical)}, "
                f"Warnings: {len(result.warnings)}, "
                f"Passed: {len(result.passed)}"
            ),
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
        return result
    except Exception as exc:
        try:
            operation_event_service.record_event(
                action_id="security.scan",
                status="failed",
                title="Run security scan",
                subtitle="Security · System hardening",
                route="/security",
                message=str(exc),
                started_at=started_at,
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as record_exc:
            logger.warning("Failed to record security scan event: %s", record_exc)
        raise


# ===== FIX ENDPOINTS =====

@router.post("/fix/default-password", response_model=FixResponse)
async def fix_default_password(
    payload: PasswordChangeRequest,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Change default password for user"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_default_password(
        username=payload.username,
        new_password=payload.new_password
    )
    _record_security_event(
        action_id="security.fix.default-password",
        title="Fix default password",
        subtitle=f"Security · {payload.username}",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.post("/fix/ssh-root-login", response_model=FixResponse)
async def fix_ssh_root_login(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Disable SSH root login"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_ssh_root_login()
    _record_security_event(
        action_id="security.fix.ssh-root-login",
        title="Disable SSH root login",
        subtitle="Security · Hardening",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.post("/fix/outdated-packages", response_model=FixResponse)
async def fix_outdated_packages(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Update all outdated packages"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_outdated_packages()
    _record_security_event(
        action_id="security.fix.outdated-packages",
        title="Update outdated packages",
        subtitle="Security · Package maintenance",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.post("/fix/outdated-packages/start", response_model=FixJobStartResponse)
async def start_outdated_packages_fix(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Start package update in the background and return job id."""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.start_outdated_packages_fix()
    _record_security_event(
        action_id="security.fix.outdated-packages.start",
        title="Start package update job",
        subtitle="Security · Package maintenance",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.get("/fix/outdated-packages/status", response_model=FixJobStatusResponse)
async def get_outdated_packages_status(
    job_id: Optional[str] = None,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Get status for a running package update job."""
    return security_service.get_outdated_packages_status(job_id)


@router.post("/fix/firewall", response_model=FixResponse)
async def fix_firewall(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Enable and configure firewall"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_firewall()
    _record_security_event(
        action_id="security.fix.firewall",
        title="Fix firewall",
        subtitle="Security · Firewall",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.post("/fix/password-auth", response_model=FixResponse)
async def fix_password_auth(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Disable password authentication in SSH"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_password_auth()
    _record_security_event(
        action_id="security.fix.password-auth",
        title="Disable SSH password authentication",
        subtitle="Security · SSH hardening",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result

@router.post("/fix/filesystem-readonly", response_model=FixResponse)
async def fix_filesystem_readonly(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Schedule filesystem check and reboot"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await security_service.fix_filesystem_readonly()
    _record_security_event(
        action_id="security.fix.filesystem-readonly",
        title="Schedule filesystem repair",
        subtitle="Security · Filesystem recovery",
        status="success" if result.status == "success" else "failed",
        message=result.message,
        started_at=started_at,
    )
    return result


@router.post("/cancel/{fix_type}")
def cancel_fix(fix_type: str, db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Cancel active fix operation"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = security_service.cancel_fix(fix_type)
    _record_security_event(
        action_id="security.fix.cancel",
        title="Cancel security fix",
        subtitle=f"Security · {fix_type}",
        status="success" if result.get("status") == "success" else "failed",
        message=result.get("message", f"Cancel fix completed for {fix_type}"),
        started_at=started_at,
    )
    return result


# ===== FIREWALL RULES =====

@router.get("/firewall/rules", response_model=List[FirewallRuleResponse])
def get_firewall_rules(db: Session = Depends(get_db), _admin: User = Depends(require_admin)):
    """Get all firewall rules"""
    return firewall_service.get_all_rules(db)


@router.post("/firewall/add", response_model=FirewallRuleResponse)
def add_firewall_rule(
    rule: FirewallRuleCreate,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Add new firewall rule"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = firewall_service.add_rule(rule, db)
        _record_security_event(
            action_id="security.firewall.add-rule",
            title="Add firewall rule",
            subtitle=f"Security · Firewall {rule.protocol.upper()}/{rule.port}",
            status="success",
            message=f"Firewall rule added for {rule.protocol.upper()}/{rule.port}",
            started_at=started_at,
        )
        return result
    except Exception as e:
        _record_security_event(
            action_id="security.firewall.add-rule",
            title="Add firewall rule",
            subtitle=f"Security · Firewall {rule.protocol.upper()}/{rule.port}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/firewall/remove/{rule_id}")
def delete_firewall_rule(
    rule_id: int,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin)
):
    """Delete firewall rule"""
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = firewall_service.delete_rule(rule_id, db)
        _record_security_event(
            action_id="security.firewall.delete-rule",
            title="Delete firewall rule",
            subtitle=f"Security · Firewall rule #{rule_id}",
            status="success",
            message=f"Firewall rule #{rule_id} deleted",
            started_at=started_at,
        )
        return result
    except Exception as e:
        _record_security_event(
            action_id="security.firewall.delete-rule",
            title="Delete firewall rule",
            subtitle=f"Security · Firewall rule #{rule_id}",
            status="failed",
            message=str(e),
            started_at=started_at,
        )
        raise HTTPException(status_code=404, detail=str(e))


# ===== AUDIT LOGS =====

@router.get("/audit-logs", response_model=AuditLogsResponse)
async def get_audit_logs(limit: int = 50, _admin: User = Depends(require_admin)) -> AuditLogsResponse:
    """Get real audit logs from system auth and SSH activity."""
    records = audit_log_service.read_recent(limit=limit)
    logs = [
        AuditLogEntry(
            timestamp=record.timestamp,
            type=record.type,
            title=record.title,
            details=record.details,
            source=record.source,
        )
        for record in records
    ]
    return AuditLogsResponse(logs=logs, total=len(logs))


def _parse_auth_log_line(line: str) -> Optional[AuditLogEntry]:
    """Parse a line from auth.log into AuditLogEntry"""
    if not line.strip():
        return None
    
    # Common patterns in auth.log
    patterns = [
        # Successful SSH login
        (r"Accepted (?:password|publickey) for (\S+) from (\S+)", "success", "Successful SSH login", "ssh"),
        # Failed SSH login
        (r"Failed password for (?:invalid user )?(\S+) from (\S+)", "warning", "Failed SSH login attempt", "ssh"),
        # Invalid user
        (r"Invalid user (\S+) from (\S+)", "warning", "Invalid user login attempt", "ssh"),
        # Connection closed
        (r"Connection closed by (?:authenticating user )?(\S+)? ?(\S+)?", "info", "SSH connection closed", "ssh"),
        # Session opened
        (r"session opened for user (\S+)", "success", "Session started", "pam"),
        # Session closed
        (r"session closed for user (\S+)", "info", "Session ended", "pam"),
        # Sudo command
        (r"(\S+) : .* COMMAND=(.+)", "info", "Sudo command executed", "sudo"),
        # Sudo auth failure
        (r"(\S+) : .*authentication failure", "warning", "Sudo authentication failed", "sudo"),
        # Too many failures
        (r"message repeated (\d+) times.*Failed", "warning", "Multiple failed attempts", "ssh"),
    ]
    
    for pattern, log_type, title, source in patterns:
        match = re.search(pattern, line, re.IGNORECASE)
        if match:
            # Extract timestamp from beginning of line
            # Format: "Dec 14 08:30:15"
            timestamp_match = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
            timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"
            
            # Build details from matched groups
            groups = [g for g in match.groups() if g]
            if source == "ssh" and len(groups) >= 2:
                details = f"User: {groups[0]} • From: {groups[1]}"
            elif source == "sudo" and len(groups) >= 2:
                details = f"User: {groups[0]} • Command: {groups[1][:50]}"
            elif groups:
                details = f"User: {groups[0]}"
            else:
                details = line[20:100] if len(line) > 20 else line
            
            return AuditLogEntry(
                timestamp=timestamp,
                type=log_type,
                title=title,
                details=details,
                source=source
            )
    
    return None


def _parse_journalctl_line(line: str) -> Optional[AuditLogEntry]:
    """Parse journalctl output line"""
    if not line.strip() or "-- " in line:  # Skip header lines
        return None
    
    # journalctl format: "Dec 14 08:30:15 hostname sshd[1234]: message"
    match = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.+)", line)
    if match:
        timestamp, service, message = match.groups()
        
        # Determine type based on message content
        log_type = "info"
        title = f"{service} event"
        
        if "Accepted" in message:
            log_type = "success"
            title = "Successful SSH login"
        elif "Failed" in message or "failure" in message.lower():
            log_type = "warning"
            title = "Failed login attempt"
        elif "Invalid" in message:
            log_type = "warning"
            title = "Invalid user attempt"
        elif "session opened" in message.lower():
            log_type = "success"
            title = "Session started"
        elif "session closed" in message.lower():
            log_type = "info"
            title = "Session ended"
            
        return AuditLogEntry(
            timestamp=timestamp,
            type=log_type,
            title=title,
            details=message[:100],
            source=service.replace("sshd", "ssh")
        )
    
    return None


# ===== THREAT MONITORING =====

class MonitoringStatusResponse(BaseModel):
    enabled: bool
    ssh_threshold: int
    auto_ban: bool
    threats_count: int
    uptime: Optional[str] = None


class MonitoringSettingsRequest(BaseModel):
    ssh_threshold: Optional[int] = None
    auto_ban: Optional[bool] = None


@router.get("/monitoring/status", response_model=MonitoringStatusResponse)
async def get_monitoring_status(_admin: User = Depends(require_admin)):
    """Get threat monitoring status"""
    return await threat_service.get_status()


@router.post("/monitoring/start")
async def start_monitoring(_admin: User = Depends(require_admin)):
    """Start threat monitoring"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.start_monitoring()
    operation_event_service.record_event(
        action_id="security.monitoring.start",
        status="success",
        title="Start threat monitoring",
        subtitle="Security · Security monitor",
        route="/security",
        message=result.get("message", "Threat monitoring started"),
        started_at=started_at,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    return {"success": True, **result}


@router.post("/monitoring/stop")
async def stop_monitoring(_admin: User = Depends(require_admin)):
    """Stop threat monitoring"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.stop_monitoring()
    operation_event_service.record_event(
        action_id="security.monitoring.stop",
        status="success",
        title="Stop threat monitoring",
        subtitle="Security · Security monitor",
        route="/security",
        message=result.get("message", "Threat monitoring stopped"),
        started_at=started_at,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    return {"success": True, **result}


@router.post("/monitoring/settings", response_model=MonitoringStatusResponse)
async def update_monitoring_settings(
    settings: MonitoringSettingsRequest,
    _admin: User = Depends(require_admin)
):
    """Update monitoring settings (threshold, auto-ban)"""
    started_at = datetime.now(timezone.utc).isoformat()
    result = await threat_service.update_settings(
        ssh_threshold=settings.ssh_threshold,
        auto_ban=settings.auto_ban
    )
    operation_event_service.record_event(
        action_id="security.monitoring.settings",
        status="success",
        title="Update threat monitoring settings",
        subtitle="Security · Security monitor",
        route="/security",
        message="Threat monitoring settings updated",
        started_at=started_at,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    return result


__all__ = ["router"]
