"""
Security Schemas

Pydantic schemas for security endpoints.
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import List, Optional, Literal
from datetime import datetime


# Security Issue
class SecurityIssue(BaseModel):
    id: str
    message: str
    status: Literal["critical", "warning", "passed"]
    details: Optional[str] = None
    fixable: bool = True


# Security Scan Response
class SecurityScanResponse(BaseModel):
    last_scan: datetime
    critical: List[SecurityIssue]
    warnings: List[SecurityIssue]
    passed: List[SecurityIssue]
    

# Fix Response
class FixResponse(BaseModel):
    status: Literal["success", "error"]
    message: str


class FixJobStartResponse(BaseModel):
    status: Literal["success", "error"]
    message: str
    job_id: Optional[str] = None


class FixJobStatusResponse(BaseModel):
    status: Literal["running", "success", "error", "idle"]
    message: Optional[str] = None
    progress: Optional[int] = None
    job_id: Optional[str] = None
    

# Firewall Rule
class FirewallRuleCreate(BaseModel):
    port: int = Field(..., gt=0, le=65535)
    protocol: Literal["tcp", "udp"] = "tcp"
    source: str = "any"
    

class FirewallRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    source: str
    action: str
    created_at: datetime


# Password Change
class PasswordChangeRequest(BaseModel):
    username: str
    new_password: str = Field(..., min_length=8)


__all__ = [
    "SecurityIssue",
    "SecurityScanResponse",
    "FixResponse",
    "FixJobStartResponse",
    "FixJobStatusResponse",
    "FirewallRuleCreate",
    "FirewallRuleResponse",
    "PasswordChangeRequest",
]
