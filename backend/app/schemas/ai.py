"""
AI Assistant Schemas

Pydantic schemas for AI endpoints.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agent.core.sanitization import (
    normalize_free_text,
    normalize_optional_text,
    sanitize_action_parameters,
    validate_action_id,
    validate_entity_type,
    validate_route,
    validate_tab,
)


# Chat message
class ChatMessage(BaseModel):
    role: Literal["user", "assistant", "system"]
    content: str


# Chat request
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    session_id: Optional[str] = Field(default=None, max_length=255)
    stream: bool = False
    temperature: Optional[float] = Field(default=None, ge=0, le=1.5)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        return normalize_free_text(value, max_length=8000)

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value, max_length=255)


# Chat response
class ChatResponse(BaseModel):
    response: str
    session_id: str
    model: str = "qwen2.5:3b"


# Installation status
class AIInstallStatus(BaseModel):
    is_installed: bool
    status: Literal["not_installed", "installing", "ready", "error"]
    model_name: Optional[str] = None
    model_path: Optional[str] = None
    ollama_url: Optional[str] = None
    installed_at: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    temperature: Optional[float] = None
    system_prompt: Optional[str] = None


# Installation response
class InstallResponse(BaseModel):
    status: Literal["success", "error", "in_progress"]
    message: str
    log: Optional[str] = None


class InstallRequest(BaseModel):
    model_name: Optional[str] = Field(default=None, max_length=120)
    temperature: Optional[float] = Field(default=None, ge=0, le=1.5)
    system_prompt: Optional[str] = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("model_name", "system_prompt")
    @classmethod
    def validate_install_fields(cls, value: Optional[str], info) -> Optional[str]:
        max_length = 120 if info.field_name == "model_name" else 2000
        return normalize_optional_text(value, max_length=max_length)


# Conversation history
class ConversationMessage(BaseModel):
    id: int
    role: str
    content: str
    created_at: datetime
    model: str
    
    model_config = ConfigDict(from_attributes=True)


class AIModelInfo(BaseModel):
    name: str
    display_name: str
    description: str
    size_gb: float
    tags: list[str] = []
    recommended: bool = False
    notes: Optional[str] = None


class AISettingsUpdate(BaseModel):
    model_name: Optional[str] = Field(default=None, max_length=120)
    temperature: Optional[float] = Field(default=None, ge=0, le=1.5)
    system_prompt: Optional[str] = Field(default=None, max_length=2000)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("model_name", "system_prompt")
    @classmethod
    def validate_settings_fields(cls, value: Optional[str], info) -> Optional[str]:
        max_length = 120 if info.field_name == "model_name" else 2000
        return normalize_optional_text(value, max_length=max_length)


class DiagnosticExplainRequest(BaseModel):
    question: str = Field(..., min_length=3, max_length=500)
    target_type: Literal["auto", "device", "domain", "service"] = "auto"
    target: Optional[str] = Field(default=None, max_length=255)
    route: Optional[str] = Field(default=None, max_length=255)
    tab: Optional[str] = Field(default=None, max_length=255)
    entity_type: Optional[str] = Field(default=None, max_length=100)
    entity_id: Optional[str] = Field(default=None, max_length=255)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("question")
    @classmethod
    def validate_question(cls, value: str) -> str:
        normalized = normalize_free_text(value, max_length=500)
        if len(normalized) < 3:
            raise ValueError("Question is too short after normalization")
        return normalized

    @field_validator("target", "entity_id")
    @classmethod
    def validate_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value, max_length=255)

    @field_validator("route")
    @classmethod
    def validate_route_field(cls, value: Optional[str]) -> Optional[str]:
        return validate_route(value)

    @field_validator("tab")
    @classmethod
    def validate_tab_field(cls, value: Optional[str]) -> Optional[str]:
        return validate_tab(value)

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type_field(cls, value: Optional[str]) -> Optional[str]:
        return validate_entity_type(value)


class DiagnosticFact(BaseModel):
    label: str
    value: str
    severity: Literal["info", "warning", "critical"] = "info"


class DiagnosticAction(BaseModel):
    action_id: str
    label: str
    description: str
    style: Literal["primary", "secondary", "danger"] = "secondary"
    requires_confirmation: bool = True
    confirmation_text: Optional[str] = None
    confirmation_token: Optional[str] = None
    parameters: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid")


class DiagnosticExplainResponse(BaseModel):
    category: Literal["device", "domain", "service", "unknown"]
    target: str
    matched: bool
    title: str
    summary: str
    confidence: Literal["high", "medium", "low"]
    section: Optional[str] = None
    subsection: Optional[str] = None
    module: Optional[str] = None
    source_status: Literal["ok", "partial", "unavailable", "stale", "conflict"] = "ok"
    source_errors: List[str] = Field(default_factory=list)
    checks_run: List[str] = Field(default_factory=list)
    facts: List[DiagnosticFact] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    reason_chain: List[str] = Field(default_factory=list)
    actions: List[DiagnosticAction] = Field(default_factory=list)


class DiagnosticActionRequest(BaseModel):
    action_id: str = Field(..., min_length=3, max_length=100)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    confirmation_token: str = Field(..., min_length=20, max_length=200)
    question: Optional[str] = Field(default=None, min_length=3, max_length=500)
    target_type: Literal["auto", "device", "domain", "service"] = "auto"
    target: Optional[str] = Field(default=None, max_length=255)
    route: Optional[str] = Field(default=None, max_length=255)
    tab: Optional[str] = Field(default=None, max_length=255)
    entity_type: Optional[str] = Field(default=None, max_length=100)
    entity_id: Optional[str] = Field(default=None, max_length=255)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("action_id")
    @classmethod
    def validate_action_id_field(cls, value: str) -> str:
        return validate_action_id(value)

    @field_validator("parameters")
    @classmethod
    def validate_parameters(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_action_parameters(value)

    @field_validator("question")
    @classmethod
    def validate_optional_question(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = normalize_free_text(value, max_length=500)
        if len(normalized) < 3:
            raise ValueError("Question is too short after normalization")
        return normalized

    @field_validator("target", "entity_id")
    @classmethod
    def validate_action_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return normalize_optional_text(value, max_length=255)

    @field_validator("route")
    @classmethod
    def validate_action_route(cls, value: Optional[str]) -> Optional[str]:
        return validate_route(value)

    @field_validator("tab")
    @classmethod
    def validate_action_tab(cls, value: Optional[str]) -> Optional[str]:
        return validate_tab(value)

    @field_validator("entity_type")
    @classmethod
    def validate_action_entity_type(cls, value: Optional[str]) -> Optional[str]:
        return validate_entity_type(value)


class DiagnosticActionResponse(BaseModel):
    action_id: str
    success: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    follow_up: Optional[DiagnosticExplainResponse] = None


class DiagnosticProbeRequest(BaseModel):
    probe_id: str = Field(..., min_length=3, max_length=100)
    parameters: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    @field_validator("probe_id")
    @classmethod
    def validate_probe_id_field(cls, value: str) -> str:
        return validate_action_id(value)

    @field_validator("parameters")
    @classmethod
    def validate_probe_parameters(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        return sanitize_action_parameters(value)


class DiagnosticProbeResponse(BaseModel):
    probe_id: str
    success: bool
    source_status: Literal["ok", "partial", "unavailable", "stale", "conflict"] = "ok"
    message: str

    model_config = ConfigDict(extra="allow")


__all__ = [
    "ChatMessage",
    "ChatRequest",
    "ChatResponse",
    "AIInstallStatus",
    "InstallResponse",
    "ConversationMessage",
    "InstallRequest",
    "AIModelInfo",
    "AISettingsUpdate",
    "DiagnosticExplainRequest",
    "DiagnosticFact",
    "DiagnosticAction",
    "DiagnosticExplainResponse",
    "DiagnosticActionRequest",
    "DiagnosticActionResponse",
    "DiagnosticProbeRequest",
    "DiagnosticProbeResponse",
]
