"""Pydantic models mirroring the AiSOC OpenAPI schema."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict

# ── Enums ─────────────────────────────────────────────────────────────────────


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class CasePriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CaseStatus(str, Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    CLOSED = "closed"


# ── Core models ───────────────────────────────────────────────────────────────

_M = ConfigDict(populate_by_name=True, from_attributes=True)


class Alert(BaseModel):
    model_config = _M

    id: str
    tenant_id: str
    title: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    source_ref: str | None = None
    mitre_tactics: list[str] = []
    ai_score: float | None = None
    case_id: str | None = None
    created_at: datetime
    updated_at: datetime


class Case(BaseModel):
    model_config = _M

    id: str
    tenant_id: str
    case_number: str
    title: str
    status: CaseStatus
    priority: CasePriority
    assignee: str | None = None
    mitre_tactics: list[str] = []
    alert_ids: list[str] = []
    created_at: datetime
    updated_at: datetime


class DetectionRule(BaseModel):
    model_config = _M

    id: str
    tenant_id: str
    name: str
    description: str | None = None
    rule_language: str
    severity: AlertSeverity
    enabled: bool
    created_at: datetime
    updated_at: datetime


class Connector(BaseModel):
    model_config = _M

    id: str
    tenant_id: str
    name: str
    connector_type: str
    is_enabled: bool
    health_status: str
    events_ingested: int = 0
    created_at: datetime
    updated_at: datetime


class PlaybookStep(BaseModel):
    model_config = _M

    id: str
    name: str
    type: str
    action: str | None = None
    parameters: dict[str, Any] | None = None
    next_steps: list[str] = []


class Playbook(BaseModel):
    model_config = _M

    id: str
    name: str
    description: str | None = None
    version: str
    steps: list[PlaybookStep] = []
    trigger_conditions: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class PlaybookRun(BaseModel):
    model_config = _M

    run_id: str
    playbook_id: str
    status: str
    started_at: datetime
    completed_at: datetime | None = None
    trigger_data: dict[str, Any] | None = None
    step_results: dict[str, Any] | None = None


class ApiKey(BaseModel):
    model_config = _M

    id: str
    name: str
    prefix: str
    scopes: list[str]
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime


# ── Pagination ────────────────────────────────────────────────────────────────

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    model_config = _M

    items: list[T]
    total: int
    page: int
    page_size: int


# ── Request / response helpers ────────────────────────────────────────────────


class AlertFilters(BaseModel):
    model_config = _M

    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    case_id: str | None = None
    search: str | None = None
    page: int = 1
    page_size: int = 20


class CaseFilters(BaseModel):
    model_config = _M

    status: CaseStatus | None = None
    priority: CasePriority | None = None
    assignee: str | None = None
    page: int = 1
    page_size: int = 20


class ApiKeyCreateRequest(BaseModel):
    model_config = _M

    name: str
    scopes: list[str]
    expires_at: datetime | None = None


class ApiKeyCreateResponse(BaseModel):
    model_config = _M

    key: ApiKey
    raw_key: str
