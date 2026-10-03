"""Pydantic models mirroring the AiSOC OpenAPI schema."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, List, Optional, TypeVar

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
    source_ref: Optional[str] = None
    mitre_tactics: List[str] = []
    ai_score: Optional[float] = None
    case_id: Optional[str] = None
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
    assignee: Optional[str] = None
    mitre_tactics: List[str] = []
    alert_ids: List[str] = []
    created_at: datetime
    updated_at: datetime


class DetectionRule(BaseModel):
    model_config = _M

    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
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
    action: Optional[str] = None
    parameters: Optional[dict[str, Any]] = None
    next_steps: List[str] = []


class Playbook(BaseModel):
    model_config = _M

    id: str
    name: str
    description: Optional[str] = None
    version: str
    steps: List[PlaybookStep] = []
    trigger_conditions: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime


class PlaybookRun(BaseModel):
    model_config = _M

    run_id: str
    playbook_id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    trigger_data: Optional[dict[str, Any]] = None
    step_results: Optional[dict[str, Any]] = None


class ApiKey(BaseModel):
    model_config = _M

    id: str
    name: str
    prefix: str
    scopes: List[str]
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime


# ── Pagination ────────────────────────────────────────────────────────────────

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    model_config = _M

    items: List[T]
    total: int
    page: int
    page_size: int


# ── Request / response helpers ────────────────────────────────────────────────


class AlertFilters(BaseModel):
    model_config = _M

    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    case_id: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 20


class CaseFilters(BaseModel):
    model_config = _M

    status: Optional[CaseStatus] = None
    priority: Optional[CasePriority] = None
    assignee: Optional[str] = None
    page: int = 1
    page_size: int = 20


class ApiKeyCreateRequest(BaseModel):
    model_config = _M

    name: str
    scopes: List[str]
    expires_at: Optional[datetime] = None


class ApiKeyCreateResponse(BaseModel):
    model_config = _M

    key: ApiKey
    raw_key: str
