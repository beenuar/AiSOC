"""Strawberry GraphQL type definitions for AiSOC.

These mirror the Pydantic response schemas used in the REST API so that
callers get the same field names/types regardless of protocol.
"""

from __future__ import annotations

import uuid
from datetime import datetime

import strawberry

# ─── Alert ────────────────────────────────────────────────────────────────────


@strawberry.type(description="A normalised security alert ingested from any connector.")
class AlertType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str | None
    severity: str
    status: str
    priority: int
    category: str | None
    mitre_tactics: strawberry.scalars.JSON
    mitre_techniques: strawberry.scalars.JSON
    connector_type: str | None
    ai_score: float | None
    ai_summary: str | None
    ai_recommendations: strawberry.scalars.JSON
    affected_ips: strawberry.scalars.JSON
    affected_hosts: strawberry.scalars.JSON
    affected_users: strawberry.scalars.JSON
    case_id: uuid.UUID | None
    tags: strawberry.scalars.JSON
    event_time: datetime
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime


@strawberry.type
class AlertPage:
    items: list[AlertType]
    total: int
    page: int
    page_size: int
    pages: int


# ─── Case ─────────────────────────────────────────────────────────────────────


@strawberry.type(description="A security case grouping one or more alerts.")
class CaseType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    case_number: str
    title: str
    description: str | None
    status: str
    priority: str
    severity: str
    case_type: str
    mitre_tactics: strawberry.scalars.JSON
    mitre_techniques: strawberry.scalars.JSON
    assigned_to_id: uuid.UUID | None
    sla_deadline: datetime | None
    sla_breached: bool
    alert_ids: strawberry.scalars.JSON
    tags: strawberry.scalars.JSON
    ticket_refs: strawberry.scalars.JSON
    summary: str | None
    resolution: str | None
    created_at: datetime
    updated_at: datetime


@strawberry.type
class CasePage:
    items: list[CaseType]
    total: int
    page: int
    page_size: int
    pages: int


# ─── Detection Rule ────────────────────────────────────────────────────────────


@strawberry.type(description="A SIEM detection rule (Sigma / YARA / custom).")
class DetectionRuleType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    description: str | None
    rule_type: str
    severity: str
    status: str
    enabled: bool
    tags: strawberry.scalars.JSON
    created_at: datetime
    updated_at: datetime


@strawberry.type
class DetectionRulePage:
    items: list[DetectionRuleType]
    total: int
    page: int
    page_size: int
    pages: int


# ─── Connector ────────────────────────────────────────────────────────────────


@strawberry.type(description="An external data-source connector configuration.")
class ConnectorType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    connector_type: str
    description: str | None
    enabled: bool
    status: str
    last_sync_at: datetime | None
    total_events_processed: int
    created_at: datetime
    updated_at: datetime


@strawberry.type
class ConnectorPage:
    items: list[ConnectorType]
    total: int
    page: int
    page_size: int
    pages: int


# ─── Playbook ─────────────────────────────────────────────────────────────────


@strawberry.type(description="An automation playbook (stored in the agents service).")
class PlaybookType:
    id: str
    name: str
    description: str | None
    enabled: bool
    trigger: strawberry.scalars.JSON
    steps: strawberry.scalars.JSON
    tags: strawberry.scalars.JSON
    created_at: str | None
    updated_at: str | None


@strawberry.type
class PlaybookRunType:
    id: str
    playbook_id: str
    status: str
    trigger_event: strawberry.scalars.JSON
    steps_executed: int
    steps_total: int
    error: str | None
    started_at: str
    completed_at: str | None


# ─── Stats ────────────────────────────────────────────────────────────────────


@strawberry.type(description="High-level SOC statistics for the current tenant.")
class SocStatsType:
    total_alerts: int
    open_cases: int
    critical_alerts: int
    alerts_last_24h: int
    mean_time_to_detect_hours: float | None
    mean_time_to_respond_hours: float | None
