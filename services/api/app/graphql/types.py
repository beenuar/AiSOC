"""Strawberry GraphQL type definitions for AiSOC.

These mirror the Pydantic response schemas used in the REST API so that
callers get the same field names/types regardless of protocol.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

import strawberry


# ─── Alert ────────────────────────────────────────────────────────────────────

@strawberry.type(description="A normalised security alert ingested from any connector.")
class AlertType:
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: Optional[str]
    severity: str
    status: str
    priority: int
    category: Optional[str]
    mitre_tactics: strawberry.scalars.JSON
    mitre_techniques: strawberry.scalars.JSON
    connector_type: Optional[str]
    ai_score: Optional[float]
    ai_summary: Optional[str]
    ai_recommendations: strawberry.scalars.JSON
    affected_ips: strawberry.scalars.JSON
    affected_hosts: strawberry.scalars.JSON
    affected_users: strawberry.scalars.JSON
    case_id: Optional[uuid.UUID]
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
    description: Optional[str]
    status: str
    priority: str
    severity: str
    case_type: str
    mitre_tactics: strawberry.scalars.JSON
    mitre_techniques: strawberry.scalars.JSON
    assigned_to_id: Optional[uuid.UUID]
    sla_deadline: Optional[datetime]
    sla_breached: bool
    alert_ids: strawberry.scalars.JSON
    tags: strawberry.scalars.JSON
    ticket_refs: strawberry.scalars.JSON
    summary: Optional[str]
    resolution: Optional[str]
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
    description: Optional[str]
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
    description: Optional[str]
    enabled: bool
    status: str
    last_sync_at: Optional[datetime]
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
    description: Optional[str]
    enabled: bool
    trigger: strawberry.scalars.JSON
    steps: strawberry.scalars.JSON
    tags: strawberry.scalars.JSON
    created_at: Optional[str]
    updated_at: Optional[str]


@strawberry.type
class PlaybookRunType:
    id: str
    playbook_id: str
    status: str
    trigger_event: strawberry.scalars.JSON
    steps_executed: int
    steps_total: int
    error: Optional[str]
    started_at: str
    completed_at: Optional[str]


# ─── Stats ────────────────────────────────────────────────────────────────────

@strawberry.type(description="High-level SOC statistics for the current tenant.")
class SocStatsType:
    total_alerts: int
    open_cases: int
    critical_alerts: int
    alerts_last_24h: int
    mean_time_to_detect_hours: Optional[float]
    mean_time_to_respond_hours: Optional[float]
