"""Strawberry GraphQL root Query type for AiSOC.

All resolvers authenticate via the same ``get_current_user`` dependency
used by the REST layer, and use the shared SQLAlchemy ``AsyncSession``.
Playbook data is fetched from the agents service (HTTP proxy – same as
the REST /playbooks endpoints).
"""
from __future__ import annotations

import math
import os
from typing import Optional

import httpx
import strawberry
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from strawberry.types import Info

from app.graphql.types import (
    AlertPage,
    AlertType,
    CasePage,
    CaseType,
    ConnectorPage,
    ConnectorType,
    DetectionRulePage,
    DetectionRuleType,
    PlaybookRunType,
    PlaybookType,
    SocStatsType,
)
from app.models.alert import Alert
from app.models.case import Case
from app.models.connector import Connector
from app.models.detection_rule import DetectionRule

_AGENTS_URL = os.getenv("AGENTS_SERVICE_URL", "http://agents:8000")

# ─── helpers ──────────────────────────────────────────────────────────────────


def _db(info: Info) -> AsyncSession:
    """Pull the async session injected by the Strawberry FastAPI integration."""
    return info.context["db"]


def _tenant_id(info: Info):  # noqa: ANN201
    """Return the current user's tenant UUID (or None for superusers)."""
    user = info.context.get("user")
    return getattr(user, "tenant_id", None)


def _orm_to_alert(row: Alert) -> AlertType:
    return AlertType(
        id=row.id,
        tenant_id=row.tenant_id,
        title=row.title,
        description=row.description,
        severity=row.severity,
        status=row.status,
        priority=row.priority,
        category=row.category,
        mitre_tactics=row.mitre_tactics or [],
        mitre_techniques=row.mitre_techniques or [],
        connector_type=row.connector_type,
        ai_score=row.ai_score,
        ai_summary=row.ai_summary,
        ai_recommendations=row.ai_recommendations or [],
        affected_ips=row.affected_ips or [],
        affected_hosts=row.affected_hosts or [],
        affected_users=row.affected_users or [],
        case_id=row.case_id,
        tags=row.tags or [],
        event_time=row.event_time,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _orm_to_case(row: Case) -> CaseType:
    return CaseType(
        id=row.id,
        tenant_id=row.tenant_id,
        case_number=row.case_number,
        title=row.title,
        description=row.description,
        status=row.status,
        priority=row.priority,
        severity=row.severity,
        case_type=row.case_type,
        mitre_tactics=row.mitre_tactics or [],
        mitre_techniques=row.mitre_techniques or [],
        assigned_to_id=row.assigned_to_id,
        sla_deadline=row.sla_deadline,
        sla_breached=row.sla_breached,
        alert_ids=row.alert_ids or [],
        tags=row.tags or [],
        ticket_refs=row.ticket_refs or [],
        summary=row.summary,
        resolution=row.resolution,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _orm_to_rule(row: DetectionRule) -> DetectionRuleType:
    return DetectionRuleType(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        description=row.description,
        rule_type=row.rule_language,
        severity=row.severity,
        status=row.status,
        enabled=True,  # DetectionRule uses status field; treat non-archived as enabled
        tags=row.tags or [],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _orm_to_connector(row: Connector) -> ConnectorType:
    return ConnectorType(
        id=row.id,
        tenant_id=row.tenant_id,
        name=row.name,
        connector_type=row.connector_type,
        description=None,
        enabled=row.is_enabled,
        status=row.health_status,
        last_sync_at=row.last_sync,
        total_events_processed=row.events_ingested,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _proxy_get(path: str, params: dict | None = None):  # noqa: ANN201
    """Call the agents service and return JSON, or raise on failure."""
    url = f"{_AGENTS_URL}/api/v1/playbooks{path}"
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.get(url, params=params or {})
    r.raise_for_status()
    return r.json()


# ─── Query ────────────────────────────────────────────────────────────────────


@strawberry.type
class Query:

    # ── Alerts ────────────────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single alert by ID.")
    async def alert(self, info: Info, id: strawberry.ID) -> Optional[AlertType]:
        db = _db(info)
        row = await db.get(Alert, id)
        return _orm_to_alert(row) if row else None

    @strawberry.field(description="Paginated list of alerts with optional filters.")
    async def alerts(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> AlertPage:
        db = _db(info)
        q = select(Alert)

        if severity:
            q = q.where(Alert.severity == severity)
        if status:
            q = q.where(Alert.status == status)
        if search:
            q = q.where(Alert.title.ilike(f"%{search}%"))

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(Alert.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return AlertPage(
            items=[_orm_to_alert(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Cases ─────────────────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single case by ID.")
    async def case(self, info: Info, id: strawberry.ID) -> Optional[CaseType]:
        db = _db(info)
        row = await db.get(Case, id)
        return _orm_to_case(row) if row else None

    @strawberry.field(description="Paginated list of cases with optional filters.")
    async def cases(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        search: Optional[str] = None,
    ) -> CasePage:
        db = _db(info)
        q = select(Case)

        if status:
            q = q.where(Case.status == status)
        if priority:
            q = q.where(Case.priority == priority)
        if search:
            q = q.where(Case.title.ilike(f"%{search}%"))

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(Case.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return CasePage(
            items=[_orm_to_case(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Detection Rules ────────────────────────────────────────────────────────

    @strawberry.field(description="Paginated list of detection rules.")
    async def detection_rules(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> DetectionRulePage:
        db = _db(info)
        q = select(DetectionRule)

        if severity:
            q = q.where(DetectionRule.severity == severity)
        if status:
            q = q.where(DetectionRule.status == status)

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(DetectionRule.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return DetectionRulePage(
            items=[_orm_to_rule(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Connectors ────────────────────────────────────────────────────────────

    @strawberry.field(description="Paginated list of connectors.")
    async def connectors(
        self,
        info: Info,
        page: int = 1,
        page_size: int = 25,
        enabled: Optional[bool] = None,
    ) -> ConnectorPage:
        db = _db(info)
        q = select(Connector)

        if enabled is not None:
            q = q.where(Connector.is_enabled == enabled)

        total_result = await db.execute(select(func.count()).select_from(q.subquery()))
        total = total_result.scalar_one()

        offset = (page - 1) * page_size
        rows_result = await db.execute(q.order_by(Connector.created_at.desc()).offset(offset).limit(page_size))
        rows = rows_result.scalars().all()

        return ConnectorPage(
            items=[_orm_to_connector(r) for r in rows],
            total=total,
            page=page,
            page_size=page_size,
            pages=max(1, math.ceil(total / page_size)),
        )

    # ── Playbooks (agents service proxy) ──────────────────────────────────────

    @strawberry.field(description="List automation playbooks from the agents service.")
    async def playbooks(self, info: Info, enabled_only: bool = False) -> list[PlaybookType]:
        try:
            data = await _proxy_get("", {"enabled_only": enabled_only})
        except Exception:
            return []

        items = data if isinstance(data, list) else data.get("items", [])
        return [
            PlaybookType(
                id=p.get("id", ""),
                name=p.get("name", ""),
                description=p.get("description"),
                enabled=p.get("enabled", True),
                trigger=p.get("trigger", {}),
                steps=p.get("steps", []),
                tags=p.get("tags", []),
                created_at=p.get("created_at"),
                updated_at=p.get("updated_at"),
            )
            for p in items
        ]

    @strawberry.field(description="List recent playbook execution runs.")
    async def playbook_runs(self, info: Info, limit: int = 50) -> list[PlaybookRunType]:
        try:
            data = await _proxy_get("/runs", {"limit": limit})
        except Exception:
            return []

        items = data if isinstance(data, list) else data.get("items", [])
        return [
            PlaybookRunType(
                id=r.get("id", ""),
                playbook_id=r.get("playbook_id", ""),
                status=r.get("status", ""),
                trigger_event=r.get("trigger_event", {}),
                steps_executed=r.get("steps_executed", 0),
                steps_total=r.get("steps_total", 0),
                error=r.get("error"),
                started_at=r.get("started_at", ""),
                completed_at=r.get("completed_at"),
            )
            for r in items
        ]

    # ── SOC Stats ─────────────────────────────────────────────────────────────

    @strawberry.field(description="High-level SOC statistics for the current tenant.")
    async def soc_stats(self, info: Info) -> SocStatsType:
        from datetime import UTC, datetime, timedelta

        db = _db(info)

        total_alerts = (await db.execute(select(func.count()).select_from(Alert))).scalar_one()
        open_cases = (
            await db.execute(
                select(func.count()).select_from(Case).where(Case.status.in_(["open", "in_progress"]))
            )
        ).scalar_one()
        critical_alerts = (
            await db.execute(
                select(func.count()).select_from(Alert).where(Alert.severity == "critical")
            )
        ).scalar_one()
        cutoff = datetime.now(UTC) - timedelta(hours=24)
        alerts_24h = (
            await db.execute(
                select(func.count()).select_from(Alert).where(Alert.created_at >= cutoff)
            )
        ).scalar_one()

        return SocStatsType(
            total_alerts=total_alerts,
            open_cases=open_cases,
            critical_alerts=critical_alerts,
            alerts_last_24h=alerts_24h,
            mean_time_to_detect_hours=None,
            mean_time_to_respond_hours=None,
        )
