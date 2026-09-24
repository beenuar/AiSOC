"""FastAPI routes for the Purple Team service."""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.purple_team import (
    AtomicTest,
    DetectionDriftSnapshot,
    TabletopSession,
    TestExecution,
)
from app.security.service_auth import require_service_auth
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)
from app.services.atomic_loader import load_atomics
from app.services.caldera_client import CalderaClient
from app.services.drift import (
    capture_snapshot,
    compute_coverage_for_tenant,
    compute_drift,
    latest_two_snapshots,
    list_snapshots,
)

LOG = logging.getLogger(__name__)

# Default-deny for the whole router, not just the mutating verbs.
#
# This service executes adversary emulation: `POST /caldera/run` starts a real
# Caldera operation against live hosts and `POST /atomics/run` records an
# execution. Both were reachable with no credential at all, and both read
# `tenant_id` and `executed_by` from the request body, so a caller declared
# their own identity and their own tenant.
#
# The read routes are included deliberately rather than left open: they take
# `tenant_id` as a plain query parameter, so an unauthenticated caller could
# enumerate any tenant's execution history and coverage posture.
#
# `/health` and the probes in `app/_health.py` are registered on the app, not
# this router, so they stay reachable for orchestrators.
router = APIRouter(dependencies=[Depends(require_service_auth)])

#: Proving the caller is a trusted service is not the same as knowing which
#: tenant it acts for. The router-level dependency above does the first; this
#: one does the second, and every route that touches tenant data takes it so
#: the tenant can never arrive as a bare query parameter.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
_engine = create_async_engine(settings.database_url, pool_pre_ping=True)
_async_session = sessionmaker(_engine, class_=AsyncSession, expire_on_commit=False)


async def _get_db() -> AsyncSession:
    async with _async_session() as session:
        return session


def _caldera() -> CalderaClient:
    return CalderaClient(settings.caldera_url, settings.caldera_api_key)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
class AtomicTestOut(BaseModel):
    id: uuid.UUID
    technique_id: str
    technique_name: str
    tactic: str
    test_guid: str
    test_name: str
    test_description: str | None
    platform: str
    executor: str

    model_config = {"from_attributes": True}


class RunAtomicRequest(BaseModel):
    tenant_id: uuid.UUID
    test_guid: str
    technique_id: str
    test_name: str
    executed_by: str | None = None


class ExecutionOut(BaseModel):
    id: uuid.UUID
    source: str
    technique_id: str
    test_name: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    detected: bool | None
    detection_latency_seconds: float | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TabletopCreateRequest(BaseModel):
    tenant_id: uuid.UUID
    name: str
    description: str | None = None
    scenario: str
    technique_ids: list[str] = []
    created_by: str | None = None


class TabletopAddFindingRequest(BaseModel):
    finding: str
    severity: str = "medium"
    owner: str | None = None


class TabletopOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    scenario: str
    technique_ids: list[str]
    findings: list[Any]
    status: str
    created_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportDetectionRequest(BaseModel):
    execution_id: uuid.UUID
    detected: bool
    alert_id: str | None = None
    detection_latency_seconds: float | None = None


# ---------------------------------------------------------------------------
# Atomic Red Team endpoints
# ---------------------------------------------------------------------------
@router.post("/api/v1/purple-team/atomics/sync", tags=["Atomic Red Team"])
async def sync_atomics(principal: ScopedPrincipal, tenant_id: uuid.UUID | None = None) -> dict:
    """Parse and upsert all Atomic Red Team tests from the local repo."""
    tenant_id = scoped_tenant_or_403(principal, tenant_id)
    tests = load_atomics(settings.art_atomics_path)
    if not tests:
        return {"synced": 0, "message": "No tests found — check art_atomics_path"}

    async with _async_session() as session:
        await session.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        synced = 0
        for t in tests:
            existing = await session.execute(
                select(AtomicTest).where(
                    AtomicTest.tenant_id == tenant_id,
                    AtomicTest.test_guid == t["test_guid"],
                )
            )
            row = existing.scalar_one_or_none()
            if row is None:
                session.add(
                    AtomicTest(
                        tenant_id=tenant_id,
                        **{k: v for k, v in t.items() if k != "tactic"},
                        tactic=t["tactic"],
                    )
                )
                synced += 1
        await session.commit()

    return {"synced": synced, "total_in_repo": len(tests)}


@router.get("/api/v1/purple-team/atomics", response_model=list[AtomicTestOut], tags=["Atomic Red Team"])
async def list_atomics(
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = None,
    technique_id: str | None = Query(None),
    tactic: str | None = Query(None),
    platform: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[AtomicTest]:
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        q = select(AtomicTest).where(AtomicTest.tenant_id == scoped)
        if technique_id:
            q = q.where(AtomicTest.technique_id == technique_id)
        if tactic:
            q = q.where(AtomicTest.tactic == tactic)
        if platform:
            q = q.where(AtomicTest.platform.contains(platform))
        q = q.order_by(AtomicTest.technique_id).offset(offset).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all())


@router.post("/api/v1/purple-team/atomics/run", response_model=ExecutionOut, tags=["Atomic Red Team"])
async def run_atomic(body: RunAtomicRequest, principal: ScopedPrincipal) -> TestExecution:
    """Create a pending execution record (actual execution is out-of-band)."""
    scoped = scoped_tenant_or_403(principal, body.tenant_id)
    async with _async_session() as session:
        execution = TestExecution(
            tenant_id=scoped,
            source="atomic",
            technique_id=body.technique_id,
            test_name=body.test_name,
            test_guid=body.test_guid,
            status="pending",
            executed_by=body.executed_by,
        )
        session.add(execution)
        await session.commit()
        await session.refresh(execution)
        return execution


# ---------------------------------------------------------------------------
# Caldera endpoints
# ---------------------------------------------------------------------------
@router.get("/api/v1/purple-team/caldera/health", tags=["Caldera"])
async def caldera_health() -> dict:
    ok = await _caldera().health()
    return {"connected": ok, "url": settings.caldera_url}


@router.get("/api/v1/purple-team/caldera/abilities", tags=["Caldera"])
async def caldera_abilities() -> list[dict]:
    try:
        return await _caldera().list_abilities()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/api/v1/purple-team/caldera/adversaries", tags=["Caldera"])
async def caldera_adversaries() -> list[dict]:
    try:
        return await _caldera().list_adversaries()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/api/v1/purple-team/caldera/operations", tags=["Caldera"])
async def caldera_operations() -> list[dict]:
    try:
        return await _caldera().list_operations()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


class CalderaRunRequest(BaseModel):
    tenant_id: uuid.UUID
    operation_name: str
    adversary_id: str
    group: str = "red"
    executed_by: str | None = None


@router.post("/api/v1/purple-team/caldera/run", response_model=ExecutionOut, tags=["Caldera"])
async def run_caldera_operation(body: CalderaRunRequest, principal: ScopedPrincipal) -> TestExecution:
    # Resolved before the Caldera call, not after: this starts a real
    # adversary-emulation operation against live hosts, so an unauthorised
    # tenant must be refused before anything executes.
    scoped = scoped_tenant_or_403(principal, body.tenant_id)
    try:
        op = await _caldera().start_operation(
            name=body.operation_name,
            adversary_id=body.adversary_id,
            group=body.group,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    async with _async_session() as session:
        execution = TestExecution(
            tenant_id=scoped,
            source="caldera",
            technique_id="multi",
            test_name=body.operation_name,
            caldera_operation_id=op.get("id"),
            status="running",
            started_at=datetime.now(UTC),
            executed_by=body.executed_by,
        )
        session.add(execution)
        await session.commit()
        await session.refresh(execution)
        return execution


# ---------------------------------------------------------------------------
# Execution management
# ---------------------------------------------------------------------------
@router.get("/api/v1/purple-team/executions", response_model=list[ExecutionOut], tags=["Executions"])
async def list_executions(
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = None,
    technique_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[TestExecution]:
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        q = select(TestExecution).where(TestExecution.tenant_id == scoped)
        if technique_id:
            q = q.where(TestExecution.technique_id == technique_id)
        if status:
            q = q.where(TestExecution.status == status)
        q = q.order_by(TestExecution.created_at.desc()).offset(offset).limit(limit)
        result = await session.execute(q)
        return list(result.scalars().all())


@router.patch(
    "/api/v1/purple-team/executions/{execution_id}/detection",
    response_model=ExecutionOut,
    tags=["Executions"],
)
async def report_detection(execution_id: uuid.UUID, body: ReportDetectionRequest, principal: ScopedPrincipal) -> TestExecution:
    # Matched on id *and* tenant. On id alone, any caller could overwrite
    # another tenant's detection outcome by naming its execution UUID.
    scoped = scoped_tenant_or_403(principal)
    async with _async_session() as session:
        result = await session.execute(select(TestExecution).where(TestExecution.id == execution_id, TestExecution.tenant_id == scoped))
        ex = result.scalar_one_or_none()
        if ex is None:
            raise HTTPException(status_code=404, detail="Execution not found")

        ex.detected = body.detected
        ex.alert_id = body.alert_id
        ex.detection_latency_seconds = body.detection_latency_seconds
        await session.commit()
        await session.refresh(ex)
        return ex


# ---------------------------------------------------------------------------
# ATT&CK Coverage heatmap
# ---------------------------------------------------------------------------
@router.get("/api/v1/purple-team/coverage", tags=["Coverage"])
async def get_coverage(principal: ScopedPrincipal, tenant_id: uuid.UUID | None = None) -> dict:
    """Live coverage matrix computed from current execution history.

    Tactics are resolved by joining executions to the tenant's Atomic
    Red Team catalog (see ``compute_coverage_for_tenant``), so the
    heatmap is grouped by real ATT&CK tactics rather than the legacy
    placeholder.
    """
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        return await compute_coverage_for_tenant(session, scoped)


# ---------------------------------------------------------------------------
# Detection drift (w1-drift)
# ---------------------------------------------------------------------------
class DriftSnapshotOut(BaseModel):
    id: uuid.UUID
    captured_at: datetime
    trigger: str
    total_techniques: int
    tested_techniques: int
    detected_techniques: int
    overall_coverage: float

    model_config = {"from_attributes": True}


class DriftSnapshotDetail(DriftSnapshotOut):
    coverage: dict[str, Any]


@router.post(
    "/api/v1/purple-team/drift/snapshot",
    response_model=DriftSnapshotDetail,
    tags=["Drift"],
)
async def trigger_drift_snapshot(
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = None,
    trigger: str = Query(
        "manual",
        description="Why this snapshot was captured (manual|scheduled|post-run)",
    ),
) -> DetectionDriftSnapshot:
    """Capture a coverage snapshot on demand (e.g. after a purple-team run)."""
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        snap = await capture_snapshot(session, scoped, trigger=trigger)
        await session.commit()
        await session.refresh(snap)
        return snap


@router.get(
    "/api/v1/purple-team/drift/snapshots",
    response_model=list[DriftSnapshotOut],
    tags=["Drift"],
)
async def list_drift_snapshots(
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = None,
    limit: int = Query(50, le=200),
) -> list[DetectionDriftSnapshot]:
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        return await list_snapshots(session, scoped, limit=limit)


@router.get("/api/v1/purple-team/drift/latest", tags=["Drift"])
async def get_latest_drift(principal: ScopedPrincipal, tenant_id: uuid.UUID | None = None) -> dict:
    """Return the most recent snapshot plus delta-vs-previous for the heatmap."""
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        current, previous = await latest_two_snapshots(session, scoped)

    return {
        "current": _serialize_snapshot(current),
        "previous": _serialize_snapshot(previous),
        "drift": compute_drift(
            current.coverage if current else None,
            previous.coverage if previous else None,
        ),
    }


def _serialize_snapshot(snap: DetectionDriftSnapshot | None) -> dict | None:
    if snap is None:
        return None
    return {
        "id": str(snap.id),
        "captured_at": snap.captured_at.isoformat() if snap.captured_at else None,
        "trigger": snap.trigger,
        "total_techniques": snap.total_techniques,
        "tested_techniques": snap.tested_techniques,
        "detected_techniques": snap.detected_techniques,
        "overall_coverage": snap.overall_coverage,
        "coverage": snap.coverage,
    }


# ---------------------------------------------------------------------------
# Tabletop simulator
# ---------------------------------------------------------------------------
@router.post("/api/v1/purple-team/tabletop", response_model=TabletopOut, tags=["Tabletop"])
async def create_tabletop(body: TabletopCreateRequest, principal: ScopedPrincipal) -> TabletopSession:
    scoped = scoped_tenant_or_403(principal, body.tenant_id)
    async with _async_session() as session:
        ts = TabletopSession(
            tenant_id=scoped,
            name=body.name,
            description=body.description,
            scenario=body.scenario,
            technique_ids=body.technique_ids,
            created_by=body.created_by,
        )
        session.add(ts)
        await session.commit()
        await session.refresh(ts)
        return ts


@router.get("/api/v1/purple-team/tabletop", response_model=list[TabletopOut], tags=["Tabletop"])
async def list_tabletops(
    principal: ScopedPrincipal,
    tenant_id: uuid.UUID | None = None,
    status: str | None = Query(None),
) -> list[TabletopSession]:
    scoped = scoped_tenant_or_403(principal, tenant_id)
    async with _async_session() as session:
        q = select(TabletopSession).where(TabletopSession.tenant_id == scoped)
        if status:
            q = q.where(TabletopSession.status == status)
        q = q.order_by(TabletopSession.created_at.desc())
        result = await session.execute(q)
        return list(result.scalars().all())


@router.get(
    "/api/v1/purple-team/tabletop/{session_id}",
    response_model=TabletopOut,
    tags=["Tabletop"],
)
async def get_tabletop(session_id: uuid.UUID, principal: ScopedPrincipal) -> TabletopSession:
    scoped = scoped_tenant_or_403(principal)
    async with _async_session() as session:
        result = await session.execute(select(TabletopSession).where(TabletopSession.id == session_id, TabletopSession.tenant_id == scoped))
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return ts


@router.post(
    "/api/v1/purple-team/tabletop/{session_id}/findings",
    response_model=TabletopOut,
    tags=["Tabletop"],
)
async def add_finding(session_id: uuid.UUID, body: TabletopAddFindingRequest, principal: ScopedPrincipal) -> TabletopSession:
    scoped = scoped_tenant_or_403(principal)
    async with _async_session() as session:
        result = await session.execute(select(TabletopSession).where(TabletopSession.id == session_id, TabletopSession.tenant_id == scoped))
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")

        findings = list(ts.findings or [])
        findings.append(
            {
                "finding": body.finding,
                "severity": body.severity,
                "owner": body.owner,
                "added_at": datetime.now(UTC).isoformat(),
            }
        )
        ts.findings = findings
        ts.updated_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(ts)
        return ts


@router.patch(
    "/api/v1/purple-team/tabletop/{session_id}/complete",
    response_model=TabletopOut,
    tags=["Tabletop"],
)
async def complete_tabletop(session_id: uuid.UUID, principal: ScopedPrincipal) -> TabletopSession:
    scoped = scoped_tenant_or_403(principal)
    async with _async_session() as session:
        result = await session.execute(select(TabletopSession).where(TabletopSession.id == session_id, TabletopSession.tenant_id == scoped))
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")
        ts.status = "completed"
        ts.updated_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(ts)
        return ts
