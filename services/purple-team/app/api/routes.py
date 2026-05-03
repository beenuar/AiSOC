"""FastAPI routes for the Purple Team service."""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.models.purple_team import AtomicTest, Base, TabletopSession, TestExecution
from app.services.atomic_loader import load_atomics
from app.services.caldera_client import CalderaClient
from app.services.coverage import build_coverage_matrix

LOG = logging.getLogger(__name__)

router = APIRouter()

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
async def sync_atomics(tenant_id: uuid.UUID) -> dict:
    """Parse and upsert all Atomic Red Team tests from the local repo."""
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
    tenant_id: uuid.UUID,
    technique_id: str | None = Query(None),
    tactic: str | None = Query(None),
    platform: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[AtomicTest]:
    async with _async_session() as session:
        q = select(AtomicTest).where(AtomicTest.tenant_id == tenant_id)
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
async def run_atomic(body: RunAtomicRequest) -> TestExecution:
    """Create a pending execution record (actual execution is out-of-band)."""
    async with _async_session() as session:
        execution = TestExecution(
            tenant_id=body.tenant_id,
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
async def run_caldera_operation(body: CalderaRunRequest) -> TestExecution:
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
            tenant_id=body.tenant_id,
            source="caldera",
            technique_id="multi",
            test_name=body.operation_name,
            caldera_operation_id=op.get("id"),
            status="running",
            started_at=datetime.now(timezone.utc),
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
    tenant_id: uuid.UUID,
    technique_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
) -> list[TestExecution]:
    async with _async_session() as session:
        q = select(TestExecution).where(TestExecution.tenant_id == tenant_id)
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
async def report_detection(execution_id: uuid.UUID, body: ReportDetectionRequest) -> TestExecution:
    async with _async_session() as session:
        result = await session.execute(
            select(TestExecution).where(TestExecution.id == execution_id)
        )
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
async def get_coverage(tenant_id: uuid.UUID) -> dict:
    async with _async_session() as session:
        result = await session.execute(
            select(TestExecution).where(TestExecution.tenant_id == tenant_id)
        )
        executions = result.scalars().all()

    rows = [
        {
            "technique_id": ex.technique_id,
            "test_name": ex.test_name,
            "tactic": "unknown",
            "status": ex.status,
            "detected": ex.detected,
        }
        for ex in executions
    ]
    return build_coverage_matrix(rows)


# ---------------------------------------------------------------------------
# Tabletop simulator
# ---------------------------------------------------------------------------
@router.post(
    "/api/v1/purple-team/tabletop", response_model=TabletopOut, tags=["Tabletop"]
)
async def create_tabletop(body: TabletopCreateRequest) -> TabletopSession:
    async with _async_session() as session:
        ts = TabletopSession(
            tenant_id=body.tenant_id,
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


@router.get(
    "/api/v1/purple-team/tabletop", response_model=list[TabletopOut], tags=["Tabletop"]
)
async def list_tabletops(
    tenant_id: uuid.UUID,
    status: str | None = Query(None),
) -> list[TabletopSession]:
    async with _async_session() as session:
        q = select(TabletopSession).where(TabletopSession.tenant_id == tenant_id)
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
async def get_tabletop(session_id: uuid.UUID) -> TabletopSession:
    async with _async_session() as session:
        result = await session.execute(
            select(TabletopSession).where(TabletopSession.id == session_id)
        )
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")
        return ts


@router.post(
    "/api/v1/purple-team/tabletop/{session_id}/findings",
    response_model=TabletopOut,
    tags=["Tabletop"],
)
async def add_finding(session_id: uuid.UUID, body: TabletopAddFindingRequest) -> TabletopSession:
    async with _async_session() as session:
        result = await session.execute(
            select(TabletopSession).where(TabletopSession.id == session_id)
        )
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")

        findings = list(ts.findings or [])
        findings.append(
            {
                "finding": body.finding,
                "severity": body.severity,
                "owner": body.owner,
                "added_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        ts.findings = findings
        ts.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(ts)
        return ts


@router.patch(
    "/api/v1/purple-team/tabletop/{session_id}/complete",
    response_model=TabletopOut,
    tags=["Tabletop"],
)
async def complete_tabletop(session_id: uuid.UUID) -> TabletopSession:
    async with _async_session() as session:
        result = await session.execute(
            select(TabletopSession).where(TabletopSession.id == session_id)
        )
        ts = result.scalar_one_or_none()
        if ts is None:
            raise HTTPException(status_code=404, detail="Session not found")
        ts.status = "completed"
        ts.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(ts)
        return ts
