"""Tenant-isolation tests for the /hunts API (regression: C-2).

These tests don't boot the FastAPI app — they call the endpoint functions
directly with a mocked :class:`DBSession` and assert that **every** SQL
statement executed contains ``tenant_id = :tenant_id`` in its WHERE clause and
that the bound parameter set carries the calling user's tenant id.

The contract being protected: under no circumstances should an authenticated
caller be able to read or mutate a hunt belonging to a different tenant.
"""

from __future__ import annotations

import re
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import hunts as hunts_module
from app.api.v1.endpoints.hunts import (
    AddFindingsRequest,
    CreateHuntRequest,
    RunHuntRequest,
    UpdateHuntRequest,
    add_findings,
    create_hunt,
    get_hunt,
    list_hunts,
    list_runs,
    run_hunt,
    update_hunt,
)
from fastapi import HTTPException


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="hunter@example.com",
    )


def _row(**overrides: Any) -> MagicMock:
    row = MagicMock()
    row.id = overrides.get("id", uuid.uuid4())
    row.hunt_id = overrides.get("hunt_id", uuid.uuid4())
    row.title = overrides.get("title", "Hunt")
    row.hypothesis = overrides.get("hypothesis", "Beacons every 60s.")
    row.mitre_tactic = overrides.get("mitre_tactic")
    row.mitre_technique = overrides.get("mitre_technique")
    row.status = overrides.get("status", "draft")
    row.priority = overrides.get("priority", "medium")
    row.query_esql = overrides.get("query_esql")
    row.query_spl = overrides.get("query_spl")
    row.query_kql = overrides.get("query_kql")
    row.findings = overrides.get("findings", [])
    row.false_positive_rate = overrides.get("false_positive_rate")
    row.assigned_to = overrides.get("assigned_to")
    row.tags = overrides.get("tags", [])
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    row.created_at = overrides.get("created_at", now)
    row.updated_at = overrides.get("updated_at", now)
    row.completed_at = overrides.get("completed_at")
    row.created_by = overrides.get("created_by", "hunter@example.com")
    row.run_at = overrides.get("run_at", now)
    row.platform = overrides.get("platform", "esql")
    row.query_used = overrides.get("query_used")
    row.hit_count = overrides.get("hit_count", 0)
    row.result_sample = overrides.get("result_sample", [])
    row.duration_ms = overrides.get("duration_ms")
    row.error = overrides.get("error")
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    """Create a mock DBSession that returns the queued rows one execute() at a time."""
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        # Capture the SQL string and bound params for assertion.
        sql = str(clause)
        params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        db.executed.append((sql, params))
        try:
            payload = next(iterator)
        except StopIteration:
            payload = None
        result = MagicMock()
        if isinstance(payload, list):
            result.fetchall = MagicMock(return_value=payload)
            result.fetchone = MagicMock(return_value=payload[0] if payload else None)
        else:
            result.fetchone = MagicMock(return_value=payload)
            result.fetchall = MagicMock(return_value=[payload] if payload else [])
        return result

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every executed statement must filter by tenant_id and bind it."""
    assert executed, "expected at least one DB call"
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        # Statements touching aisoc_hunts/aisoc_hunt_runs must scope on tenant_id.
        if "aisoc_hunts" in normalized or "aisoc_hunt_runs" in normalized:
            assert "tenant_id" in normalized, f"tenant_id missing from SQL: {sql}"
            assert "tenant_id" in params, f"tenant_id not bound for SQL: {sql}"
            assert params["tenant_id"] == tenant_id, f"wrong tenant bound: {params['tenant_id']} != {tenant_id}"


# ────────────────────────────────────────────────────────────────────────────
# list_hunts
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_hunts_scopes_by_tenant() -> None:
    user = _user()
    db = _mk_db([[_row(title="A"), _row(title="B")]])
    result = await list_hunts(db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_hunts_with_filters_keeps_tenant_scope() -> None:
    user = _user()
    db = _mk_db([[]])
    await list_hunts(db=db, user=user, hunt_status="active", priority="high")
    sql, params = db.executed[0]
    assert "tenant_id = :tenant_id" in sql.replace("\n", " ")
    assert params["tenant_id"] == user.tenant_id
    assert params["status"] == "active"
    assert params["priority"] == "high"


# ────────────────────────────────────────────────────────────────────────────
# get / update / findings — must 404 cross-tenant
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_hunt_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_hunt(hunt_id=uuid.uuid4(), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_hunt_cross_tenant_returns_404() -> None:
    user = _user()
    # RETURNING * yields nothing → endpoint must 404 rather than silently succeed.
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await update_hunt(
            hunt_id=uuid.uuid4(),
            body=UpdateHuntRequest(title="rename"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    sql, params = db.executed[0]
    assert "tenant_id = :tenant_id" in sql.replace("\n", " ")
    assert params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_add_findings_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await add_findings(
            hunt_id=uuid.uuid4(),
            body=AddFindingsRequest(findings=[{"k": "v"}]),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# runs — list & execute
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_runs_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # parent check returns no row.
    with pytest.raises(HTTPException) as exc:
        await list_runs(hunt_id=uuid.uuid4(), db=db, user=user)
    assert exc.value.status_code == 404
    # The single executed query is the parent check; it must be scoped.
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_runs_returns_results_scoped() -> None:
    user = _user()
    hunt_id = uuid.uuid4()
    parent = _row(id=hunt_id)
    runs = [_row(hunt_id=hunt_id), _row(hunt_id=hunt_id)]
    db = _mk_db([parent, runs])
    result = await list_runs(hunt_id=hunt_id, db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Both statements must reference tenant_id.
    parent_sql, _ = db.executed[0]
    runs_sql, _ = db.executed[1]
    assert "tenant_id" in parent_sql
    assert "tenant_id" in runs_sql


@pytest.mark.asyncio
async def test_run_hunt_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await run_hunt(
            hunt_id=uuid.uuid4(),
            body=RunHuntRequest(platform="esql"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# create — both rows must carry tenant_id
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_hunt_binds_tenant_id(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    db = _mk_db([_row(title="phish recon")])

    async def _no_llm(*_a: Any, **_kw: Any) -> None:
        return None

    monkeypatch.setattr(hunts_module, "_generate_queries", _no_llm)
    result = await create_hunt(
        body=CreateHuntRequest(title="phish", hypothesis="suspicious DNS spikes"),
        db=db,
        user=user,
    )
    assert result.title == "phish recon"
    sql, params = db.executed[0]
    assert "tenant_id" in sql
    assert params["tenant_id"] == user.tenant_id
