"""Tenant-isolation tests for the /cases API (regression: P2-W1).

Mirrors ``test_hunts_tenant_isolation.py`` (Batch 2 / C-2): call the endpoint
functions directly with a mocked :class:`DBSession` and assert that **every**
SQL statement touching ``aisoc_cases``, ``aisoc_case_comments`` or
``aisoc_case_tasks`` filters on ``tenant_id = :tenant_id`` *and* binds the
caller's tenant id.

The contract being protected: under no circumstances should an authenticated
caller be able to read or mutate a case, comment, or task belonging to a
different tenant — including via the human-readable ``INC-NNN`` short id.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints.cases import (
    AddAlertsRequest,
    AddCommentRequest,
    CreateCaseRequest,
    CreateTaskRequest,
    UpdateCaseRequest,
    UpdateObservablesRequest,
    UpdateTaskRequest,
    _resolve_case_id,
    add_alerts,
    add_comment,
    case_timeline,
    create_case,
    create_task,
    evidence_report,
    get_case,
    list_cases,
    list_comments,
    list_tasks,
    update_case,
    update_observables,
    update_task,
)
from fastapi import HTTPException

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="analyst",
        email="analyst@example.com",
    )


def _case_row(**overrides: Any) -> MagicMock:
    """A row object shaped like a SQLAlchemy ``aisoc_cases`` result."""
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "case_number": "INC-001",
        "title": "Phish wave",
        "description": "Phishing detected",
        "severity": "high",
        "status": "new",
        "assignee": "analyst@example.com",
        "mitre_techniques": [],
        "alert_ids": [],
        "observable_graph": {},
        "evidence_chain": [],
        "compliance_frameworks": [],
        "opened_at": now,
        "triaged_at": None,
        "resolved_at": None,
        "closed_at": None,
        "created_at": now,
        "updated_at": now,
        "created_by": "analyst@example.com",
        "tags": {},
        "sla_due_at": None,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _task_row(**overrides: Any) -> MagicMock:
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "title": "Investigate sender",
        "status": "todo",
        "assignee": None,
        "due_at": None,
        "created_at": now,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _comment_row(**overrides: Any) -> MagicMock:
    row = MagicMock()
    now = datetime.now(UTC)
    defaults = {
        "id": uuid.uuid4(),
        "case_id": uuid.uuid4(),
        "author": "analyst@example.com",
        "body": "note body",
        "is_system": False,
        "created_at": now,
    }
    defaults.update(overrides)
    for k, v in defaults.items():
        setattr(row, k, v)
    return row


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock DBSession that returns queued rows one execute() at a time."""
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    iterator = iter(rows)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = str(clause)
        try:
            params = dict(clause.compile().params) if hasattr(clause, "compile") else {}
        except Exception:  # pragma: no cover — defensive: never crash the mock.
            params = {}
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


_TENANT_TABLES = ("aisoc_cases", "aisoc_case_comments", "aisoc_case_tasks")


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every executed statement against a tenant-owned table must scope on tenant_id."""
    assert executed, "expected at least one DB call"
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if any(table in normalized for table in _TENANT_TABLES):
            assert "tenant_id" in normalized, f"tenant_id missing from SQL: {sql}"
            assert "tenant_id" in params, f"tenant_id not bound for SQL: {sql}"
            assert params["tenant_id"] == tenant_id, f"wrong tenant bound: {params['tenant_id']} != {tenant_id}"


# ────────────────────────────────────────────────────────────────────────────
# _resolve_case_id — the human-readable INC-NNN form must be tenant-scoped
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_resolve_case_id_uuid_does_not_hit_db() -> None:
    """UUID identifiers are returned as-is; per-endpoint queries enforce tenant."""
    user = _user()
    db = _mk_db([])  # no rows; if a query fires, fetch will return None.
    target = uuid.uuid4()
    result = await _resolve_case_id(str(target), db, user.tenant_id)
    assert result == target
    # No DB round-trip needed for the UUID branch.
    assert db.executed == []


@pytest.mark.asyncio
async def test_resolve_case_id_case_number_scopes_by_tenant() -> None:
    user = _user()
    expected_id = uuid.uuid4()
    row = MagicMock()
    row.id = expected_id
    db = _mk_db([row])
    result = await _resolve_case_id("INC-001", db, user.tenant_id)
    assert result == expected_id
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id
    assert params["case_number"] == "INC-001"


@pytest.mark.asyncio
async def test_resolve_case_id_cross_tenant_returns_404() -> None:
    """Tenant B's INC-001 must 404 for tenant A even if it exists somewhere."""
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await _resolve_case_id("INC-001", db, user.tenant_id)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# list_cases / get_case
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_cases_scopes_by_tenant() -> None:
    user = _user()
    db = _mk_db([[_case_row(title="A"), _case_row(title="B")]])
    result = await list_cases(db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_cases_with_filters_keeps_tenant_scope() -> None:
    user = _user()
    db = _mk_db([[]])
    await list_cases(
        db=db,
        user=user,
        status_filter="investigating",
        severity="high",
        assignee="analyst@example.com",
    )
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id
    assert params["status"] == "investigating"
    assert params["severity"] == "high"


@pytest.mark.asyncio
async def test_get_case_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_case(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_get_case_returns_row_when_tenant_matches() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid)])
    result = await get_case(case_id=str(cid), db=db, user=user)
    assert result.id == cid
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# create_case — INSERT must carry tenant_id
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_case_binds_tenant_id() -> None:
    user = _user()
    db = _mk_db([_case_row(title="phish")])
    result = await create_case(
        body=CreateCaseRequest(title="phish wave", severity="high"),
        db=db,
        user=user,
    )
    assert result.title == "phish"
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "insert into aisoc_cases" in normalized
    assert "tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


# ────────────────────────────────────────────────────────────────────────────
# update_case / add_alerts / update_observables — cross-tenant must 404
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_case_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # SELECT existing returns no row.
    with pytest.raises(HTTPException) as exc:
        await update_case(
            case_id=str(uuid.uuid4()),
            body=UpdateCaseRequest(title="rename"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_case_scopes_update_statement() -> None:
    user = _user()
    cid = uuid.uuid4()
    existing = MagicMock()
    existing.status = "new"
    db = _mk_db([existing, _case_row(id=cid, title="renamed")])
    await update_case(
        case_id=str(cid),
        body=UpdateCaseRequest(title="renamed"),
        db=db,
        user=user,
    )
    # Two statements: SELECT then UPDATE. Both must scope by tenant_id.
    assert len(db.executed) >= 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    upd_sql, upd_params = db.executed[1]
    assert "update aisoc_cases" in re.sub(r"\s+", " ", upd_sql).lower()
    assert upd_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_add_alerts_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # UPDATE ... RETURNING * yields nothing.
    with pytest.raises(HTTPException) as exc:
        await add_alerts(
            case_id=str(uuid.uuid4()),
            body=AddAlertsRequest(alert_ids=[uuid.uuid4()]),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_observables_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await update_observables(
            case_id=str(uuid.uuid4()),
            body=UpdateObservablesRequest(nodes=[], edges=[]),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# Comments — INSERT and SELECT must both carry tenant_id
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_comment_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # parent case check returns no row.
    with pytest.raises(HTTPException) as exc:
        await add_comment(
            case_id=str(uuid.uuid4()),
            body=AddCommentRequest(body="hi"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_add_comment_inserts_with_tenant_id() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), _comment_row(case_id=cid)])
    await add_comment(
        case_id=str(cid),
        body=AddCommentRequest(body="manual note"),
        db=db,
        user=user,
    )
    # Two statements: parent SELECT then INSERT. Both must scope by tenant_id.
    assert len(db.executed) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    ins_sql, ins_params = db.executed[1]
    normalized = re.sub(r"\s+", " ", ins_sql).lower()
    assert "insert into aisoc_case_comments" in normalized
    assert ins_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_list_comments_scopes_by_tenant() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([[_comment_row(case_id=cid)]])
    result = await list_comments(case_id=str(cid), db=db, user=user)
    assert len(result) == 1
    _assert_tenant_scoped(db.executed, user.tenant_id)
    sql, params = db.executed[0]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "from aisoc_case_comments" in normalized
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


# ────────────────────────────────────────────────────────────────────────────
# Evidence / timeline
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_evidence_report_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await evidence_report(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_case_timeline_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await case_timeline(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_case_timeline_scopes_comments_and_tasks() -> None:
    user = _user()
    cid = uuid.uuid4()
    # Sequence: case row → comments → (no alerts loop) → tasks
    db = _mk_db(
        [
            _case_row(id=cid),
            [_comment_row(case_id=cid)],
            [_task_row()],
        ]
    )
    await case_timeline(case_id=str(cid), db=db, user=user)
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Verify both the comments and tasks queries reference their tenant column.
    joined = " | ".join(re.sub(r"\s+", " ", s).lower() for s, _ in db.executed)
    assert "from aisoc_case_comments" in joined
    assert "from aisoc_case_tasks" in joined


# ────────────────────────────────────────────────────────────────────────────
# Tasks
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_tasks_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])  # parent check returns no row.
    with pytest.raises(HTTPException) as exc:
        await list_tasks(case_id=str(uuid.uuid4()), db=db, user=user)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_tasks_scopes_by_tenant() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), [_task_row(), _task_row()]])
    result = await list_tasks(case_id=str(cid), db=db, user=user)
    assert len(result) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Second statement is the tasks SELECT; check it filters by tenant_id.
    sql, params = db.executed[1]
    normalized = re.sub(r"\s+", " ", sql).lower()
    assert "from aisoc_case_tasks" in normalized
    assert "tenant_id = :tenant_id" in normalized
    assert params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_create_task_cross_tenant_returns_404() -> None:
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await create_task(
            case_id=str(uuid.uuid4()),
            body=CreateTaskRequest(title="Investigate"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_create_task_inserts_with_tenant_id() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_case_row(id=cid), _task_row()])
    await create_task(
        case_id=str(cid),
        body=CreateTaskRequest(title="Investigate"),
        db=db,
        user=user,
    )
    assert len(db.executed) == 2
    _assert_tenant_scoped(db.executed, user.tenant_id)
    ins_sql, ins_params = db.executed[1]
    normalized = re.sub(r"\s+", " ", ins_sql).lower()
    assert "insert into aisoc_case_tasks" in normalized
    assert ins_params["tenant_id"] == user.tenant_id


@pytest.mark.asyncio
async def test_update_task_cross_tenant_returns_404() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([None])  # UPDATE ... RETURNING yields nothing.
    with pytest.raises(HTTPException) as exc:
        await update_task(
            case_id=str(cid),
            task_id=uuid.uuid4(),
            body=UpdateTaskRequest(status="in_progress"),
            db=db,
            user=user,
        )
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_update_task_scopes_update_statement() -> None:
    user = _user()
    cid = uuid.uuid4()
    db = _mk_db([_task_row()])
    await update_task(
        case_id=str(cid),
        task_id=uuid.uuid4(),
        body=UpdateTaskRequest(status="done"),
        db=db,
        user=user,
    )
    _assert_tenant_scoped(db.executed, user.tenant_id)
    upd_sql, upd_params = db.executed[0]
    normalized = re.sub(r"\s+", " ", upd_sql).lower()
    assert "update aisoc_case_tasks" in normalized
    assert upd_params["tenant_id"] == user.tenant_id
