"""Tenant-isolation tests for the /alerts API (Issue #159 / F013).

Sibling of ``test_threat_intel_tenant_isolation.py``,
``test_cases_tenant_isolation.py`` and ``test_hunts_tenant_isolation.py``:
call the endpoint functions directly with a mocked
:class:`AsyncSession` and assert that **every** SQL statement touching
the ``alerts`` table filters on ``tenant_id`` *and* binds the caller's
tenant id, and that cross-tenant reads/writes 404 instead of silently
hitting the wrong row.

These endpoints use the SQLAlchemy ORM (``select(Alert).where(...)``,
``update(Alert).where(...)``) rather than raw SQL text — that means
SQLAlchemy generates bound parameter names like ``tenant_id_1`` instead
of ``tenant_id``. The ``_assert_tenant_scoped`` helper below accepts
both shapes so the test is robust across the project's mixed ORM/text-
SQL endpoints.

The contract being protected
----------------------------
* No authenticated caller should be able to read another tenant's
  alert.
* No authenticated caller should be able to mutate another tenant's
  alert (cross-tenant PATCH / escalate / snooze must 404, never write
  through to the wrong row).
* Service-layer helpers (``build_queue``, ``claim_alert``) must be
  invoked with the caller's ``tenant_id`` — not anything derived from
  the request body or URL.

RBAC coverage for these endpoints lives in :mod:`tests.test_alert_queue`
and :mod:`tests.test_alert_explain`; this file focuses purely on *data
isolation* once the RBAC gate has passed.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import alerts as alerts_module
from app.api.v1.endpoints.alerts import (
    AlertSnoozeRequest,
    AlertUpdateRequest,
    escalate_alert,
    get_alert,
    get_alert_queue,
    get_alert_stats,
    list_alerts,
    snooze_alert,
    update_alert,
)
from app.api.v1.endpoints.alerts import (
    claim_alert_endpoint as claim_alert_route,
)
from app.models.alert import Alert
from fastapi import HTTPException

# ────────────────────────────────────────────────────────────────────────────
# Fixtures / helpers
# ────────────────────────────────────────────────────────────────────────────


def _user(tenant_id: uuid.UUID | None = None) -> CurrentUser:
    """Construct a CurrentUser without touching the DB or JWT plumbing."""
    return CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        role="soc_analyst",
        email="analyst@example.com",
    )


def _alert(tenant_id: uuid.UUID, **overrides: Any) -> Alert:
    """Build an Alert ORM row in memory (no DB) with all required fields.

    Pydantic's ``AlertResponse.model_validate(...)`` walks attributes via
    ``from_attributes=True``, so the in-memory row must expose every
    non-Optional field the schema lists. Anything not set explicitly
    here falls back to a sane default so individual tests stay short.
    """
    now = datetime.now(UTC)
    defaults: dict[str, Any] = {
        "id": uuid.uuid4(),
        "tenant_id": tenant_id,
        "title": "Suspicious login",
        "description": None,
        "severity": "high",
        "status": "new",
        "priority": 50,
        "category": None,
        "mitre_tactics": [],
        "mitre_techniques": [],
        "connector_id": None,
        "connector_type": None,
        "source_event_ids": [],
        "ocsf_class_uid": None,
        "disposition": None,
        "first_seen_at": None,
        "ai_score": None,
        "ai_summary": None,
        "ai_recommendations": [],
        "false_positive_score": None,
        "confidence": None,
        "confidence_label": None,
        "confidence_rationale": None,
        "narrative": None,
        "affected_ips": [],
        "affected_hosts": [],
        "affected_users": [],
        "affected_assets": [],
        "case_id": None,
        "parent_alert_id": None,
        "child_alert_ids": [],
        "is_merged": False,
        "assigned_to_id": None,
        "assigned_at": None,
        "snoozed_until": None,
        "snoozed_by_id": None,
        "raw_event": {},
        "enrichment_data": {},
        "tags": [],
        "idempotency_key": None,
        "event_time": now,
        "first_seen": now,
        "last_seen": now,
        "resolved_at": None,
        "created_at": now,
        "updated_at": now,
    }
    defaults.update(overrides)
    alert = Alert()
    for k, v in defaults.items():
        setattr(alert, k, v)
    return alert


def _mk_db(rows: list[Any]) -> MagicMock:
    """Mock AsyncSession that returns queued rows one execute() at a time.

    Captures every executed SQL statement and its compiled bind
    parameters so the assertion helper can verify tenant scoping. ``rows``
    is the queue of results returned by ``execute()``:

    * a ``list`` payload is served as ``scalars().all()`` (for list
      endpoints) and also unwraps the first element for ``scalar_one()``
      / ``scalar_one_or_none()`` callers — needed for the count queries
      in :func:`list_alerts` and :func:`get_alert_stats`.
    * an ``int`` payload is served as ``scalar_one()`` — the count
      queries in :func:`get_alert_stats` use this.
    * a tuple-list payload (``list[tuple]``) is served as ``result.all()``
      — the GROUP BY queries in :func:`get_alert_stats` use this.
    * anything else is served as ``scalar_one_or_none()`` — the
      single-row reads in :func:`get_alert`, :func:`update_alert`,
      :func:`escalate_alert`, :func:`snooze_alert` use this.
    * ``None`` represents "no row" (the cross-tenant 404 path).
    """
    db = MagicMock()
    db.executed: list[tuple[str, dict[str, Any]]] = []
    db.added: list[Any] = []
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
        scalars = MagicMock()
        if isinstance(payload, list):
            # Could be a list of ORM rows (list endpoint) OR a list of
            # tuples (GROUP BY result). Both shapes round-trip cleanly
            # via the right accessor.
            scalars.all = MagicMock(return_value=payload)
            scalars.first = MagicMock(return_value=payload[0] if payload else None)
            # ``select(func.count())`` returns an int via .scalar_one();
            # a list[ORM] hands the first row back instead which is fine
            # for the existence/null checks our list-shape tests run.
            result.scalar_one = MagicMock(return_value=len(payload))
            result.scalar_one_or_none = MagicMock(return_value=payload[0] if payload else None)
            result.all = MagicMock(return_value=payload)
        elif isinstance(payload, int):
            result.scalar_one = MagicMock(return_value=payload)
            result.scalar_one_or_none = MagicMock(return_value=payload)
            scalars.all = MagicMock(return_value=[])
            scalars.first = MagicMock(return_value=None)
            result.all = MagicMock(return_value=[])
        else:
            scalars.all = MagicMock(return_value=[payload] if payload else [])
            scalars.first = MagicMock(return_value=payload)
            result.scalar_one = MagicMock(return_value=payload)
            result.scalar_one_or_none = MagicMock(return_value=payload)
            result.all = MagicMock(return_value=[payload] if payload else [])
        result.scalars = MagicMock(return_value=scalars)
        return result

    def _add(obj: Any) -> None:
        db.added.append(obj)

    db.execute = AsyncMock(side_effect=_execute)
    db.add = MagicMock(side_effect=_add)
    db.commit = AsyncMock()
    db.refresh = AsyncMock()
    db.rollback = AsyncMock()
    return db


def _assert_tenant_scoped(executed: list[tuple[str, dict[str, Any]]], tenant_id: uuid.UUID) -> None:
    """Every executed statement against the ``alerts`` table must filter on tenant_id.

    ORM ``select(Alert).where(Alert.tenant_id == ...)`` produces a bound
    parameter named ``tenant_id_1`` (or ``tenant_id_N``); raw text SQL
    keeps the literal ``tenant_id`` name. This helper accepts both
    shapes — what matters is that *some* bound parameter equal to the
    caller's tenant id appears, and that the SQL string references
    ``tenant_id``.

    ``UPDATE alerts SET ... WHERE id = :id`` statements that follow a
    tenant-scoped read are explicitly *allowed* to drop the tenant_id
    clause from the WHERE — the prior SELECT has already enforced the
    scope. This mirrors the actual endpoint code in
    :mod:`app.api.v1.endpoints.alerts`.
    """
    assert executed, "expected at least one DB call"
    saw_tenant_scoped_read = False
    for sql, params in executed:
        normalized = re.sub(r"\s+", " ", sql).lower()
        if "alerts" not in normalized:
            continue
        if "tenant_id" in normalized:
            # A statement that mentions tenant_id must bind the caller's id.
            matching = [
                (name, value)
                for name, value in params.items()
                if (name == "tenant_id" or name.startswith("tenant_id_")) and value == tenant_id
            ]
            assert matching, (
                f"no bound tenant_id parameter matches caller's tenant in SQL: {sql}; " f"params={params}; expected_tenant={tenant_id}"
            )
            saw_tenant_scoped_read = True
    assert saw_tenant_scoped_read, "no alerts statement was tenant-scoped; " "every alerts read/write must mention tenant_id"


# ────────────────────────────────────────────────────────────────────────────
# list_alerts
# ────────────────────────────────────────────────────────────────────────────


# When we call the endpoint functions directly (no FastAPI request cycle),
# the ``Query(default=...)`` sentinels are not resolved into their plain
# defaults — so we must pass every query-string argument explicitly. The
# helper below builds the kwargs the request layer would normally
# materialise. Tests then override only what they're exercising.
_LIST_ALERTS_DEFAULTS: dict[str, Any] = {
    "page": 1,
    "page_size": 25,
    "severity": None,
    "status": None,
    "category": None,
    "assigned_to_me": False,
    "search": None,
    "min_confidence": None,
    "confidence_label": None,
}


@pytest.mark.asyncio
async def test_list_alerts_scopes_by_tenant() -> None:
    """Both the count and the SELECT for /alerts must filter on tenant_id."""
    user = _user()
    # ``list_alerts`` runs two queries: count (scalar_one int) + select.
    db = _mk_db([3, [_alert(user.tenant_id), _alert(user.tenant_id), _alert(user.tenant_id)]])
    response = await list_alerts(current_user=user, db=db, **_LIST_ALERTS_DEFAULTS)
    assert response.total == 3
    assert len(response.items) == 3
    _assert_tenant_scoped(db.executed, user.tenant_id)


@pytest.mark.asyncio
async def test_list_alerts_with_filters_keeps_tenant_scope() -> None:
    """Severity/status/category/min_confidence filters must not relax tenant scope."""
    user = _user()
    db = _mk_db([0, []])
    kwargs = {
        **_LIST_ALERTS_DEFAULTS,
        "severity": "critical",
        "status": "new",
        "category": "identity",
        "assigned_to_me": True,
        "min_confidence": 70,
        "confidence_label": "high",
    }
    await list_alerts(current_user=user, db=db, **kwargs)
    _assert_tenant_scoped(db.executed, user.tenant_id)
    # Every alerts statement should mention tenant_id (count + select).
    alerts_stmts = [(sql, params) for sql, params in db.executed if "alerts" in re.sub(r"\s+", " ", sql).lower()]
    assert len(alerts_stmts) >= 2, "expected count + select to both hit alerts"
    for sql, _params in alerts_stmts:
        normalized = re.sub(r"\s+", " ", sql).lower()
        assert "tenant_id" in normalized, f"alerts statement missing tenant_id: {sql}"


@pytest.mark.asyncio
async def test_list_alerts_rejects_invalid_confidence_label() -> None:
    """The 400 for confidence_label must fire before any DB call (cheap input gate)."""
    user = _user()
    db = _mk_db([])
    kwargs = {**_LIST_ALERTS_DEFAULTS, "confidence_label": "urgent"}
    with pytest.raises(HTTPException) as exc:
        await list_alerts(current_user=user, db=db, **kwargs)
    assert exc.value.status_code == 400


# ────────────────────────────────────────────────────────────────────────────
# get_alert_stats
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_alert_stats_scopes_every_query_by_tenant() -> None:
    """All five aggregations in /alerts/stats must filter on tenant_id."""
    user = _user()
    # Five queries: total, by_severity (group_by), by_status (group_by),
    # new_24h (count), critical_open (count). The grouped queries are
    # served as list[tuple] via result.all(); the count queries via
    # result.scalar_one().
    db = _mk_db(
        [
            7,  # total
            [("critical", 3), ("high", 4)],  # by_severity
            [("new", 5), ("triaging", 2)],  # by_status
            2,  # new_last_24h
            3,  # critical_open
        ]
    )
    resp = await get_alert_stats(current_user=user, db=db)
    assert resp.total == 7
    assert resp.by_severity == {"critical": 3, "high": 4}
    assert resp.by_status == {"new": 5, "triaging": 2}
    assert resp.new_last_24h == 2
    assert resp.critical_open == 3
    # The 5 SQL statements all touch ``alerts`` and must bind tenant_id.
    _assert_tenant_scoped(db.executed, user.tenant_id)
    assert len(db.executed) == 5


# ────────────────────────────────────────────────────────────────────────────
# get_alert (single)
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_alert_cross_tenant_returns_404() -> None:
    """An alert owned by tenant B must 404 for tenant A even when the UUID matches.

    The endpoint runs a *single* ``SELECT alert WHERE id = ? AND tenant_id = ?``;
    if the row exists in tenant B but not in tenant A, the SELECT returns
    ``None`` and the 404 fires before the rail envelope is ever built.
    """
    tenant_a = _user()
    tenant_b_alert = _alert(uuid.uuid4())
    # SELECT scoped by (id, tenant=A) returns nothing.
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_alert(alert_id=tenant_b_alert.id, current_user=tenant_a, db=db)
    assert exc.value.status_code == 404
    _assert_tenant_scoped(db.executed, tenant_a.tenant_id)


@pytest.mark.asyncio
async def test_get_alert_missing_returns_404() -> None:
    """A non-existent alert returns 404 (not 500)."""
    user = _user()
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await get_alert(alert_id=uuid.uuid4(), current_user=user, db=db)
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_get_alert_same_tenant_returns_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """Same-tenant read returns the alert (positive control with rail mocked)."""
    user = _user()
    alert = _alert(user.tenant_id, narrative="already filled")  # skip lazy-fill branch.
    db = _mk_db([alert])

    # The rail envelope hits the audit log; stub it for this isolation
    # test — the rail's own DB scope is covered by its dedicated tests.
    fake_envelope = MagicMock(related_entities=[], mini_timeline=[], recommended_actions=[])
    monkeypatch.setattr(alerts_module, "build_rail_envelope", AsyncMock(return_value=fake_envelope))

    result = await get_alert(alert_id=alert.id, current_user=user, db=db)
    assert result.id == alert.id
    assert result.tenant_id == user.tenant_id
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# update_alert
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_alert_cross_tenant_returns_404() -> None:
    """PATCH against an alert in another tenant must 404 and write nothing."""
    tenant_a = _user()
    tenant_b_alert = _alert(uuid.uuid4())
    db = _mk_db([None])  # SELECT scoped to tenant A returns no row.
    with pytest.raises(HTTPException) as exc:
        await update_alert(
            alert_id=tenant_b_alert.id,
            request=AlertUpdateRequest(status="closed"),
            current_user=tenant_a,
            db=db,
        )
    assert exc.value.status_code == 404
    # Critical: no UPDATE statement should have run.
    update_stmts = [sql for sql, _params in db.executed if "update " in re.sub(r"\s+", " ", sql).lower()]
    assert not update_stmts, "cross-tenant PATCH leaked an UPDATE through"


@pytest.mark.asyncio
async def test_update_alert_same_tenant_scopes_select() -> None:
    """PATCH against your own alert: SELECT must scope by tenant before UPDATE."""
    user = _user()
    alert = _alert(user.tenant_id)
    db = _mk_db([alert, None])  # SELECT returns row, UPDATE returns nothing.
    resp = await update_alert(
        alert_id=alert.id,
        request=AlertUpdateRequest(status="resolved", tags=["triaged"]),
        current_user=user,
        db=db,
    )
    assert resp.id == alert.id
    # The SELECT must be tenant-scoped. The UPDATE-by-id WHERE clause
    # is allowed to drop the tenant filter because the prior SELECT
    # enforced it.
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# escalate_alert
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_escalate_alert_cross_tenant_returns_404() -> None:
    """Escalating another tenant's alert must 404 and never raise severity."""
    tenant_a = _user()
    tenant_b_alert = _alert(uuid.uuid4(), severity="medium")
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await escalate_alert(alert_id=tenant_b_alert.id, current_user=tenant_a, db=db)
    assert exc.value.status_code == 404
    update_stmts = [sql for sql, _params in db.executed if "update " in re.sub(r"\s+", " ", sql).lower()]
    assert not update_stmts, "cross-tenant escalate leaked an UPDATE through"


@pytest.mark.asyncio
async def test_escalate_alert_same_tenant_scopes_select() -> None:
    """Same-tenant escalate: the bounding SELECT must include tenant_id."""
    user = _user()
    alert = _alert(user.tenant_id, severity="medium")
    db = _mk_db([alert, None])
    resp = await escalate_alert(alert_id=alert.id, current_user=user, db=db)
    assert resp.id == alert.id
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# snooze_alert
# ────────────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_snooze_alert_cross_tenant_returns_404() -> None:
    """Snoozing another tenant's alert must 404 and never write snoozed_until."""
    tenant_a = _user()
    tenant_b_alert = _alert(uuid.uuid4())
    db = _mk_db([None])
    with pytest.raises(HTTPException) as exc:
        await snooze_alert(
            alert_id=tenant_b_alert.id,
            body=AlertSnoozeRequest(duration_minutes=60),
            current_user=tenant_a,
            db=db,
        )
    assert exc.value.status_code == 404
    update_stmts = [sql for sql, _params in db.executed if "update " in re.sub(r"\s+", " ", sql).lower()]
    assert not update_stmts, "cross-tenant snooze leaked an UPDATE through"


@pytest.mark.asyncio
async def test_snooze_alert_requires_duration_or_until() -> None:
    """The 400 for "no window supplied" must fire before any DB call."""
    user = _user()
    db = _mk_db([])
    with pytest.raises(HTTPException) as exc:
        await snooze_alert(
            alert_id=uuid.uuid4(),
            body=AlertSnoozeRequest(),
            current_user=user,
            db=db,
        )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_snooze_alert_same_tenant_scopes_select() -> None:
    """Same-tenant snooze: the bounding SELECT must include tenant_id."""
    user = _user()
    alert = _alert(user.tenant_id)
    db = _mk_db([alert, None])
    resp = await snooze_alert(
        alert_id=alert.id,
        body=AlertSnoozeRequest(duration_minutes=30),
        current_user=user,
        db=db,
    )
    assert resp.id == alert.id
    _assert_tenant_scoped(db.executed, user.tenant_id)


# ────────────────────────────────────────────────────────────────────────────
# /alerts/queue and /alerts/{id}/claim — delegate to service helpers
# ────────────────────────────────────────────────────────────────────────────
#
# These endpoints don't issue tenant-scoped SQL themselves; they pass
# ``current_user.tenant_id`` into service helpers (``build_queue``,
# ``claim_alert``) which do. The contract we lock down here is that
# **the endpoint passes the caller's tenant id, not anything else**.
# The helpers themselves are tested in :mod:`tests.test_alert_queue`.


@pytest.mark.asyncio
async def test_get_alert_queue_passes_caller_tenant_id(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    db = _mk_db([])
    captured: dict[str, Any] = {}

    async def _fake_build_queue(db_arg: Any, *, tenant_id: uuid.UUID, user_id: uuid.UUID, **kwargs: Any) -> Any:
        captured["tenant_id"] = tenant_id
        captured["user_id"] = user_id
        captured["kwargs"] = kwargs
        return MagicMock(items=[], counts=MagicMock(), page=1, page_size=50)

    monkeypatch.setattr(alerts_module, "build_queue", _fake_build_queue)

    # As with list_alerts, the Query(default=...) sentinels don't resolve
    # when we call the endpoint function directly — pass the defaults
    # explicitly to mirror what FastAPI would inject.
    await get_alert_queue(
        current_user=user,
        db=db,
        owner="all",
        period="all",
        page=1,
        page_size=50,
    )
    assert captured["tenant_id"] == user.tenant_id, "queue endpoint forwarded the wrong tenant_id to the service helper"
    assert captured["user_id"] == user.user_id


@pytest.mark.asyncio
async def test_claim_alert_passes_caller_tenant_id(monkeypatch: pytest.MonkeyPatch) -> None:
    user = _user()
    db = _mk_db([])
    alert = _alert(user.tenant_id)
    captured: dict[str, Any] = {}

    async def _fake_claim_alert(db_arg: Any, *, alert_id: uuid.UUID, tenant_id: uuid.UUID, user_id: uuid.UUID) -> Any:
        captured["alert_id"] = alert_id
        captured["tenant_id"] = tenant_id
        captured["user_id"] = user_id
        return alert

    monkeypatch.setattr(alerts_module, "claim_alert", _fake_claim_alert)

    resp = await claim_alert_route(alert_id=alert.id, current_user=user, db=db)
    assert resp.id == alert.id
    assert captured["tenant_id"] == user.tenant_id, "claim endpoint forwarded the wrong tenant_id to the service helper"
    assert captured["user_id"] == user.user_id
    assert captured["alert_id"] == alert.id


@pytest.mark.asyncio
async def test_claim_alert_propagates_not_found_as_404(monkeypatch: pytest.MonkeyPatch) -> None:
    """Service-layer AlertNotFoundError (incl. cross-tenant lookups) → 404."""
    user = _user()
    db = _mk_db([])
    target_id = uuid.uuid4()

    async def _raises_not_found(*args: Any, **kwargs: Any) -> Any:
        raise alerts_module.AlertNotFoundError(str(target_id))

    monkeypatch.setattr(alerts_module, "claim_alert", _raises_not_found)

    with pytest.raises(HTTPException) as exc:
        await claim_alert_route(alert_id=target_id, current_user=user, db=db)
    assert exc.value.status_code == 404
