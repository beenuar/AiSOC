"""Tests for the resolved->closed auto-close sweep.

Pure cutoff logic, plus behavioural coverage of :func:`sweep_auto_close`
itself over a mocked session: the claim UPDATE's predicates, custody
stamping, the human-raced row, fail-soft per case, the cross-tenant
precondition, and the off-by-default posture the carry settled on.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from app.core.config import settings
from app.db.cross_tenant import CrossTenantPreconditionError
from app.workers.case_auto_close import AutoCloseSweepResult, cutoff, run_forever, sweep_auto_close


def test_cutoff_is_days_in_the_past():
    now = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    assert cutoff(now, 7) == datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
    assert cutoff(now, 0) == now


def test_cutoff_selects_only_past_window():
    now = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)
    boundary = cutoff(now, 7)
    assert (now - timedelta(days=7)) <= boundary
    assert (now - timedelta(days=7, hours=-1)) > boundary


def test_sweep_result_defaults_empty():
    result = AutoCloseSweepResult()
    assert result.closed == 0
    assert result.failed == 0
    assert result.by_tenant == {}


@pytest.mark.parametrize("days", [1, 7, 30])
def test_cutoff_monotonic_in_days(days):
    now = datetime(2026, 11, 16, tzinfo=UTC)
    assert cutoff(now, days) == now - timedelta(days=days)


# ─────────────────────────────────────────────────────────────────────────────
# Behavioural coverage (carry review additions)
# ─────────────────────────────────────────────────────────────────────────────

_NOW = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def _due_row(tenant: uuid.UUID, days_resolved: int = 10) -> dict[str, Any]:
    return {
        "id": uuid.uuid4(),
        "tenant_id": tenant,
        "case_number": "INC-042",
        "resolved_at": _NOW - timedelta(days=days_resolved),
    }


def _mk_db(
    rows: list[dict[str, Any]],
    *,
    bound_tenant: str | None = None,
    close_rowcounts: list[int] | None = None,
    close_raises: list[bool] | None = None,
) -> MagicMock:
    """A session double that answers the sweep's exact call sequence.

    ``scalar`` serves the cross-tenant probe first, then one evidence-chain
    read per successfully claimed case. ``execute`` serves the tenant
    enumeration, then per tenant the due SELECT (filtered on the bound
    ``tenant_id``, the way the real predicate behaves), then per case the
    claim UPDATE (scripted rowcount or raise) and the custody UPDATE.
    """
    db = MagicMock()
    # Annotate the list, then attach it: annotating `db.executed` directly is
    # a mypy `misc` error (declaration on a non-self attribute).
    executed: list[str] = []
    db.executed = executed
    tenants = sorted({row["tenant_id"] for row in rows}, key=str)
    rowcounts = list(close_rowcounts or [1] * len(rows))
    raises = list(close_raises or [False] * len(rows))

    scalars: list[Any] = [bound_tenant] + [[] for _ in rows]
    db.scalar = AsyncMock(side_effect=scalars)

    async def _execute(clause: Any, *args: Any, **kwargs: Any) -> MagicMock:
        sql = re.sub(r"\s+", " ", str(clause)).strip().lower()
        db.executed.append(sql)
        result = MagicMock()
        if sql.startswith("select id from tenants"):
            result.scalars.return_value.all.return_value = tenants
            return result
        if sql.startswith("select id, tenant_id"):
            params = args[0] if args else kwargs.get("parameters", {})
            tenant = params.get("tenant_id") if isinstance(params, dict) else None
            result.mappings.return_value.all.return_value = [r for r in rows if r["tenant_id"] == tenant]
            return result
        if sql.startswith("update aisoc_cases set status"):
            if raises and raises.pop(0):
                raise RuntimeError("deadlock, say")
            result.rowcount = rowcounts.pop(0) if rowcounts else 1
            return result
        return result  # custody UPDATE

    db.execute = AsyncMock(side_effect=_execute)
    db.commit = AsyncMock()
    db.rollback = AsyncMock()
    return db


@pytest.mark.asyncio
async def test_sweep_closes_due_cases_and_stamps_custody() -> None:
    tenant_a, tenant_b = uuid.uuid4(), uuid.uuid4()
    rows = [_due_row(tenant_a), _due_row(tenant_b)]
    db = _mk_db(rows)

    result = await sweep_auto_close(db, now=_NOW, days=7, limit=100)

    assert result.closed == 2
    assert result.failed == 0
    assert result.by_tenant == {str(tenant_a): 1, str(tenant_b): 1}
    assert db.commit.await_count == 2, "each close must be its own transaction"

    close_sqls = [s for s in db.executed if s.startswith("update aisoc_cases set status")]
    assert len(close_sqls) == 2
    for sql in close_sqls:
        # The claim predicates: only a case still sitting resolved, in its
        # own tenant, may be promoted — a human's concurrent reopen or close
        # wins the race by construction.
        assert "status = 'resolved'" in sql
        assert "tenant_id = :tenant_id" in sql
        assert "closed_at = :now" in sql

    # The due SELECT itself carries the tenant predicate (the sweep visits
    # each tenant under its own id — no cross-tenant read of aisoc_cases).
    due_sqls = [s for s in db.executed if s.startswith("select id, tenant_id")]
    assert due_sqls, "expected per-tenant due SELECTs"
    for sql in due_sqls:
        assert "tenant_id = :tenant_id" in sql

    custody_sqls = [s for s in db.executed if "evidence_chain = cast" in s]
    assert len(custody_sqls) == 2, "every system close must land in the custody chain"


@pytest.mark.asyncio
async def test_a_human_raced_row_is_skipped_not_failed() -> None:
    rows = [_due_row(uuid.uuid4())]
    db = _mk_db(rows, close_rowcounts=[0])

    result = await sweep_auto_close(db, now=_NOW, days=7, limit=100)

    assert result.closed == 0
    assert result.failed == 0
    assert db.commit.await_count == 0
    assert not [s for s in db.executed if "evidence_chain = cast" in s]


@pytest.mark.asyncio
async def test_one_bad_row_does_not_end_the_sweep() -> None:
    tenant = uuid.uuid4()
    rows = [_due_row(tenant), _due_row(tenant)]
    db = _mk_db(rows, close_raises=[True, False])

    result = await sweep_auto_close(db, now=_NOW, days=7, limit=100)

    assert result.failed == 1
    assert result.closed == 1
    assert db.rollback.await_count == 1


@pytest.mark.asyncio
async def test_a_tenant_bound_session_is_refused() -> None:
    """A session that silently bound one tenant would close only that
    tenant's cases and report success — the precondition is asserted."""
    db = _mk_db([], bound_tenant=str(uuid.uuid4()))
    with pytest.raises(CrossTenantPreconditionError):
        await sweep_auto_close(db, now=_NOW, days=7, limit=100)
    assert not [s for s in db.executed if s.startswith("update")]


@pytest.mark.asyncio
async def test_disabled_worker_exits_immediately(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "CASE_AUTO_CLOSE_ENABLED", False)
    await run_forever()  # returns, rather than looping — would hang the test otherwise


def test_the_sweep_ships_off_by_default() -> None:
    """The carry's governance decision, pinned: closing cases changes what
    every closure metric reports, so an upgrade must not start doing it
    silently. The operator turns the janitor on."""
    assert settings.model_fields["CASE_AUTO_CLOSE_ENABLED"].default is False
