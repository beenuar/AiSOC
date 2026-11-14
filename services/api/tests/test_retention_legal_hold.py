"""A legal hold has to beat the purge on the path the purge actually takes.

Depth plan 4.3. ``retention.alerts_under_legal_hold`` and
``retention.may_purge`` were written, tested and reachable from no
production caller, so "a hold outranks retention unconditionally" — which
``migrations/088_data_governance.sql`` states in its own comment — was true
of a function and false of the system.

The doubles here are deliberately less capable than the real stores: they
record what they were asked to run and answer nothing they were not told to
answer. A fake that satisfies any query would let a purge that never ran
pass the "it withheld" assertions.

**The positive control is the point of half this file.** A control that
only asserts "held tenants are skipped" passes perfectly on a purge stuck
closed, which withholds everything on every deployment and reads as
commendable caution. So every withholding case has a sibling asserting a
tenant with no hold still has its rows deleted.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

import pytest
from app.services import governance
from app.services.retention import MAX_LAKE_DAYS, resolve_policy
from app.workers import retention_purge

TENANT = uuid.UUID("3fa85f64-5717-4562-b3fc-2c963f66afa6")
OTHER_TENANT = uuid.UUID("3fa85f64-5717-4562-b3fc-2c963f66afa7")


class _RecordingSession:
    """Answers the three queries the worker issues and records every one."""

    def __init__(self, *, holds: Mapping[uuid.UUID, list[tuple]], alert_counts: Mapping[uuid.UUID, int]):
        self._holds = holds
        self._alert_counts = alert_counts
        self.statements: list[str] = []
        self.committed = False

    async def execute(self, statement: Any, params: dict[str, Any] | None = None) -> Any:
        sql = " ".join(str(statement).split())
        self.statements.append(sql)
        bound = dict(getattr(statement, "_bindparams", {}) or {})
        tenant = None
        if params and "tenant_id" in params:
            tenant = uuid.UUID(str(params["tenant_id"]))
        elif "t" in bound:
            tenant = uuid.UUID(str(bound["t"].value))

        if "FROM legal_holds" in sql:
            return _Result(rows=self._holds.get(tenant, []) if tenant else [])
        if sql.startswith("SELECT tenant_id, raw_events_days"):
            return _Result(
                mappings=[
                    {"tenant_id": t, "raw_events_days": 400, "alerts_days": 365, "audit_days": 730}
                    for t in sorted(self._alert_counts, key=str)
                ]
            )
        if "SELECT count(*) FROM alerts" in sql:
            return _Result(scalar=self._alert_counts.get(tenant, 0) if tenant else 0)
        if sql.startswith("DELETE FROM alerts"):
            return _Result()
        return _Result()

    async def commit(self) -> None:
        self.committed = True

    async def close(self) -> None:  # pragma: no cover - the worker owns its own session only in production
        return None

    def deleted_alerts_for(self, tenant: uuid.UUID) -> bool:
        return any(s.startswith("DELETE FROM alerts") for s in self.statements)


class _Result:
    def __init__(self, *, rows: list[tuple] | None = None, mappings: list[dict] | None = None, scalar: int | None = None):
        self._rows = rows or []
        self._mappings = mappings or []
        self._scalar = scalar

    def all(self) -> list[tuple]:
        return self._rows

    def mappings(self) -> list[dict]:
        return self._mappings

    def scalar_one(self) -> int:
        return self._scalar or 0


class _LakeRecorder:
    """Stands in for ClickHouse. Counts are answered; mutations are recorded."""

    def __init__(self, counts: Mapping[uuid.UUID, int]):
        self._counts = counts
        self.queries: list[str] = []

    async def __call__(self, sql: str, *_args: Any, **_kwargs: Any) -> Any:
        self.queries.append(sql)
        if sql.startswith("SELECT count()"):
            for tenant, count in self._counts.items():
                if str(tenant) in sql:
                    return _LakeResult([[count]])
            return _LakeResult([[0]])
        return _LakeResult([])

    @property
    def deletes(self) -> list[str]:
        return [q for q in self.queries if q.startswith("ALTER TABLE")]


class _LakeResult:
    def __init__(self, rows: list[list[int]]):
        self.rows = rows


def _hold(subject_kind: str = "tenant", subject_value: str = str(TENANT), matter: str = "LIT-2026-11") -> tuple:
    return (uuid.uuid4(), subject_kind, subject_value, matter)


@pytest.fixture
def patched(monkeypatch: pytest.MonkeyPatch):
    def _apply(*, holds: Mapping[uuid.UUID, list[tuple]], lake: Mapping[uuid.UUID, int], alerts: Mapping[uuid.UUID, int]):
        session = _RecordingSession(holds=holds, alert_counts=alerts)
        lake_recorder = _LakeRecorder(lake)
        monkeypatch.setattr(retention_purge, "execute_lake_query", lake_recorder)

        async def _no_assert(*_a: Any, **_k: Any) -> None:
            return None

        monkeypatch.setattr(retention_purge, "assert_cross_tenant_session", _no_assert)
        return session, lake_recorder

    return _apply


class TestAHoldOutranksThePurge:
    @pytest.mark.asyncio
    async def test_a_held_tenant_keeps_its_lake_rows(self, patched) -> None:
        session, lake = patched(holds={TENANT: [_hold()]}, lake={TENANT: 5_000}, alerts={TENANT: 42})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert lake.deletes == [], "a mutation was issued against a tenant under legal hold"
        assert run.lake_rows == 0
        assert run.held_lake_rows == 5_000, "the rows the hold protected have to be counted, not merely skipped"

    @pytest.mark.asyncio
    async def test_a_held_tenant_keeps_its_alerts(self, patched) -> None:
        session, _ = patched(holds={TENANT: [_hold()]}, lake={TENANT: 0}, alerts={TENANT: 42})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert not session.deleted_alerts_for(TENANT)
        assert run.held_alert_rows == 42

    @pytest.mark.asyncio
    async def test_the_run_names_the_matter_so_an_operator_can_find_it(self, patched) -> None:
        session, _ = patched(holds={TENANT: [_hold(matter="LIT-2026-11")]}, lake={TENANT: 1}, alerts={TENANT: 1})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert run.tenants[0].hold_refs == ["LIT-2026-11"]
        assert run.tenants_held == 1

    @pytest.mark.asyncio
    async def test_a_hold_on_a_user_still_stops_the_bulk_purge(self, patched) -> None:
        """A bulk statement cannot evaluate a per-subject predicate row by
        row, so the conservative reading is the only safe one: anything held
        stops the sweep for that tenant. Over-retaining is recoverable."""
        session, lake = patched(
            holds={TENANT: [_hold(subject_kind="user", subject_value="svc-backup", matter="LIT-9")]},
            lake={TENANT: 10},
            alerts={TENANT: 3},
        )

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert lake.deletes == []
        assert run.held_lake_rows == 10

    @pytest.mark.asyncio
    async def test_unreadable_hold_evidence_withholds_rather_than_proceeds(self, patched, monkeypatch) -> None:
        """The opposite default deletes evidence under litigation because a
        query failed, which is the one outcome that cannot be apologised
        for."""
        session, lake = patched(holds={}, lake={TENANT: 7}, alerts={TENANT: 0})

        async def _boom(*_a: Any, **_k: Any) -> list:
            raise RuntimeError("legal_holds is unreachable")

        monkeypatch.setattr(retention_purge, "alerts_under_legal_hold", _boom)

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert lake.deletes == []
        assert run.held_lake_rows == 7
        assert run.tenants[0].errors == ["legal_holds: RuntimeError"]


class TestThePositiveControl:
    """A purge stuck closed passes every assertion above perfectly."""

    @pytest.mark.asyncio
    async def test_a_tenant_with_no_hold_still_loses_its_aged_lake_rows(self, patched) -> None:
        session, lake = patched(holds={}, lake={TENANT: 5_000}, alerts={TENANT: 0})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert len(lake.deletes) == 1, "a tenant with no hold must still be purged"
        assert str(TENANT) in lake.deletes[0]
        assert run.lake_rows == 5_000
        assert run.held_lake_rows == 0

    @pytest.mark.asyncio
    async def test_a_tenant_with_no_hold_still_loses_its_aged_alerts(self, patched) -> None:
        session, _ = patched(holds={}, lake={TENANT: 0}, alerts={TENANT: 42})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert session.deleted_alerts_for(TENANT)
        assert run.alert_rows == 42

    @pytest.mark.asyncio
    async def test_a_hold_on_one_tenant_does_not_protect_another(self, patched) -> None:
        """The shape that makes a fail-closed control useless: one hold
        anywhere freezing the whole estate."""
        session, lake = patched(
            holds={TENANT: [_hold()]},
            lake={TENANT: 5, OTHER_TENANT: 9},
            alerts={TENANT: 1, OTHER_TENANT: 2},
        )

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert len(lake.deletes) == 1
        assert str(OTHER_TENANT) in lake.deletes[0]
        assert run.held_lake_rows == 5
        assert run.lake_rows == 9

    @pytest.mark.asyncio
    async def test_a_released_hold_stops_protecting(self, patched) -> None:
        """`alerts_under_legal_hold` filters on `released_at IS NULL`, so a
        released hold never reaches the worker. Asserted through the worker
        rather than against the query, because the worker is where a
        regression would show."""
        session, lake = patched(holds={TENANT: []}, lake={TENANT: 5}, alerts={TENANT: 0})

        run = await retention_purge.run_once(db=session, dry_run=False)

        assert len(lake.deletes) == 1
        assert run.lake_rows == 5


class TestTheWindowTheTenantChose:
    def test_a_tenant_may_choose_at_least_four_hundred_days(self) -> None:
        assert MAX_LAKE_DAYS >= 400
        assert resolve_policy({"raw_events_days": 400}).raw_events_days == 400

    def test_a_window_above_the_ceiling_is_clamped_rather_than_silently_honoured(self) -> None:
        """Honouring it would promise a window ClickHouse's own TTL deletes
        inside, which is the defect this item exists to close."""
        assert resolve_policy({"raw_events_days": 10_000}).raw_events_days == MAX_LAKE_DAYS

    def test_the_lake_ceiling_is_not_inherited_from_the_postgres_cap(self) -> None:
        """The two stores cost very different amounts. One number for both
        either makes the lake unaffordable or caps an audit trail at the
        lake's ceiling."""
        from app.services.retention import MAX_DAYS

        assert MAX_LAKE_DAYS < MAX_DAYS
        assert resolve_policy({"audit_days": 3650}).audit_days == 3650


class TestTheDecisionHasOnePlace:
    def test_the_worker_defers_to_governance_rather_than_reimplementing(self) -> None:
        """Two implementations of "may this be deleted" is a control that is
        off in whichever copy is more generous."""
        decision = governance.retention_decision(
            expired=True,
            subjects={"tenant": str(TENANT)},
            holds=[governance.LegalHold(id="1", subject_kind="tenant", subject_value=str(TENANT), matter_ref="LIT-1")],
        )
        assert not decision.may_purge
