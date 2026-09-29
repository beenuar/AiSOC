"""Approvals nobody answered stop waiting forever (deferral 9b).

Four things must hold, and each closes a specific way this could go wrong:
only elapsed rows are touched, expiring dispatches nothing, the safe default
matches the one the other half of the system already declares, and an
approval with no deadline is *counted* rather than given one.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from app.workers.approval_expiry import EXPIRED_STATUS, SAFE_DEFAULT, run_once

REPO_ROOT = Path(__file__).resolve().parents[3]


class _Result:
    def __init__(self, rows: list[dict] | None = None, scalar: int = 0) -> None:
        self._rows = rows or []
        self._scalar = scalar

    def mappings(self) -> _Result:
        return self

    def all(self) -> list[dict]:
        return self._rows

    def scalar_one(self) -> int:
        return self._scalar


class _Session:
    """Answers the sweep's two statements and records what it was asked."""

    def __init__(self, expired_rows: list[dict] | None = None, no_deadline: int = 0) -> None:
        self.expired_rows = expired_rows or []
        self.no_deadline = no_deadline
        self.sql: list[str] = []
        self.params: list[dict] = []
        self.commits = 0

    async def execute(self, statement: object, params: dict | None = None) -> _Result:
        sql = str(statement)
        self.sql.append(sql)
        self.params.append(params or {})
        if "current_setting" in sql:  # the cross-tenant precondition probe
            return _Result(scalar=0)
        if sql.strip().upper().startswith("UPDATE"):
            return _Result(rows=self.expired_rows)
        return _Result(scalar=self.no_deadline)

    async def scalar(self, _statement: object) -> str | None:
        # `assert_cross_tenant_session` reads the bound tenant; None means
        # nothing is bound, which is the precondition the sweep requires.
        return None

    async def commit(self) -> None:
        self.commits += 1

    async def close(self) -> None:
        return None


def _row(risk: str = "high") -> dict:
    return {"id": uuid.uuid4(), "tenant_id": uuid.uuid4(), "risk_level": risk}


class TestOnlyElapsedApprovalsAreExpired:
    @pytest.mark.asyncio
    async def test_the_predicate_names_pending_a_deadline_and_the_past(self) -> None:
        session = _Session(expired_rows=[_row()])

        await run_once(db=session)

        update = next(s for s in session.sql if s.strip().upper().startswith("UPDATE"))
        normalised = " ".join(update.split())
        assert "status = 'pending'" in normalised
        assert "expires_at IS NOT NULL" in normalised
        assert "expires_at < now()" in normalised

    @pytest.mark.asyncio
    async def test_an_empty_sweep_reports_zero_and_commits(self) -> None:
        session = _Session(expired_rows=[])

        sweep = await run_once(db=session)

        assert sweep.expired == 0
        assert session.commits == 1

    @pytest.mark.asyncio
    async def test_it_refuses_a_session_bound_to_one_tenant(self) -> None:
        """A bound session would expire one tenant's approvals and report
        success for every tenant — the cross-tenant defect the precondition
        helper exists to catch."""
        from app.db.cross_tenant import CrossTenantPreconditionError

        class _Bound(_Session):
            async def scalar(self, _statement: object) -> str | None:
                return str(uuid.uuid4())

        with pytest.raises(CrossTenantPreconditionError):
            await run_once(db=_Bound())


class TestExpiringIsNotDeciding:
    @pytest.mark.asyncio
    async def test_the_sweep_writes_only_a_status_and_a_note(self) -> None:
        """Nothing is dispatched. An expired approval is a request that
        stopped pretending to be live, not a decision taken for the
        operator — and `/decide` still accepts an expired row."""
        session = _Session(expired_rows=[_row()])

        await run_once(db=session)

        update = " ".join(next(s for s in session.sql if s.strip().upper().startswith("UPDATE")).split())
        assert "SET status = :expired" in update
        for forbidden in ("decided_by_id", "decided_at", "action ="):
            assert forbidden not in update, f"the sweep must not write {forbidden}"

    def test_the_decide_endpoint_still_accepts_an_expired_row(self) -> None:
        source = (REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "approvals.py").read_text(encoding="utf-8")
        assert 'row.status not in {"pending", "expired"}' in source, (
            "the guard changed; if `expired` no longer decides, this worker silently becomes a way to close approvals"
        )

    @pytest.mark.asyncio
    async def test_the_note_says_nothing_was_dispatched(self) -> None:
        session = _Session(expired_rows=[_row()])

        await run_once(db=session)

        note = next(p["note"] for p in session.params if "note" in p)
        assert "nothing was dispatched" in note
        assert "can still be decided" in note


class TestTheSafeDefaultIsTheOneAlreadyDeclared:
    def test_it_matches_the_slack_bot_and_migration_062(self) -> None:
        """Two halves timing out two different ways is worse than either."""
        migration = (REPO_ROOT / "services" / "api" / "migrations" / "062_approval_timers.sql").read_text(encoding="utf-8")
        scheduler = (REPO_ROOT / "services" / "slack-bot" / "app" / "services" / "approval_timeout.py").read_text(encoding="utf-8")

        assert f"DEFAULT '{SAFE_DEFAULT}'" in migration
        assert re.search(rf'safe_default: SafeDefault = "{SAFE_DEFAULT}"', scheduler)

    def test_the_status_written_is_in_the_declared_vocabulary(self) -> None:
        approvals = (REPO_ROOT / "services" / "api" / "app" / "api" / "v1" / "endpoints" / "approvals.py").read_text(encoding="utf-8")
        assert f'"{EXPIRED_STATUS}"' in approvals, "the worker writes a status the API does not recognise"


class TestAnApprovalWithNoDeadlineIsCountedNotInvented:
    @pytest.mark.asyncio
    async def test_they_are_reported_rather_than_swept(self) -> None:
        """Inventing a window for an approval whose creator did not set one
        would start expiring containments on a schedule nobody chose. The
        number is surfaced so the gap is visible instead of read as zero."""
        session = _Session(expired_rows=[], no_deadline=17)

        sweep = await run_once(db=session)

        assert sweep.pending_without_deadline == 17
        assert sweep.expired == 0

    @pytest.mark.asyncio
    async def test_the_breakdown_by_risk_travels_with_the_count(self) -> None:
        """'Three expired' is a number; 'two of them critical' is a finding."""
        session = _Session(expired_rows=[_row("critical"), _row("critical"), _row("low")])

        sweep = await run_once(db=session)

        assert sweep.expired == 3
        assert sweep.by_risk == {"critical": 2, "low": 1}


class TestItIsWiredIntoTheApiLifespan:
    def test_the_worker_is_started_and_cancelled(self) -> None:
        """A worker nobody starts is the defect this deferral is about."""
        main = (REPO_ROOT / "services" / "api" / "app" / "main.py").read_text(encoding="utf-8")

        assert "run_approval_expiry" in main
        assert "approval_expiry_task.cancel()" in main
        assert "APPROVAL_EXPIRY_ENABLED" in main

    def test_a_disabled_worker_says_so_out_loud(self) -> None:
        main = (REPO_ROOT / "services" / "api" / "app" / "main.py").read_text(encoding="utf-8")
        assert "approval_expiry worker disabled" in main

    def test_the_sweep_started_at_is_timezone_aware(self) -> None:
        from app.workers.approval_expiry import ExpirySweep

        sweep = ExpirySweep(started_at=datetime.now(UTC))
        assert sweep.started_at.tzinfo is not None
