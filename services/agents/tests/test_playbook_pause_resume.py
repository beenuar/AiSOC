"""A playbook pauses at an approval, survives a restart, and resumes.

Parity plan 5.2: a persisted pause that "resumes from
`/approvals/{id}/decide`, survives restarts, expires with a recorded
outcome".

The three properties, and why each is tested separately
--------------------------------------------------------
**Resuming** is the easy one and the least interesting: an in-memory
`asyncio.Event` would satisfy it.

**Surviving a restart** is the one that forces the design. The pause is
simulated here by building a fresh engine from stored rows rather than by
keeping any object alive, because that is what a restart leaves you with.

**Expiring with a recorded outcome** is the one that is easy to skip. A
pause with no expiry is a run that hangs forever and an operator who never
learns it did, and `expired` is a decision rather than the absence of one.

The dangerous case this file pins
----------------------------------
A decision that arrives twice. A double-tap in the responder app or a
retried webhook must resume the run **once**: the pause is resolved before
the run continues, so the second attempt matches no `waiting` row.
"""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta

import pytest
from app.playbook import pause as playbook_pause
from app.playbook.engine import PlaybookEngine, RunStatus, StepStatus
from app.playbook.models import Playbook, PlaybookStep, StepType


class _FakeRows:
    """A stand-in for `aisoc_playbook_pauses` with the semantics that matter.

    Specifically the partial unique index on `status = 'waiting'`, which is
    what makes a double decision resolve once.
    """

    def __init__(self) -> None:
        self.rows: list[dict] = []

    async def execute(self, sql: str, *args):  # noqa: ANN001, ANN202
        if "INSERT INTO aisoc_playbook_pauses" in sql:
            self.rows.append(
                {
                    "id": args[0],
                    "tenant_id": args[1],
                    "run_id": args[2],
                    "playbook_id": args[3],
                    "playbook_name": args[4],
                    "step_index": args[5],
                    "step_id": args[6],
                    "run_context": args[7],
                    "step_results": args[8],
                    "approval_id": args[9],
                    "expires_at": args[10],
                    "status": "waiting",
                }
            )
            return "INSERT 0 1"
        if "UPDATE aisoc_playbook_pauses" in sql and "WHERE id =" in sql:
            for row in self.rows:
                if row["id"] == args[0] and str(row.get("tenant_id")) == str(args[3]) and row["status"] == "waiting":
                    row["status"] = args[1]
                    row["resolution"] = args[2]
                    return "UPDATE 1"
            return "UPDATE 0"
        return "OK"

    async def fetchrow(self, sql: str, *args):  # noqa: ANN001, ANN202
        # The tenant filter is honoured here on purpose. A fake that
        # ignored it would pass against a query that ignored it too,
        # which is the shape that lets a cross-tenant read ship.
        for row in self.rows:
            if row.get("approval_id") == args[0] and str(row.get("tenant_id")) == str(args[1]) and row["status"] == "waiting":
                return row
        return None

    async def fetch(self, sql: str, *args):  # noqa: ANN001, ANN202
        if "status = 'expired'" in sql:
            due = args[0]
            out = []
            for row in self.rows:
                if row["status"] == "waiting" and row["expires_at"] <= due:
                    row["status"] = "expired"
                    row["resolution"] = "no decision before the approval deadline"
                    out.append({"run_id": row["run_id"]})
            return out
        return []


class _FakePool:
    def __init__(self, rows: _FakeRows) -> None:
        self._rows = rows

    @asynccontextmanager
    async def acquire(self):
        yield self._rows


@pytest.fixture
def store(monkeypatch):  # noqa: ANN001, ANN201
    rows = _FakeRows()
    pool = _FakePool(rows)

    async def _pool():  # noqa: ANN202
        return pool

    monkeypatch.setattr(playbook_pause, "_pool", _pool)
    return rows


def _playbook(*steps: PlaybookStep) -> Playbook:
    return Playbook(
        id="pb-1",
        name="Containment with sign-off",
        description="",
        trigger={"on": "alert.created"},
        steps=list(steps),
        enabled=True,
    )


@pytest.mark.asyncio
class TestSuspending:
    async def test_a_pause_records_where_to_resume(self, store) -> None:  # noqa: ANN001
        pause = await playbook_pause.suspend(
            tenant_id=str(uuid.uuid4()),
            run_id="run-1",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=2,
            step_id="gate",
            run_context={"host": "WIN-01"},
            step_results=[{"step_id": "s1"}],
        )
        assert pause is not None
        assert pause.step_index == 2
        assert pause.resume_index == 3, (
            "resume must start past the approval step, or a replayed decision pauses again on the same step forever"
        )

    async def test_the_context_is_stored_not_just_the_position(self, store) -> None:  # noqa: ANN001
        """Without it the resumed half sees an empty context and every
        templated parameter resolves to nothing."""
        await playbook_pause.suspend(
            tenant_id=str(uuid.uuid4()),
            run_id="run-2",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={"host": "WIN-01", "user": "j.doe"},
            step_results=[],
        )
        stored = store.rows[-1]["run_context"]
        assert "WIN-01" in stored and "j.doe" in stored

    async def test_no_database_returns_none_rather_than_raising(self, monkeypatch) -> None:  # noqa: ANN001
        async def _none():  # noqa: ANN202
            return None

        monkeypatch.setattr(playbook_pause, "_pool", _none)
        assert (
            await playbook_pause.suspend(
                tenant_id=str(uuid.uuid4()),
                run_id="r",
                playbook_id="p",
                playbook_name="n",
                step_index=0,
                step_id="s",
                run_context={},
                step_results=[],
            )
            is None
        )


@pytest.mark.asyncio
class TestSurvivingARestart:
    async def test_a_pause_is_found_by_approval_id_from_a_cold_start(self, store) -> None:  # noqa: ANN001
        """Nothing is kept alive between the suspend and the lookup, which
        is what a restart leaves you with."""
        approval_id = str(uuid.uuid4())
        tenant = str(uuid.uuid4())
        await playbook_pause.suspend(
            tenant_id=tenant,
            run_id="run-3",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=1,
            step_id="gate",
            run_context={"host": "WIN-01"},
            step_results=[{"step_id": "s1", "status": "success"}],
            approval_id=approval_id,
        )

        found = await playbook_pause.find_waiting(approval_id=approval_id, tenant_id=tenant)
        assert found is not None
        assert found.run_id == "run-3"
        assert found.run_context["host"] == "WIN-01"
        assert found.step_results[0]["step_id"] == "s1"


@pytest.mark.asyncio
class TestADecisionThatArrivesTwice:
    async def test_the_second_resolution_does_not_claim_it(self, store) -> None:  # noqa: ANN001
        """A double-tap in the responder app, or a retried webhook."""
        approval_id = str(uuid.uuid4())
        tenant = str(uuid.uuid4())
        pause = await playbook_pause.suspend(
            tenant_id=tenant,
            run_id="run-4",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
            approval_id=approval_id,
        )
        assert pause is not None

        first = await playbook_pause.resolve(pause_id=pause.id, tenant_id=pause.tenant_id, status="resumed", resolution="approved")
        second = await playbook_pause.resolve(pause_id=pause.id, tenant_id=pause.tenant_id, status="resumed", resolution="approved again")
        assert first is True
        assert second is False, "the same pause was claimed twice, so the run would resume twice"

    async def test_a_resolved_pause_is_no_longer_found(self, store) -> None:  # noqa: ANN001
        approval_id = str(uuid.uuid4())
        tenant = str(uuid.uuid4())
        pause = await playbook_pause.suspend(
            tenant_id=tenant,
            run_id="run-5",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
            approval_id=approval_id,
        )
        assert pause is not None
        await playbook_pause.resolve(pause_id=pause.id, tenant_id=pause.tenant_id, status="denied", resolution="no")
        assert await playbook_pause.find_waiting(approval_id=approval_id, tenant_id=tenant) is None


@pytest.mark.asyncio
class TestExpiry:
    async def test_a_pause_past_its_deadline_expires_with_a_reason(self, store) -> None:  # noqa: ANN001
        pause = await playbook_pause.suspend(
            tenant_id=str(uuid.uuid4()),
            run_id="run-6",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
            ttl_hours=0.0001,
        )
        assert pause is not None

        expired = await playbook_pause.expire_due(now=datetime.now(UTC) + timedelta(hours=1))
        assert "run-6" in expired
        row = next(r for r in store.rows if r["run_id"] == "run-6")
        assert row["status"] == "expired"
        assert "deadline" in row["resolution"], (
            "an expired approval must say why, or it is indistinguishable from a pause still legitimately waiting"
        )

    async def test_a_pause_inside_its_deadline_is_left_alone(self, store) -> None:  # noqa: ANN001
        await playbook_pause.suspend(
            tenant_id=str(uuid.uuid4()),
            run_id="run-7",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
            ttl_hours=72,
        )
        assert await playbook_pause.expire_due(now=datetime.now(UTC)) == []

    def test_there_is_a_default_deadline(self) -> None:
        """A pause with no expiry is a run that hangs forever."""
        assert playbook_pause.DEFAULT_TTL_HOURS > 0


@pytest.mark.asyncio
class TestTheEngineResumesWhereItStopped:
    async def test_it_does_not_re_run_the_steps_before_the_approval(self, store) -> None:  # noqa: ANN001
        """Repeating them would re-send notifications and re-dispatch
        actions that already ran."""
        ran: list[str] = []

        pb = _playbook(
            PlaybookStep(id="first", name="note", type=StepType.CONDITION),
            PlaybookStep(id="gate", name="sign-off", type=StepType.APPROVAL),
            PlaybookStep(id="after", name="note2", type=StepType.CONDITION),
        )

        class _Pause:
            run_id = "run-8"
            resume_index = 2
            run_context: dict = {"tenant_id": "t-1"}
            step_results: list = [{"step_id": "first", "status": "success"}]

        run = await PlaybookEngine().resume(pb, _Pause())
        touched = [r["step_id"] for r in run.step_results]
        assert touched.count("first") == 1, (
            f"the pre-approval step appears {touched.count('first')} times, so resume re-ran what had already executed"
        )
        assert "after" in touched, "the step after the approval never ran"
        assert ran == []

    async def test_a_resumed_run_keeps_its_original_id(self, store) -> None:  # noqa: ANN001
        """Otherwise it appears in the realtime stream and the ledger as a
        second, unrelated run that starts halfway through."""
        pb = _playbook(PlaybookStep(id="after", name="note", type=StepType.CONDITION))

        class _Pause:
            run_id = "run-9"
            resume_index = 0
            run_context: dict = {"tenant_id": "t-1"}
            step_results: list = []

        run = await PlaybookEngine().resume(pb, _Pause())
        assert run.run_id == "run-9"


class TestTheRunStatus:
    def test_paused_is_distinct_from_failed(self) -> None:
        """A paused run reads to an operator as one doing what it was
        written to do; a failed one reads as a broken playbook."""
        assert RunStatus.PAUSED.value == "paused"
        assert RunStatus.PAUSED is not RunStatus.FAILED

    def test_a_paused_step_is_pending_not_success(self) -> None:
        assert StepStatus.PENDING.value != StepStatus.SUCCESS.value


@pytest.mark.asyncio
class TestCrossTenant:
    """Resuming another tenant's run should take two mistakes, not one.

    The approval id is an unguessable UUID, which is an argument for it
    being hard to reach the wrong row and not an argument for being
    allowed to.
    """

    async def test_another_tenant_cannot_find_the_pause(self, store) -> None:  # noqa: ANN001
        approval_id = str(uuid.uuid4())
        owner = str(uuid.uuid4())
        await playbook_pause.suspend(
            tenant_id=owner,
            run_id="run-x",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
            approval_id=approval_id,
        )

        assert await playbook_pause.find_waiting(approval_id=approval_id, tenant_id=str(uuid.uuid4())) is None
        assert await playbook_pause.find_waiting(approval_id=approval_id, tenant_id=owner) is not None

    async def test_another_tenant_cannot_resolve_the_pause(self, store) -> None:  # noqa: ANN001
        owner = str(uuid.uuid4())
        pause = await playbook_pause.suspend(
            tenant_id=owner,
            run_id="run-y",
            playbook_id="pb-1",
            playbook_name="x",
            step_index=0,
            step_id="gate",
            run_context={},
            step_results=[],
        )
        assert pause is not None

        stolen = await playbook_pause.resolve(
            pause_id=pause.id,
            tenant_id=str(uuid.uuid4()),
            status="resumed",
            resolution="not mine",
        )
        assert stolen is False, "another tenant resumed this run"
        assert await playbook_pause.resolve(pause_id=pause.id, tenant_id=owner, status="resumed", resolution="mine") is True
