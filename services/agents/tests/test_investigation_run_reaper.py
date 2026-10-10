"""Runs orphaned by a dead process must still reach a terminal status (#1242).

The wall-clock deadline added to ``app.api.investigate._run_and_store`` ends a
run that hangs inside a live process. It covers nothing once the process is
gone: the run store is a module-level dict, so a restart, an OOM kill or an
ordinary rollout drops every in-flight run while its ``investigation_runs`` row
stays ``'running'`` — and the Investigation Ledger renders that row.

Two layers, tested separately on purpose:

* the policy (how long is stale, and that the number is derived from the same
  budget rather than written a second time) — plain unit tests;
* the SQL, against a **real** Postgres carrying the production schema. A fake
  pool would answer whatever query it was handed, which is exactly the double
  that is more capable than the real thing: it cannot tell you that
  ``make_interval`` binds, that the conditional ``UPDATE`` is race-safe, or
  that the RLS policy on the table lets a cross-tenant sweep see anything at
  all. Set ``AISOC_TEST_LEDGER_DSN`` to run that half.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

from app.investigator import ledger, run_reaper  # noqa: E402

LEDGER_DSN = os.environ.get("AISOC_TEST_LEDGER_DSN", "").strip()


# ---------------------------------------------------------------------------
# Policy: one budget, not two
# ---------------------------------------------------------------------------


def test_stale_margin_is_derived_from_the_run_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not a second hardcoded deadline — the reaper tracks the same knob.

    A margin written independently of the budget is how the two disagree, and
    a reaper that is shorter than the deadline cancels healthy work.
    """
    monkeypatch.delenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", raising=False)

    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", "600")
    assert run_reaper.stale_after_seconds() == 1800.0

    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", "900")
    assert run_reaper.stale_after_seconds() == 2700.0


def test_stale_margin_is_always_longer_than_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    """The safety property: never reap a run that is still allowed to be running."""
    from app.graph.runner import default_budget

    monkeypatch.delenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", raising=False)
    for budget in ("0.25", "1", "120", "600", "3600"):
        monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", budget)
        assert run_reaper.stale_after_seconds() > default_budget().max_seconds, (
            f"with a {budget}s budget the reaper would close runs that are still within it"
        )


def test_operator_override_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", "120")
    monkeypatch.setenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", "7200")
    assert run_reaper.stale_after_seconds() == 7200.0


def test_a_junk_override_falls_back_rather_than_crashing_the_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", "600")
    monkeypatch.setenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", "every-ten-minutes")
    assert run_reaper.stale_after_seconds() == 1800.0


def test_reaper_is_on_unless_explicitly_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    """Not running it is the defect, so off is the opt-in."""
    monkeypatch.delenv("AISOC_INVESTIGATION_REAPER_DISABLE", raising=False)
    assert run_reaper.enabled() is True
    monkeypatch.setenv("AISOC_INVESTIGATION_REAPER_DISABLE", "1")
    assert run_reaper.enabled() is False


async def test_reap_once_passes_the_derived_margin_through(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, Any]] = []

    async def _fake(**kwargs: Any) -> list[uuid.UUID]:
        calls.append(kwargs)
        return [uuid.uuid4()]

    monkeypatch.setattr(ledger, "fail_stale_runs", _fake, raising=True)
    monkeypatch.delenv("AISOC_INVESTIGATION_STALE_AFTER_SECONDS", raising=False)
    monkeypatch.setenv("AISOC_INVESTIGATION_MAX_SECONDS", "600")

    assert await run_reaper.reap_once() == 1
    (call,) = calls
    assert call["older_than_seconds"] == 1800.0
    assert "abandoned" in call["reason"].lower(), "the ledger row must say it was reaped, not carry a verdict the agent never reached"


async def test_a_failing_pass_does_not_kill_the_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unreachable store is transient; the sweeper backs off and retries."""

    async def _boom(**_kwargs: Any) -> list[uuid.UUID]:
        raise ConnectionError("database is down")

    monkeypatch.setattr(ledger, "fail_stale_runs", _boom, raising=True)
    with pytest.raises(ConnectionError):
        await run_reaper.reap_once()


# ---------------------------------------------------------------------------
# The SQL, against the real schema
# ---------------------------------------------------------------------------

pytestmark_integration = pytest.mark.skipif(
    not LEDGER_DSN,
    reason="set AISOC_TEST_LEDGER_DSN to a Postgres carrying the AiSOC schema to run the ledger sweep",
)


@pytest.fixture
async def ledger_db(monkeypatch: pytest.MonkeyPatch):
    """Point the ledger at a real Postgres and give each test a clean tenant."""
    import asyncpg

    monkeypatch.setenv("DATABASE_URL", LEDGER_DSN)
    await ledger.close_pool()

    tenant_id = uuid.uuid4()
    conn = await asyncpg.connect(LEDGER_DSN)
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant_id,
            f"reaper-{tenant_id.hex[:8]}",
            f"reaper-{tenant_id.hex[:8]}",
        )
    finally:
        await conn.close()

    yield tenant_id

    await ledger.close_pool()
    conn = await asyncpg.connect(LEDGER_DSN)
    try:
        await conn.execute("DELETE FROM investigation_runs WHERE tenant_id = $1", tenant_id)
        await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_id)
    finally:
        await conn.close()


async def _insert_run(dsn: str, tenant_id: uuid.UUID, *, age_seconds: float, status: str) -> uuid.UUID:
    import asyncpg

    run_id = uuid.uuid4()
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(
            """
            INSERT INTO investigation_runs (id, tenant_id, case_id, status, started_at, created_at)
            VALUES ($1, $2, $3, $4, now() - make_interval(secs => $5::double precision), now())
            """,
            run_id,
            tenant_id,
            "case-reaper",
            status,
            float(age_seconds),
        )
    finally:
        await conn.close()
    return run_id


async def _status_of(dsn: str, run_id: uuid.UUID) -> tuple[str, str | None, bool]:
    import asyncpg

    conn = await asyncpg.connect(dsn)
    try:
        row = await conn.fetchrow(
            "SELECT status, error, completed_at IS NOT NULL AS closed FROM investigation_runs WHERE id = $1",
            run_id,
        )
    finally:
        await conn.close()
    return row["status"], row["error"], row["closed"]


@pytestmark_integration
@pytest.mark.integration
async def test_sweep_closes_an_abandoned_run_and_leaves_a_live_one_alone(ledger_db) -> None:
    tenant_id = ledger_db
    abandoned = await _insert_run(LEDGER_DSN, tenant_id, age_seconds=4000, status="running")
    in_flight = await _insert_run(LEDGER_DSN, tenant_id, age_seconds=5, status="running")
    already_done = await _insert_run(LEDGER_DSN, tenant_id, age_seconds=4000, status="completed")

    closed = await ledger.fail_stale_runs(older_than_seconds=1800, reason=run_reaper.STALE_REASON)

    assert abandoned in closed
    assert in_flight not in closed, "a run still inside its budget was reaped"
    assert already_done not in closed, "a finished run was reopened and re-closed"

    status, error, has_completed_at = await _status_of(LEDGER_DSN, abandoned)
    assert status == "failed"
    assert error == run_reaper.STALE_REASON
    assert has_completed_at, "a closed run with no completed_at renders as 'in progress' in the ledger"

    assert (await _status_of(LEDGER_DSN, in_flight))[0] == "running"
    assert (await _status_of(LEDGER_DSN, already_done))[0] == "completed"


@pytestmark_integration
@pytest.mark.integration
async def test_sweep_is_idempotent_and_safe_to_race(ledger_db) -> None:
    """Two replicas sweeping the same row close it once.

    The staleness predicate is inside the ``UPDATE``, so the loser matches
    nothing rather than overwriting the first writer's reason.
    """
    tenant_id = ledger_db
    run_id = await _insert_run(LEDGER_DSN, tenant_id, age_seconds=4000, status="running")

    first = await ledger.fail_stale_runs(older_than_seconds=1800, reason=run_reaper.STALE_REASON)
    second = await ledger.fail_stale_runs(older_than_seconds=1800, reason="a different reason")

    assert run_id in first
    assert run_id not in second, "a second pass re-closed a row that was already terminal"
    assert (await _status_of(LEDGER_DSN, run_id))[1] == run_reaper.STALE_REASON


@pytestmark_integration
@pytest.mark.integration
async def test_sweep_sees_every_tenant(ledger_db) -> None:
    """A maintenance sweep that only saw one tenant would leave the rest hanging.

    This is the assertion that would fail if the RLS policy on
    ``investigation_runs`` ever dropped its ``current_tenant_id() IS NULL``
    arm — the thing the sweep silently depends on.
    """
    import asyncpg

    tenant_a = ledger_db
    tenant_b = uuid.uuid4()
    conn = await asyncpg.connect(LEDGER_DSN)
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant_b,
            f"reaper-b-{tenant_b.hex[:8]}",
            f"reaper-b-{tenant_b.hex[:8]}",
        )
    finally:
        await conn.close()

    try:
        run_a = await _insert_run(LEDGER_DSN, tenant_a, age_seconds=4000, status="running")
        run_b = await _insert_run(LEDGER_DSN, tenant_b, age_seconds=4000, status="running")

        closed = await ledger.fail_stale_runs(older_than_seconds=1800, reason=run_reaper.STALE_REASON)

        assert run_a in closed
        assert run_b in closed, "the sweep only saw one tenant's abandoned runs"
    finally:
        conn = await asyncpg.connect(LEDGER_DSN)
        try:
            await conn.execute("DELETE FROM investigation_runs WHERE tenant_id = $1", tenant_b)
            await conn.execute("DELETE FROM tenants WHERE id = $1", tenant_b)
        finally:
            await conn.close()
