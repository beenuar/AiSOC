"""A detection that fires again after its alert was closed must reach the queue.

GHSA-qp9f-459j-w89c, reported by Jake Davis. ``alert_sink._INSERT_SQL``
guards its insert with

    WHERE NOT EXISTS (
        SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11::text
    )

and that predicate carries no status. So the row an analyst closed keeps
absorbing every later firing of the same detection: the insert is filtered,
the sink answers DUPLICATE, and no open alert exists. An attacker who trips a
detection, waits for the alert to be closed, and repeats the activity is
invisible to the queue — detection evasion against an operating detection,
not a cosmetic dedup complaint.

Why this suite has to be live
-----------------------------
The defect is in SQL and in a unique index, and neither is visible to a fake
store. Three of the facts asserted here exist only in Postgres:

* ``uq_alerts_tenant_dedup`` (migration 120) is UNIQUE on
  ``(tenant_id, dedup_hash) WHERE dedup_hash IS NOT NULL``, so "insert a
  second row for the recurrence" is not an available remedy. A stub pool
  would happily accept one and the suite would certify a design the database
  refuses;
* the reopen is one conditional UPDATE whose ``status = ANY(terminal)``
  predicate *is* the open-alert control. Only the database can show that it
  matches nothing when the alert is open;
* ``resolved_at`` must come back to NULL, because an open alert carrying a
  resolution timestamp is what the MTTR query averages over.

The suite runs as the DML-only ``NOBYPASSRLS`` runtime role, because that is
what fusion connects as. Seeding a tenant is done by the owner, which the
production path never does.

Against the pre-fix tree:
``test_a_recurrence_after_closure_returns_an_open_alert`` fails with the alert
still ``resolved``, and the reopen-provenance tests fail because the columns do
not exist. ``test_firing_twice_while_the_alert_is_open_is_still_one_row``
passes before *and* after — it is the control that says recurrence was not
bought by breaking dedup.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_RECURRENCE_DSN", "").strip(),
        reason="ISOLATION_RECURRENCE_DSN is not set; this suite needs a live Postgres",
    ),
]

_FUSION = Path(__file__).resolve().parents[2] / "services" / "fusion"

#: Every status the canonical vocabulary calls finished. Kept as a literal
#: here rather than imported, because the thing under test is whether fusion
#: and `app.services.alert_status` agree: importing the list the fix uses
#: would make this a producer compared against a copy of itself.
TERMINAL_STATUSES = ("resolved", "closed", "false_positive", "fp", "dismissed")


def _dsn() -> str:
    value = os.environ.get("ISOLATION_RECURRENCE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_RECURRENCE_DSN is not set")
    return value


def _admin_dsn() -> str:
    """The schema owner, for fixtures only — creating tenants is not a fusion act."""
    value = os.environ.get("ISOLATION_RECURRENCE_ADMIN_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_RECURRENCE_ADMIN_DSN is not set")
    return value


@pytest.fixture(scope="module", autouse=True)
def _fusion_importable() -> None:
    """`services/fusion` names its package `app`, as three other services do.

    Imported inside the fixture rather than at module scope so the
    collection-only job, which installs no service dependencies, does not take
    unrelated tests down with it.
    """
    import sys

    if str(_FUSION) not in sys.path:
        sys.path.insert(0, str(_FUSION))


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    import asyncpg

    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    assert created is not None
    try:
        yield created
    finally:
        await created.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def admin_pool():
    import asyncpg

    created = await asyncpg.create_pool(_admin_dsn(), min_size=1, max_size=2)
    assert created is not None
    try:
        yield created
    finally:
        await created.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def make_tenant(admin_pool):
    async def _make(label: str) -> uuid.UUID:
        new_id = uuid.uuid4()
        async with admin_pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
                new_id,
                f"recurrence {label} {new_id.hex[:8]}",
                f"recurrence-{label}-{new_id.hex[:8]}",
            )
        return new_id

    return _make


@pytest.fixture(scope="module", autouse=True)
def _runtime_role_cannot_bypass_rls() -> None:
    """Refuse to grade anything as a role that sails past the policies.

    Validating this as the owner is the recorded way a Postgres assertion
    becomes a false pass.
    """


def _raw(tenant: uuid.UUID, *, event_time: datetime, source_event_ids=()):
    from app.models.alert import AlertSeverity, RawAlert

    alert = RawAlert(
        tenant_id=tenant,
        source="AWS GuardDuty",
        title="UnauthorizedAccess:EC2/SSHBruteForce",
        severity=AlertSeverity.HIGH,
        src_ip="203.0.113.17",
        hostname="i-0abc123def456",
        mitre_techniques=["T1110"],
        connector_type="aws_guardduty",
        source_event_ids=list(source_event_ids),
        ocsf_class_uid=2004,
        event_time=event_time,
    )
    alert.id = alert.deterministic_id()
    return alert


def _fused(tenant: uuid.UUID, *, event_time: datetime, source_event_ids=(), decision=None):
    from app.models.alert import FusedAlert, FusionDecision

    raw = _raw(tenant, event_time=event_time, source_event_ids=source_event_ids)
    return FusedAlert(
        id=raw.id,
        tenant_id=tenant,
        fusion_decision=decision or FusionDecision.NEW_ALERT,
        alert=raw,
    )


async def _sink(pool):
    from app.services.alert_sink import AlertSink

    sink = AlertSink(_dsn())
    sink._pool = pool
    return sink


async def _rows(pool, tenant: uuid.UUID):
    async with pool.acquire() as conn:
        return await conn.fetch(
            "SELECT * FROM alerts WHERE tenant_id = $1 ORDER BY created_at",
            tenant,
        )


async def _close(pool, tenant: uuid.UUID, *, status: str = "resolved") -> None:
    """Close the alert the way the console does: terminal status + resolved_at."""
    async with pool.acquire() as conn:
        updated = await conn.execute(
            "UPDATE alerts SET status = $2, resolved_at = NOW() WHERE tenant_id = $1",
            tenant,
            status,
        )
    assert updated.endswith(" 1"), f"expected to close exactly one alert, got {updated!r}"


# ── the advisory, reproduced ──────────────────────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_a_recurrence_after_closure_returns_an_open_alert(pool, make_tenant) -> None:
    """Fire, close, fire again. The queue must show the second firing.

    This is Jake Davis's proof of concept executed against the real sink. On
    the pre-fix tree the second firing is absorbed: one row, still `resolved`,
    nothing open, and the attacker's repeat is invisible.
    """
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("recur")
    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)

    first = await sink.persist(_fused(tenant, event_time=base, source_event_ids=["gd-1"]))
    assert first.outcome is PersistOutcome.INSERTED

    await _close(pool, tenant, status="resolved")

    # The attacker repeats the activity.
    await sink.persist(_fused(tenant, event_time=base + timedelta(hours=2), source_event_ids=["gd-2"]))

    rows = await _rows(pool, tenant)
    assert len(rows) == 1, "the unique index allows exactly one row per fingerprint"

    row = rows[0]
    assert row["status"] not in TERMINAL_STATUSES, (
        f"the detection fired again and the alert is still {row['status']!r}: "
        "the recurrence was absorbed into the closed row and no analyst will ever see it"
    )
    assert row["resolved_at"] is None, (
        "the alert is open again but still carries a resolution timestamp, which is the column the MTTR average subtracts"
    )


@pytest.mark.asyncio(loop_scope="module")
@pytest.mark.parametrize("terminal", TERMINAL_STATUSES)
async def test_every_terminal_status_is_reopened_not_just_resolved(pool, make_tenant, terminal: str) -> None:
    """Five words mean finished, and a fix that knows one of them is a hole.

    `false_positive` and `fp` are both written (the bulk-close endpoint and the
    feedback path), `closed` comes from vendor writeback and `dismissed` from a
    case cascade. A recurrence after any of them is the same evasion.
    """
    tenant = await make_tenant(f"term-{terminal}")
    sink = await _sink(pool)
    base = datetime(2026, 11, 2, 9, 0, tzinfo=UTC)

    await sink.persist(_fused(tenant, event_time=base, source_event_ids=["a"]))
    await _close(pool, tenant, status=terminal)
    await sink.persist(_fused(tenant, event_time=base + timedelta(hours=1), source_event_ids=["b"]))

    rows = await _rows(pool, tenant)
    assert len(rows) == 1
    assert rows[0]["status"] not in TERMINAL_STATUSES, f"a recurrence after {terminal!r} stayed invisible"


@pytest.mark.asyncio(loop_scope="module")
async def test_the_reopen_is_counted_timestamped_and_reasoned(pool, make_tenant) -> None:
    """Reopening is an analyst-visible state change, so it leaves a record.

    `services/agents` already refuses to re-open a closed alert on re-read of
    *existing* evidence, with the docstring "re-opening a closed alert is an
    analyst-visible state change". A new firing is new evidence from the
    world, and the audit trail is what makes the distinction legible: without
    a count, a reopened alert is indistinguishable from one never closed.
    """
    tenant = await make_tenant("provenance")
    sink = await _sink(pool)
    base = datetime(2026, 11, 3, 9, 0, tzinfo=UTC)

    await sink.persist(_fused(tenant, event_time=base, source_event_ids=["p-1"]))
    await _close(pool, tenant, status="false_positive")
    await sink.persist(_fused(tenant, event_time=base + timedelta(hours=1), source_event_ids=["p-2"]))

    row = (await _rows(pool, tenant))[0]
    assert row["reopen_count"] == 1, f"reopen_count is {row['reopen_count']}"
    assert row["reopened_at"] is not None, "a reopen with no timestamp cannot be audited"
    assert row["reopen_reason"], "an unexplained reopen is the thing an auditor asks about"

    # Closed and recurring a second time: the count distinguishes a flapping
    # detection from one that came back once.
    await _close(pool, tenant, status="resolved")
    await sink.persist(_fused(tenant, event_time=base + timedelta(hours=3), source_event_ids=["p-3"]))
    row = (await _rows(pool, tenant))[0]
    assert row["reopen_count"] == 2, f"second recurrence did not count: {row['reopen_count']}"


@pytest.mark.asyncio(loop_scope="module")
async def test_the_investigation_thread_survives_the_reopen(pool, make_tenant) -> None:
    """The alert keeps its id, so cases, source links and occurrences still resolve.

    This is the half a new-row remedy would have cost: every link into this
    alert is by id.
    """
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("thread")
    sink = await _sink(pool)
    base = datetime(2026, 11, 4, 9, 0, tzinfo=UTC)

    first = await sink.persist(_fused(tenant, event_time=base, source_event_ids=["t-1"]))
    assert first.outcome is PersistOutcome.INSERTED
    original_id = first.alert_id

    await _close(pool, tenant, status="resolved")
    again = await sink.persist(_fused(tenant, event_time=base + timedelta(hours=1), source_event_ids=["t-2"]))

    assert again.alert_id == original_id, "the recurrence resolved to a different alert id"
    async with pool.acquire() as conn:
        occurrences = await conn.fetchval(
            "SELECT occurrence_count FROM alert_occurrences WHERE tenant_id = $1",
            tenant,
        )
    assert occurrences == 2, f"the recurrence was not counted as an occurrence ({occurrences})"


@pytest.mark.asyncio(loop_scope="module")
async def test_a_recurrence_fusion_itself_calls_a_duplicate_also_reopens(pool, make_tenant) -> None:
    """The second way into the dedup path, which is a different branch.

    `_persist_on_conn` folds a repeat in three places: fusion's own Redis
    verdict returns *before* the insert is attempted, the unique index can
    raise on a concurrent writer, and the `WHERE NOT EXISTS` guard filters the
    statement. The tests above drive the third. This drives the first, because
    whether a recurrence arrives as `NEW_ALERT` or as `DUPLICATE` depends only
    on whether the fingerprint is still in Redis — an attacker does not choose
    it, and a fix that reopened on one branch would leave the hole open on a
    timer.
    """
    from app.models.alert import FusionDecision
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("fusion-dup")
    sink = await _sink(pool)
    base = datetime(2026, 11, 7, 9, 0, tzinfo=UTC)

    await sink.persist(_fused(tenant, event_time=base, source_event_ids=["d-1"]))
    await _close(pool, tenant, status="closed")

    result = await sink.persist(
        _fused(
            tenant,
            event_time=base + timedelta(hours=1),
            source_event_ids=["d-2"],
            decision=FusionDecision.DUPLICATE,
        )
    )
    assert result.outcome is PersistOutcome.DUPLICATE
    assert result.reopened is True, "the sink did not report the reopen, so nothing downstream can count it"

    row = (await _rows(pool, tenant))[0]
    assert row["status"] not in TERMINAL_STATUSES, f"a recurrence arriving as fusion's own DUPLICATE verdict stayed {row['status']!r}"
    assert row["reopen_count"] == 1


# ── the control: dedup must still work ────────────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_firing_twice_while_the_alert_is_open_is_still_one_row(pool, make_tenant) -> None:
    """The control the reporter named. Passes before the fix and after it.

    Recurrence must not be bought by breaking dedup. An open alert that fires
    again is one alert: no second row, no status churn, and no reopen
    recorded, because nothing was ever closed.
    """
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("open-control")
    sink = await _sink(pool)
    base = datetime(2026, 11, 5, 9, 0, tzinfo=UTC)

    first = await sink.persist(_fused(tenant, event_time=base, source_event_ids=["o-1"]))
    assert first.outcome is PersistOutcome.INSERTED

    for n in range(2, 12):
        result = await sink.persist(_fused(tenant, event_time=base + timedelta(minutes=n), source_event_ids=[f"o-{n}"]))
        assert result.outcome is PersistOutcome.DUPLICATE, f"firing {n} while open created a new alert"

    rows = await _rows(pool, tenant)
    assert len(rows) == 1, f"ten firings against one open alert produced {len(rows)} rows"
    assert rows[0]["status"] == "new", f"an open alert's status was churned to {rows[0]['status']!r}"


@pytest.mark.asyncio(loop_scope="module")
async def test_an_open_alert_that_an_analyst_is_working_is_not_dragged_backwards(pool, make_tenant) -> None:
    """A recurrence must not reset `triaging` to `new` under the analyst.

    The reopen predicate is `status = ANY(terminal)`, so a claimed alert is
    untouched. Pinned because the obvious wrong fix — "set status = 'new' on
    every dedup hit" — would pass the test above and fail this one.
    """
    tenant = await make_tenant("inflight")
    sink = await _sink(pool)
    base = datetime(2026, 11, 6, 9, 0, tzinfo=UTC)

    await sink.persist(_fused(tenant, event_time=base, source_event_ids=["w-1"]))
    async with pool.acquire() as conn:
        await conn.execute("UPDATE alerts SET status = 'triaging' WHERE tenant_id = $1", tenant)

    await sink.persist(_fused(tenant, event_time=base + timedelta(minutes=5), source_event_ids=["w-2"]))

    row = (await _rows(pool, tenant))[0]
    assert row["status"] == "triaging", f"an analyst's claim was overwritten with {row['status']!r}"
    assert row["reopen_count"] == 0, "nothing was closed, so nothing was reopened"


@pytest.mark.asyncio(loop_scope="module")
async def test_the_runtime_role_cannot_bypass_rls(pool) -> None:
    """Everything above is graded as the role fusion really connects as."""
    async with pool.acquire() as conn:
        role = await conn.fetchval("SELECT current_user")
        bypasses = await conn.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
        assert not bypasses, (
            f"ISOLATION_RECURRENCE_DSN connects as {role}, which bypasses RLS; "
            "every assertion in this suite would pass for the wrong reason"
        )
