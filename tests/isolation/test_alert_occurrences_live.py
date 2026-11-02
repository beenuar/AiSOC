"""A repeated vendor finding is counted, against real Postgres.

Wave 2, Phase 3.3. The offline suite
(`services/fusion/tests/test_alert_occurrences.py`) drives a stub connection
that records statements and answers everything happily. That is enough to
prove the sink *issues* the write and that a failure cannot cost the alert;
it is not enough to prove the statement is correct, and the parts of this
statement most likely to be wrong are exactly the parts a stub cannot see:

* `payload_ids - 0` — the jsonb-minus-integer form that evicts the oldest
  element. A stub accepts any string;
* the `WHERE NOT (ao.payload_ids @> …)` on the `ON CONFLICT … DO UPDATE`,
  which is the redelivery guard. Postgres is the only thing that can show it
  actually suppresses the second increment;
* `LEAST`/`GREATEST` over a `timestamptz` and a possibly-NULL `event_time`;
* the `CHECK (occurrence_count >= 2)` and both foreign keys;
* the RLS policy, which a superuser would silently bypass — so this suite
  runs its isolation assertion as a `NOBYPASSRLS` role.

Against the pre-3.3 tree every test here fails at setup: `alert_occurrences`
does not exist, and the sink issues no statement that mentions it.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_OCCURRENCES_DSN", "").strip(),
        reason="ISOLATION_OCCURRENCES_DSN is not set; this suite needs a live Postgres",
    ),
]

_FUSION = Path(__file__).resolve().parents[2] / "services" / "fusion"


def _dsn() -> str:
    """The **runtime** role: DML-only, `NOBYPASSRLS`, no tenant session bound.

    This is what the code under test connects as, because it is what fusion
    connects as in production. A suite that drove the sink as the schema
    owner would bypass every policy on the way through and could not have
    found the `WITH CHECK` defect recorded in migration 151.
    """
    value = os.environ.get("ISOLATION_OCCURRENCES_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_OCCURRENCES_DSN is not set")
    return value


def _admin_dsn() -> str:
    """The schema owner, for fixtures only.

    Creating a tenant is not something the production path does, and doing it
    under forced RLS from an unbound session is a different problem from the
    one under test. Keeping the two roles apart is what lets the production
    path be judged under the policies it really runs under.
    """
    value = os.environ.get("ISOLATION_OCCURRENCES_ADMIN_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_OCCURRENCES_ADMIN_DSN is not set")
    return value


@pytest.fixture(scope="module", autouse=True)
def _fusion_importable() -> None:
    """`services/fusion` names its package `app`, as three other services do.

    Imported here rather than at module scope so the collection-only job,
    which installs no service dependencies, does not take 200 unrelated tests
    down with it — the recorded failure mode for a module-scope service
    import in a shared suite.
    """
    import sys

    if str(_FUSION) not in sys.path:
        sys.path.insert(0, str(_FUSION))


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pool():
    """The pool the sink runs on — the runtime role, as in production."""
    import asyncpg

    created = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    assert created is not None
    try:
        yield created
    finally:
        await created.close()


#: Same pool, named for what the RLS assertions are asking of it. An alias
#: rather than a second connection so there is no chance of the policy being
#: judged against a role the production path does not use.
@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def runtime_pool(pool):
    return pool


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
                f"laneF {label} {new_id.hex[:8]}",
                f"lanef-{label}-{new_id.hex[:8]}",
            )
        return new_id

    return _make


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def tenant_id(make_tenant) -> uuid.UUID:
    return await make_tenant("occ")


def _raw(tenant: uuid.UUID, *, source_event_ids, event_time: datetime):
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


def _fused(tenant: uuid.UUID, *, source_event_ids, event_time: datetime, decision=None):
    from app.models.alert import FusedAlert, FusionDecision

    raw = _raw(tenant, source_event_ids=source_event_ids, event_time=event_time)
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


async def _read(pool, tenant: uuid.UUID):
    async with pool.acquire() as conn:
        return await conn.fetchrow(
            "SELECT * FROM alert_occurrences WHERE tenant_id = $1",
            tenant,
        )


# ── the measurement the feature exists to make possible ───────────────────


@pytest.mark.asyncio(loop_scope="module")
async def test_a_vendor_repeating_a_finding_79_times_is_one_alert_that_says_79(pool, tenant_id) -> None:
    """The plan's sentence, executed.

    79 total sightings: the alert itself, then 78 repeats. The count includes
    the surviving alert, which is why a reader joining this table uses
    `COALESCE(occurrence_count, 1)` — no row means one sighting, not zero.
    """
    from app.services.alert_sink import PersistOutcome

    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 9, 0, tzinfo=UTC)

    first = await sink.persist(_fused(tenant_id, source_event_ids=["gd-0001"], event_time=base))
    assert first.outcome is PersistOutcome.INSERTED

    # No row yet: one sighting is the alert, and a rollup for it would be
    # noise on every alert in the system.
    assert await _read(pool, tenant_id) is None

    for n in range(2, 80):
        result = await sink.persist(
            _fused(
                tenant_id,
                source_event_ids=[f"gd-{n:04d}"],
                event_time=base + timedelta(minutes=n),
            )
        )
        assert result.outcome is PersistOutcome.DUPLICATE, f"repeat {n} was not folded"

    row = await _read(pool, tenant_id)
    assert row is not None, "78 repeats folded onto the alert and none was counted"
    assert row["occurrence_count"] == 79, f"the alert says {row['occurrence_count']} sightings; the vendor reported it 79 times"
    assert row["first_seen"] == base
    assert row["last_seen"] == base + timedelta(minutes=79)


@pytest.mark.asyncio(loop_scope="module")
async def test_a_redelivered_message_does_not_inflate_the_count(pool, make_tenant) -> None:
    """A consumer-group rebalance must not become a vendor repeat.

    The guard is `WHERE NOT (ao.payload_ids @> …)` on the DO UPDATE. Only
    Postgres can show that it suppresses the write rather than merely being
    present in the string.
    """
    from app.services.alert_sink import PersistOutcome

    tenant = await make_tenant("redelivery")

    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 10, 0, tzinfo=UTC)
    await sink.persist(_fused(tenant, source_event_ids=["gd-a"], event_time=base))

    repeat = _fused(tenant, source_event_ids=["gd-b"], event_time=base + timedelta(minutes=1))
    assert (await sink.persist(repeat)).outcome is PersistOutcome.DUPLICATE
    after_first = await _read(pool, tenant)
    assert after_first["occurrence_count"] == 2

    # The same message again, which is exactly what a rebalance delivers.
    for _ in range(5):
        assert (await sink.persist(repeat)).outcome is PersistOutcome.DUPLICATE

    after_redeliveries = await _read(pool, tenant)
    assert after_redeliveries["occurrence_count"] == 2, (
        f"five redeliveries of one message took the count to "
        f"{after_redeliveries['occurrence_count']}, so the number measures "
        "Kafka delivery rather than the vendor"
    )


@pytest.mark.asyncio(loop_scope="module")
async def test_the_payload_window_evicts_the_oldest_and_says_it_is_no_longer_complete(pool, make_tenant) -> None:
    """`payload_ids - 0` is the eviction, and it only runs in Postgres."""
    from app.services.alert_sink import _MAX_OCCURRENCE_PAYLOAD_IDS

    tenant = await make_tenant("window")

    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 11, 0, tzinfo=UTC)
    await sink.persist(_fused(tenant, source_event_ids=["w-0000"], event_time=base))

    total_repeats = _MAX_OCCURRENCE_PAYLOAD_IDS + 5
    for n in range(1, total_repeats + 1):
        await sink.persist(_fused(tenant, source_event_ids=[f"w-{n:04d}"], event_time=base + timedelta(seconds=n)))

    row = await _read(pool, tenant)
    ids = json.loads(row["payload_ids"]) if isinstance(row["payload_ids"], str) else row["payload_ids"]

    assert row["occurrence_count"] == total_repeats + 1, "eviction must not stop the count"
    assert len(ids) == _MAX_OCCURRENCE_PAYLOAD_IDS, f"window holds {len(ids)}"
    assert row["payload_ids_complete"] is False, (
        "the window evicted ids and still reports itself complete, so a reader is told a partial list is the whole set"
    )
    # Newest kept, oldest gone — the direction that puts the redelivery
    # guard's coverage where redelivery happens.
    assert ids[-1] == f"w-{total_repeats:04d}"
    assert "w-0001" not in ids


@pytest.mark.asyncio(loop_scope="module")
async def test_a_connector_that_sets_no_event_id_is_still_counted(pool, make_tenant) -> None:
    """Most normalisers leave `source_event_ids` empty.

    Gating the count on an id would make the published number mean "repeats
    from connectors that happen to set an id", which is not a number anybody
    asked for.
    """
    tenant = await make_tenant("noids")

    sink = await _sink(pool)
    base = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
    await sink.persist(_fused(tenant, source_event_ids=[], event_time=base))
    for n in range(1, 4):
        await sink.persist(_fused(tenant, source_event_ids=[], event_time=base + timedelta(minutes=n)))

    row = await _read(pool, tenant)
    assert row is not None, "a repeat from an id-less connector was not counted at all"
    assert row["occurrence_count"] == 4
    ids = json.loads(row["payload_ids"]) if isinstance(row["payload_ids"], str) else row["payload_ids"]
    assert ids == [], "no id was available, and an invented one would be worse than none"
    assert row["payload_ids_complete"] is True, "nothing was evicted; nothing is missing"


@pytest.mark.asyncio(loop_scope="module")
async def test_occurrences_are_tenant_isolated_under_forced_rls(runtime_pool, tenant_id) -> None:
    """Judged as a role that cannot bypass RLS.

    Running this as the owner would pass whatever the policy said, which is
    the recorded way an RLS fix gets validated into a false pass. This suite
    therefore refuses to grade the assertion at all when the connected role
    bypasses RLS, rather than reporting a pass it did not earn.
    """
    async with runtime_pool.acquire() as conn:
        role = await conn.fetchval("SELECT current_user")
        bypasses = await conn.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
        assert not bypasses, (
            f"ISOLATION_OCCURRENCES_RUNTIME_DSN connects as {role}, which bypasses RLS. "
            "This assertion would pass for the wrong reason; point it at the DML-only runtime role."
        )

        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant_id))
        mine = await conn.fetchval("SELECT count(*) FROM alert_occurrences")
        assert mine >= 1, "the tenant cannot see its own occurrence rows"

        await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(uuid.uuid4()))
        theirs = await conn.fetchval("SELECT count(*) FROM alert_occurrences")
        assert theirs == 0, "another tenant can read these occurrence rows"
        await conn.execute("SELECT set_config('app.current_tenant_id', '', false)")


@pytest.mark.asyncio(loop_scope="module")
async def test_fusion_can_write_an_occurrence_with_no_tenant_session_bound(runtime_pool, tenant_id) -> None:
    """The defect this suite found in its own migration, pinned.

    Fusion is a Kafka consumer. It holds no request, binds no
    `app.current_tenant_id`, and writes rows for whichever tenant the event
    belonged to — the same posture under which it writes `alerts`. The first
    cut of migration 151 carried the usual `WITH CHECK (tenant_id =
    current_tenant_id())`, which under an unbound session evaluates
    `tenant_id = NULL` and refuses the write.

    It would not have been noticed. `_record_deduplicated_event` is
    deliberately best-effort, so the refusal is logged at warning and the
    alert verdict stands: every occurrence row would simply never appear, and
    the feature would read as "this vendor never repeats". Migration 123 is
    the same shape — a correct-looking policy over a row nothing can write.

    Reverting the `WITH CHECK` to the stricter form fails this test with
    "new row violates row-level security policy".
    """
    alert_id = uuid.uuid4()
    async with runtime_pool.acquire() as conn:
        # Unbound, exactly as fusion connects. Asserted rather than assumed:
        # a bound session would make this pass for the wrong reason.
        await conn.execute("SELECT set_config('app.current_tenant_id', '', false)")
        assert await conn.fetchval("SELECT current_tenant_id() IS NULL") is True

        await conn.execute(
            "INSERT INTO alerts (id, tenant_id, title, dedup_hash) VALUES ($1, $2, $3, $4)",
            alert_id,
            tenant_id,
            "unbound-session probe",
            f"probe-{alert_id.hex[:12]}",
        )
        await conn.execute(
            """
            INSERT INTO alert_occurrences
                (tenant_id, alert_id, occurrence_count, first_seen, last_seen)
            VALUES ($1, $2, 2, NOW(), NOW())
            """,
            tenant_id,
            alert_id,
        )
        written = await conn.fetchval(
            "SELECT occurrence_count FROM alert_occurrences WHERE tenant_id = $1 AND alert_id = $2",
            tenant_id,
            alert_id,
        )
        assert written == 2
