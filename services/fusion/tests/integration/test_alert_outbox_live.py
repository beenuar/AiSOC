"""The notification journal, against a real Postgres and the real migration.

``tests/test_alert_outbox.py`` drives the worker and the relay over an
in-memory journal, which proves the *decisions*. It cannot prove the SQL:
``FOR UPDATE SKIP LOCKED``, the lease, the ``ON CONFLICT`` upsert and the
``jsonb`` round trip are all properties of the database, and a double that
implements them in Python is exactly the kind of test that passes while the
statement it stands for has never run.

So this applies ``services/api/migrations/121_fusion_alert_outbox.sql`` to a
real server and exercises the claim path from two connections at once.

Skips cleanly when no server is reachable, and says so rather than passing
quietly -- a skipped integration test that reads like a pass is how a
never-executed gate stays green.

    docker run -d --name aisoc-outbox-pg -e POSTGRES_PASSWORD=aisoc_secret \\
        -e POSTGRES_USER=aisoc -e POSTGRES_DB=aisoc -p 55432:5432 \\
        postgres:16-alpine

    AISOC_TEST_POSTGRES=postgresql://aisoc:aisoc_secret@127.0.0.1:55432/aisoc \\
        pytest tests/integration/test_alert_outbox_live.py
"""

from __future__ import annotations

import os
import pathlib
import uuid

import pytest
import pytest_asyncio
from app.services.alert_outbox import AlertNotificationOutbox, NotificationRelay

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip()
pytestmark = pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES=postgresql://... to run the live journal proof")

_REPO = pathlib.Path(__file__).resolve().parents[4]
_MIGRATION = _REPO / "services" / "api" / "migrations" / "121_fusion_alert_outbox.sql"

#: `current_tenant_id()` lives in migration 002. Only the function is needed
#: here -- the policy this migration installs reads it, and CREATE POLICY
#: fails outright without it.
_TENANT_GUC_FN = """
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID
LANGUAGE plpgsql STABLE AS $$
BEGIN
    RETURN NULLIF(current_setting('app.current_tenant_id', TRUE), '')::uuid;
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END;
$$;
"""


@pytest_asyncio.fixture
async def pool():  # noqa: ANN201
    asyncpg = pytest.importorskip("asyncpg")
    created = await asyncpg.create_pool(DSN, min_size=1, max_size=4)
    async with created.acquire() as conn:
        await conn.execute("DROP TABLE IF EXISTS fusion_alert_outbox")
        await conn.execute(_TENANT_GUC_FN)
        await conn.execute(_MIGRATION.read_text(encoding="utf-8"))
    yield created
    await created.close()


def _envelope(alert_id: str) -> dict:
    return {"id": alert_id, "alert_row_id": alert_id, "persist_outcome": "inserted", "alert": {"title": "LSASS access"}}


@pytest.mark.asyncio
async def test_the_migration_applies_and_a_record_round_trips(pool):  # noqa: ANN001
    outbox = AlertNotificationOutbox(lambda: pool)
    tenant, alert_id = str(uuid.uuid4()), str(uuid.uuid4())

    assert await outbox.record(
        tenant_id=tenant, alert_id=alert_id, topic="aisoc.alerts.fused", key=alert_id, payload=_envelope(alert_id), error="broker down"
    )

    count, oldest, by_tenant = await outbox.backlog()
    assert count == 1
    assert oldest is not None and oldest >= 0.0
    assert by_tenant == {tenant: 1}, "an operator needs to know whose notifications are stuck, not just how many"

    claimed = await outbox.claim(limit=10, lease_seconds=30.0, grace_seconds=0.0)
    assert len(claimed) == 1
    # The jsonb round trip is the half a Python double cannot vouch for.
    assert claimed[0].payload == _envelope(alert_id)
    assert claimed[0].key == alert_id
    assert claimed[0].attempts == 1

    await outbox.resolve(claimed)
    assert (await outbox.backlog())[0] == 0


@pytest.mark.asyncio
async def test_repeated_failures_for_one_alert_do_not_grow_the_backlog(pool):  # noqa: ANN001
    """A long broker outage must not turn a bounded backlog into an unbounded one."""
    outbox = AlertNotificationOutbox(lambda: pool)
    tenant, alert_id = str(uuid.uuid4()), str(uuid.uuid4())

    for n in range(5):
        assert await outbox.record(
            tenant_id=tenant, alert_id=alert_id, topic="t", key=alert_id, payload=_envelope(alert_id), error=f"attempt {n}"
        )

    assert (await outbox.backlog())[0] == 1
    claimed = await outbox.claim(limit=10, lease_seconds=30.0, grace_seconds=0.0)
    assert claimed[0].attempts == 5, "the attempt count is the record of how long this has been owed"


@pytest.mark.asyncio
async def test_a_leased_row_is_not_handed_to_a_second_replica(pool):  # noqa: ANN001
    """Two relays, one row. Exactly one may publish it.

    This is the property ``FOR UPDATE SKIP LOCKED`` plus the lease exists
    for, and it cannot be tested without a real server: the second claim has
    to observe the first one's committed lease.
    """
    first = AlertNotificationOutbox(lambda: pool)
    second = AlertNotificationOutbox(lambda: pool)
    tenant = str(uuid.uuid4())
    for _ in range(3):
        alert_id = str(uuid.uuid4())
        await first.record(tenant_id=tenant, alert_id=alert_id, topic="t", key=alert_id, payload=_envelope(alert_id), error="down")

    claimed_a = await first.claim(limit=10, lease_seconds=60.0, grace_seconds=0.0)
    claimed_b = await second.claim(limit=10, lease_seconds=60.0, grace_seconds=0.0)

    assert len(claimed_a) == 3
    assert claimed_b == [], "a leased notification must not be published twice"


@pytest.mark.asyncio
async def test_an_expired_lease_is_reclaimable(pool):  # noqa: ANN001
    """A relay that dies mid-publish must not strand the row forever."""
    outbox = AlertNotificationOutbox(lambda: pool)
    tenant, alert_id = str(uuid.uuid4()), str(uuid.uuid4())
    await outbox.record(tenant_id=tenant, alert_id=alert_id, topic="t", key=alert_id, payload=_envelope(alert_id), error="down")

    # A lease that has already expired stands in for the replica that died.
    assert len(await outbox.claim(limit=10, lease_seconds=-1.0, grace_seconds=0.0)) == 1
    assert len(await outbox.claim(limit=10, lease_seconds=60.0, grace_seconds=0.0)) == 1, "an expired lease must be re-claimable"


@pytest.mark.asyncio
async def test_the_grace_period_keeps_the_relay_off_an_in_flight_retry(pool):  # noqa: ANN001
    """Fresh rows belong to the consumer's inline retry, not to the relay."""
    outbox = AlertNotificationOutbox(lambda: pool)
    tenant, alert_id = str(uuid.uuid4()), str(uuid.uuid4())
    await outbox.record(tenant_id=tenant, alert_id=alert_id, topic="t", key=alert_id, payload=_envelope(alert_id), error="down")

    assert await outbox.claim(limit=10, lease_seconds=30.0, grace_seconds=300.0) == []
    assert len(await outbox.claim(limit=10, lease_seconds=30.0, grace_seconds=0.0)) == 1


@pytest.mark.asyncio
async def test_the_relay_drains_the_real_table(pool):  # noqa: ANN001
    """End to end over the real store: claim, publish, delete."""
    outbox = AlertNotificationOutbox(lambda: pool)
    tenant = str(uuid.uuid4())
    ids = [str(uuid.uuid4()) for _ in range(3)]
    for alert_id in ids:
        await outbox.record(tenant_id=tenant, alert_id=alert_id, topic="t", key=alert_id, payload=_envelope(alert_id), error="down")

    published: list[tuple[dict, str]] = []

    async def publish(payload, key):  # noqa: ANN001, ANN202
        published.append((payload, key))

    relay = NotificationRelay(outbox, publish, grace_seconds=0.0)
    assert await relay.drain_once() == 3
    assert sorted(key for _, key in published) == sorted(ids)
    assert (await outbox.backlog())[0] == 0


@pytest.mark.asyncio
async def test_a_missing_table_is_reported_rather_than_silently_absorbed(pool):  # noqa: ANN001
    """A deployment that has not run the migration must say so.

    ``record`` returning False is what tells the consumer the alert is not
    recoverable. Returning True here -- or auto-creating the table, which
    would swallow a permissions failure into a log line -- would leave the
    service reporting a healthy journal that holds nothing.
    """
    async with pool.acquire() as conn:
        await conn.execute("DROP TABLE fusion_alert_outbox")
    outbox = AlertNotificationOutbox(lambda: pool)

    assert await outbox.record(tenant_id=str(uuid.uuid4()), alert_id=str(uuid.uuid4()), topic="t", key="k", payload={}, error="x") is False
    assert outbox.available is False
    assert await outbox.backlog() == (None, None, {}), "an unreadable backlog is not an empty one"
