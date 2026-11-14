"""Versioned posture snapshots, against live Postgres (depth plan 2.5).

Run against a real database on purpose. Every property worth asserting here
is enforced by the schema rather than by Python — a partial unique index, a
CHECK constraint, and an interval query — and a fake session that answers
any query cannot tell a working temporal lookup from a broken one. The
project has shipped that exact failure before: a store whose tests passed
against a double while the production table had no writer at all.

What is being pinned, and why each one matters:

* **One live version per provider.** Two rows with ``valid_until IS NULL``
  make "the current posture" ambiguous and the resolver takes whichever the
  planner returns first. The index refuses it; this proves the index is
  really there, not just the application convention.

* **An unchanged re-collection does not open a version.** Otherwise a
  collector on an hourly schedule writes a version an hour and "when did
  this posture last change" becomes unanswerable, because every row is a
  change.

* **A point-in-time read returns the version in force then.** This is the
  whole reason the table is versioned. An alert is triaged minutes to days
  after the event, and what the identity can do *now* — after someone
  revoked the role — is a different question with a different answer.

* **An event predating the first collection returns nothing.** Falling back
  to the live snapshot would answer a question nobody asked, in a way no
  reader could detect.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.services.posture_store import (
    content_hash,
    counts,
    live_snapshot,
    save_snapshot,
    snapshot_at,
    snapshot_history,
)
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0c100000-0000-0000-0000-000000001030")
OTHER_TENANT = uuid.UUID("0c100000-0000-0000-0000-000000001040")


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(
                "MSSP_ISOLATION_REQUIRED is set but no database answered at DATABASE_URL — "
                f"the posture-store proof did not run: {type(exc).__name__}: {exc}"
            )
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await _reset(session)
        try:
            yield session
        finally:
            await _reset(session)
    await engine.dispose()


async def _reset(session) -> None:
    await session.rollback()
    for tenant in (TENANT, OTHER_TENANT):
        await session.execute(
            text("DELETE FROM posture_snapshots WHERE tenant_id = CAST(:t AS uuid)"),
            {"t": str(tenant)},
        )
    await session.commit()


def _snapshot(n_principals: int, *, marker: str = "") -> dict:
    return {
        "principals": [{"id": f"arn:aws:iam::1:user/u{i}", "name": f"u{i}"} for i in range(n_principals)],
        "policies": [],
        "marker": marker,
    }


async def _save(db, snapshot: dict, **kw):
    saved = await save_snapshot(
        db,
        tenant_id=kw.pop("tenant_id", TENANT),
        provider=kw.pop("provider", "aws"),
        connector_id=kw.pop("connector_id", "aws_security_hub"),
        snapshot=snapshot,
        principal_count=len(snapshot.get("principals") or []),
        **kw,
    )
    await db.commit()
    return saved


@pytest.mark.asyncio
async def test_first_collection_becomes_the_live_version(db) -> None:
    saved = await _save(db, _snapshot(3))

    assert saved.is_live
    assert saved.principal_count == 3
    assert saved.content_hash == content_hash(_snapshot(3))

    live = await live_snapshot(db, tenant_id=TENANT, provider="aws")
    assert live is not None
    assert live.id == saved.id


@pytest.mark.asyncio
async def test_unchanged_recollection_does_not_open_a_version(db) -> None:
    """Every row in the history must be a real posture change."""
    first = await _save(db, _snapshot(3))
    second = await _save(db, _snapshot(3))

    assert second.id == first.id
    assert len(await snapshot_history(db, tenant_id=TENANT, provider="aws")) == 1


@pytest.mark.asyncio
async def test_unchanged_recollection_still_records_a_newly_lost_read(db) -> None:
    """A collection that lost access to half the estate returns exactly the
    snapshot it can still see, so the content is identical and the *gap* is
    the only thing that changed. Dropping it would leave a snapshot claiming
    to be complete."""
    await _save(db, _snapshot(3))

    refreshed = await _save(
        db,
        _snapshot(3),
        partial=True,
        collection_notes=["organisation members: HTTP 403 on page 2"],
    )

    assert refreshed.partial is True
    assert refreshed.collection_notes == ["organisation members: HTTP 403 on page 2"]


@pytest.mark.asyncio
async def test_a_changed_estate_opens_a_version_and_closes_the_old_one(db) -> None:
    first = await _save(db, _snapshot(3))
    second = await _save(db, _snapshot(4))

    assert second.id != first.id
    assert second.is_live

    history = await snapshot_history(db, tenant_id=TENANT, provider="aws")
    assert [s.id for s in history] == [second.id, first.id]
    assert history[1].valid_until is not None, "the superseded version was never closed"


@pytest.mark.asyncio
async def test_only_one_version_is_ever_live(db) -> None:
    """The invariant the whole table rests on, asserted against the database
    rather than against the writer that is supposed to maintain it."""
    for n in range(2, 6):
        await _save(db, _snapshot(n))

    result = await db.execute(
        text(
            """
            SELECT COUNT(*) FROM posture_snapshots
             WHERE tenant_id = CAST(:t AS uuid) AND provider = 'aws' AND valid_until IS NULL
            """
        ),
        {"t": str(TENANT)},
    )
    assert result.scalar_one() == 1


@pytest.mark.asyncio
async def test_a_second_live_row_is_refused_by_the_database(db) -> None:
    """The negative control for the index.

    Without it the application convention is the only thing holding the
    invariant, and a writer that forgets to close the old row leaves two
    live versions with nothing complaining.
    """
    from sqlalchemy.exc import IntegrityError

    await _save(db, _snapshot(3))

    with pytest.raises(IntegrityError):
        await db.execute(
            text(
                """
                INSERT INTO posture_snapshots
                    (tenant_id, provider, connector_id, snapshot, content_hash)
                VALUES
                    (CAST(:t AS uuid), 'aws', 'aws_security_hub', CAST('{}' AS jsonb), 'a-different-hash')
                """
            ),
            {"t": str(TENANT)},
        )
    await db.rollback()


@pytest.mark.asyncio
async def test_point_in_time_read_returns_the_version_in_force_then(db) -> None:
    """The reason the table is versioned at all.

    The cutover instant is taken from the *database* clock and read back,
    rather than from ``datetime.now()`` here. Mixing the two clocks makes a
    temporal assertion depend on host/container skew — which on this machine
    is enough to push ``valid_until`` behind ``valid_from`` and trip the
    interval CHECK, turning a query test into a clock test.
    """
    before = await _save(db, _snapshot(2, marker="before"))
    # Backdate the first version so the two intervals are an hour apart
    # rather than milliseconds: an alert triaged "during" a version is the
    # case being modelled, and two adjacent instants cannot express it.
    cutover = (
        await db.execute(
            text(
                """
                UPDATE posture_snapshots
                   SET valid_from = NOW() - INTERVAL '1 hour', valid_until = NOW()
                 WHERE tenant_id = CAST(:t AS uuid) AND id = CAST(:i AS uuid)
                RETURNING valid_until
                """
            ),
            {"t": str(TENANT), "i": str(before.id)},
        )
    ).scalar_one()
    await db.execute(
        text(
            """
            INSERT INTO posture_snapshots
                (tenant_id, provider, connector_id, snapshot, content_hash, valid_from)
            VALUES
                (CAST(:t AS uuid), 'aws', 'aws_security_hub', CAST(:s AS jsonb), 'after-hash', :c)
            """
        ),
        {"t": str(TENANT), "s": '{"principals": [], "marker": "after"}', "c": cutover},
    )
    await db.commit()

    at_event = await snapshot_at(db, tenant_id=TENANT, provider="aws", at=cutover - timedelta(minutes=30))
    assert at_event is not None
    assert at_event.snapshot["marker"] == "before", "a point-in-time read returned the posture in force now, not then"

    now = await snapshot_at(db, tenant_id=TENANT, provider="aws", at=cutover + timedelta(minutes=5))
    assert now is not None
    assert now.snapshot["marker"] == "after"

    # The boundary itself belongs to the new version: the interval is
    # [valid_from, valid_until), so an event at the exact cutover instant
    # must not match both rows.
    boundary = await snapshot_at(db, tenant_id=TENANT, provider="aws", at=cutover)
    assert boundary is not None
    assert boundary.snapshot["marker"] == "after"


@pytest.mark.asyncio
async def test_an_event_predating_every_collection_has_no_posture(db) -> None:
    """Returning the live snapshot here would answer a question nobody asked
    and no reader could detect."""
    await _save(db, _snapshot(3))

    answer = await snapshot_at(
        db,
        tenant_id=TENANT,
        provider="aws",
        at=datetime.now(UTC) - timedelta(days=30),
    )
    assert answer is None


@pytest.mark.asyncio
async def test_one_tenants_snapshot_is_invisible_to_another(db) -> None:
    await _save(db, _snapshot(3))
    await _save(db, _snapshot(9), tenant_id=OTHER_TENANT)

    mine = await live_snapshot(db, tenant_id=TENANT, provider="aws")
    theirs = await live_snapshot(db, tenant_id=OTHER_TENANT, provider="aws")

    assert mine is not None and theirs is not None
    assert mine.principal_count == 3
    assert theirs.principal_count == 9
    assert mine.id != theirs.id


@pytest.mark.asyncio
async def test_providers_version_independently(db) -> None:
    """Collecting AWS must not close GitHub's live row."""
    aws = await _save(db, _snapshot(3))
    gh = await _save(db, _snapshot(5), provider="github", connector_id="github")
    await _save(db, _snapshot(4))

    # Bound and asserted non-None first: `live_snapshot` returns Optional,
    # and dereferencing it inline would report "NoneType has no attribute
    # id" when the real failure is that no live row exists at all.
    live_github = await live_snapshot(db, tenant_id=TENANT, provider="github")
    live_aws = await live_snapshot(db, tenant_id=TENANT, provider="aws")
    assert live_github is not None, "github has no live snapshot"
    assert live_aws is not None, "aws has no live snapshot"

    assert live_github.id == gh.id
    assert live_aws.id != aws.id


@pytest.mark.asyncio
async def test_an_unknown_provider_is_refused_with_a_sentence(db) -> None:
    with pytest.raises(ValueError, match="unknown provider"):
        await save_snapshot(
            db,
            tenant_id=TENANT,
            provider="not-a-cloud",
            connector_id="x",
            snapshot={},
        )


def test_content_hash_ignores_key_order() -> None:
    """Two collections of an unchanged estate differ only in dict ordering,
    and without this every re-collection looks like a posture change."""
    assert content_hash({"a": 1, "b": [1, 2]}) == content_hash({"b": [1, 2], "a": 1})
    assert content_hash({"a": 1}) != content_hash({"a": 2})


def test_counts_are_read_off_the_collected_document() -> None:
    """Counting the document rather than a running total is what makes a
    truncated collection show up as a smaller number instead of agreeing
    with whatever the collector believed it had fetched."""
    assert counts(
        {
            "principals": [{"id": "a"}, {"id": "b"}],
            "resources": [{"id": "r"}],
            "policies": [{"id": "p"}],
            "role_definitions": [{"id": "rd"}],
        }
    ) == (2, 1, 2)


async def test_counts_are_derived_when_the_caller_does_not_supply_them(db) -> None:
    """The columns are filled from the snapshot unless measured separately.

    They used to default to 0, so a caller that forgot them wrote "this
    estate has no principals" -- the one value an operator reads as "our
    credential lost its read permission", published about an estate that was
    read perfectly well.
    """
    snapshot = {
        "principals": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
        "resources": [{"id": "r"}],
        "policies": [{"id": "p1"}, {"id": "p2"}],
    }

    saved = await save_snapshot(
        db,
        tenant_id=TENANT,
        provider="gcp",
        connector_id="gcp_scc",
        snapshot=snapshot,
    )

    assert (saved.principal_count, saved.resource_count, saved.policy_count) == (3, 1, 2)


async def test_a_measured_count_is_not_overwritten_by_the_derived_one(db) -> None:
    """A collector that knows it truncated can say so.

    Deriving unconditionally would discard the one number that is better
    than the document: a collector that fetched 900 of 1,000 principals and
    knows it knows something `len()` cannot see.
    """
    saved = await save_snapshot(
        db,
        tenant_id=TENANT,
        provider="github",
        connector_id="github",
        snapshot={"principals": [{"id": "a"}]},
        principal_count=900,
        partial=True,
        collection_notes=["page 2 of the member list timed out"],
    )

    assert saved.principal_count == 900
    assert saved.partial is True
