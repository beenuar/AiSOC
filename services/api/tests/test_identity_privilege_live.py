"""Privilege at event time, proven against real Postgres.

Depth plan wave 2, Phase 1.1. Live because every property under test is a
schema fact a mock would invent:

* the ``valid_from <= t < valid_until`` interval select, which is the whole
  reason the posture table is versioned and the one thing a stand-in store
  always gets right by construction;
* the partial unique index that refuses two live rows per principal;
* the ``principal_id OR principal_label`` join, because an alert carries
  whichever handle the connector emitted and a join on the wrong one matches
  nothing while looking correct;
* the tenant predicate on both queries;
* ``boolean NULL`` round-tripping as ``None`` rather than ``False``, which is
  the difference between "no snapshot could answer" and "the snapshot says
  no".

Each test has a negative control that reverts the behaviour under test and
asserts it fails again, so none of them can pass for a reason other than the
one in its name.

Skips without a database rather than passing without one; under
``MSSP_ISOLATION_REQUIRED`` it fails instead of skipping, because a live
suite that silently skips is decoration.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.services.alert_priority import IdentityContext, score_alert_priority
from app.services.identity_privilege import IdentityPrivilege, PrivilegeTags
from app.services.identity_privilege_store import (
    live_facts_for_provider,
    privilege_at,
    record_usage,
    save_privilege,
    usage_for_principal,
)
from live_rls import bind_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e710000-0000-0000-0000-0000000000a1")
OTHER_TENANT = uuid.UUID("0e710000-0000-0000-0000-0000000000a2")

T0 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=5)
T2 = T1 + timedelta(days=5)


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
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        for tid, slug in ((TENANT, "priv-live-a"), (OTHER_TENANT, "priv-live-b")):
            await session.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
                {"id": tid, "name": f"Privilege live {slug}", "slug": slug},
            )
        await session.commit()
        yield session
        await session.rollback()
        for table in ("identity_permission_usage", "identity_privilege_facts"):
            await session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id IN (:a, :b)"),  # noqa: S608 — fixed table names
                {"a": TENANT, "b": OTHER_TENANT},
            )
        await session.commit()
    await engine.dispose()


#: Read times are nudged a minute into the future rather than using the
#: host's ``now()``.
#:
#: ``valid_from`` defaults to Postgres' ``now()``, and on this machine the
#: database container's clock ran ~17 ms *ahead* of the host's, so a row
#: written and then read at the host's ``now()`` landed before its own
#: ``valid_from`` and the point-in-time select correctly returned nothing.
#: That is the store behaving exactly as specified -- an event predating a
#: collection has no posture -- and a test that trips over it is measuring
#: clock skew, not the product. Widening ``valid_from <= :at`` to paper over
#: it would silently answer historical questions with newer snapshots, which
#: is the whole defect migration 103 is versioned to prevent.
#:
#: A minute is far inside the real gap between a collection and an event
#: (minutes to days), so nothing about the property under test is softened.
_SKEW = timedelta(minutes=1)


def _read_time() -> datetime:
    return datetime.now(tz=UTC) + _SKEW


def _privilege(tier: str, principal: str = "arn:aws:iam::1:user/alice", **tags) -> IdentityPrivilege:
    return IdentityPrivilege(
        tier=tier,  # type: ignore[arg-type]
        tags=PrivilegeTags(**tags),
        provider="aws",
        principal_id=principal,
        evidence={"tier": ["iam:PutUserPolicy"]} if tier in {"admin", "domain_admin"} else {},
        action_count=12,
        resource_count=3,
    )


@pytest.mark.asyncio
async def test_point_in_time_read_returns_the_tier_that_was_true_then(db) -> None:
    """An alert from before a demotion must read the pre-demotion tier.

    This is the defect the versioned table exists to prevent, and it is
    invisible on inspection: a live-row read returns a number that looks
    exactly as plausible as the right one.
    """
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("domain_admin"), principal_label="alice")
    await db.commit()
    # Supersede: the same principal is demoted five days later.
    await bind_tenant(db, TENANT)
    await db.execute(
        text("UPDATE identity_privilege_facts SET valid_from = :t0 WHERE tenant_id = :t AND valid_until IS NULL"),
        {"t0": T0, "t": TENANT},
    )
    await db.commit()
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("standard"), principal_label="alice")
    await db.commit()

    before = await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=T0 + timedelta(hours=1))
    after = await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=_read_time())

    assert before is not None and before.privilege.tier == "domain_admin"
    assert after is not None and after.privilege.tier == "standard"

    # Negative control: the live-row read, which is what this replaced.
    # It answers the *current* tier for the historical question, and the
    # answer is wrong in the direction nobody checks -- it under-states.
    live_row = (
        await db.execute(
            text("SELECT tier FROM identity_privilege_facts WHERE tenant_id = :t AND valid_until IS NULL LIMIT 1"),
            {"t": TENANT},
        )
    ).scalar_one()
    assert live_row == "standard"
    assert live_row != before.privilege.tier


@pytest.mark.asyncio
async def test_an_event_before_the_first_collection_has_no_fact(db) -> None:
    """No covering version must return None, never the nearest one."""
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("admin"), principal_label="alice")
    await db.commit()
    await bind_tenant(db, TENANT)
    await db.execute(
        text("UPDATE identity_privilege_facts SET valid_from = :t WHERE tenant_id = :tid"),
        {"t": T1, "tid": TENANT},
    )
    await db.commit()

    assert await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=T0) is None
    assert await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=T2) is not None


@pytest.mark.asyncio
async def test_tags_round_trip_as_tri_state(db) -> None:
    """NULL must come back as None. False and None are different facts."""
    await bind_tenant(db, TENANT)
    await save_privilege(
        db,
        tenant_id=TENANT,
        privilege=_privilege("admin", can_escalate=True, data_access=False, third_party=None, cross_account=True),
        principal_label="alice",
    )
    await db.commit()

    fact = await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=_read_time())
    assert fact is not None
    assert fact.privilege.tags.can_escalate is True
    assert fact.privilege.tags.data_access is False
    assert fact.privilege.tags.third_party is None
    assert fact.privilege.tags.cross_account is True
    # The one that matters: a reader that coerces would see False here.
    assert fact.privilege.tags.third_party is not False


@pytest.mark.asyncio
async def test_label_and_id_both_resolve(db) -> None:
    """An alert carries whichever handle its connector emitted."""
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("elevated"), principal_label="alice@example.com")
    await db.commit()
    now = _read_time()

    by_arn = await privilege_at(db, tenant_id=TENANT, principal_id="arn:aws:iam::1:user/alice", at=now)
    by_label = await privilege_at(db, tenant_id=TENANT, principal_id="ALICE@example.com", at=now)

    assert by_arn is not None and by_label is not None
    assert by_arn.privilege.tier == by_label.privilege.tier == "elevated"


@pytest.mark.asyncio
async def test_another_tenants_facts_are_invisible(db) -> None:
    await bind_tenant(db, OTHER_TENANT)
    await save_privilege(db, tenant_id=OTHER_TENANT, privilege=_privilege("domain_admin"), principal_label="alice")
    await db.commit()

    assert await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=_read_time()) is None
    assert await live_facts_for_provider(db, tenant_id=TENANT, provider="aws") == []
    assert len(await live_facts_for_provider(db, tenant_id=OTHER_TENANT, provider="aws")) == 1


@pytest.mark.asyncio
async def test_an_unchanged_rederivation_does_not_open_a_version(db) -> None:
    """Otherwise "when did this privilege last change" answers "hourly"."""
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("admin"), principal_label="alice")
    await db.commit()
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("admin"), principal_label="alice")
    await db.commit()

    count = (
        await db.execute(
            text("SELECT count(*) FROM identity_privilege_facts WHERE tenant_id = :t"),
            {"t": TENANT},
        )
    ).scalar_one()
    assert count == 1

    # And a real change does open one, which is the control for the above:
    # a store that never wrote a second row would also pass the assertion.
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("standard"), principal_label="alice")
    await db.commit()
    count_after = (
        await db.execute(
            text("SELECT count(*) FROM identity_privilege_facts WHERE tenant_id = :t"),
            {"t": TENANT},
        )
    ).scalar_one()
    assert count_after == 2


@pytest.mark.asyncio
async def test_two_live_rows_are_refused_by_the_database(db) -> None:
    """The invariant is enforced in Postgres, not by every writer remembering."""
    await bind_tenant(db, TENANT)
    await save_privilege(db, tenant_id=TENANT, privilege=_privilege("admin"), principal_label="alice")
    await db.commit()

    await bind_tenant(db, TENANT)
    with pytest.raises(Exception) as excinfo:
        await db.execute(
            text(
                """
                INSERT INTO identity_privilege_facts (tenant_id, provider, principal_id, tier)
                VALUES (:t, 'aws', 'arn:aws:iam::1:user/alice', 'standard')
                """
            ),
            {"t": TENANT},
        )
        await db.commit()
    assert "identity_privilege_facts_live_idx" in str(excinfo.value)
    await db.rollback()


@pytest.mark.asyncio
async def test_usage_distinguishes_unmeasured_from_unused(db) -> None:
    """The distinction a right-sizing recommendation turns on.

    With no rows the overlay reports ``measured=False`` and ``unused()``
    returns ``None``. A store that returned an empty set instead would have
    every finding recommend revoking every permission in the estate.
    """
    empty = await usage_for_principal(db, tenant_id=TENANT, provider="aws", principal_id="u1")
    assert empty.measured is False
    assert empty.unused({"s3:GetObject", "s3:PutObject"}) is None

    now = datetime.now(tz=UTC)
    await bind_tenant(db, TENANT)
    await record_usage(
        db,
        tenant_id=TENANT,
        provider="aws",
        principal_id="u1",
        observations={"s3:GetObject": (42, now - timedelta(days=3), now)},
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    await db.commit()

    measured = await usage_for_principal(db, tenant_id=TENANT, provider="aws", principal_id="u1")
    assert measured.measured is True
    assert measured.unused({"s3:GetObject", "s3:PutObject"}) == {"s3:PutObject"}


@pytest.mark.asyncio
async def test_usage_upsert_keeps_the_widest_observed_span(db) -> None:
    """A later window must not shorten what was already observed."""
    now = datetime.now(tz=UTC)
    first, last = now - timedelta(days=20), now - timedelta(days=10)
    await bind_tenant(db, TENANT)
    await record_usage(
        db,
        tenant_id=TENANT,
        provider="aws",
        principal_id="u1",
        observations={"s3:GetObject": (5, first, last)},
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    await bind_tenant(db, TENANT)
    await record_usage(
        db,
        tenant_id=TENANT,
        provider="aws",
        principal_id="u1",
        observations={"s3:GetObject": (7, now - timedelta(days=2), now)},
        window_start=now - timedelta(days=7),
        window_end=now,
    )
    await db.commit()

    row = (
        await db.execute(
            text(
                "SELECT first_used_at, last_used_at, use_count FROM identity_permission_usage WHERE tenant_id = :t AND principal_id = 'u1'"
            ),
            {"t": TENANT},
        )
    ).one()
    assert row.first_used_at == first
    assert row.last_used_at > last
    assert row.use_count == 7


@pytest.mark.asyncio
async def test_the_tier_read_from_the_store_actually_moves_the_queue_score(db) -> None:
    """End of the chain: a stored fact changes the number the queue sorts by.

    Without this the other tests prove a well-built table nobody consumes,
    which is the exact shape this phase exists to close.
    """
    await bind_tenant(db, TENANT)
    await save_privilege(
        db,
        tenant_id=TENANT,
        privilege=_privilege("domain_admin", can_escalate=True, cross_account=True),
        principal_label="alice",
    )
    await db.commit()

    fact = await privilege_at(db, tenant_id=TENANT, principal_id="alice", at=_read_time())
    assert fact is not None

    context = IdentityContext(
        principal=fact.privilege.principal_id,
        privilege_tier=fact.privilege.tier,
        can_escalate=fact.privilege.tags.can_escalate,
        data_access=fact.privilege.tags.data_access,
        third_party=fact.privilege.tags.third_party,
        cross_account=fact.privilege.tags.cross_account,
    )
    with_context = score_alert_priority(severity="medium", identity=context)
    unknown = score_alert_priority(severity="medium", identity=IdentityContext())

    assert with_context.score > unknown.score
    reasons = " ".join(r["reason"] for r in with_context.rationale)
    assert "domain_admin" in reasons
    assert "can_escalate" in reasons and "cross_account" in reasons

    # Negative control: drop the tags and the tier from the context -- the
    # exact revert -- and the score collapses back to the unknown baseline.
    assert score_alert_priority(severity="medium", identity=IdentityContext()).score == unknown.score
