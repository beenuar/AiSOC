"""Access review against real Postgres (depth plan wave 2, Phase 1.2).

Live because the properties are schema facts a stand-in would invent: the
unique index that turns a nightly re-run into an update rather than a
ninetieth copy, the `(principal, kind) <> ALL` delete that retires a
finding somebody fixed, the tenant predicate on every statement, and the
acknowledgement write landing on the caller's own row only.

Each test carries a negative control. Skips without a database rather than
passing without one; fails rather than skips under
``MSSP_ISOLATION_REQUIRED``.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.services.access_review_store import acknowledge, list_findings, run_review, summary
from app.services.identity_privilege import IdentityPrivilege, PrivilegeTags
from app.services.identity_privilege_store import record_usage, save_privilege
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

TENANT = uuid.UUID("0e720000-0000-0000-0000-0000000000b1")
OTHER_TENANT = uuid.UUID("0e720000-0000-0000-0000-0000000000b2")
USER = uuid.UUID("0e720000-0000-0000-0000-0000000000b3")

ADMIN_ARN = "arn:aws:iam::1:user/root-ish"


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
        for tid, slug in ((TENANT, "review-live-a"), (OTHER_TENANT, "review-live-b")):
            await session.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
                {"id": tid, "name": f"Review live {slug}", "slug": slug},
            )
        await session.commit()
        yield session
        await session.rollback()
        for table in (
            "access_review_findings",
            "access_review_runs",
            "identity_permission_usage",
            "identity_privilege_facts",
        ):
            await session.execute(
                text(f"DELETE FROM {table} WHERE tenant_id IN (:a, :b)"),  # noqa: S608 — fixed table names
                {"a": TENANT, "b": OTHER_TENANT},
            )
        await session.commit()
    await engine.dispose()


async def _seed_admin(db, tenant_id=TENANT, *, principal: str = ADMIN_ARN) -> None:
    await save_privilege(
        db,
        tenant_id=tenant_id,
        privilege=IdentityPrivilege(
            tier="admin",
            tags=PrivilegeTags(can_escalate=True, third_party=None),
            provider="aws",
            principal_id=principal,
            evidence={"can_escalate": ["iam:PutUserPolicy", "iam:CreateAccessKey"]},
            action_count=40,
        ),
        principal_label="root-ish",
    )
    await db.commit()


async def _seed_usage(db, *, principal: str = ADMIN_ARN, days_ago: int, action: str = "s3:GetObject") -> None:
    now = datetime.now(tz=UTC)
    when = now - timedelta(days=days_ago)
    await record_usage(
        db,
        tenant_id=TENANT,
        provider="aws",
        principal_id=principal,
        observations={action: (3, when, when)},
        window_start=now - timedelta(days=90),
        window_end=now,
    )
    await db.commit()


@pytest.mark.asyncio
async def test_a_review_with_no_posture_is_nothing_reviewed_not_a_clean_bill(db) -> None:
    result = await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()

    assert result["state"] == "nothing_reviewed"
    assert result["reviewed_principals"] == 0
    assert result["findings"] == 0
    # The sentence is the point: a reader must not take the zero for an
    # all-clear, and the only thing standing between them and that reading
    # is this string.
    assert "not a clean bill of health" in result["note"]


@pytest.mark.asyncio
async def test_unmeasured_usage_suppresses_the_usage_findings(db) -> None:
    """No lake means no unused-access, dormancy or right-sizing findings."""
    await _seed_admin(db)
    result = await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()

    kinds = {f["kind"] for f in await list_findings(db, tenant_id=TENANT)}
    assert "unused_write_access" not in kinds
    assert "dormant_admin" not in kinds
    assert result["usage_measured_for"] == 0
    assert "partial review" in (result.get("note") or "")

    # Negative control: give the same principal measured usage with the
    # grants unexercised, and the suppressed findings appear.
    await _seed_usage(db, days_ago=200)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()
    kinds_after = {f["kind"] for f in await list_findings(db, tenant_id=TENANT)}
    assert "dormant_admin" in kinds_after
    assert "escalation_without_use" in kinds_after


@pytest.mark.asyncio
async def test_a_nightly_rerun_updates_rather_than_duplicates(db) -> None:
    await _seed_admin(db)
    await _seed_usage(db, days_ago=200)
    for _ in range(3):
        await run_review(db, tenant_id=TENANT, provider="aws")
        await db.commit()

    rows = await list_findings(db, tenant_id=TENANT)
    keys = [(r["principal_id"], r["kind"]) for r in rows]
    assert len(keys) == len(set(keys)), f"duplicate findings accumulated: {keys}"

    # Control: three runs really did happen, so the de-duplication is doing
    # the work rather than two of the runs having silently found nothing.
    runs = (
        await db.execute(
            text("SELECT count(*) FROM access_review_runs WHERE tenant_id = :t"),
            {"t": TENANT},
        )
    ).scalar_one()
    assert runs == 3


@pytest.mark.asyncio
async def test_a_finding_that_stops_reproducing_is_retired(db) -> None:
    """A page listing a permission somebody removed is a page nobody opens."""
    await _seed_admin(db)
    await _seed_usage(db, days_ago=200)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()
    assert {f["kind"] for f in await list_findings(db, tenant_id=TENANT)} >= {"dormant_admin"}

    # The admin is demoted and starts being used: both findings should go.
    await save_privilege(
        db,
        tenant_id=TENANT,
        privilege=IdentityPrivilege(
            tier="standard",
            tags=PrivilegeTags(),
            provider="aws",
            principal_id=ADMIN_ARN,
            evidence={},
            action_count=2,
        ),
        principal_label="root-ish",
    )
    await _seed_usage(db, days_ago=1)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()

    assert await list_findings(db, tenant_id=TENANT) == []


@pytest.mark.asyncio
async def test_another_tenants_findings_are_invisible_and_unacknowledgeable(db) -> None:
    await _seed_admin(db, OTHER_TENANT)
    await run_review(db, tenant_id=OTHER_TENANT, provider="aws")
    await db.commit()

    theirs = await list_findings(db, tenant_id=OTHER_TENANT)
    assert theirs, "the other tenant's review produced nothing, so this proves nothing"
    assert await list_findings(db, tenant_id=TENANT) == []

    # A 404 rather than a 403: the route must not be an existence oracle
    # over another tenant's finding ids.
    assert await acknowledge(db, tenant_id=TENANT, finding_id=uuid.UUID(theirs[0]["id"]), user_id=USER) is None


@pytest.mark.asyncio
async def test_acknowledgement_records_the_person_and_hides_the_row(db) -> None:
    await _seed_admin(db)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()
    open_rows = await list_findings(db, tenant_id=TENANT)
    assert open_rows

    updated = await acknowledge(
        db,
        tenant_id=TENANT,
        finding_id=uuid.UUID(open_rows[0]["id"]),
        user_id=USER,
        note="accepted: break-glass account, reviewed quarterly",
    )
    await db.commit()
    assert updated is not None
    assert updated["acknowledged_by"] == str(USER)
    assert "break-glass" in updated["acknowledged_note"]

    remaining = await list_findings(db, tenant_id=TENANT)
    assert len(remaining) == len(open_rows) - 1
    # Hidden, not deleted: "who decided this was fine" is the question an
    # auditor asks, and a deleted row cannot answer it.
    assert len(await list_findings(db, tenant_id=TENANT, include_acknowledged=True)) == len(open_rows)


@pytest.mark.asyncio
async def test_an_acknowledgement_survives_the_next_run(db) -> None:
    """Otherwise a nightly review un-acknowledges everything every night."""
    await _seed_admin(db)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()
    first = await list_findings(db, tenant_id=TENANT)
    await acknowledge(db, tenant_id=TENANT, finding_id=uuid.UUID(first[0]["id"]), user_id=USER)
    await db.commit()

    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()

    still_open = {f["kind"] for f in await list_findings(db, tenant_id=TENANT)}
    assert first[0]["kind"] not in still_open


@pytest.mark.asyncio
async def test_summary_distinguishes_never_run_from_reviewed(db) -> None:
    never = await summary(db, tenant_id=TENANT)
    assert never["state"] == "never_run"
    assert "not a clean bill of health" in never["note"]

    await _seed_admin(db)
    await run_review(db, tenant_id=TENANT, provider="aws")
    await db.commit()

    after = await summary(db, tenant_id=TENANT)
    assert after["state"] == "reviewed"
    assert after["providers"][0]["provider"] == "aws"
    assert after["providers"][0]["reviewed_principals"] == 1
