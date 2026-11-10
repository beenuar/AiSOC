"""The demo seeder's generated cases must satisfy the ``aisoc_cases`` CHECK.

``make demo`` aborted on a fresh install with::

    CheckViolationError: new row for relation "aisoc_cases" violates check
    constraint "aisoc_cases_status_check"

``_make_case`` and ``_make_synthetic_case`` drew a status from
``open | in_progress | pending | resolved | closed`` — the vocabulary of the
old ``cases`` table. Migration 083 pointed the ``Case`` model at
``aisoc_cases``, whose constraint (migration 012) admits only the console's
state machine in ``app.services.case_status``. Three of the five values could
never be written, and because the seeder inserts every case in one flush, one
bad row rolled back the whole demo dataset.

The first test is pure and runs anywhere. The second writes the builders'
output into a real ``aisoc_cases`` so the constraint itself is the judge, not
a copy of it. It skips without a database rather than passing without one.
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from app.scripts.seed_demo import _make_case, _make_synthetic_case
from app.services.case_status import ALL_STATUSES
from live_rls import bind_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
TENANT = uuid.UUID("5eed0000-0000-0000-0000-0000000000c1")

# Enough draws that every weighted choice turns up: the rarest status is
# weighted 10 of 100, so 60 draws per builder miss it with p < 0.002 — and
# the seeder's RNG is seeded, so the draw is the same on every run anyway.
_DRAWS = 60


def _built_cases() -> list:
    now = datetime.now(UTC)
    cases = []
    for idx in range(_DRAWS):
        cases.append(_make_case(TENANT, idx, now, []))
        cases.append(_make_synthetic_case(TENANT, idx, now, []))
    return cases


def test_every_generated_case_status_is_a_console_state() -> None:
    statuses = {c.status for c in _built_cases()}
    outside = statuses - set(ALL_STATUSES)
    assert not outside, f"seeder generates case statuses aisoc_cases refuses: {sorted(outside)}"


def test_closed_at_is_set_exactly_for_terminal_statuses() -> None:
    for case in _built_cases():
        assert (case.closed_at is not None) == (case.status in ("resolved", "closed")), case.status


@pytest_asyncio.fixture
async def db():
    if "postgres" not in DSN:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    engine = create_async_engine(DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__})")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        await session.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug) ON CONFLICT (id) DO NOTHING"),
            {"id": TENANT, "name": "Seed status live", "slug": "seed-status-live"},
        )
        await session.commit()
        yield session
        await session.rollback()
        await bind_tenant(session, TENANT)
        await session.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = :t"), {"t": TENANT})
        await session.commit()
    await engine.dispose()


async def test_generated_cases_are_accepted_by_aisoc_cases(db) -> None:
    cases = _built_cases()
    run = uuid.uuid4().hex[:8]
    for i, case in enumerate(cases):
        # case_number is globally unique; keep these clear of the real demo's INC-/CASE-SYN- rows.
        case.case_number = f"T-{run}-{i:03d}"

    await bind_tenant(db, TENANT)
    db.add_all(cases)
    await db.flush()

    landed = (await db.execute(text("SELECT DISTINCT status FROM aisoc_cases WHERE tenant_id = :t"), {"t": TENANT})).scalars().all()
    assert set(landed) == {c.status for c in cases}
