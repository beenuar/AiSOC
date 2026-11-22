"""The root-cause record's Postgres truths, against real Postgres (WS7.1).

Why this has to be live
-----------------------
The statements behind the record are the kind a stub connection accepts
happily and Postgres does not:

* ``ON CONFLICT (tenant_id, case_id)`` — one record per case is the unique
  constraint's behaviour, and a second upsert must *replace*, not duplicate;
* the citation existence check joins against ``investigation_events``'s
  real ``UNIQUE (run_id, seq)`` rows;
* the RLS policies on both tables, which a superuser silently bypasses — so
  this suite reads through the DML-only ``aisoc_app`` role, the same
  NOBYPASSRLS role the services run as.

Against the pre-change tree every test here fails at setup: neither
``case_root_cause_records`` nor ``case_root_cause_citations`` exists.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CASE_ROOT_CAUSE_DSN", "").strip(),
        reason="ISOLATION_CASE_ROOT_CAUSE_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
CASE_A = uuid.uuid4()
CASE_B = uuid.uuid4()
RUN_A = uuid.uuid4()


def _dsn(name: str) -> str:
    return os.environ[name].strip()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(_dsn("ISOLATION_CASE_ROOT_CAUSE_ADMIN_DSN"))
    app = await asyncpg.connect(_dsn("ISOLATION_CASE_ROOT_CAUSE_DSN"))

    # Fixtures as owner: scratch tenants, a case each, and a ledger run with
    # two events for tenant A — the rows the citations must resolve against.
    # Slugs carry a per-run suffix because tenants.slug is UNIQUE and prior
    # runs' tenants stay behind by design: the Investigation Ledger is
    # append-only (a trigger refuses DELETE), so a tenant that owns ledger
    # rows can never be deleted — not by this teardown and not by cascade.
    # The scratch database is per-job in CI and throwaway locally.
    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT_A, f"rc-live-a-{suffix}"), (TENANT_B, f"rc-live-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
            tenant,
            label,
        )
    for tenant, case_id, number in ((TENANT_A, CASE_A, "RC-A-1"), (TENANT_B, CASE_B, "RC-B-1")):
        await admin.execute(
            """
            INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status)
            VALUES ($1, $2, $3, 'root-cause live fixture', 'investigating')
            ON CONFLICT (id) DO NOTHING
            """,
            case_id,
            tenant,
            f"{number}-{uuid.uuid4().hex[:6]}",
        )
    await admin.execute(
        """
        INSERT INTO investigation_runs (id, tenant_id, case_id, status)
        VALUES ($1, $2, $3, 'completed') ON CONFLICT (id) DO NOTHING
        """,
        RUN_A,
        TENANT_A,
        str(CASE_A),
    )
    for seq, kind in ((0, "model_call"), (1, "triage_verdict")):
        await admin.execute(
            """
            INSERT INTO investigation_events (id, run_id, tenant_id, seq, kind, agent, summary, payload)
            VALUES ($1, $2, $3, $4, $5, 'forensic', 'live fixture', '{}'::jsonb)
            ON CONFLICT (run_id, seq) DO NOTHING
            """,
            uuid.uuid4(),
            RUN_A,
            TENANT_A,
            seq,
            kind,
        )

    yield admin, app

    # Ledger rows (and therefore their run and tenants) are append-only by
    # design — the inv_events_immutable trigger refuses DELETE — so teardown
    # removes only what can honestly be removed. Fresh uuids every run keep
    # reruns collision-free.
    for tenant in (TENANT_A, TENANT_B):
        await admin.execute("DELETE FROM case_root_cause_citations WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM case_root_cause_records WHERE tenant_id = $1", tenant)
    for case_id in (CASE_A, CASE_B):
        await admin.execute("DELETE FROM aisoc_cases WHERE id = $1", case_id)
    await admin.close()
    await app.close()


async def _bind(conn, tenant: uuid.UUID) -> None:
    # Parameterized set_config, the sibling suites' shape — SET takes no
    # bind parameters, and an f-string here is the exact pattern the
    # Semgrep sqli rule exists to flag.
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant))


async def _upsert(conn, tenant: uuid.UUID, case_id: uuid.UUID, status: str, summary: str):
    return await conn.fetchrow(
        """
        INSERT INTO case_root_cause_records (tenant_id, case_id, status, summary)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (tenant_id, case_id) DO UPDATE SET
            status = EXCLUDED.status, summary = EXCLUDED.summary, updated_at = now()
        RETURNING id, status, summary
        """,
        tenant,
        case_id,
        status,
        summary,
    )


async def test_one_record_per_case_replaces_rather_than_duplicates(pools):
    _, app = pools
    await _bind(app, TENANT_A)
    first = await _upsert(app, TENANT_A, CASE_A, "hypothesis", "first")
    second = await _upsert(app, TENANT_A, CASE_A, "determined", "second")
    assert first["id"] == second["id"]
    n = await app.fetchval(
        "SELECT COUNT(*) FROM case_root_cause_records WHERE tenant_id = $1 AND case_id = $2",
        TENANT_A,
        CASE_A,
    )
    assert n == 1
    assert second["status"] == "determined"


async def test_citations_resolve_against_real_ledger_rows(pools):
    _, app = pools
    await _bind(app, TENANT_A)
    # The service's existence check, run as real SQL: 2 of the 3 cited pairs
    # exist (seq 0 and 1); seq 99 does not.
    n = await app.fetchval(
        """
        SELECT COUNT(*) FROM investigation_events
        WHERE (run_id = $1 AND seq = 0) OR (run_id = $1 AND seq = 1) OR (run_id = $1 AND seq = 99)
        """,
        RUN_A,
    )
    assert n == 2, "the shortfall is what the route's 422 names"


async def test_rls_hides_one_tenants_record_from_the_other(pools):
    _, app = pools
    await _bind(app, TENANT_A)
    record = await _upsert(app, TENANT_A, CASE_A, "hypothesis", "tenant A's record")
    await app.execute(
        """
        INSERT INTO case_root_cause_citations
            (tenant_id, record_id, run_id, seq, source, description)
        VALUES ($1, $2, $3, 0, 'ledger', 'cited entry')
        """,
        TENANT_A,
        record["id"],
        RUN_A,
    )

    await _bind(app, TENANT_B)
    visible_records = await app.fetchval("SELECT COUNT(*) FROM case_root_cause_records")
    visible_citations = await app.fetchval("SELECT COUNT(*) FROM case_root_cause_citations")
    assert visible_records == 0, "tenant B can see tenant A's root-cause record through RLS"
    assert visible_citations == 0, "tenant B can see tenant A's citations through RLS"

    await _bind(app, TENANT_A)
    assert await app.fetchval("SELECT COUNT(*) FROM case_root_cause_records") >= 1


async def test_status_vocabulary_is_db_enforced(pools):
    import asyncpg

    _, app = pools
    await _bind(app, TENANT_A)
    with pytest.raises(asyncpg.CheckViolationError):
        await _upsert(app, TENANT_A, CASE_A, "definitely", "not a valid status")
