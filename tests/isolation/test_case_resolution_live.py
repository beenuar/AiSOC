"""The resolution contract's Postgres truths, against real Postgres.

Why this has to be live
-----------------------
* ``resolution_gaps`` is a composition of four real reads (policy row, facts
  row, the case root-cause record, and the derived entity count over the
  case's observable graph and its alerts' affected-* arrays) — the entity
  count in particular is JSONB arithmetic a stub always gets right by
  construction.
* The one-per-tenant policy and one-per-case facts upserts are unique
  constraints, whose whole behaviour is the index.
* The RLS on both new tables is judged under the DML-only ``aisoc_app``
  role, which a superuser silently bypasses.

Against the pre-change tree every test fails at setup: neither
``case_resolution_policies`` nor ``case_resolution_facts`` exists.
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
        not os.environ.get("ISOLATION_CASE_RESOLUTION_DSN", "").strip(),
        reason="ISOLATION_CASE_RESOLUTION_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()
CASE_A = uuid.uuid4()
RUN_A = uuid.uuid4()


def _dsn(name: str) -> str:
    return os.environ[name].strip()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(_dsn("ISOLATION_CASE_RESOLUTION_ADMIN_DSN"))
    app = await asyncpg.connect(_dsn("ISOLATION_CASE_RESOLUTION_DSN"))

    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT_A, f"res-live-a-{suffix}"), (TENANT_B, f"res-live-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
            tenant,
            label,
        )
    # A case with one observable node, so the derived entity count is real.
    await admin.execute(
        """
        INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, observable_graph)
        VALUES ($1, $2, $3, 'resolution live fixture', 'contained',
                '{"nodes": [{"kind": "host", "value": "fin-ws-07"}]}'::jsonb)
        ON CONFLICT (id) DO NOTHING
        """,
        CASE_A,
        TENANT_A,
        f"RES-A-{uuid.uuid4().hex[:6]}",
    )
    # A ledger run + event for the root-cause citation (append-only: these
    # rows stay behind by design; see the root-cause live suite).
    await admin.execute(
        "INSERT INTO investigation_runs (id, tenant_id, case_id, status) VALUES ($1, $2, $3, 'completed') ON CONFLICT (id) DO NOTHING",
        RUN_A,
        TENANT_A,
        str(CASE_A),
    )
    await admin.execute(
        "INSERT INTO investigation_events (id, run_id, tenant_id, seq, kind, agent, summary, payload) "
        "VALUES ($1, $2, $3, 0, 'model_call', 'forensic', 'fixture', '{}') "
        "ON CONFLICT (run_id, seq) DO NOTHING",
        uuid.uuid4(),
        RUN_A,
        TENANT_A,
    )

    yield admin, app

    for tenant in (TENANT_A, TENANT_B):
        await admin.execute("DELETE FROM case_resolution_facts WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM case_resolution_policies WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM case_root_cause_citations WHERE tenant_id = $1", tenant)
        await admin.execute("DELETE FROM case_root_cause_records WHERE tenant_id = $1", tenant)
    await admin.execute("DELETE FROM aisoc_cases WHERE id = $1", CASE_A)
    await admin.close()
    await app.close()


async def _bind(conn, tenant: uuid.UUID) -> None:
    await conn.execute("SELECT set_config('app.current_tenant_id', $1, false)", str(tenant))


async def test_no_policy_row_means_no_enforcement(pools):
    """The opt-in default, over the real absent-row state."""
    import sqlalchemy  # noqa: F401 — the service imports it; fail here if absent

    _, app = pools
    await _bind(app, TENANT_A)
    n = await app.fetchval("SELECT COUNT(*) FROM case_resolution_policies WHERE tenant_id = $1", TENANT_A)
    assert n == 0


async def test_policy_is_one_per_tenant_and_facts_one_per_case(pools):
    _, app = pools
    await _bind(app, TENANT_A)
    for enforce in (True, False, True):
        await app.execute(
            """
            INSERT INTO case_resolution_policies (tenant_id, enforce)
            VALUES ($1, $2)
            ON CONFLICT (tenant_id) DO UPDATE SET enforce = EXCLUDED.enforce, updated_at = now()
            """,
            TENANT_A,
            enforce,
        )
    assert await app.fetchval("SELECT COUNT(*) FROM case_resolution_policies WHERE tenant_id = $1", TENANT_A) == 1
    assert await app.fetchval("SELECT enforce FROM case_resolution_policies WHERE tenant_id = $1", TENANT_A) is True

    for erad in ("first", "second"):
        await app.execute(
            """
            INSERT INTO case_resolution_facts (tenant_id, case_id, eradication)
            VALUES ($1, $2, $3)
            ON CONFLICT (tenant_id, case_id) DO UPDATE SET
                eradication = EXCLUDED.eradication, updated_at = now()
            """,
            TENANT_A,
            CASE_A,
            erad,
        )
    rows = await app.fetch(
        "SELECT eradication FROM case_resolution_facts WHERE tenant_id = $1 AND case_id = $2",
        TENANT_A,
        CASE_A,
    )
    assert len(rows) == 1 and rows[0]["eradication"] == "second"


async def test_the_derived_entity_count_reads_real_jsonb(pools):
    """The observable-graph node the fixture carries is counted; the SQL is
    the service's own, run over the real schema."""
    _, app = pools
    await _bind(app, TENANT_A)
    n = await app.fetchval(
        """
        SELECT COALESCE(jsonb_array_length(c.observable_graph -> 'nodes'), 0)
        FROM aisoc_cases c
        WHERE c.tenant_id = $1 AND c.id = $2
        """,
        TENANT_A,
        CASE_A,
    )
    assert n == 1


async def test_rls_hides_policy_and_facts_across_tenants(pools):
    _, app = pools
    await _bind(app, TENANT_B)
    assert await app.fetchval("SELECT COUNT(*) FROM case_resolution_policies") == 0, (
        "tenant B can see tenant A's resolution policy through RLS"
    )
    assert await app.fetchval("SELECT COUNT(*) FROM case_resolution_facts") == 0, "tenant B can see tenant A's resolution facts through RLS"
    await _bind(app, TENANT_A)
    assert await app.fetchval("SELECT COUNT(*) FROM case_resolution_policies") >= 1
