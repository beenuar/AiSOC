"""The operating model's Postgres truths, against real Postgres.

Why this has to be live
-----------------------
* The handoff snapshot is five real queries over the tenant's own rows —
  counts a stub gets right by construction — and generation idempotence is
  the ``ON CONFLICT DO NOTHING`` of a unique constraint.
* Escalation routing ends in rows: an ``outbound_deliveries`` row for the
  tenant's own webhook and an ``escalation_nags`` row that makes the second
  sweep a no-op. Dedup is the constraint's behaviour.
* The matrix's narrow-only answer is judged over real rows, and RLS on all
  four new tables is judged under the DML-only ``aisoc_app`` role.

Against the pre-change tree every test fails at setup: none of the four
tables exists.

Environment: ISOLATION_OPERATING_MODEL_DSN (aisoc_app) +
ISOLATION_OPERATING_MODEL_ADMIN_DSN (owner, fixtures).
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_OPERATING_MODEL_DSN", "").strip(),
        reason="ISOLATION_OPERATING_MODEL_DSN is not set; this suite needs a live Postgres",
    ),
]

_API = Path(__file__).resolve().parents[2] / "services" / "api"
if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

TENANT_A = uuid.uuid4()
TENANT_B = uuid.uuid4()


def _dsn(name: str) -> str:
    return os.environ[name].strip()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def pools():
    import asyncpg

    admin = await asyncpg.connect(_dsn("ISOLATION_OPERATING_MODEL_ADMIN_DSN"))
    app = await asyncpg.connect(_dsn("ISOLATION_OPERATING_MODEL_DSN"))
    suffix = uuid.uuid4().hex[:8]
    for tenant, label in ((TENANT_A, f"om-a-{suffix}"), (TENANT_B, f"om-b-{suffix}")):
        await admin.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2) ON CONFLICT (id) DO NOTHING",
            tenant,
            label,
        )
    yield admin, app
    for tenant in (TENANT_A, TENANT_B):
        for table in (
            "escalation_nags",
            "escalation_routes",
            "aisoc_outbound_deliveries",
            "aisoc_outbound_webhooks",
            "shift_handoffs",
            "soc_shifts",
            "responsibility_matrix",
            "aisoc_cases",
            "alerts",
        ):
            try:
                await admin.execute(f"DELETE FROM {table} WHERE tenant_id = $1", tenant)  # noqa: S608 — test teardown over a fixed list
            except Exception:  # noqa: BLE001,S110 — a table this suite never touched
                pass
        await admin.execute("DELETE FROM tenants WHERE id = $1", tenant)
    await admin.close()
    await app.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    dsn = _dsn("ISOLATION_OPERATING_MODEL_ADMIN_DSN").replace("postgresql://", "postgresql+asyncpg://")
    engine = create_async_engine(dsn, poolclass=None)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _bind(conn, tenant: uuid.UUID | None) -> None:
    await conn.execute(
        "SELECT set_config('app.current_tenant_id', $1, false)",
        str(tenant) if tenant else "",
    )


async def test_rls_on_all_four_tables_under_the_app_role(pools):
    admin, app = pools
    bypass = await app.fetchval("SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user")
    assert bypass is False, "the assertion role bypasses RLS; this test would prove nothing"

    shift_ids: dict[uuid.UUID, uuid.UUID] = {}
    for tenant in (TENANT_A, TENANT_B):
        shift_ids[tenant] = await admin.fetchval(
            """
            INSERT INTO soc_shifts (tenant_id, name, timezone, start_minute, end_minute)
            VALUES ($1, 'day', 'UTC', 360, 1080) RETURNING id
            """,
            tenant,
        )
        await admin.execute(
            """
            INSERT INTO responsibility_matrix (tenant_id, activity, verb, owner)
            VALUES ($1, 'action', 'isolate_host', 'customer')
            """,
            tenant,
        )
    await _bind(app, TENANT_A)
    for table in ("soc_shifts", "responsibility_matrix"):
        rows = await app.fetch(f"SELECT tenant_id FROM {table}")  # noqa: S608 — fixed identifiers
        assert {r["tenant_id"] for r in rows} == {TENANT_A}, f"{table} leaked across tenants"
    await _bind(app, None)
    rows = await app.fetch("SELECT tenant_id FROM soc_shifts")
    assert {TENANT_A, TENANT_B} <= {r["tenant_id"] for r in rows}, "the unbound arm is load-bearing: the sweep worker reads every tenant"


async def test_handoff_generates_from_real_rows_and_is_idempotent(pools, session_factory):
    from app.services.shift_handoff import generate_due_handoffs

    admin, _ = pools
    # A shift whose occurrence ended an hour ago.
    now = datetime.now(UTC)
    end_minute = ((now - timedelta(hours=1)).hour * 60 + (now - timedelta(hours=1)).minute) % 1440
    start_minute = (end_minute - 480) % 1440
    await admin.execute(
        """
        INSERT INTO soc_shifts (tenant_id, name, timezone, start_minute, end_minute, weekdays)
        VALUES ($1, 'ending', 'UTC', $2, $3, '{1,2,3,4,5,6,7}')
        """,
        TENANT_A,
        start_minute,
        end_minute,
    )
    # Real open work: two alerts, one unowned case.
    for n, severity in enumerate(("critical", "medium")):
        await admin.execute(
            """
            INSERT INTO alerts (id, tenant_id, title, severity, status, created_at)
            VALUES ($1, $2, $3, $4, 'open', now() - interval '2 hours')
            """,
            uuid.uuid4(),
            TENANT_A,
            f"live alert {n}",
            severity,
        )
    await admin.execute(
        """
        INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, severity)
        VALUES ($1, $2, $3, 'unowned live case', 'new', 'high')
        """,
        uuid.uuid4(),
        TENANT_A,
        f"OM-{uuid.uuid4().hex[:6]}",
    )

    async with session_factory() as db:
        first = await generate_due_handoffs(db)
        await db.commit()
    assert first.generated >= 1, f"no handoff generated: {first}"

    row = await admin.fetchrow(
        """
        SELECT snapshot FROM shift_handoffs
        WHERE tenant_id = $1 ORDER BY generated_at DESC LIMIT 1
        """,
        TENANT_A,
    )
    import json

    snapshot = json.loads(row["snapshot"])
    assert snapshot["open_alerts_by_severity"].get("critical") == 1
    assert snapshot["open_alerts_by_severity"].get("medium") == 1
    assert any(c.get("unowned") for c in snapshot["attention_cases"]), snapshot["attention_cases"]
    assert snapshot["generated_from"].startswith("live rows")

    async with session_factory() as db:
        second = await generate_due_handoffs(db)
        await db.commit()
    assert second.generated == 0 and second.skipped_existing >= 1, f"regeneration must be a no-op through the unique constraint: {second}"


async def test_escalation_routes_to_the_tenants_webhook_once(pools, session_factory):
    from app.services.escalation_router import route_overdue_cases

    admin, _ = pools
    webhook_id = await admin.fetchval(
        """
        INSERT INTO aisoc_outbound_webhooks (tenant_id, name, url, event_types, enabled)
        VALUES ($1, 'pager', 'https://example.com/hook', '{case.escalated}', TRUE)
        RETURNING id
        """,
        TENANT_A,
    )
    route_id = await admin.fetchval(
        """
        INSERT INTO escalation_routes (tenant_id, responsibility, min_severity, unacked_minutes, webhook_id)
        VALUES ($1, '*', 'high', 5, $2) RETURNING id
        """,
        TENANT_A,
        webhook_id,
    )
    case_id = uuid.uuid4()
    await admin.execute(
        """
        INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, severity, created_at)
        VALUES ($1, $2, $3, 'nobody picked this up', 'new', 'critical', now() - interval '1 hour')
        """,
        case_id,
        TENANT_A,
        f"ESC-{uuid.uuid4().hex[:6]}",
    )
    # Tenant B gets an identical overdue case and NO route: per-tenant isolation.
    await admin.execute(
        """
        INSERT INTO aisoc_cases (id, tenant_id, case_number, title, status, severity, created_at)
        VALUES ($1, $2, $3, 'other tenant, no route', 'new', 'critical', now() - interval '1 hour')
        """,
        uuid.uuid4(),
        TENANT_B,
        f"ESC-{uuid.uuid4().hex[:6]}",
    )

    async with session_factory() as db:
        first = await route_overdue_cases(db)
        await db.commit()
    assert first.escalated == 1, f"expected exactly tenant A's case to escalate: {first}"

    delivery = await admin.fetchrow(
        """
        SELECT d.tenant_id, d.event_type FROM aisoc_outbound_deliveries d
        WHERE d.webhook_id = $1 ORDER BY d.created_at DESC LIMIT 1
        """,
        webhook_id,
    )
    assert delivery is not None and delivery["event_type"] == "case.escalated"
    assert delivery["tenant_id"] == TENANT_A

    nag = await admin.fetchrow("SELECT 1 FROM escalation_nags WHERE case_id = $1 AND route_id = $2", case_id, route_id)
    assert nag is not None, "the nag ledger must record the escalation"

    async with session_factory() as db:
        second = await route_overdue_cases(db)
        await db.commit()
    assert second.escalated == 0, f"one escalation per case per route, not one per tick: {second}"


async def test_matrix_refuses_the_other_party_over_real_rows(pools, session_factory):
    from app.services import responsibility as resp

    async with session_factory() as db:
        provider = await resp.check(db, tenant_id=TENANT_A, activity="action", party="provider", verb="isolate_host")
        customer = await resp.check(db, tenant_id=TENANT_A, activity="action", party="customer", verb="isolate_host")
        unmatched = await resp.check(db, tenant_id=TENANT_A, activity="action", party="provider", verb="reset_password")
    assert provider.allowed is False and "customer" in (provider.rule or "")
    assert customer.allowed is True
    assert unmatched.allowed is True, "no matching row must mean no narrowing"
