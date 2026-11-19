"""SOC insights through the production HTTP app and real PostgreSQL.

The database connection and clock are supplied by the fixture; authentication,
tenant resolution, routing, SQL execution and response serialization are real.
Run against the API migration chain with MSSP_ISOLATION_REQUIRED=1 to make an
unavailable database fail instead of skipping these checks.
"""

from __future__ import annotations

import os
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from app.api.v1.endpoints import insights
from app.core.security import create_access_token
from app.db.database import _normalize_async_pg_url, get_db
from app.main import create_application
from live_rls import bind_tenant
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

NOW = datetime(2026, 11, 19, 12, tzinfo=UTC)
DATA_TABLES = re.compile(r"\b(?:FROM|JOIN)\s+(?:alerts|aisoc_cases|aisoc_run_costs|investigation_runs)\b", re.IGNORECASE)


class _Clock(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW.astimezone(tz) if tz is not None else NOW.replace(tzinfo=None)


@dataclass
class InsightsAPI:
    client: httpx.AsyncClient
    db: AsyncSession
    tenant: uuid.UUID
    other_tenant: uuid.UUID
    statements: list[str]
    run_ids: list[str] = field(default_factory=list)

    async def alert(
        self,
        created: datetime,
        *,
        acknowledged: float | None = None,
        resolved: float | None = None,
        disposition: str | None = None,
        tenant: uuid.UUID | None = None,
    ) -> None:
        tenant = tenant or self.tenant
        await bind_tenant(self.db, tenant)
        await self.db.execute(
            text("""INSERT INTO alerts
                (id, tenant_id, title, severity, event_time, first_seen, last_seen,
                 created_at, first_seen_at, resolved_at, disposition)
                VALUES (:id, :tenant, 'Insights regression fixture', 'high', :created,
                        :created, :created, :created, :acknowledged, :resolved, :disposition)"""),
            {
                "id": uuid.uuid4(),
                "tenant": tenant,
                "created": created,
                "acknowledged": created + timedelta(hours=acknowledged) if acknowledged is not None else None,
                "resolved": created + timedelta(hours=resolved) if resolved is not None else None,
                "disposition": disposition,
            },
        )
        await self.db.commit()

    async def case(self, created: datetime, status: str, *, tenant: uuid.UUID | None = None) -> None:
        tenant = tenant or self.tenant
        case_id = uuid.uuid4()
        await bind_tenant(self.db, tenant)
        await self.db.execute(
            text("""INSERT INTO aisoc_cases
                (id, tenant_id, case_number, title, severity, status, created_at)
                VALUES (:id, :tenant, :number, 'Insights regression fixture', 'high', :status, :created)"""),
            {"id": case_id, "tenant": tenant, "number": f"SOC-{case_id.hex[:20]}", "status": status, "created": created},
        )
        await self.db.commit()

    async def run(self, created: datetime, costs: list[float], *, tenant: uuid.UUID | None = None) -> None:
        tenant = tenant or self.tenant
        run_id = uuid.uuid4()
        self.run_ids.append(str(run_id))
        await bind_tenant(self.db, tenant)
        await self.db.execute(
            text("""INSERT INTO investigation_runs (id, tenant_id, case_id, started_at)
                VALUES (:id, :tenant, 'insights-regression', :created)"""),
            {"id": run_id, "tenant": tenant, "created": created},
        )
        # The legacy cost writer uses aliases on an unbound connection.
        # End the tenant-bound investigation write before reproducing that.
        await self.db.commit()
        for i, cost in enumerate(costs):
            await self.db.execute(
                text("""INSERT INTO aisoc_run_costs
                    (run_id, tenant_id, model, measured_cost_usd, measured_call_count, estimated_cost_usd)
                    VALUES (:run, :tenant, :model, :cost, 1, 999)"""),
                # Cost writers may use a tenant alias. The investigation run
                # remains the authoritative owner of these rows.
                {"run": str(run_id), "tenant": f"alias-{tenant}", "model": f"fixture-{i}", "cost": cost},
            )
        await self.db.commit()

    async def get(self, window: str = "24h") -> dict[str, Any]:
        self.statements.clear()
        response = await self.client.get("/api/v1/insights/soc", params={"window": window})
        assert response.status_code == 200, response.text
        return response.json()


@pytest_asyncio.fixture
async def api(monkeypatch):
    dsn = os.environ.get("DATABASE_URL", "")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")
    if "postgres" not in dsn:
        if required:
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires PostgreSQL with the API migration chain")
    url, connect_args = _normalize_async_pg_url(dsn)
    engine = create_async_engine(url, connect_args=connect_args)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"PostgreSQL is required but unavailable: {type(exc).__name__}: {exc}")
        pytest.skip(f"PostgreSQL unavailable ({type(exc).__name__})")

    monkeypatch.setattr(insights, "datetime", _Clock)
    monkeypatch.setenv("AISOC_DEV_AUTH_BYPASS", "0")
    tenant, other_tenant, user_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    statements: list[str] = []

    def record(_conn, _cursor, statement, _parameters, _context, _executemany):
        if DATA_TABLES.search(statement):
            statements.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", record)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            for tid in (tenant, other_tenant):
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'Insights test', :slug)"),
                    {"id": tid, "slug": f"insights-{tid}"},
                )
            await bind_tenant(db, tenant)
            await db.execute(
                text("""INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active)
                    VALUES (:id, :tenant, :email, 'insights-test', '!test-only!', 'soc_analyst', TRUE)"""),
                {"id": user_id, "tenant": tenant, "email": f"insights-{user_id}@example.test"},
            )
            await db.commit()
            token = create_access_token({"sub": str(user_id), "tenant_id": str(tenant), "role": "soc_analyst"})
            app = create_application()

            async def session():
                # Reads remain unbound so RLS cannot conceal an omitted
                # tenant predicate in the aggregate queries.
                yield db

            app.dependency_overrides[get_db] = session
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app, raise_app_exceptions=False),
                base_url="http://api.test",
                headers={"Authorization": f"Bearer {token}"},
            ) as client:
                harness = InsightsAPI(client, db, tenant, other_tenant, statements)
                try:
                    yield harness
                finally:
                    await db.rollback()
                    if harness.run_ids:
                        await db.execute(
                            text("DELETE FROM aisoc_run_costs WHERE run_id = ANY(CAST(:ids AS TEXT[]))"),
                            {"ids": harness.run_ids},
                        )
                    for tid in (tenant, other_tenant):
                        await bind_tenant(db, tid)
                        for table in ("investigation_runs", "alerts", "aisoc_cases", "users"):
                            await db.execute(text(f"DELETE FROM {table} WHERE tenant_id = :tenant"), {"tenant": tid})
                        await db.execute(text("DELETE FROM tenants WHERE id = :tenant"), {"tenant": tid})
                        await db.commit()
    finally:
        await engine.dispose()


@pytest.mark.parametrize(("window", "days"), [("24h", 1), ("7d", 7), ("30d", 30)])
async def test_metrics_and_buckets_preserve_bounds_denominators_and_tenant_scope(api: InsightsAPI, window: str, days: int) -> None:
    delta = timedelta(days=days)
    start, previous = NOW - delta, NOW - 2 * delta
    width = delta / 24
    await api.alert(previous, acknowledged=6, resolved=8, disposition="false_positive")
    await api.alert(start - timedelta(microseconds=1), disposition="needs_review")
    await api.alert(start, acknowledged=0, resolved=0, disposition="true_positive")
    await api.alert(start + width, acknowledged=2, resolved=4, disposition="false_positive")
    await api.alert(start + width + timedelta(microseconds=1), acknowledged=4, disposition="true_positive")
    await api.alert(NOW - timedelta(microseconds=1), disposition="needs_review")
    for outside in (previous - timedelta(microseconds=1), NOW):
        await api.alert(outside, acknowledged=999, resolved=999, disposition="false_positive")
    await api.alert(start, acknowledged=999, resolved=999, disposition="false_positive", tenant=api.other_tenant)

    await api.case(previous, "closed")
    await api.case(previous + width, "resolved")
    await api.case(previous + 2 * width, "resolved")
    await api.case(start, "closed")
    await api.case(start + width, "closed")
    await api.case(NOW - timedelta(microseconds=1), "resolved")
    await api.case(NOW, "closed")
    await api.case(start, "closed", tenant=api.other_tenant)

    await api.run(previous, [2.0])
    await api.run(start, [0.1, 0.2])
    await api.run(start + width, [0.7])
    await api.run(NOW, [999.0])
    await api.run(start, [999.0], tenant=api.other_tenant)

    response = await api.get(window)
    tiles = {tile["key"]: tile for tile in response["tiles"]}
    assert response["window"] == window
    assert response["tenant_id"] == str(api.tenant)
    assert response["manual_investigation_minutes"] == 45
    assert (tiles["mtta"]["value"], tiles["mtta"]["sample_count"]) == (2.0, 3)
    assert (tiles["mttr"]["value"], tiles["mttr"]["sample_count"]) == (2.0, 2)
    assert (tiles["fp_rate"]["value"], tiles["fp_rate"]["sample_count"]) == (0.3333, 3)
    assert tiles["mtta"]["previous_value"] == 6.0
    assert tiles["mttr"]["previous_value"] == 8.0
    assert tiles["fp_rate"]["previous_value"] == 1.0
    assert tiles["alerts_per_day"]["value"] == round(4 / days, 2)
    assert tiles["alerts_per_day"]["previous_value"] == round(2 / days, 2)
    assert tiles["cases_per_day"]["value"] == round(3 / days, 2)
    assert (tiles["agent_cost_per_investigation"]["value"], tiles["agent_cost_per_investigation"]["sample_count"]) == (0.5, 2)
    assert tiles["agent_cost_per_investigation"]["previous_value"] == 2.0
    assert tiles["analyst_hours_saved"]["value"] == 1.5
    assert tiles["analyst_hours_saved"]["sample_count"] == 2
    assert tiles["analyst_hours_saved"]["previous_value"] == 0.75, "both windows must count closed cases, not resolved cases"
    assert tiles["analyst_hours_saved"]["delta_pct"] == 100.0
    assert tiles["alerts_per_day"]["sparkline"]["points"] == [1.0, 2.0, *([0.0] * 21), 1.0]
    assert tiles["cases_per_day"]["sparkline"]["points"] == [1.0, 1.0, *([0.0] * 21), 1.0]
    assert tiles["agent_cost_per_investigation"]["sparkline"]["points"] == pytest.approx([0.3, 0.7, *([0.0] * 22)])


async def test_large_window_uses_three_aggregate_reads_not_one_read_per_tile(api: InsightsAPI) -> None:
    await bind_tenant(api.db, api.tenant)
    await api.db.execute(
        text("""INSERT INTO alerts (id, tenant_id, title, severity, event_time, first_seen, last_seen, created_at)
            SELECT gen_random_uuid(), :tenant, 'Insights volume fixture', 'low', :created,
                   :created, :created, :created FROM generate_series(1, 10000)"""),
        {"tenant": api.tenant, "created": NOW - timedelta(hours=1)},
    )
    await api.db.commit()
    response = await api.get()
    assert next(tile for tile in response["tiles"] if tile["key"] == "alerts_per_day")["value"] == 10000
    assert len(api.statements) == 3, "one grouped read per alerts, cases and cost dataset; authentication reads are excluded"
    assert all("GROUP BY" in statement.upper() for statement in api.statements), "bucket raw rows inside PostgreSQL"


async def test_cost_join_stays_bounded_under_runtime_rls_and_generic_plans(api: InsightsAPI) -> None:
    await bind_tenant(api.db, api.tenant)
    rows = await api.db.execute(
        text("""INSERT INTO investigation_runs (id, tenant_id, case_id, started_at)
            SELECT gen_random_uuid(), :tenant, 'insights-regression',
                   CAST(:now AS TIMESTAMPTZ) - CASE WHEN i <= 2000 THEN INTERVAL '1 hour' ELSE INTERVAL '25 hours' END
            FROM generate_series(1, 4000) i
            RETURNING id"""),
        {"tenant": api.tenant, "now": NOW},
    )
    api.run_ids.extend(str(row[0]) for row in rows)
    await api.db.execute(
        text("""INSERT INTO aisoc_run_costs (run_id, tenant_id, model, measured_cost_usd, measured_call_count)
            SELECT r.id::text, r.tenant_id::text, 'fixture-' || i::text, 0.1 * i, 1
            FROM investigation_runs r CROSS JOIN generate_series(1, 2) i
            WHERE r.tenant_id = :tenant"""),
        {"tenant": api.tenant},
    )
    await api.db.commit()
    # asyncpg's prepared statements eventually use a generic plan. RLS's
    # cardinality estimates made the old join repeatedly scan visible runs,
    # taking seconds and then timing out after otherwise successful requests.
    # Bound database work, not HTTP wall time: optional-query timeout must
    # not silently turn this known, measured spend into an empty cost tile.
    await api.db.execute(text("SET LOCAL plan_cache_mode = force_generic_plan"))
    await api.db.execute(text("SET LOCAL statement_timeout = '2s'"))
    response = await api.get()
    cost = next(tile for tile in response["tiles"] if tile["key"] == "agent_cost_per_investigation")
    assert (cost["value"], cost["sample_count"], cost["previous_value"]) == (0.3, 2000, 0.3)
    assert sum(cost["sparkline"]["points"]) == pytest.approx(600.0)
    assert len(api.statements) == 3


async def test_empty_tenant_is_unmeasured_but_volume_is_zero(api: InsightsAPI) -> None:
    response = await api.get()
    tiles = {tile["key"]: tile for tile in response["tiles"]}
    for key in ("mtta", "mttr", "fp_rate", "agent_cost_per_investigation", "analyst_hours_saved"):
        assert tiles[key]["sample_count"] == 0
        assert tiles[key]["delta_pct"] is None
    for key in ("alerts_per_day", "cases_per_day"):
        assert tiles[key]["value"] == 0
    assert all(tile["sparkline"]["points"] == [0.0] * 24 for tile in tiles.values())


async def test_unavailable_optional_costs_do_not_abort_other_metrics_or_transaction(api: InsightsAPI) -> None:
    await api.alert(NOW - timedelta(hours=1), acknowledged=1)
    # A session-local shadow reproduces an older cost schema without touching
    # the shared migrated table. PostgreSQL raises a real UndefinedColumn.
    await api.db.execute(text("CREATE TEMP TABLE aisoc_run_costs (run_id TEXT) ON COMMIT DROP"))
    response = await api.get()
    tiles = {tile["key"]: tile for tile in response["tiles"]}
    assert tiles["mtta"]["value"] == 1.0
    assert tiles["alerts_per_day"]["value"] == 1.0
    assert tiles["agent_cost_per_investigation"]["sample_count"] == 0
    assert await api.db.scalar(text("SELECT 42")) == 42, "optional cost failure must roll back its savepoint"


async def test_authentication_and_window_validation_use_real_dependencies(api: InsightsAPI) -> None:
    response = await api.client.get("/api/v1/insights/soc?window=365d")
    assert response.status_code == 422
    response = await api.client.get("/api/v1/insights/soc", headers={"Authorization": "Bearer invalid-test-token"})
    assert response.status_code == 401
