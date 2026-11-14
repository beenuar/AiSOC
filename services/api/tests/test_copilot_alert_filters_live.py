"""Real PostgreSQL queries: Copilot windows/hosts must constrain rows and counts.

Requires the API migration chain. Only auth identity is supplied by a fixture;
FastAPI query validation, permission checks, SQL and response serialization run.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.alerts import router
from app.db.rls import get_tenant_db
from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

TENANT_A = uuid.UUID("0c100000-0000-0000-0000-00000000504a")
TENANT_B = uuid.UUID("0c100000-0000-0000-0000-00000000504b")
NOW = datetime(2026, 11, 11, 3, tzinfo=UTC)


@pytest_asyncio.fixture
async def api():
    dsn = os.environ.get("DATABASE_URL", "")
    if "postgres" not in dsn:
        if os.environ.get("MSSP_ISOLATION_REQUIRED", "") not in ("", "0", "false"):
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires live PostgreSQL with the API migration chain")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "") not in ("", "0", "false")
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at DATABASE_URL: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at DATABASE_URL ({type(exc).__name__}) — runs in integration.yml")
    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        try:
            for tenant in (TENANT_A, TENANT_B):
                await db.execute(text("DELETE FROM alerts WHERE tenant_id=:t"), {"t": tenant})
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:t, 'Copilot test', :s) ON CONFLICT(id) DO NOTHING"),
                    {"t": tenant, "s": "copilot-" + str(tenant)},
                )
            fixtures = [
                (TENANT_A, "current matching", NOW - timedelta(hours=1), "WS-42", False),
                (TENANT_A, "old matching", NOW - timedelta(days=3), "WS-42", False),
                (TENANT_A, "wrong host", NOW - timedelta(hours=1), "WS-420", False),
                (TENANT_A, "legacy matching", NOW - timedelta(hours=1), "WS-42", True),
                (TENANT_B, "other tenant", NOW - timedelta(hours=1), "WS-42", False),
            ]
            for tenant, title, event, host, legacy in fixtures:
                await db.execute(
                    text("""INSERT INTO alerts
                    (id, tenant_id, title, severity, status, event_time, first_seen, last_seen, created_at, updated_at,
                     entities, affected_hosts, connector_type)
                    VALUES (:id, :tenant, :title, 'high', 'new', :event, :event, :event, :now, :now,
                            CAST(:entities AS jsonb), CAST(:hosts AS jsonb), 'syslog')"""),
                    {
                        "id": uuid.uuid4(),
                        "tenant": tenant,
                        "title": title,
                        "event": event,
                        "now": NOW,
                        "entities": json.dumps([] if legacy else [{"type": "host", "value": host}]),
                        "hosts": json.dumps([host] if legacy else []),
                    },
                )
            await db.commit()
            principal = CurrentUser(
                user_id=uuid.uuid4(),
                tenant_id=TENANT_A,
                role="analyst",
                email="copilot@example.test",
                resolved_permissions=frozenset({"alerts:read"}),
            )
            app = FastAPI()
            app.include_router(router, prefix="/api/v1")
            app.dependency_overrides[get_current_user] = lambda: principal

            async def session():
                yield db

            app.dependency_overrides[get_tenant_db] = session
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
                yield client, principal
        finally:
            await db.rollback()
            for tenant in (TENANT_A, TENANT_B):
                await db.execute(text("DELETE FROM alerts WHERE tenant_id=:t"), {"t": tenant})
                await db.execute(text("DELETE FROM tenants WHERE id=:t"), {"t": tenant})
            await db.commit()
    await engine.dispose()


@pytest.mark.asyncio
async def test_window_host_tenant_and_facets_all_match(api):
    client, _ = api
    response = await client.get(
        "/api/v1/alerts",
        params={
            "event_since": (NOW - timedelta(hours=24)).isoformat(),
            "event_until": NOW.isoformat(),
            "hostname": "WS-42",
            "sort": "priority",
            "page_size": 1,
        },
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["total"] == 2, "old, foreign-tenant and different-host records must not be counted"
    assert data["facets"]["by_severity"] == {"high": 2}
    second = await client.get(
        "/api/v1/alerts",
        params={
            "event_since": (NOW - timedelta(hours=24)).isoformat(),
            "event_until": NOW.isoformat(),
            "hostname": "WS-42",
            "sort": "priority",
            "page_size": 1,
            "page": 2,
        },
    )
    titles = {data["items"][0]["title"], second.json()["items"][0]["title"]}
    assert titles == {"current matching", "legacy matching"}
    assert all(row["tenant_id"] == str(TENANT_A) for row in data["items"])


@pytest.mark.asyncio
async def test_omitted_filters_preserve_existing_list_and_no_foreign_tenant(api):
    client, _ = api
    response = await client.get("/api/v1/alerts")
    assert response.status_code == 200, response.text
    assert response.json()["total"] == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "params, status",
    [
        ({"event_since": NOW.isoformat(), "event_until": NOW.isoformat()}, 400),
        ({"event_since": "2026-11-11T00:00:00"}, 422),
        ({"hostname": ""}, 422),
    ],
)
async def test_bad_filters_are_refused_not_silently_ignored(api, params, status):
    client, _ = api
    assert (await client.get("/api/v1/alerts", params=params)).status_code == status


@pytest.mark.asyncio
async def test_reader_without_permission_is_not_upgraded_by_copilot(api):
    client, principal = api
    principal.resolved_permissions = frozenset()
    assert (await client.get("/api/v1/alerts")).status_code == 403
