"""Entity filters through the shipped HTTP app and real PostgreSQL.

Only the authenticated identity is supplied by the fixture. Query validation,
permission checks, the tenant-scoped database dependency, JSONB predicates,
pagination and response serialization run unchanged. Seed rows mirror both
fusion's entities/IOCs and the denormalized affected-entity columns.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

pytestmark = pytest.mark.asyncio

HOST = "WKS-42"
IP = "2001:db8::42"
DOMAIN = "reports.example.test"
URL = "https://reports.example.test/a?x=1&y=2"
LITERAL = "Finance & Legal/%_+Team"


@pytest_asyncio.fixture
async def api():
    dsn = os.environ.get("DATABASE_MIGRATION_URL") or os.environ.get("DATABASE_URL", "")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "").lower() not in ("", "0", "false")
    if "postgres" not in dsn:
        if required:
            pytest.fail("entity-filter proof requires live PostgreSQL with the API migration chain")
        pytest.skip("requires live PostgreSQL with the API migration chain")
    dsn = dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    seed_engine = create_async_engine(dsn)
    try:
        async with seed_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:
        await seed_engine.dispose()
        if required:
            pytest.fail(f"entity-filter database did not answer: {type(exc).__name__}: {exc}")
        pytest.skip(f"no entity-filter database: {type(exc).__name__}")

    from app.api.v1.deps import CurrentUser, get_current_user
    from app.db.database import engine as app_engine
    from app.main import app

    tenant, foreign_tenant = uuid.uuid4(), uuid.uuid4()
    now = datetime.now(UTC)
    fixtures = [
        {
            "title": "pipeline host",
            "severity": "critical",
            "entities": [{"type": "host", "value": HOST}, {"type": "user", "value": "alice"}],
            "hosts": [HOST],
            "users": ["alice"],
            "ips": [IP],
            "iocs": [{"type": "ip", "value": IP}, {"type": "domain", "value": DOMAIN}, {"type": "url", "value": URL}],
            "disposition": "needs_review",
        },
        {"title": "alias host", "severity": "high", "status": "triaged", "entities": [{"type": "device", "value": HOST}]},
        {"title": "legacy host", "status": "resolved", "hosts": [HOST], "age": 72},
        {"title": "longer host", "entities": [{"type": "host", "value": HOST + "0"}]},
        {"title": "different case", "entities": [{"type": "host", "value": HOST.lower()}]},
        {"title": "same value user", "entities": [{"type": "user", "value": HOST}]},
        {"title": "split type and value", "entities": [{"type": "host", "value": "other"}, {"type": "user", "value": HOST}]},
        {"title": "unsupported kind", "entities": [{"type": "hash", "value": HOST}]},
        {"title": "legacy user", "users": ["alice"]},
        {"title": "legacy ip", "ips": [IP]},
        {"title": "alias ip", "entities": [{"type": "src_ip", "value": IP}]},
        {"title": "entity domain", "entities": [{"type": "domain", "value": DOMAIN}]},
        {"title": "entity url", "entities": [{"type": "url", "value": URL}]},
        {"title": "legacy asset", "assets": [LITERAL]},
        {"title": "literal entity", "entities": [{"type": "asset", "value": LITERAL}]},
        {"title": "empty entities"},
        {"title": "foreign host", "foreign": True, "severity": "critical", "entities": [{"type": "host", "value": HOST}]},
        {"title": "foreign ip", "foreign": True, "iocs": [{"type": "ip", "value": IP}, {"type": "domain", "value": DOMAIN}]},
    ]
    principal = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant,
        role="analyst",
        email="entity-filter@example.test",
        resolved_permissions=frozenset({"alerts:read"}),
    )
    previous_auth = app.dependency_overrides.get(get_current_user)
    try:
        async with seed_engine.begin() as conn:
            for tenant_id in (tenant, foreign_tenant):
                await conn.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'Entity filter test', :slug)"),
                    {"id": tenant_id, "slug": f"entity-filter-{tenant_id.hex}"},
                )
            for index, row in enumerate(fixtures):
                event_time = now - timedelta(hours=row.get("age", 1), minutes=index)
                await conn.execute(
                    text("""INSERT INTO alerts
                        (id, tenant_id, title, severity, status, disposition, event_time, first_seen, last_seen,
                         created_at, updated_at, entities, iocs, affected_hosts, affected_users, affected_ips, affected_assets)
                        VALUES (:id, :tenant, :title, :severity, :status, :disposition, :ts, :ts, :ts, :ts, :ts,
                                CAST(:entities AS jsonb), CAST(:iocs AS jsonb), CAST(:hosts AS jsonb),
                                CAST(:users AS jsonb), CAST(:ips AS jsonb), CAST(:assets AS jsonb))"""),
                    {
                        "id": uuid.uuid4(),
                        "tenant": foreign_tenant if row.get("foreign") else tenant,
                        "title": row["title"],
                        "severity": row.get("severity", "low"),
                        "status": row.get("status", "new"),
                        "disposition": row.get("disposition"),
                        "ts": event_time,
                        **{key: json.dumps(row.get(key, [])) for key in ("entities", "iocs", "hosts", "users", "ips", "assets")},
                    },
                )
        app.dependency_overrides[get_current_user] = lambda: principal
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            yield client, principal, foreign_tenant
    finally:
        if previous_auth is None:
            app.dependency_overrides.pop(get_current_user, None)
        else:
            app.dependency_overrides[get_current_user] = previous_auth
        await app_engine.dispose()
        async with seed_engine.begin() as conn:
            for tenant_id in (tenant, foreign_tenant):
                await conn.execute(text("DELETE FROM alerts WHERE tenant_id=:id"), {"id": tenant_id})
                await conn.execute(text("DELETE FROM tenants WHERE id=:id"), {"id": tenant_id})
        await seed_engine.dispose()


async def _list(api, **params):
    client, _, _ = api
    response = await client.get("/api/v1/alerts", params=params)
    assert response.status_code == 200, response.text
    return response.json()


async def test_entity_type_and_value_match_the_same_object_and_count_once(api):
    data = await _list(api, entity_type="host", entity_value=HOST)
    assert {row["title"] for row in data["items"]} == {"pipeline host", "alias host", "legacy host"}
    assert data["total"] == 3
    assert data["facets"] == {
        "by_severity": {"critical": 1, "high": 1, "low": 1},
        "by_status": {"new": 1, "triaged": 1, "resolved": 1},
        "unresolved": 2,
    }


async def test_entity_value_without_type_includes_supported_types_only(api):
    data = await _list(api, entity_value=HOST)
    assert {row["title"] for row in data["items"]} == {
        "pipeline host",
        "alias host",
        "legacy host",
        "same value user",
        "split type and value",
    }
    assert data["total"] == 5


@pytest.mark.parametrize(
    "kind, value, expected",
    [
        ("user", "alice", {"pipeline host", "legacy user"}),
        ("ip", IP, {"pipeline host", "legacy ip", "alias ip"}),
        ("domain", DOMAIN, {"pipeline host", "entity domain"}),
        ("url", URL, {"pipeline host", "entity url"}),
        ("asset", LITERAL, {"legacy asset", "literal entity"}),
    ],
)
async def test_fusion_iocs_aliases_and_legacy_columns(api, kind, value, expected):
    data = await _list(api, entity_type=kind, entity_value=value)
    assert {row["title"] for row in data["items"]} == expected
    assert data["total"] == len(expected)


async def test_pagination_and_facets_use_the_same_entity_scope(api):
    pages = [await _list(api, entity_type="host", entity_value=HOST, page_size=1, page=page, sort="priority") for page in (1, 2, 3)]
    assert [page["items"][0]["title"] for page in pages] == ["pipeline host", "alias host", "legacy host"]
    assert all(page["total"] == 3 and page["pages"] == 3 and page["page_size"] == 1 for page in pages)
    assert all(page["facets"] == pages[0]["facets"] for page in pages)


async def test_combines_with_existing_filters_and_hostname(api):
    data = await _list(
        api,
        entity_type="host",
        entity_value=f"  {HOST}  ",
        severity="critical",
        status="new",
        disposition="needs_review",
        unresolved_only="true",
        created_within_hours=24,
        search="pipeline",
        hostname=HOST,
    )
    assert [row["title"] for row in data["items"]] == ["pipeline host"]
    assert data["total"] == data["facets"]["unresolved"] == 1
    assert (await _list(api, entity_type="host", entity_value=HOST, hostname="other"))["total"] == 0


async def test_no_match_is_empty_and_special_characters_are_literal(api):
    for value in ("missing", "WKS", "%", "_", "' OR 1=1 --"):
        data = await _list(api, entity_value=value)
        assert data["items"] == []
        assert data["total"] == data["pages"] == 0
        assert data["facets"] == {"by_severity": {}, "by_status": {}, "unresolved": 0}


async def test_unfiltered_and_legacy_hostname_contracts_still_work(api):
    assert (await _list(api))["total"] == 16
    assert {row["title"] for row in (await _list(api, hostname=HOST))["items"]} == {"pipeline host", "legacy host"}


async def test_query_parameters_cannot_select_another_tenant(api):
    _, principal, foreign_tenant = api
    data = await _list(api, entity_type="host", entity_value=HOST, tenant_id=str(foreign_tenant), tenantId=str(foreign_tenant))
    assert data["total"] == 3
    assert all(row["tenant_id"] == str(principal.tenant_id) for row in data["items"])
    principal.tenant_id = foreign_tenant
    foreign = await _list(api, entity_type="host", entity_value=HOST)
    assert [row["title"] for row in foreign["items"]] == ["foreign host"]
    assert foreign["facets"]["by_severity"] == {"critical": 1}


@pytest.mark.parametrize(
    "params, expected",
    [
        ({"entity_type": "host"}, 400),
        ({"entity_type": "invalid", "entity_value": HOST}, 422),
        ({"entity_value": ""}, 422),
        ({"entity_value": " \t "}, 422),
        ({"entity_value": "x" * 2049}, 422),
    ],
)
async def test_incomplete_and_invalid_entity_filters_are_rejected(api, params, expected):
    client, _, _ = api
    response = await client.get("/api/v1/alerts", params=params)
    assert response.status_code == expected, response.text


async def test_entity_filter_does_not_bypass_read_permission(api):
    client, principal, _ = api
    principal.resolved_permissions = frozenset()
    response = await client.get("/api/v1/alerts", params={"entity_type": "host", "entity_value": HOST})
    assert response.status_code == 403, response.text
