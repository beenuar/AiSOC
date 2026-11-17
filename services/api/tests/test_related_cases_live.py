"""Related-case evidence through HTTP and real PostgreSQL.

The previous route selected the observable graph but only matched alert UUIDs.
These checks exercise the production route, permission dependency, PostgreSQL
array/JSONB expressions and response serialization. Only the authenticated
principal and database connection are supplied by the fixture.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints.cases import router
from app.db.database import get_db
from fastapi import FastAPI
from live_rls import bind_tenant
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

NOW = datetime(2026, 11, 17, 3, tzinfo=UTC)


def _node(kind: str, value: Any) -> dict[str, Any]:
    # Node ids are local to each graph, not identities shared across cases.
    return {"id": str(uuid.uuid4()), "kind": kind, "value": value, "tags": []}


@dataclass
class RelatedCasesAPI:
    client: httpx.AsyncClient
    db: AsyncSession
    principal: CurrentUser
    other_tenant: uuid.UUID

    async def add_case(
        self,
        *,
        graph: Any = None,
        alerts: list[uuid.UUID] | None = None,
        tenant: uuid.UUID | None = None,
        created: datetime = NOW,
        case_id: uuid.UUID | None = None,
    ) -> tuple[str, str]:
        case_id = case_id or uuid.uuid4()
        tenant = tenant or self.principal.tenant_id
        case_number = f"REL-{case_id.hex[:20]}"
        await bind_tenant(self.db, tenant)
        await self.db.execute(
            text("""INSERT INTO aisoc_cases
                (id, tenant_id, case_number, title, severity, status, alert_ids, observable_graph, created_at)
                VALUES (:id, :tenant, :number, :title, 'high', 'new', CAST(:alerts AS UUID[]), CAST(:graph AS JSONB), :created)"""),
            {
                "id": case_id,
                "tenant": tenant,
                "number": case_number,
                "title": f"Case {case_number}",
                "alerts": alerts or [],
                "graph": json.dumps(graph),
                "created": created,
            },
        )
        await self.db.commit()
        return str(case_id), case_number

    async def related(self, case_id: str) -> dict[str, Any]:
        response = await self.client.get(f"/api/v1/cases/{case_id}/related")
        assert response.status_code == 200, response.text
        return response.json()


@pytest_asyncio.fixture
async def api():
    dsn = os.environ.get("DATABASE_URL", "")
    required = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")
    if "postgres" not in dsn:
        if required:
            pytest.fail("live PostgreSQL is required")
        pytest.skip("requires PostgreSQL with the API migration chain")
    engine = create_async_engine(dsn)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if required:
            pytest.fail(f"PostgreSQL is required but unavailable: {type(exc).__name__}: {exc}")
        pytest.skip(f"PostgreSQL unavailable ({type(exc).__name__}); integration.yml runs this suite")

    tenant, other_tenant = uuid.uuid4(), uuid.uuid4()
    factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory() as db:
            for tid in (tenant, other_tenant):
                await db.execute(
                    text("INSERT INTO tenants (id, name, slug) VALUES (:id, 'Related cases test', :slug)"),
                    {"id": tid, "slug": f"related-{tid}"},
                )
            await db.commit()
            principal = CurrentUser(
                user_id=uuid.uuid4(),
                tenant_id=tenant,
                role="analyst",
                email="related@example.test",
                resolved_permissions=frozenset({"cases:read"}),
            )
            app = FastAPI()
            app.include_router(router, prefix="/api/v1")
            app.dependency_overrides[get_current_user] = lambda: principal

            async def session():
                # Leave reads unbound, as cases.py's DBSession does, so RLS
                # cannot hide a missing tenant predicate in the route's SQL.
                yield db

            app.dependency_overrides[get_db] = session
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://api.test") as client:
                    yield RelatedCasesAPI(client, db, principal, other_tenant)
            finally:
                await db.rollback()
                for tid in (tenant, other_tenant):
                    await bind_tenant(db, tid)
                    await db.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = :tenant"), {"tenant": tid})
                    await db.execute(text("DELETE FROM tenants WHERE id = :tenant"), {"tenant": tid})
                    await db.commit()
    finally:
        await engine.dispose()


async def test_shared_observable_without_shared_alert_is_related(api: RelatedCasesAPI) -> None:
    source, number = await api.add_case(graph={"nodes": [_node("host", "dc-01")]})
    candidate, _ = await api.add_case(graph={"nodes": [_node("host", "dc-01")]})

    result = await api.related(source)
    assert [row["id"] for row in result["related"]] == [candidate], "observable-only evidence must not be silently ignored"
    item = result["related"][0]
    assert item["reason"] == "shared_observables"
    assert item["shared_alert_ids"] == []
    assert item["shared_alert_count"] == 0
    assert item["shared_observables"] == [{"kind": "host", "value": "dc-01"}]
    assert item["shared_observable_count"] == 1
    assert result["limit"] == 20
    assert result["has_more"] is False
    assert await api.related(number) == result


async def test_shared_alerts_remain_supported_and_evidence_is_deduplicated(api: RelatedCasesAPI) -> None:
    alert_id = uuid.uuid4()
    source, _ = await api.add_case(alerts=[alert_id, alert_id], graph={"nodes": [_node("ip", "192.0.2.10")]})
    candidate, _ = await api.add_case(
        alerts=[alert_id, alert_id],
        graph={"nodes": [_node("ip", "192.0.2.10"), _node("ip", "192.0.2.10")]},
    )

    result = await api.related(source)
    assert [row["id"] for row in result["related"]] == [candidate]
    item = result["related"][0]
    assert item["reason"] == "shared_alerts"
    assert item["shared_alert_ids"] == [str(alert_id)]
    assert item["shared_alert_count"] == 1
    assert item["shared_observables"] == [{"kind": "ip", "value": "192.0.2.10"}]
    assert item["shared_observable_count"] == 1


async def test_evidence_must_match_kind_and_value_exactly(api: RelatedCasesAPI) -> None:
    source, _ = await api.add_case(graph={"nodes": [_node("host", "web-01")]})
    await api.add_case(graph={"nodes": [_node("user", "web-01")]})
    await api.add_case(graph={"nodes": [_node("host", "web-010")]})
    await api.add_case(graph={"nodes": [_node("host", "WEB-01")]})
    await api.add_case(graph={"nodes": [_node("host", " web-01 ")]})

    assert (await api.related(source))["related"] == []


async def test_shared_candidates_and_source_identifiers_stay_inside_tenant(api: RelatedCasesAPI) -> None:
    alert_id = uuid.uuid4()
    graph = {"nodes": [_node("domain", "example.test")]}
    source, _ = await api.add_case(graph=graph, alerts=[alert_id])
    candidate, _ = await api.add_case(graph=graph, alerts=[alert_id])
    foreign, foreign_number = await api.add_case(graph=graph, alerts=[alert_id], tenant=api.other_tenant)

    assert [item["id"] for item in (await api.related(source))["related"]] == [candidate]
    for identifier in (foreign, foreign_number, str(uuid.uuid4()), "REL-missing"):
        response = await api.client.get(f"/api/v1/cases/{identifier}/related")
        assert response.status_code == 404, response.text


async def test_cases_read_permission_is_required(api: RelatedCasesAPI) -> None:
    source, _ = await api.add_case()
    api.principal.resolved_permissions = frozenset({"alerts:read"})
    response = await api.client.get(f"/api/v1/cases/{source}/related")
    assert response.status_code == 403


@pytest.mark.parametrize("graph", [None, [], "invalid", {}, {"nodes": None}, {"nodes": {}}, {"nodes": "invalid"}])
async def test_malformed_graph_shapes_do_not_hide_shared_alerts(api: RelatedCasesAPI, graph: Any) -> None:
    alert_id = uuid.uuid4()
    source, _ = await api.add_case(graph=graph, alerts=[alert_id])
    candidate, _ = await api.add_case(graph=graph, alerts=[alert_id])

    result = await api.related(source)
    assert [item["id"] for item in result["related"]] == [candidate]
    assert result["related"][0]["shared_alert_count"] == 1
    assert result["related"][0]["shared_observable_count"] == 0


async def test_malformed_nodes_are_ignored_without_hiding_valid_evidence(api: RelatedCasesAPI) -> None:
    invalid: list[Any] = [
        None,
        [],
        1,
        "node",
        {},
        _node("host", ""),
        _node("host", " \t\n"),
        _node("host", None),
        _node("host", 42),
        _node("host", {"value": "web-01"}),
        _node("unknown-kind", "value"),
        {"kind": {"type": "host"}, "value": "web-01"},
    ]
    source, _ = await api.add_case(graph={"nodes": [*invalid, _node("host", "web-01")]})
    await api.add_case(graph={"nodes": invalid})
    candidate, _ = await api.add_case(graph={"nodes": [*invalid, _node("host", "web-01")]})
    await api.add_case(graph={"nodes": {"host": "web-01"}})

    result = await api.related(source)
    assert [item["id"] for item in result["related"]] == [candidate]
    assert result["related"][0]["shared_observables"] == [{"kind": "host", "value": "web-01"}]


async def test_evidence_lists_are_bounded_but_counts_are_complete(api: RelatedCasesAPI) -> None:
    alerts = [uuid.uuid4() for _ in range(13)]
    nodes = [_node("host", f"host-{i:02d}") for i in range(14)]
    source, _ = await api.add_case(alerts=alerts + alerts, graph={"nodes": nodes + nodes})
    candidate, _ = await api.add_case(alerts=alerts + alerts, graph={"nodes": nodes + nodes})

    result = await api.related(source)
    assert [item["id"] for item in result["related"]] == [candidate]
    item = result["related"][0]
    assert item["shared_alert_count"] == 13
    assert item["shared_observable_count"] == 14
    assert item["shared_alert_ids"] == sorted(str(alert) for alert in alerts)[:10]
    assert item["shared_observables"] == [{"kind": "host", "value": f"host-{i:02d}"} for i in range(10)]


async def test_matches_are_ranked_before_the_result_limit(api: RelatedCasesAPI) -> None:
    alerts = [uuid.uuid4(), uuid.uuid4()]
    source, _ = await api.add_case(alerts=alerts, graph={"nodes": [_node("host", "web-01"), _node("ip", "192.0.2.1")]})
    expected = []
    for i in range(21):
        candidate, _ = await api.add_case(alerts=[alerts[0]], created=NOW + timedelta(seconds=i))
        expected.append(candidate)
    # Both are older than the weak candidates, but carry stronger evidence.
    two_alerts, _ = await api.add_case(alerts=alerts, created=NOW - timedelta(days=40))
    both_kinds, _ = await api.add_case(
        alerts=[alerts[0]],
        graph={"nodes": [_node("host", "web-01"), _node("ip", "192.0.2.1")]},
        created=NOW - timedelta(days=50),
    )
    # An unrelated recent case must not consume one of the result slots.
    await api.add_case(created=NOW + timedelta(days=1))

    result = await api.related(source)
    assert result["limit"] == 20
    assert result["has_more"] is True
    assert [row["id"] for row in result["related"]] == [two_alerts, both_kinds, *list(reversed(expected))[:18]]


async def test_tied_results_use_stable_id_order_and_twenty_is_not_truncated(api: RelatedCasesAPI) -> None:
    source, _ = await api.add_case(graph={"nodes": [_node("host", "web-01")]})
    expected = []
    for _ in range(20):
        candidate, _ = await api.add_case(graph={"nodes": [_node("host", "web-01")]})
        expected.append(candidate)

    first = await api.related(source)
    second = await api.related(source)
    assert [row["id"] for row in first["related"]] == sorted(expected)
    assert first == second
    assert first["has_more"] is False


async def test_a_case_without_evidence_returns_an_honest_empty_result(api: RelatedCasesAPI) -> None:
    source, _ = await api.add_case(graph={"nodes": []})
    await api.add_case(graph={"nodes": [_node("host", "web-01")]})

    assert await api.related(source) == {"related": [], "limit": 20, "has_more": False}
