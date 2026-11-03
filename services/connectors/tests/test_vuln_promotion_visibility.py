"""A failing patch-window sweep has to be visible somewhere an operator looks.

The sweep's per-tenant ``except Exception: logger.exception(...)`` is the
right call — one tenant's failure must not stop the others' — and it left the
failure visible *nowhere else*. The upsert inside it raised on every tenant on
every deployment for the whole life of the statement, and the only trace was a
log line in a service nobody tails. Every alert the job exists to create was
simply absent, which looks exactly like a tenant with no overdue CVEs.

So the sweep now records its outcome, ``/readyz`` reports it as a
**non-required** dependency, and ``/api/v1/health`` carries the reason.
Non-required on purpose: failing readiness over a six-hourly background job
would pull the connector API's front door out of the load balancer to flag a
job that is not serving traffic — the same reasoning ingest applies to its
opt-in WebSocket.
"""

from __future__ import annotations

import pytest
from app._health import install_health_routes, register_dependency
from app.api.router import health_router
from app.scheduler import ConnectorScheduler
from fastapi import FastAPI
from fastapi.testclient import TestClient


class _ExplodingEngine:
    """An engine whose every transaction raises, like a broken statement does."""

    def __init__(self, message: str) -> None:
        self._message = message

    def connect(self):  # noqa: ANN201
        raise RuntimeError(self._message)

    def begin(self):  # noqa: ANN201
        raise RuntimeError(self._message)


class _OneTenantEngine:
    """Enumerates one tenant, then raises inside that tenant's transaction.

    The two halves matter separately: the tenant enumeration has its own
    `except` and returns early, so an engine that fails on `connect` never
    reaches the per-tenant loop the recording lives in.
    """

    def __init__(self, tenant_id: str, message: str) -> None:
        self._tenant_id = tenant_id
        self._message = message

    def connect(self):  # noqa: ANN201
        return _Ctx(_TenantResult(self._tenant_id))

    def begin(self):  # noqa: ANN201
        raise RuntimeError(self._message)


class _Ctx:
    def __init__(self, result) -> None:  # noqa: ANN001
        self._result = result

    async def __aenter__(self):  # noqa: ANN204
        return self

    async def __aexit__(self, *exc) -> bool:  # noqa: ANN002
        return False

    async def execute(self, *_args, **_kwargs):  # noqa: ANN202
        return self._result


class _TenantResult:
    def __init__(self, tenant_id: str) -> None:
        self._tenant_id = tenant_id

    def scalars(self):  # noqa: ANN202
        return self

    def all(self):  # noqa: ANN202
        return [self._tenant_id]


def _app_with(scheduler: ConnectorScheduler) -> TestClient:
    app = FastAPI()
    mark_ready, _ = install_health_routes(app, service_name="aisoc-connectors")
    register_dependency(app, "vuln_promotion", scheduler.promotion_sweep_healthy, required=False)
    app.state.scheduler = scheduler
    app.include_router(health_router, prefix="/api/v1")
    mark_ready()
    return TestClient(app)


def test_a_clean_sweep_keeps_readiness_green() -> None:
    """The positive control. A probe stuck closed reads as working caution."""
    scheduler = ConnectorScheduler(engine=None)
    client = _app_with(scheduler)

    response = client.get("/readyz")

    assert response.status_code == 200
    assert response.json()["status"] == "ready"
    assert response.json()["vuln_promotion"] is True


@pytest.mark.asyncio
async def test_a_failing_sweep_degrades_readiness_and_names_the_reason() -> None:
    scheduler = ConnectorScheduler(
        engine=_OneTenantEngine("11111111-1111-1111-1111-111111111111", 'syntax error at or near ":"'),
    )

    await scheduler._promote_overdue_findings()  # noqa: SLF001 — the sweep is the unit under test

    client = _app_with(scheduler)
    response = client.get("/readyz")

    # Degraded, not down: the HTTP surface still serves and the sweep is an
    # auxiliary job. 200 with a named problem, which is the honest answer.
    assert response.status_code == 200
    assert response.json()["status"] == "ready_degraded"
    assert response.json()["vuln_promotion"] is False

    detail = client.get("/api/v1/health").json()["vuln_promotion"]
    assert detail["tenants_failing"] == ["11111111-1111-1111-1111-111111111111"]
    assert 'syntax error at or near ":"' in detail["last_error"]


@pytest.mark.asyncio
async def test_a_recovered_tenant_clears_its_own_failure() -> None:
    """A sticky failure is a second defect: it reports a fault that is over."""
    tenant = "22222222-2222-2222-2222-222222222222"
    scheduler = ConnectorScheduler(engine=_OneTenantEngine(tenant, "boom"))
    await scheduler._promote_overdue_findings()  # noqa: SLF001
    assert scheduler.promotion_sweep_healthy() is False

    scheduler._engine = _HealthyEngine(tenant)  # noqa: SLF001
    await scheduler._promote_overdue_findings()  # noqa: SLF001

    assert scheduler.promotion_sweep_healthy() is True
    assert scheduler.promotion_sweep_detail() == {"tenants_failing": [], "last_error": None}


class _HealthyEngine(_OneTenantEngine):
    def __init__(self, tenant_id: str) -> None:
        super().__init__(tenant_id, "unused")

    def begin(self):  # noqa: ANN201
        return _Ctx(_EmptyResult())


class _EmptyResult:
    rowcount = 0

    def fetchall(self):  # noqa: ANN202
        return []

    def scalars(self):  # noqa: ANN202
        return self

    def all(self):  # noqa: ANN202
        return []


def test_the_enumeration_failure_is_not_silently_healthy() -> None:
    """An engine that cannot even list tenants must not read as a clean sweep.

    This case is the reason the recording cannot live only in the per-tenant
    handler: the enumeration has its own `except` and returns before the loop.
    It is recorded as its own entry rather than attributed to a tenant.
    """
    scheduler = ConnectorScheduler(engine=_ExplodingEngine("could not connect"))

    import asyncio

    asyncio.run(scheduler._promote_overdue_findings())  # noqa: SLF001

    assert scheduler.promotion_sweep_healthy() is False
    assert "could not connect" in (scheduler.promotion_sweep_detail()["last_error"] or "")
