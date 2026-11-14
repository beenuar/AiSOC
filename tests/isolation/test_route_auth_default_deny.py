"""Default-deny routes, and by-id reads that carry a tenant predicate.

``test_route_tenant_scope.py`` covers the question "where did the tenant come
from" for routes that take one. This file covers the two shapes that question
could not reach.

**Routes with no auth dependency at all.** ``services/agents`` had 37. None of
them took a tenant, so the parameter gate never looked at them, and they
included ``POST /api/v1/playbooks``, ``DELETE /api/v1/playbooks/{id}`` and
``POST /api/v1/playbooks/{id}/run`` — create, delete and *execute* a response
playbook, for a caller holding no credential. Reproduced below against the
real routers over ASGI, with credential material configured, so the result is
not "the service was unconfigured".

**Reads addressed by an id with no tenant predicate.** A ``query_id`` was a
bearer capability for another tenant's osquery results: ``osquery_distributed_
query`` carries no ``tenant_id`` of its own, it is scoped through the node it
was sent to, and the lookup never joined. Seeded here for two tenants against
a real database, with both tenants' rows asserted present before anything is
asserted absent — a scoped read against an empty table passes for the wrong
reason.

Three layers, same as the neighbouring file: live routers, live store, and a
meta-assertion that the repository-wide gates stay green so neither shape can
come back without this suite noticing.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AGENTS_ROOT = REPO_ROOT / "services" / "agents"
OSQUERY_ROOT = REPO_ROOT / "services" / "osquery-tls"

TENANT_A = uuid.UUID("aaaaaaaa-0000-0000-0000-00000000000a")
TENANT_B = uuid.UUID("bbbbbbbb-0000-0000-0000-00000000000b")

SECRET = "isolation-suite-secret-key-at-least-32-chars"
SERVICE_TOKEN = "isolation-suite-service-token"

# Reuse the token minter from the sibling suite rather than writing a second
# one: two implementations of "what a valid session looks like" drift, and the
# drift shows up as a test that passes against a token the service rejects.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_route_tenant_scope import console_token  # noqa: E402

# ---------------------------------------------------------------------------
# Layer 1 — services/agents answers nobody without a credential
# ---------------------------------------------------------------------------


@pytest.fixture
def agents_app(monkeypatch: pytest.MonkeyPatch):
    """The real agents routers, mounted with credential material configured."""
    monkeypatch.setenv("SECRET_KEY", SECRET)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", SERVICE_TOKEN)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    monkeypatch.syspath_prepend(str(AGENTS_ROOT))

    pytest.importorskip("httpx")
    from app.api.contextual import router as contextual_router  # noqa: PLC0415
    from app.api.copilot import router as copilot_router  # noqa: PLC0415
    from app.api.hunt_search import router as hunt_search_router  # noqa: PLC0415
    from app.api.playbooks import router as playbooks_router  # noqa: PLC0415
    from fastapi import FastAPI  # noqa: PLC0415

    app = FastAPI()
    for router in (playbooks_router, copilot_router, hunt_search_router, contextual_router):
        app.include_router(router)
    return app


#: (method, path, json) for routes that were reachable with no credential.
#: The three playbook entries are the ones that mattered: they create, execute
#: and delete a response playbook.
_AGENT_ROUTES = [
    ("POST", "/api/v1/playbooks", {"id": "probe", "name": "p", "enabled": True, "trigger": {"type": "manual"}, "steps": []}),
    ("GET", "/api/v1/playbooks", None),
    ("POST", "/api/v1/playbooks/probe/run", {"context": {}, "dry_run": True}),
    ("DELETE", "/api/v1/playbooks/probe", None),
    ("GET", "/api/v1/copilot/conversations", None),
    ("POST", "/api/v1/hunt/search", {"query": "*", "limit": 1}),
    ("GET", "/api/v1/contextual/actions", None),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(("method", "path", "body"), _AGENT_ROUTES)
async def test_agents_routes_refuse_an_anonymous_caller(agents_app, method: str, path: str, body: dict | None) -> None:
    """No credential at all — including on the routes that change state."""
    import httpx  # noqa: PLC0415

    transport = httpx.ASGITransport(app=agents_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://agents.test") as client:
        resp = await client.request(method, path, json=body)
    assert resp.status_code == 401, f"{method} {path} answered an anonymous caller with {resp.status_code}: {resp.text[:200]}"


@pytest.mark.asyncio
async def test_agents_routes_still_serve_a_real_console_session(agents_app) -> None:
    """The refusal must be about the credential, not about the route.

    A default-deny pass that returns 401 to everybody is indistinguishable
    from one that broke the console, and the console reaches these routes
    directly through a Next rewrite.
    """
    import httpx  # noqa: PLC0415

    transport = httpx.ASGITransport(app=agents_app)
    headers = {"Authorization": f"Bearer {console_token(TENANT_A)}"}
    async with httpx.AsyncClient(transport=transport, base_url="http://agents.test") as client:
        listed = await client.get("/api/v1/playbooks", headers=headers)
        actions = await client.get("/api/v1/contextual/actions", headers=headers)

    assert listed.status_code == 200, f"a valid console session was refused: {listed.text[:200]}"
    assert isinstance(listed.json(), list) and listed.json(), "the playbook corpus came back empty — this assertion would be vacuous"
    assert actions.status_code == 200


@pytest.mark.asyncio
async def test_agents_routes_refuse_a_service_token_that_declares_no_tenant(agents_app) -> None:
    """A service token identifies a service, not a tenant. Absent is not all."""
    import httpx  # noqa: PLC0415

    transport = httpx.ASGITransport(app=agents_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://agents.test") as client:
        undeclared = await client.get("/api/v1/playbooks", headers={"Authorization": f"Bearer {SERVICE_TOKEN}"})
        declared = await client.get(
            "/api/v1/playbooks",
            headers={"Authorization": f"Bearer {SERVICE_TOKEN}", "X-AiSOC-Tenant-ID": str(TENANT_B)},
        )
    assert undeclared.status_code == 403
    assert declared.status_code == 200


@pytest.mark.asyncio
async def test_agents_routes_refuse_a_forged_or_expired_session(agents_app) -> None:
    import httpx  # noqa: PLC0415

    transport = httpx.ASGITransport(app=agents_app)
    forged = console_token(TENANT_A, secret="a-different-secret-key-at-least-32-chars")
    expired = console_token(TENANT_A, ttl=-3600)
    unsigned = console_token(TENANT_A, alg="none")
    refresh = console_token(TENANT_A, token_type="refresh")
    async with httpx.AsyncClient(transport=transport, base_url="http://agents.test") as client:
        for label, token in (("forged", forged), ("expired", expired), ("alg none", unsigned), ("refresh", refresh)):
            resp = await client.get("/api/v1/playbooks", headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 401, f"{label} token was accepted ({resp.status_code})"


# ---------------------------------------------------------------------------
# Layer 2 — a by-id read, seeded for two tenants against a real database
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_distributed_query_status_is_scoped_through_its_node() -> None:
    """Seed A and B for real, then read A's query_id as B.

    ``osquery_distributed_query`` has no ``tenant_id`` column — it is reached
    through ``osquery_node`` — so the lookup has to join. Before the join it
    matched on ``query_id`` alone, which made the id a bearer capability for
    another tenant's host telemetry.
    """
    pytest.importorskip("aiosqlite")
    # SQLAlchemy's async layer needs greenlet; skip rather than fail where the
    # extra is not installed, the way the Redis-backed suites skip.
    pytest.importorskip("greenlet")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: PLC0415

    # Every service in this repo roots its package at `app`, so whichever one
    # imported first owns the name for the rest of the session. Swap the
    # binding for the duration rather than relying on collection order — the
    # agents fixture above has already claimed it.
    saved_modules = {name: mod for name, mod in sys.modules.items() if name == "app" or name.startswith("app.")}
    saved_path = list(sys.path)
    for name in saved_modules:
        del sys.modules[name]
    sys.path.insert(0, str(OSQUERY_ROOT))
    try:
        from app.db.base import Base  # noqa: PLC0415
        from app.models.distributed_query import OsqueryDistributedQuery  # noqa: PLC0415
        from app.models.node import OsqueryNode  # noqa: PLC0415
        from app.services.distributed_queue import get_query_by_id  # noqa: PLC0415
    finally:
        sys.path[:] = saved_path

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)

        async with session_factory() as db:
            node_a = OsqueryNode(host_identifier="a-dc-01", node_key="key-a", tenant_id=str(TENANT_A))
            node_b = OsqueryNode(host_identifier="b-lap-09", node_key="key-b", tenant_id=str(TENANT_B))
            db.add_all([node_a, node_b])
            await db.flush()
            query_a = OsqueryDistributedQuery(
                node_id=node_a.id,
                query_id="query-owned-by-tenant-a",
                query_text="SELECT * FROM users;",
                status="completed",
                results_json=[{"username": "ceo", "uid": 0}],
            )
            query_b = OsqueryDistributedQuery(
                node_id=node_b.id,
                query_id="query-owned-by-tenant-b",
                query_text="SELECT * FROM processes;",
                status="completed",
                results_json=[{"name": "intern-laptop"}],
            )
            db.add_all([query_a, query_b])
            await db.commit()

            # Non-vacuity first: if neither row exists, every assertion below
            # is trivially true and proves nothing about the scoping.
            own_a = await get_query_by_id(db, "query-owned-by-tenant-a", TENANT_A)
            own_b = await get_query_by_id(db, "query-owned-by-tenant-b", TENANT_B)
            assert own_a is not None, "tenant A seeded no query — the assertions below would be vacuous"
            assert own_b is not None, "tenant B seeded no query — the assertions below would be vacuous"
            assert own_a.results_json == [{"username": "ceo", "uid": 0}]

            # The read that used to succeed.
            leaked = await get_query_by_id(db, "query-owned-by-tenant-a", TENANT_B)
            assert leaked is None, "tenant B read tenant A's distributed-query results by naming its query_id"

            crossed = await get_query_by_id(db, "query-owned-by-tenant-b", TENANT_A)
            assert crossed is None, "tenant A read tenant B's distributed-query results"
    finally:
        await engine.dispose()
        for name in [n for n in sys.modules if n == "app" or n.startswith("app.")]:
            del sys.modules[name]
        sys.modules.update(saved_modules)


# ---------------------------------------------------------------------------
# Layer 3 — the repository-wide gates
# ---------------------------------------------------------------------------


def _run_gate(script: str, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / script), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


def test_every_route_authenticates_or_records_why_not() -> None:
    result = _run_gate("check_route_auth.py")
    assert result.returncode == 0, f"check_route_auth reported violations:\n{result.stdout}\n{result.stderr}"


def test_route_auth_gate_detects_injected_drift() -> None:
    result = _run_gate("check_route_auth.py", "--self-test")
    assert result.returncode == 0, f"route-auth gate self-test failed:\n{result.stdout}\n{result.stderr}"


def test_every_tenant_scoped_query_carries_a_tenant_predicate() -> None:
    result = _run_gate("check_tenant_query_predicates.py")
    assert result.returncode == 0, f"check_tenant_query_predicates reported violations:\n{result.stdout}\n{result.stderr}"


def test_tenant_predicate_gate_detects_injected_drift() -> None:
    result = _run_gate("check_tenant_query_predicates.py", "--self-test")
    assert result.returncode == 0, f"tenant-predicate gate self-test failed:\n{result.stdout}\n{result.stderr}"


def test_gates_name_what_they_scanned() -> None:
    """A gate that prints OK without saying what it opened is not evidence.

    Both gates resolve their root from ``git rev-parse`` rather than
    ``__file__`` — a previous gate in this repository would have printed a
    confident OK about a tree it never opened.
    """
    for script, needle in (
        ("check_route_auth.py", "scanned 601 routes"),
        ("check_tenant_query_predicates.py", "statements touch"),
    ):
        result = _run_gate(script)
        assert result.returncode == 0, result.stderr
        assert "scanned" in result.stdout, f"{script} did not say what it scanned"
        if needle.startswith("scanned "):
            # Route count is allowed to move; assert the shape, not the number.
            assert "routes across" in result.stdout and "files under" in result.stdout
