"""Graph reads must be scoped to the querying tenant.

Two real cross-tenant leaks lived here.

`get_entity_neighbors` accepted a `tenant_id` argument and never used it. The
Cypher had no tenant predicate and the parameter was not even passed to the
driver, so any authenticated user could read any other tenant's host, user or
IOC node plus all of its neighbours — with full node properties — just by
naming the id.

`get_blast_radius` filtered only the traversal's *start* node, and accepted
`tenant_id IS NULL`. The APOC expansion could therefore leave the tenant's
estate through a shared entity such as a public IP and enumerate another
tenant's hosts and users. Blast radius is exactly the query an attacker would
want for reconnaissance.

These tests assert the shape of the query and, critically, that `tenant_id` is
bound at all. The original bug was not a subtly wrong predicate; it was a
parameter that never reached the database, which is why a review reading the
function signature saw a tenant-scoped API.
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest

graph_service = pytest.importorskip(
    "app.services.graph_service",
    reason="neo4j driver not installed",
)


class _FakeResult:
    def __init__(self, record: Any) -> None:
        self._record = record

    async def single(self) -> Any:
        return self._record

    def __aiter__(self):
        async def _gen():
            if False:  # pragma: no cover — empty async iterator
                yield None

        return _gen()


class _FakeSession:
    """Captures every Cypher statement and its bound parameters."""

    def __init__(self, record: Any = None) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self._record = record

    async def run(self, cypher: str, **params: Any) -> _FakeResult:
        self.calls.append((cypher, params))
        return _FakeResult(self._record)


@pytest.fixture
def session(monkeypatch: pytest.MonkeyPatch) -> _FakeSession:
    fake = _FakeSession(record={"source": None, "neighbors": [], "all_nodes": [], "affected": []})

    @contextlib.asynccontextmanager
    async def _get_session():
        yield fake

    monkeypatch.setattr(graph_service, "get_session", _get_session)
    return fake


TENANT = "tenant-a"


def _assert_scoped(cypher: str, params: dict[str, Any], variables: list[str]) -> None:
    """Every named variable is tenant-scoped, and tenant_id is really bound."""
    assert params.get("tenant_id") == TENANT, "tenant_id was not bound to the query"
    assert params.get("global_labels"), "global reference labels were not bound"
    for var in variables:
        assert f"{var}.tenant_id = $tenant_id" in cypher, f"{var} is not tenant-scoped"


# ── neighbours ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_neighbours_binds_the_tenant_and_scopes_both_ends(session: _FakeSession):
    """The regression: tenant_id was accepted and then dropped entirely."""
    await graph_service.get_entity_neighbors(entity_id="host-1", entity_type="host", tenant_id=TENANT)
    cypher, params = session.calls[0]
    _assert_scoped(cypher, params, ["n", "neighbor"])


@pytest.mark.asyncio
async def test_neighbours_does_not_accept_an_untagged_node(session: _FakeSession):
    """An untagged node would bridge tenant A into tenant B's estate."""
    await graph_service.get_entity_neighbors(entity_id="host-1", entity_type="host", tenant_id=TENANT)
    cypher, _ = session.calls[0]
    assert "tenant_id IS NULL" not in cypher


# ── blast radius ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_blast_radius_scopes_every_node_of_every_path(session: _FakeSession):
    """Filtering only the start node let the expansion walk out of the tenant."""
    await graph_service.get_blast_radius(entity_id="1.2.3.4", entity_type="ioc", tenant_id=TENANT)
    cypher, params = session.calls[0]
    _assert_scoped(cypher, params, ["start", "pn"])
    assert "all(pn IN nodes(path)" in cypher, "path nodes are not checked collectively"


@pytest.mark.asyncio
async def test_blast_radius_no_longer_accepts_untagged_nodes(session: _FakeSession):
    await graph_service.get_blast_radius(entity_id="1.2.3.4", entity_type="ioc", tenant_id=TENANT)
    cypher, _ = session.calls[0]
    assert "tenant_id IS NULL" not in cypher


@pytest.mark.asyncio
async def test_the_apoc_free_fallback_is_scoped_too(session: _FakeSession):
    """The fallback runs whenever APOC is absent, so it is not a lesser path.

    It previously had no predicate on `start`, left the intermediate nodes of
    the variable-length path unchecked, and accepted `tenant_id IS NULL` on
    the endpoint.
    """
    await graph_service._blast_radius_fallback("1.2.3.4", "ioc", TENANT, hops=2)
    cypher, params = session.calls[0]
    _assert_scoped(cypher, params, ["start", "pn"])
    assert "tenant_id IS NULL" not in cypher


# ── global reference data ─────────────────────────────────────────────────


def test_mitre_techniques_stay_readable_by_every_tenant():
    """Techniques are shared reference data, not tenant estate.

    Requiring a tenant_id on them would make every technique node unreachable,
    so the scoping predicate carries a narrow exemption for these labels.
    """
    assert "Technique" in graph_service._GLOBAL_LABELS
    predicate = graph_service._scoped("n")
    assert "labels(n)" in predicate
    assert "$global_labels" in predicate
