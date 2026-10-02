"""The production graph reader, against a live Neo4j.

Maturity: the evidence that takes **Entity graph (Neo4j)** to Stable.
See `docs/audit/MATURITY_DEFINITION.md` for what the label requires.

Why this exists when `test_live_stores.py` already touches Neo4j
----------------------------------------------------------------
That test writes its own Cypher and asserts a tenant-scoped `MATCH`
behaves. It proves the *pattern* is sound, and it has a real negative
control. What it does not do is call anything a deployment runs: if
`graph_service.get_entity_neighbors` stopped binding `tenant_id`
tomorrow, that test would still pass.

That is not hypothetical. The docstring on `get_entity_neighbors` records
exactly that defect — the function accepted `tenant_id`, never bound it,
and any authenticated user could read any other tenant's host, user or
IOC node with all of its properties by naming the id. The unit tests for
it assert on Cypher *text* through a `_FakeSession`, so they would have
passed too; a text assertion cannot notice that a parameter is missing
from the call.

So every query below comes from `services/api/app/services/graph_service.py`
and runs through `app.db.neo4j.get_session`, which is the driver a
deployment uses. Nothing here re-implements a query.

The negative control
--------------------
`test_an_unscoped_read_sees_both_tenants` seeds two tenants and proves an
unscoped read returns both. Without it, every scoped assertion below
could pass against an empty graph and prove nothing — the vacuous-pass
shape this repository has caught in gates five separate times.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio

pytestmark = [pytest.mark.asyncio]

TENANT_A = "11111111-1111-1111-1111-111111111111"
TENANT_B = "22222222-2222-2222-2222-222222222222"

# Set at import, before anything under `app.` is loaded.
#
# `app.core.config.settings` is a module-level singleton built when it is
# first imported, so a fixture that sets NEO4J_URI later would configure
# nothing and the driver would quietly dial localhost:7687. Doing it here
# means the production driver reads the live container the same way a
# deployment reads its own.
_URI = os.environ.get("ISOLATION_NEO4J_URI", "").strip()
if _URI:
    os.environ["NEO4J_URI"] = _URI
    os.environ["NEO4J_USER"] = os.environ.get("ISOLATION_NEO4J_USER", "neo4j")
    os.environ["NEO4J_PASSWORD"] = os.environ.get("ISOLATION_NEO4J_PASSWORD", "neo4j")


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        pytest.skip(f"{name} is not set; this suite needs a live Neo4j")
    return value


@pytest.fixture(scope="module")
def neo4j_env():
    """Confirm a live Neo4j was named, and that its driver is installed."""
    uri = _require("ISOLATION_NEO4J_URI")
    pytest.importorskip("neo4j")
    return uri


@pytest_asyncio.fixture
async def seeded(neo4j_env):  # noqa: ANN001
    """Two tenants' worth of nodes, written by the production upserts.

    `upsert_host` and `upsert_alert_node` rather than raw Cypher, so the
    write path is the one a deployment uses and a change to either is
    graded here.
    """
    from app.db.neo4j import close_neo4j, get_session, init_neo4j
    from app.services import graph_service

    await init_neo4j()
    marker = uuid.uuid4().hex[:8]
    host_a = f"host-a-{marker}"
    host_b = f"host-b-{marker}"

    await graph_service.upsert_host(host_id=host_a, hostname=f"WIN-A-{marker}", tenant_id=TENANT_A)
    await graph_service.upsert_host(host_id=host_b, hostname=f"WIN-B-{marker}", tenant_id=TENANT_B)
    await graph_service.upsert_alert_node(
        alert_id=f"alert-a-{marker}",
        title="Encoded PowerShell",
        severity="high",
        tenant_id=TENANT_A,
        host_id=host_a,
    )
    await graph_service.upsert_alert_node(
        alert_id=f"alert-b-{marker}",
        title="Encoded PowerShell",
        severity="high",
        tenant_id=TENANT_B,
        host_id=host_b,
    )

    # A global MITRE node attached to tenant B's host.
    #
    # This is what makes the *anchor* scope independently testable, and
    # the first version of this suite was missing it. `_scoped` admits
    # `Technique`, `Tactic` and `Mitigation` as shared reference data, so
    # without a global neighbour the neighbour predicate masks an
    # unscoped anchor: reading B's host as A matched nothing either way,
    # and removing `WHERE {_scoped("n")}` entirely still left all six
    # tests green. A negative control that cannot distinguish the two
    # scopes is only testing one of them.
    async with get_session() as session:
        await session.run(
            "MERGE (t:Technique {technique_id: $tid}) WITH t MATCH (h:Host {id: $host}) MERGE (h)-[:EXHIBITS]->(t)",
            tid=f"T1059-{marker}",
            host=host_b,
        )

    yield {"marker": marker, "host_a": host_a, "host_b": host_b}

    async with get_session() as session:
        await session.run(
            "MATCH (n) WHERE n.id ENDS WITH $m OR n.hostname ENDS WITH $m OR n.technique_id ENDS WITH $m DETACH DELETE n",
            m=marker,
        )
    await close_neo4j()


class TestTheNegativeControl:
    async def test_an_unscoped_read_sees_both_tenants(self, seeded) -> None:  # noqa: ANN001
        """Without this, every scoped assertion could pass on an empty graph.

        Run first and deliberately: it is the only thing standing between
        "tenant B's node is correctly excluded" and "nothing was written
        and the read returned nothing".
        """
        from app.db.neo4j import get_session

        async with get_session() as session:
            result = await session.run(
                "MATCH (h:Host) WHERE h.id IN [$a, $b] RETURN count(h) AS n",
                a=seeded["host_a"],
                b=seeded["host_b"],
            )
            record = await result.single()

        assert record["n"] == 2, (
            f"expected both tenants' hosts present before scoping is tested, found "
            f"{record['n']}. Every assertion below is vacuous without this."
        )


class TestTheProductionReaderScopes:
    async def test_neighbors_excludes_another_tenant(self, seeded) -> None:  # noqa: ANN001
        """`get_entity_neighbors` is the function whose docstring records
        accepting `tenant_id` and never binding it.

        Tenant B's host carries a global `Technique` neighbour, which
        `_scoped` admits for every tenant. So this exercises the **anchor**
        predicate on its own: without it the pattern matches through the
        global node and B's hostname and properties come back to A.
        """
        from app.services import graph_service

        result = await graph_service.get_entity_neighbors(entity_id=seeded["host_b"], entity_type="host", tenant_id=TENANT_A)
        source = (result or {}).get("source") or {}
        assert not source.get("id"), (
            f"tenant A read tenant B's host through the production reader: {source!r}. "
            "This is the exact defect get_entity_neighbors' own docstring records."
        )

    async def test_neighbors_returns_its_own_tenants_node(self, seeded) -> None:  # noqa: ANN001
        """The other half. A reader that returns nothing for everyone is
        'scoped' in the uninteresting sense."""
        from app.services import graph_service

        result = await graph_service.get_entity_neighbors(entity_id=seeded["host_a"], entity_type="host", tenant_id=TENANT_A)
        source = (result or {}).get("source") or {}
        assert source.get("id") == seeded["host_a"], f"tenant A could not read its own host through the production reader: {result!r}"

    async def test_blast_radius_does_not_traverse_into_another_tenant(self, seeded) -> None:  # noqa: ANN001
        """`get_blast_radius` filtered only the traversal's start node, so
        an expansion could walk through a shared entity into another
        tenant's estate. Every node of every path is scoped now."""
        from app.services import graph_service

        result = await graph_service.get_blast_radius(entity_id=seeded["host_a"], entity_type="host", tenant_id=TENANT_A, hops=3)
        blob = repr(result)
        assert seeded["host_b"] not in blob, "a blast-radius expansion from tenant A reached tenant B's host"

    async def test_another_tenants_blast_radius_is_empty(self, seeded) -> None:  # noqa: ANN001
        from app.services import graph_service

        result = await graph_service.get_blast_radius(entity_id=seeded["host_b"], entity_type="host", tenant_id=TENANT_A, hops=3)
        nodes = (result or {}).get("nodes") or []
        assert not nodes, f"tenant A got a blast radius for tenant B's host: {nodes!r}"


class TestTheWritePathIsReal:
    async def test_an_upsert_is_visible_to_the_reader(self, seeded) -> None:  # noqa: ANN001
        """Proves the fixture wrote through production code rather than
        leaving the reader to find nothing and call that isolation."""
        from app.services import graph_service

        result = await graph_service.get_entity_neighbors(entity_id=seeded["host_a"], entity_type="host", tenant_id=TENANT_A)
        neighbors = (result or {}).get("neighbors") or []
        assert neighbors, (
            "the alert upserted against this host is not reachable from it, so either the write path or the relationship is broken"
        )
