"""``GET /api/v1/graph`` — the Attack Graph console's only data source.

The route did not exist. The console called it, got 404, and rendered its
error state, while ``/graph/neighbors/...`` and ``/graph/mitre-coverage``
returned 200 from the same Neo4j instance holding real graph-at-ingest data.

Tenant scoping for the traversal lives in ``test_graph_tenant_isolation.py``
with the other graph reads, because that is the property all of them share.
What is asserted here is the contract the console consumes, and in particular
the distinction the endpoint exists to preserve:

    an empty graph and an unreachable graph must not look the same.

"No attack relationships exist in your estate" is a security claim. Making it
because a database was down is the failure this codebase keeps rediscovering —
``IncidentContextResponse`` carries ``partial``/``errors`` for exactly this
reason, and ``evidence_fingerprint`` reported a flat zero for a whole release
because nothing distinguished "found none" from "never looked".
"""

from __future__ import annotations

import contextlib
from typing import Any

import pytest

pytest.importorskip("neo4j", reason="neo4j driver not installed")

from app.api.v1.endpoints import graph as graph_endpoint  # noqa: E402
from app.services import graph_service  # noqa: E402
from fastapi import HTTPException  # noqa: E402

TENANT = "11111111-1111-1111-1111-111111111111"


class _User:
    tenant_id = TENANT


class _Result:
    def __init__(self, record: Any = None, rows: list[dict[str, Any]] | None = None) -> None:
        self._record = record
        self._rows = rows or []

    async def single(self) -> Any:
        return self._record

    def __aiter__(self):
        async def _gen():
            for row in self._rows:
                yield row

        return _gen()


class _Session:
    """Answers the node statement then the edge statement, in that order."""

    def __init__(self, nodes: list[dict[str, Any]], edges: list[dict[str, Any]]) -> None:
        self._nodes = nodes
        self._edges = edges
        self.calls: list[str] = []

    async def run(self, cypher: str, **_params: Any) -> _Result:
        self.calls.append(cypher)
        if "collect({" in cypher and "ref: elementId(n)" in cypher:
            return _Result(record={"nodes": self._nodes})
        return _Result(rows=self._edges)


def _install(monkeypatch: pytest.MonkeyPatch, nodes: list[dict], edges: list[dict]) -> _Session:
    session = _Session(nodes, edges)

    @contextlib.asynccontextmanager
    async def _get_session():
        yield session

    monkeypatch.setattr(graph_service, "get_session", _get_session)
    return session


def _node(ref: str, node_id: str, labels: list[str], **properties: Any) -> dict[str, Any]:
    return {"ref": ref, "id": node_id, "labels": labels, "properties": properties}


# ── empty is not broken, and broken is not empty ──────────────────────────


@pytest.mark.asyncio
async def test_a_tenant_with_no_graph_gets_an_honest_empty_answer(monkeypatch: pytest.MonkeyPatch):
    """200 and no nodes. The console renders "No graph yet", not an error."""
    _install(monkeypatch, nodes=[], edges=[])
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert response.nodes == []
    assert response.edges == []
    assert response.truncated is False
    assert response.generatedAt


@pytest.mark.asyncio
async def test_an_unreachable_graph_is_503_and_never_an_empty_graph(monkeypatch: pytest.MonkeyPatch):
    """The distinction this endpoint exists to keep.

    Degrading to ``{"nodes": []}`` here would tell an analyst their estate has
    no attack relationships, on evidence nobody retrieved.
    """

    @contextlib.asynccontextmanager
    async def _boom():
        raise RuntimeError("Neo4j driver not initialized")
        yield  # pragma: no cover

    monkeypatch.setattr(graph_service, "get_session", _boom)
    with pytest.raises(HTTPException) as exc_info:
        await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert exc_info.value.status_code == 503
    assert "unavailable" in exc_info.value.detail


# ── the shape the console consumes ────────────────────────────────────────


@pytest.mark.asyncio
async def test_nodes_and_edges_render_in_the_console_contract(monkeypatch: pytest.MonkeyPatch):
    _install(
        monkeypatch,
        nodes=[
            _node("n1", "host-1", ["Host"], hostname="WIN-DB01", risk_score=92),
            _node("n2", "alert-1", ["Alert"], title="Credential dump", severity="critical"),
        ],
        edges=[{"ref": "r1", "source": "n2", "target": "n1", "type": "OBSERVED_ON", "properties": {}}],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())

    by_id = {n.id: n for n in response.nodes}
    assert by_id["host-1"].kind == "host"
    assert by_id["host-1"].label == "WIN-DB01"
    assert by_id["host-1"].riskScore == 92.0
    assert by_id["alert-1"].kind == "alert"
    assert by_id["alert-1"].severity == "critical"

    assert len(response.edges) == 1
    assert (response.edges[0].source, response.edges[0].target) == ("alert-1", "host-1")
    assert response.edges[0].label == "OBSERVED_ON"


@pytest.mark.asyncio
async def test_an_edge_to_a_dropped_node_is_dropped_too(monkeypatch: pytest.MonkeyPatch):
    """An edge whose endpoint did not survive would draw a line into nothing."""
    _install(
        monkeypatch,
        nodes=[_node("n1", "host-1", ["Host"], hostname="WIN-DB01")],
        edges=[{"ref": "r1", "source": "n1", "target": "n-unknown", "type": "PEER_OF", "properties": {}}],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert response.edges == []


@pytest.mark.asyncio
async def test_a_node_with_no_identifier_is_dropped_rather_than_collapsed(monkeypatch: pytest.MonkeyPatch):
    """Cytoscape keys elements by id; a blank one merges every such node into
    a single element claiming to be all of them."""
    _install(
        monkeypatch,
        nodes=[_node("n1", "host-1", ["Host"]), {"ref": "n2", "id": None, "labels": ["Host"], "properties": {}}],
        edges=[],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert [n.id for n in response.nodes] == ["host-1"]


@pytest.mark.asyncio
async def test_a_vendor_severity_is_dropped_rather_than_guessed(monkeypatch: pytest.MonkeyPatch):
    """The console shades by severity. Coercing an unrecognised vendor string
    onto the five-tier ladder would shade a node by a fact nobody established."""
    _install(
        monkeypatch,
        nodes=[_node("n1", "alert-1", ["Alert"], title="x", severity="SEV-2")],
        edges=[],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert response.nodes[0].severity is None


@pytest.mark.asyncio
async def test_an_unscored_node_is_not_reported_as_scoring_zero(monkeypatch: pytest.MonkeyPatch):
    _install(monkeypatch, nodes=[_node("n1", "host-1", ["Host"], hostname="h")], edges=[])
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert response.nodes[0].riskScore is None


@pytest.mark.asyncio
async def test_labels_outside_the_console_union_keep_their_real_identity(monkeypatch: pytest.MonkeyPatch):
    """The console knows ten kinds; the graph schema declares 29 labels.

    Projecting the remainder onto the generic ``asset`` glyph is fine as long
    as the projection does not *lose* the label, so the real one travels in
    ``attributes``.
    """
    _install(monkeypatch, nodes=[_node("n1", "fin7", ["ThreatActor"], name="FIN7")], edges=[])
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert response.nodes[0].kind == "asset"
    assert response.nodes[0].attributes["labels"] == ["ThreatActor"]


@pytest.mark.asyncio
async def test_iocs_resolve_by_their_own_type(monkeypatch: pytest.MonkeyPatch):
    _install(
        monkeypatch,
        nodes=[
            _node("n1", "1.2.3.4", ["IOC"], value="1.2.3.4", ioc_type="ipv4"),
            _node("n2", "evil.test", ["IOC"], value="evil.test", ioc_type="domain"),
            _node("n3", "deadbeef", ["IOC"], value="deadbeef", ioc_type="sha256"),
            _node("n4", "mystery", ["IOC"], value="mystery", ioc_type="something_new"),
        ],
        edges=[],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert [n.kind for n in response.nodes] == ["ip", "domain", "hash", "asset"]


@pytest.mark.asyncio
async def test_a_duplicated_relationship_yields_one_edge(monkeypatch: pytest.MonkeyPatch):
    """Two writers can MERGE the same relationship shape between one pair."""
    _install(
        monkeypatch,
        nodes=[_node("n1", "a", ["Host"], hostname="a"), _node("n2", "b", ["Host"], hostname="b")],
        edges=[
            {"ref": "r1", "source": "n1", "target": "n2", "type": "PEER_OF", "properties": {}},
            {"ref": "r2", "source": "n1", "target": "n2", "type": "PEER_OF", "properties": {}},
        ],
    )
    response = await graph_endpoint.get_graph_overview(depth=3, entity=None, current_user=_User())
    assert len(response.edges) == 1
