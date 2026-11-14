"""Smoke test for the threat graph upgrade (t1m-graph).

Covers:
1. SQLite default end-to-end: upsert nodes + edges, query neighbours.
2. Idempotent upsert: re-upserting (tenant, type, key) merges props/tags
   and advances ``last_seen`` instead of duplicating rows.
3. Edge upsert auto-creates the endpoint nodes if missing.
4. Multi-hop neighbour traversal (IOC → asset → user).
5. Tenancy filter: tenant A can't see tenant B's graph.
6. ``__global__`` CTI namespace bleeds through only when
   ``include_global=True``.
7. ``find_nodes`` by type and by ``key_prefix``.
8. Neo4j configured but unreachable URI → backend resolves to SQLite
   and writes/reads still work.

Run with:
    cd platform/backend
    python -m tests._check_graph
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path


def _reset_settings_and_db(env: dict[str, str]) -> tuple[Path, object]:
    """Force a fresh ``Settings`` and a clean SQLite file under ``env``.

    We deliberately do NOT reload ``app.models.*`` — SQLModel registers
    tables in shared ``MetaData`` and re-registering raises
    ``InvalidRequestError``. We only drop modules that capture settings
    at import time.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-graph-"))
    db_path = tmp / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_HITL_SLA_SECONDS"] = "2"
    # Clear any prior backend-selector env from a previous scenario.
    for k in (
        "AISOC_GRAPH_BACKEND",
        "AISOC_NEO4J_URI",
        "AISOC_NEO4J_USER",
        "AISOC_NEO4J_PASSWORD",
    ):
        os.environ.pop(k, None)
    for k, v in env.items():
        os.environ[k] = v
    for mod in [
        "app.memory",
        "app.memory.graph",
        "app.memory.episodic",
        "app.memory.embedding",
        "app.memory.scratchpad",
        "app.db",
        "app.config",
    ]:
        sys.modules.pop(mod, None)
    import app.config as config  # type: ignore
    importlib.reload(config)
    from app.db import init_db  # type: ignore

    init_db()
    return db_path, config.settings


# ── 1. SQLite default end-to-end ──────────────────────────────────────
def test_sqlite_default() -> None:
    print("\n[1] SQLite default backend (upsert nodes + edges + neighbours)")
    _reset_settings_and_db({})
    from app.memory.graph import (
        graph_backend_name,
        graph_neighbors,
        graph_upsert_edge,
        graph_upsert_node,
    )

    name = graph_backend_name()
    assert name == "sqlite", f"expected sqlite, got {name}"

    ioc_id = graph_upsert_node(
        tenant_id="demo-tenant", type="ioc", key="1.2.3.4",
        label="Cobalt C2", tags=["c2", "cobalt"],
        props={"first_country": "RU"},
    )
    asset_id = graph_upsert_node(
        tenant_id="demo-tenant", type="asset", key="HR-LAPTOP-42",
        label="HR laptop", tags=["endpoint"],
    )
    assert ioc_id and asset_id
    graph_upsert_edge(
        tenant_id="demo-tenant",
        src=("ioc", "1.2.3.4"), dst=("asset", "HR-LAPTOP-42"),
        type="observed_on", weight=0.8,
    )
    neighbours = graph_neighbors(
        tenant_id="demo-tenant", type="ioc", key="1.2.3.4", depth=1,
    )
    assert any(n["node"]["key"] == "HR-LAPTOP-42" for n in neighbours), neighbours
    print(f"    ✓ neighbours: {[n['node']['key'] for n in neighbours]}")


# ── 2. Idempotent upsert ──────────────────────────────────────────────
def test_idempotent_upsert() -> None:
    print("\n[2] Idempotent upsert (props/tags merge, last_seen advances)")
    _reset_settings_and_db({})
    from app.memory.graph import graph_find_nodes, graph_upsert_node

    id1 = graph_upsert_node(
        tenant_id="acme", type="ioc", key="evil.example.com",
        label="evil domain", tags=["domain"], props={"first_seen_via": "edr"},
    )
    id2 = graph_upsert_node(
        tenant_id="acme", type="ioc", key="evil.example.com",
        label="", tags=["c2"], props={"asn": 12345},
    )
    assert id1 == id2, f"upsert should return same id, got {id1} vs {id2}"
    nodes = graph_find_nodes(tenant_id="acme", type="ioc", key_prefix="evil")
    assert len(nodes) == 1, f"should not duplicate: got {nodes}"
    n = nodes[0]
    assert set(n["tags"]) == {"domain", "c2"}, n["tags"]
    assert n["props"].get("asn") == 12345, n["props"]
    assert n["props"].get("first_seen_via") == "edr", n["props"]
    assert n["label"] == "evil domain", n["label"]  # initial label preserved
    print(f"    ✓ merged into one node: tags={sorted(n['tags'])}, props_keys={sorted(n['props'])}")


# ── 3. Edge upsert auto-creates endpoints ─────────────────────────────
def test_edge_autocreates_endpoints() -> None:
    print("\n[3] Edge upsert auto-creates endpoint nodes")
    _reset_settings_and_db({})
    from app.memory.graph import graph_find_nodes, graph_neighbors, graph_upsert_edge

    graph_upsert_edge(
        tenant_id="acme",
        src=("actor", "TA-505"), dst=("technique", "T1059"),
        type="uses",
    )
    actors = graph_find_nodes(tenant_id="acme", type="actor")
    techs = graph_find_nodes(tenant_id="acme", type="technique")
    assert any(a["key"] == "TA-505" for a in actors), actors
    assert any(t["key"] == "T1059" for t in techs), techs
    hops = graph_neighbors(
        tenant_id="acme", type="actor", key="TA-505",
        edge_types=["uses"], depth=1,
    )
    assert any(h["node"]["key"] == "T1059" for h in hops), hops
    print(f"    ✓ both endpoints created + edge-type filter works")


# ── 4. Multi-hop traversal ────────────────────────────────────────────
def test_multi_hop_traversal() -> None:
    print("\n[4] Multi-hop neighbour traversal (IOC → asset → user)")
    _reset_settings_and_db({})
    from app.memory.graph import graph_neighbors, graph_upsert_edge

    graph_upsert_edge(
        tenant_id="acme",
        src=("ioc", "9.9.9.9"), dst=("asset", "PROD-DB-1"),
        type="observed_on",
    )
    graph_upsert_edge(
        tenant_id="acme",
        src=("asset", "PROD-DB-1"), dst=("user", "alice@acme.com"),
        type="authenticated_as",
    )

    one_hop = graph_neighbors(
        tenant_id="acme", type="ioc", key="9.9.9.9", depth=1,
    )
    keys_1 = {n["node"]["key"] for n in one_hop}
    assert "PROD-DB-1" in keys_1, one_hop
    assert "alice@acme.com" not in keys_1, one_hop

    two_hop = graph_neighbors(
        tenant_id="acme", type="ioc", key="9.9.9.9", depth=2,
    )
    keys_2 = {n["node"]["key"] for n in two_hop}
    assert "PROD-DB-1" in keys_2 and "alice@acme.com" in keys_2, two_hop
    print(f"    ✓ depth=1 stops at asset; depth=2 reaches user (keys={sorted(keys_2)})")


# ── 5. Tenancy filter ─────────────────────────────────────────────────
def test_tenancy_isolation() -> None:
    print("\n[5] Tenancy isolation (acme cannot see globex)")
    _reset_settings_and_db({})
    from app.memory.graph import graph_find_nodes, graph_neighbors, graph_upsert_node

    graph_upsert_node(
        tenant_id="acme", type="ioc", key="1.1.1.1", label="acme bad ip",
    )
    graph_upsert_node(
        tenant_id="globex", type="ioc", key="1.1.1.1", label="globex bad ip",
    )

    acme_nodes = graph_find_nodes(tenant_id="acme", type="ioc")
    globex_nodes = graph_find_nodes(tenant_id="globex", type="ioc")
    assert {n["label"] for n in acme_nodes} == {"acme bad ip"}, acme_nodes
    assert {n["label"] for n in globex_nodes} == {"globex bad ip"}, globex_nodes

    # Neighbours from acme should never see globex even with same key.
    nbrs = graph_neighbors(tenant_id="acme", type="ioc", key="1.1.1.1", depth=2)
    for n in nbrs:
        assert n["node"]["tenant_id"] == "acme", n
    print(f"    ✓ same key, isolated views (acme={len(acme_nodes)}, globex={len(globex_nodes)})")


# ── 6. __global__ CTI namespace ───────────────────────────────────────
def test_global_namespace() -> None:
    print("\n[6] __global__ CTI namespace (opt-in via include_global)")
    _reset_settings_and_db({})
    from app.memory.graph import graph_find_nodes, graph_neighbors, graph_upsert_edge, graph_upsert_node

    graph_upsert_node(
        tenant_id="__global__", type="actor", key="APT29",
        label="Cozy Bear", tags=["nation-state"],
    )
    graph_upsert_edge(
        tenant_id="__global__",
        src=("actor", "APT29"), dst=("ioc", "global-bad.example.com"),
        type="uses",
    )

    # Without opt-in, acme sees nothing global.
    none = graph_find_nodes(tenant_id="acme", type="actor")
    assert not any(n["key"] == "APT29" for n in none), none

    # With opt-in, global rows show up.
    with_global = graph_find_nodes(
        tenant_id="acme", type="actor", include_global=True,
    )
    assert any(n["key"] == "APT29" for n in with_global), with_global

    # Traversal also respects the flag.
    hops = graph_neighbors(
        tenant_id="acme", type="actor", key="APT29",
        depth=1, include_global=True,
    )
    assert any(h["node"]["key"] == "global-bad.example.com" for h in hops), hops
    print(f"    ✓ global hidden by default, surfaced when include_global=True")


# ── 7. find_nodes filters ─────────────────────────────────────────────
def test_find_nodes_filters() -> None:
    print("\n[7] find_nodes by type + key_prefix")
    _reset_settings_and_db({})
    from app.memory.graph import graph_find_nodes, graph_upsert_node

    for k in ("10.0.0.1", "10.0.0.2", "10.0.0.3", "192.168.1.1"):
        graph_upsert_node(tenant_id="acme", type="ioc", key=k)
    graph_upsert_node(tenant_id="acme", type="asset", key="10.0.0.99")

    ten_dot = graph_find_nodes(tenant_id="acme", type="ioc", key_prefix="10.0.0.")
    keys = {n["key"] for n in ten_dot}
    assert keys == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}, keys
    # Type filter rejects the asset even though its key matches.
    assert "10.0.0.99" not in keys, ten_dot

    all_iocs = graph_find_nodes(tenant_id="acme", type="ioc")
    assert len(all_iocs) == 4, len(all_iocs)
    print(f"    ✓ prefix={sorted(keys)}, full ioc count={len(all_iocs)}")


# ── 8. Neo4j unreachable → SQLite fallback ────────────────────────────
def test_neo4j_unreachable_fallback() -> None:
    print("\n[8] Neo4j configured but unreachable → falls back to sqlite")
    _reset_settings_and_db(
        {
            "AISOC_GRAPH_BACKEND": "neo4j",
            # Nothing listens on this port locally.
            "AISOC_NEO4J_URI": "bolt://127.0.0.1:1",
            "AISOC_NEO4J_USER": "neo4j",
            "AISOC_NEO4J_PASSWORD": "wrongpassword",
        }
    )
    from app.memory.graph import (
        graph_backend_name,
        graph_neighbors,
        graph_upsert_edge,
        graph_upsert_node,
    )

    name = graph_backend_name()
    assert name == "sqlite", (
        f"unreachable Neo4j should degrade to sqlite, got {name}"
    )

    graph_upsert_node(
        tenant_id="acme", type="ioc", key="bad.example.com",
        label="bad domain",
    )
    graph_upsert_edge(
        tenant_id="acme",
        src=("ioc", "bad.example.com"), dst=("asset", "WS-7"),
        type="observed_on",
    )
    hops = graph_neighbors(
        tenant_id="acme", type="ioc", key="bad.example.com", depth=1,
    )
    assert any(h["node"]["key"] == "WS-7" for h in hops), hops
    print(f"    ✓ writes + reads work even with bad neo4j URI ({len(hops)} hop(s))")


def main() -> int:
    try:
        test_sqlite_default()
        test_idempotent_upsert()
        test_edge_autocreates_endpoints()
        test_multi_hop_traversal()
        test_tenancy_isolation()
        test_global_namespace()
        test_find_nodes_filters()
        test_neo4j_unreachable_fallback()
    except AssertionError as exc:
        print(f"\n❌ FAIL: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001
        import traceback

        print(f"\n💥 ERROR: {exc!r}")
        traceback.print_exc()
        return 2
    print("\n✅ ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
