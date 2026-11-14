"""Smoke test for graph autopopulation from alerts and IOCs (t1m-autopop).

Covers:

1. ``populate_from_ioc`` upserts a single tagged IOC node carrying
   threat_score, sources, and the cyble_native flag.
2. ``populate_from_alert`` produces the expected node/edge fan-out
   (case, asset, user, src_ip IOC, dst_ip IOC, file_hash IOC, tool,
   MITRE technique nodes), all linked back to the case via
   ``INVOLVED_IN`` so ``graph_neighbors(case)`` reconstructs the blast
   radius.
3. Idempotency: re-running ``populate_from_alert`` on the same alert
   does not duplicate nodes (graph upsert dedupes on
   ``(tenant_id, type, key)``).
4. Tenant strictness: an alert tagged with tenant A cannot bleed any
   nodes/edges into tenant B's graph view.
5. Hash-length heuristic: 32-char hex → md5, 64-char hex → sha256.
6. Best-effort: ``populate_from_alert(None)`` and a malformed alert
   (missing ``case_id``, missing entities) return a clean summary and
   do not raise.

Run with:
    cd platform/backend
    python -m tests._check_autopop
"""
from __future__ import annotations

import importlib
import os
import sys
import tempfile
from pathlib import Path


# ── env / db plumbing (mirrors tests/_check_graph.py) ─────────────────
def _reset_settings_and_db() -> Path:
    """Force a fresh ``Settings`` and a clean SQLite file.

    SQLModel registers tables in a shared ``MetaData`` at import-time, so
    we deliberately do NOT reload ``app.models.*`` — only the modules
    that capture settings at import time.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-autopop-"))
    db_path = tmp / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    # Clear any backend selector lingering from a prior run.
    for k in (
        "AISOC_GRAPH_BACKEND",
        "AISOC_NEO4J_URI",
        "AISOC_NEO4J_USER",
        "AISOC_NEO4J_PASSWORD",
    ):
        os.environ.pop(k, None)
    for mod in [
        "app.memory",
        "app.memory.autopop",
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
    return db_path


def _make_alert(**overrides):
    """Build an Alert object with sensible defaults for the demo case."""
    from app.models.alert import Alert  # type: ignore

    defaults: dict = dict(
        external_id="ext-1",
        tenant_id="acme",
        source="splunk",
        title="Lateral movement: WS-7 → srv-db-01",
        description="EDR flagged unusual auth chain.",
        severity="high",
        detection_rule="T1021.001",
        mitre_tactics=["lateral-movement"],
        mitre_techniques=["T1021.001", "T1078"],
        src_user="acme\\alice",
        src_host="WS-7",
        src_ip="10.0.0.7",
        dst_ip="203.0.113.66",
        process_name="psexec.exe",
        # 64-char hex → should be classified as sha256.
        file_hash="a" * 64,
        case_id=42,
    )
    defaults.update(overrides)
    return Alert(**defaults)


def _make_ioc(**overrides):
    from app.models.ioc import IOC, IOCType  # type: ignore

    defaults: dict = dict(
        tenant_id="acme",
        value="bad.example.com",
        type=IOCType.DOMAIN,
        threat_score=87,
        confidence=0.92,
        sources=["cyble-cti", "ransomwatch"],
        tags=["ransomware", "qakbot"],
        cyble_native=True,
        description="C2 domain seen in qakbot intrusions",
    )
    defaults.update(overrides)
    return IOC(**defaults)


# ── 1. populate_from_ioc emits one IOC node with provenance tags ─────
def test_populate_from_ioc_basic() -> None:
    print("\n[1] populate_from_ioc upserts a single tagged IOC node")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_ioc  # type: ignore
    from app.memory.graph import graph_find_nodes  # type: ignore

    ioc = _make_ioc()
    summary = populate_from_ioc(ioc)
    assert summary["errors"] == [], summary
    assert len(summary["nodes"]) == 1, summary
    node = summary["nodes"][0]
    assert node["type"] == "ioc", node
    assert node["key"] == "domain:bad.example.com", node

    hits = graph_find_nodes(tenant_id="acme", type="ioc", key_prefix="domain:")
    assert len(hits) == 1, hits
    stored = hits[0]
    tags = set(stored.get("tags") or [])
    assert "ransomware" in tags, tags
    assert "cyble_native" in tags, tags
    assert "src:cyble-cti" in tags and "src:ransomwatch" in tags, tags

    props = stored.get("props") or {}
    assert props.get("threat_score") == 87, props
    assert props.get("ioc_type") == "domain", props
    print(f"    ✓ node={stored['key']}, tags={sorted(tags)}, score={props.get('threat_score')}")


# ── 2. populate_from_alert builds the expected blast radius ───────────
def test_populate_from_alert_fanout() -> None:
    print("\n[2] populate_from_alert builds case/asset/user/IOC/tool/technique fan-out")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_alert  # type: ignore
    from app.memory.graph import graph_find_nodes, graph_neighbors  # type: ignore

    alert = _make_alert()
    summary = populate_from_alert(alert)
    assert summary["errors"] == [], summary

    node_types = {(n["type"], n["key"]) for n in summary["nodes"]}
    # The case anchors the investigation.
    assert ("case", "42") in node_types, node_types
    # Asset + user.
    assert ("asset", "WS-7") in node_types, node_types
    assert ("user", "acme\\alice") in node_types, node_types
    # src_ip + dst_ip IOCs.
    assert ("ioc", "ip:10.0.0.7") in node_types, node_types
    assert ("ioc", "ip:203.0.113.66") in node_types, node_types
    # file_hash IOC (64-char hex → sha256).
    assert ("ioc", "sha256:" + "a" * 64) in node_types, node_types
    # Process name → tool node.
    assert ("tool", "psexec.exe") in node_types, node_types
    # MITRE techniques.
    assert ("technique", "T1021.001") in node_types, node_types
    assert ("technique", "T1078") in node_types, node_types

    # Edges: asset --authenticated_as--> user
    edge_kinds = {(e["src"], e["dst"], e["type"]) for e in summary["edges"]}
    assert ("WS-7", "acme\\alice", "authenticated_as") in edge_kinds, edge_kinds
    # src_ip --observed_on--> asset
    assert ("ip:10.0.0.7", "WS-7", "observed_on") in edge_kinds, edge_kinds
    # asset --communicates_with--> dst_ip
    assert ("WS-7", "ip:203.0.113.66", "communicates_with") in edge_kinds, edge_kinds
    # technique --part_of--> case
    assert ("T1021.001", "42", "part_of") in edge_kinds, edge_kinds

    # Case neighbours should rebuild the blast radius in 1 hop.
    case_neighbours = graph_neighbors(
        tenant_id="acme", type="case", key="42", depth=1,
    )
    keys = {h["node"]["key"] for h in case_neighbours}
    # asset + user reach the case via INVOLVED_IN; IOCs/tool reach it
    # via INVOLVED_IN (added in the second pass); techniques reach it
    # via PART_OF.
    assert "WS-7" in keys, keys
    assert "acme\\alice" in keys, keys
    assert "ip:10.0.0.7" in keys, keys
    assert "ip:203.0.113.66" in keys, keys
    assert "psexec.exe" in keys, keys
    assert "T1021.001" in keys, keys

    # And sanity: find_nodes by type returns the same population we
    # produced (no leftover rows from a previous scenario).
    iocs = graph_find_nodes(tenant_id="acme", type="ioc")
    assert len(iocs) == 3, iocs  # src_ip, dst_ip, file_hash
    print(f"    ✓ {len(summary['nodes'])} nodes, {len(summary['edges'])} edges, blast-radius={len(keys)} hops")


# ── 3. Idempotency: replay does not duplicate nodes ───────────────────
def test_idempotent_replay() -> None:
    print("\n[3] populate_from_alert is idempotent on replay")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_alert  # type: ignore
    from app.memory.graph import graph_find_nodes  # type: ignore

    alert = _make_alert()
    populate_from_alert(alert)
    iocs_first = graph_find_nodes(tenant_id="acme", type="ioc")
    assets_first = graph_find_nodes(tenant_id="acme", type="asset")

    # Replay.
    populate_from_alert(alert)
    iocs_second = graph_find_nodes(tenant_id="acme", type="ioc")
    assets_second = graph_find_nodes(tenant_id="acme", type="asset")

    assert len(iocs_first) == len(iocs_second), (iocs_first, iocs_second)
    assert len(assets_first) == len(assets_second), (assets_first, assets_second)
    print(f"    ✓ iocs={len(iocs_second)}, assets={len(assets_second)} stable across replay")


# ── 4. Tenant strictness: tenant A's alert never bleeds into tenant B ──
def test_tenancy_isolation() -> None:
    print("\n[4] tenant strictness — tenant B sees none of tenant A's autopop")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_alert, populate_from_ioc  # type: ignore
    from app.memory.graph import graph_find_nodes, graph_neighbors  # type: ignore

    alert_a = _make_alert(tenant_id="acme", external_id="ext-A")
    populate_from_alert(alert_a)

    ioc_a = _make_ioc(tenant_id="acme", value="evil.example.org")
    populate_from_ioc(ioc_a)

    # Tenant B should see absolutely nothing.
    for ntype in ("case", "asset", "user", "ioc", "tool", "technique"):
        rows = graph_find_nodes(tenant_id="other-tenant", type=ntype)
        assert rows == [], (ntype, rows)

    # And neighbour queries scoped to tenant B should be empty too.
    b_hops = graph_neighbors(
        tenant_id="other-tenant", type="case", key="42", depth=2,
    )
    assert b_hops == [], b_hops
    print(f"    ✓ tenant_b sees 0 nodes, 0 hops")


# ── 5. Hash length heuristic ──────────────────────────────────────────
def test_hash_length_heuristic() -> None:
    print("\n[5] file_hash length classifies into md5 / sha1 / sha256")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_alert  # type: ignore
    from app.memory.graph import graph_find_nodes  # type: ignore

    cases = [
        ("d41d8cd98f00b204e9800998ecf8427e", "md5", 32),       # md5
        ("a" * 40, "sha1", 40),                                # sha1
        ("b" * 64, "sha256", 64),                              # sha256
    ]
    for i, (h, expected_kind, _len) in enumerate(cases):
        alert = _make_alert(
            external_id=f"hash-{i}",
            case_id=900 + i,
            src_host=f"HOST-{i}",
            src_user=None,
            src_ip=None,
            dst_ip=None,
            process_name=None,
            mitre_techniques=[],
            file_hash=h,
        )
        populate_from_alert(alert)
        # Look up the IOC node by its expected key prefix.
        hits = graph_find_nodes(
            tenant_id="acme", type="ioc", key_prefix=f"{expected_kind}:",
        )
        assert any(n["key"] == f"{expected_kind}:{h}" for n in hits), (expected_kind, hits)
    print(f"    ✓ md5/sha1/sha256 keys all materialized")


# ── 6. Best-effort: None alert and sparse alert never raise ──────────
def test_best_effort_safety() -> None:
    print("\n[6] best-effort — None alert + sparse alert return clean summaries")
    _reset_settings_and_db()
    from app.memory.autopop import populate_from_alert, populate_from_ioc  # type: ignore

    # 6a. None.
    out = populate_from_alert(None)  # type: ignore[arg-type]
    assert out == {"nodes": [], "edges": [], "errors": []}, out

    # 6b. Sparse alert with no entities at all and no case_id.
    bare = _make_alert(
        case_id=None,
        src_user=None,
        src_host=None,
        src_ip=None,
        dst_ip=None,
        process_name=None,
        file_hash=None,
        mitre_techniques=[],
    )
    out = populate_from_alert(bare)
    assert out["nodes"] == [], out
    assert out["edges"] == [], out
    assert out["errors"] == [], out

    # 6c. None IOC / IOC with empty value.
    from app.models.ioc import IOC, IOCType  # type: ignore
    out = populate_from_ioc(None)  # type: ignore[arg-type]
    assert out == {"nodes": [], "errors": []}, out
    empty = IOC(tenant_id="acme", value="", type=IOCType.DOMAIN)
    out = populate_from_ioc(empty)
    assert out["nodes"] == [], out
    print(f"    ✓ no exceptions raised on None / sparse inputs")


def main() -> int:
    try:
        test_populate_from_ioc_basic()
        test_populate_from_alert_fanout()
        test_idempotent_replay()
        test_tenancy_isolation()
        test_hash_length_heuristic()
        test_best_effort_safety()
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
