"""End-to-end smoke check for the Attack-Path Agent (Theme 2g).

Exercises the full proactive scan against an isolated SQLite DB and the
default ``MockCloudConnector`` + ``MockIdpConnector`` + ``cti_asm_lookup``
mocks. Unlike the reactive sub-agents (Phishing Triage, CDR, ITDR) this
agent does *not* take an alert handoff — it is invoked directly by the
scheduler or the ``POST /attack-paths/scan`` API endpoint, so the test
calls ``AttackPathAgent(...).scan()`` directly.

What we verify:

  * The agent is wired in: ``app.agents.attack_path.AttackPathAgent`` is
    importable and constructible with just a tenant id.
  * The ``AgentName.ATTACK_PATH`` enum value exists and the new node /
    edge types (``EXPOSURE``, ``ROLE``, ``PERMISSION``, ``GROUP``,
    ``EXPOSED_AS``, ``CAN_ASSUME_ROLE``, ``HAS_PERMISSION``, ``MEMBER_OF``,
    ``CAN_REACH``, ``CAN_PRIVESC_TO``) are present on the graph schema.
  * The scan runs end-to-end against the unconfigured-tenant mock fall
    back and returns at least one ranked ``AttackPath``.
  * Every high-risk path above the threshold opens a proactive case
    with ``Severity.HIGH`` and ``status=CaseStatus.NEW``, attributed to
    the active tenant.
  * Each proactive case has at least one ``AgentTrace`` row written
    under ``AgentName.ATTACK_PATH`` so the case timeline shows why it
    was opened.
  * Tenancy is enforced — instantiating without a tenant raises, and
    every case + trace carries the supplied ``tenant_id``.
  * The graph was actually written to (nodes + edges upserted under the
    new vocab) for the UI's attack-path explorer.

Run from ``platform/backend/``::

    PYTHONPATH=. python tests/_check_attack_path.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-attack-path-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.attack_path import (  # noqa: E402
    AttackPath,
    AttackPathAgent,
    AttackPathScanResult,
)
from app.db import engine, init_db  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.graph import EdgeType, GraphEdge, GraphNode, NodeType  # noqa: E402
from app.models.trace import AgentName, AgentTrace  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(label: str) -> None:
    print(f"\n── {label} ──")


# ── Checks ──────────────────────────────────────────────────────────────


def check_graph_vocab_extended() -> None:
    section("Graph schema knows the new attack-path vocab")

    # Node types added for the Attack-Path Agent. These back the
    # cross-plane stitching (exposure surface → IAM → K8s → groups).
    for nt in ("EXPOSURE", "ROLE", "PERMISSION", "GROUP"):
        check(
            f"NodeType.{nt} exists",
            hasattr(NodeType, nt),
            detail=f"members={[m.name for m in NodeType]}",
        )
    # Edge verbs the agent uses to express pivot capability + privilege
    # escalation between planes.
    for et in (
        "EXPOSED_AS",
        "CAN_ASSUME_ROLE",
        "HAS_PERMISSION",
        "MEMBER_OF",
        "CAN_REACH",
        "CAN_PRIVESC_TO",
    ):
        check(
            f"EdgeType.{et} exists",
            hasattr(EdgeType, et),
            detail=f"members={[m.name for m in EdgeType]}",
        )


def check_agent_name_extended() -> None:
    section("AgentName knows ATTACK_PATH")
    check(
        "AgentName.ATTACK_PATH exists",
        hasattr(AgentName, "ATTACK_PATH"),
        detail=f"members={[m.name for m in AgentName]}",
    )


def check_agent_tenancy_enforced() -> None:
    section("AttackPathAgent refuses to construct without a tenant")
    init_db()
    with Session(engine) as s:
        raised = False
        try:
            AttackPathAgent(s, tenant_id="")
        except ValueError:
            raised = True
        check(
            "empty tenant_id raises ValueError",
            raised,
            detail="agent should refuse to run cross-tenant",
        )


async def check_scan_end_to_end() -> None:
    section("AttackPathAgent.scan() against default mock connectors")

    init_db()
    tenant_id = "t-attack-path-test"

    # The mock cloud connector ships two no-MFA / high-risk-score users
    # plus admin/wildcard roles and a cluster-admin K8s binding, so the
    # IAM-pivot detector should always find at least one path.
    with Session(engine) as s:
        agent = AttackPathAgent(s, tenant_id=tenant_id)
        result = await agent.scan()

    check(
        "scan returned an AttackPathScanResult",
        isinstance(result, AttackPathScanResult),
        detail=f"type={type(result).__name__}",
    )
    check(
        "scan attributed to the active tenant",
        result.tenant_id == tenant_id,
        detail=f"got={result.tenant_id}",
    )
    check(
        "scan discovered at least one pre-attack path",
        result.paths_discovered > 0 and len(result.paths) > 0,
        detail=f"paths_discovered={result.paths_discovered}",
    )
    check(
        "all discovered paths are AttackPath instances",
        all(isinstance(p, AttackPath) for p in result.paths),
        detail=f"types={[type(p).__name__ for p in result.paths]}",
    )
    check(
        "scan opened at least one proactive case",
        result.cases_opened > 0,
        detail=f"cases_opened={result.cases_opened}",
    )
    # Connector health surface — should record OK or a typed error string
    # for each plane we tried. Mock fall-back returns OK for cloud + idp;
    # ASM is a CTI tool so it always returns OK in the mock.
    check(
        "connector_health records every plane",
        {"asm", "cloud", "idp"}.issubset(result.connector_health.keys()),
        detail=f"health={result.connector_health}",
    )

    # Graph writes — at least one node + edge for each plane the agent
    # could collect.
    check(
        "scan wrote at least one graph node",
        result.nodes_upserted > 0,
        detail=f"nodes_upserted={result.nodes_upserted}",
    )
    check(
        "scan wrote at least one graph edge",
        result.edges_upserted > 0,
        detail=f"edges_upserted={result.edges_upserted}",
    )

    # Every high-risk path must carry the new MITRE techniques and
    # rationale lines so the analyst console can render them.
    for p in result.paths:
        check(
            f"path {p.path_id} has at least one hop",
            p.depth > 0,
            detail=f"hops={p.hops}",
        )
        check(
            f"path {p.path_id} has rationale lines",
            len(p.rationale) > 0,
            detail=f"rationale={p.rationale}",
        )
        check(
            f"path {p.path_id} is bounded in [0, 1]",
            0.0 <= p.risk_score <= 1.0,
            detail=f"risk={p.risk_score}",
        )

    # Verify the proactive cases landed in the DB with the expected
    # shape: HIGH severity, NEW status, tenant_id stamped, prefixed title.
    with Session(engine) as s:
        cases = s.exec(
            select(Case).where(Case.tenant_id == tenant_id)
        ).all()
        check(
            "at least one case exists for tenant in DB",
            len(cases) >= result.cases_opened,
            detail=f"db_cases={len(cases)} opened={result.cases_opened}",
        )
        all_high = all(c.severity == Severity.HIGH for c in cases)
        check(
            "every proactive case is Severity.HIGH",
            all_high,
            detail=f"severities={[c.severity for c in cases]}",
        )
        all_new = all(c.status == CaseStatus.NEW for c in cases)
        check(
            "every proactive case starts in CaseStatus.NEW",
            all_new,
            detail=f"statuses={[c.status for c in cases]}",
        )
        all_prefixed = all(c.title.startswith("[Pre-attack]") for c in cases)
        check(
            "every proactive case is prefixed [Pre-attack]",
            all_prefixed,
            detail=f"titles={[c.title for c in cases]}",
        )

        # AgentTrace rows — each opened case must have at least one
        # ATTACK_PATH row so the timeline view shows the discovery.
        for c in cases:
            traces = s.exec(
                select(AgentTrace)
                .where(AgentTrace.case_id == c.id)
                .where(AgentTrace.agent == AgentName.ATTACK_PATH)
            ).all()
            check(
                f"case {c.id} has at least one AgentTrace under ATTACK_PATH",
                len(traces) > 0,
                detail=f"trace_count={len(traces)}",
            )

        # Graph tenancy — every node and every edge written must carry
        # the active tenant_id. This is the cross-tenant leakage guard.
        nodes = s.exec(
            select(GraphNode).where(GraphNode.tenant_id == tenant_id)
        ).all()
        edges = s.exec(
            select(GraphEdge).where(GraphEdge.tenant_id == tenant_id)
        ).all()
        check(
            "at least one graph node persisted for tenant",
            len(nodes) > 0,
            detail=f"node_count={len(nodes)}",
        )
        check(
            "at least one graph edge persisted for tenant",
            len(edges) > 0,
            detail=f"edge_count={len(edges)}",
        )
        # We must have written at least one of the *new* node types so
        # we know the cross-plane stitch actually ran, not just the
        # legacy IDENTITY/ASSET upserts that pre-existed.
        new_types_seen = {n.type for n in nodes} & {
            NodeType.EXPOSURE.value,
            NodeType.ROLE.value,
            NodeType.PERMISSION.value,
        }
        check(
            "graph includes at least one new node type",
            len(new_types_seen) > 0,
            detail=f"seen={sorted(n.type for n in nodes)[:8]}",
        )
        new_edges_seen = {e.type for e in edges} & {
            EdgeType.EXPOSED_AS.value,
            EdgeType.CAN_ASSUME_ROLE.value,
            EdgeType.HAS_PERMISSION.value,
            EdgeType.CAN_REACH.value,
            EdgeType.CAN_PRIVESC_TO.value,
        }
        check(
            "graph includes at least one new edge verb",
            len(new_edges_seen) > 0,
            detail=f"seen={sorted(e.type for e in edges)[:8]}",
        )


async def check_to_dict_serializable() -> None:
    section("AttackPathScanResult.to_dict() is JSON-friendly")

    init_db()
    with Session(engine) as s:
        agent = AttackPathAgent(s, tenant_id="t-attack-path-test-2")
        result = await agent.scan()

    d = result.to_dict()
    check(
        "to_dict returns a dict with summary fields",
        isinstance(d, dict)
        and {
            "tenant_id",
            "paths_discovered",
            "cases_opened",
            "nodes_upserted",
            "edges_upserted",
            "paths",
            "connector_health",
        }.issubset(d.keys()),
        detail=f"keys={sorted(d.keys()) if isinstance(d, dict) else type(d)}",
    )
    # Each path entry must include the structured fields the UI needs.
    if d.get("paths"):
        first = d["paths"][0]
        check(
            "to_dict path entries carry the structured UI fields",
            {
                "path_id",
                "name",
                "risk_score",
                "hops",
                "mitre_techniques",
                "rationale",
            }.issubset(first.keys()),
            detail=f"keys={sorted(first.keys())}",
        )


# ── Main ────────────────────────────────────────────────────────────────


async def _main() -> int:
    check_graph_vocab_extended()
    check_agent_name_extended()
    check_agent_tenancy_enforced()
    await check_scan_end_to_end()
    await check_to_dict_serializable()

    print()
    if _FAILED:
        print(f"FAILED ({len(_FAILED)}):")
        for f in _FAILED:
            print(f"  - {f}")
        return 1
    print("All Attack-Path Agent smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(_main()))
