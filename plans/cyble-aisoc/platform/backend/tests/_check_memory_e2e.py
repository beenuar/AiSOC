"""End-to-end smoke test for the memory substrate (t1m-smoke).

This test stitches together everything Theme 1's memory work shipped:

* Scratchpad (Redis with in-process fallback).
* Episodic memory (Qdrant with SQLite fallback) backed by real embeddings
  with a hash-bag fallback.
* Threat graph (Neo4j with SQLModel fallback) populated by
  ``populate_from_alert`` / ``populate_from_ioc``.
* Agent tool surface (``BaseAgent.call_tool``) that injects tenant + case
  context.

The story we play out:

  1. Tenant "acme" has a *prior* resolved case sitting in episodic memory
     (the kind of historical context a real SOC accumulates).
  2. A *new* alert arrives. The ingestion path calls
     ``populate_from_alert``, mirroring entities into the threat graph.
  3. An investigator agent on tenant acme:
       a. writes its working hypothesis to the scratchpad,
       b. recalls similar past cases from episodic memory,
       c. walks the graph from the case node and reaches every entity the
          autopop pass put there (asset, user, IOCs, MITRE techniques,
          tooling),
       d. records a verdict back into episodic memory after closing.
  4. Tenant "globex" runs the same flow with its own alert and verifies
     that *none* of acme's substrate leaks across tenants — neither in
     scratchpad, episodic recall, nor graph neighbours.

If this passes, the memory substrate is wired correctly end-to-end and
the agent surface exercises it the same way a real Investigator would.

Run with::

    cd platform/backend
    python -m tests._check_memory_e2e
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sys
import tempfile
from pathlib import Path


# ── env / db plumbing (mirrors _check_memory_tools.py) ────────────────
def _reset() -> Path:
    """Force a fresh Settings + clean SQLite DB so each scenario is hermetic.

    We deliberately do NOT reload ``app.models.*`` — SQLModel registers
    tables in a shared ``MetaData``, and re-registering raises.
    """
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-mem-e2e-"))
    db_path = tmp / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_HITL_SLA_SECONDS"] = "2"
    # Drop any backend selectors lingering from a prior run so the
    # fallbacks engage.
    for k in (
        "AISOC_GRAPH_BACKEND",
        "AISOC_EPISODIC_BACKEND",
        "AISOC_SCRATCHPAD_BACKEND",
        "AISOC_NEO4J_URI",
        "AISOC_REDIS_URL",
        "AISOC_QDRANT_URL",
    ):
        os.environ.pop(k, None)
    for mod in [
        "app.memory",
        "app.memory.autopop",
        "app.memory.graph",
        "app.memory.episodic",
        "app.memory.embedding",
        "app.memory.scratchpad",
        "app.tools",
        "app.tools.memory",
        "app.tools.registry",
        "app.agents.base",
        "app.db",
        "app.config",
    ]:
        sys.modules.pop(mod, None)
    import app.config as config  # type: ignore

    importlib.reload(config)
    from app.db import init_db  # type: ignore

    init_db()
    return db_path


# ── lightweight agent stand-in ────────────────────────────────────────
def _make_agent(*, tenant_id: str, case_id: int):
    """Build the smallest viable BaseAgent so call_tool can dispatch.

    We override ``trace`` to capture details in-process so assertions
    don't need to round-trip through the agent_traces table.
    """
    from sqlmodel import Session

    from app.agents.base import BaseAgent
    from app.db import engine
    from app.models.trace import AgentTrace

    class _Probe(BaseAgent):
        name = "investigator"  # type: ignore[assignment]
        role = "test probe"
        allowed_tools: list[str] = []  # all tools

        def __init__(self, db: Session, case_id: int, tenant_id: str) -> None:
            super().__init__(db=db, case_id=case_id, tenant_id=tenant_id)
            self.traces: list[dict] = []

        def trace(  # type: ignore[override]
            self,
            step,
            summary,
            detail=None,
            tokens_in=0,
            tokens_out=0,
            latency_ms=0,
        ) -> AgentTrace:
            self.traces.append({"step": step, "summary": summary, "detail": detail or {}})
            return AgentTrace(
                case_id=self.case_id,
                tenant_id=self.tenant_id,
                agent=self.name,
                step=step,
                summary=summary,
                detail=detail or {},
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                latency_ms=latency_ms,
            )

    session = Session(engine)
    return _Probe(db=session, case_id=case_id, tenant_id=tenant_id)


def _make_alert(**overrides):
    """Build a representative Alert for autopopulation."""
    from app.models.alert import Alert  # type: ignore

    defaults: dict = dict(
        external_id="ext-e2e-1",
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
        file_hash="a" * 64,
        case_id=42,
    )
    defaults.update(overrides)
    return Alert(**defaults)


# ── 1. End-to-end happy path (single tenant) ──────────────────────────
def test_e2e_happy_path() -> None:
    print("\n[1] End-to-end: autopop → scratchpad → episodic recall → graph pivot → verdict")
    _reset()
    import app.tools  # noqa: F401  (registers memory tools)
    from app.memory import episodic_record, populate_from_alert

    # 1a. Pre-seed episodic memory with a *prior* similar case so the
    #     investigator has something to recall later. Real SOCs build
    #     this up over months; we materialise one row.
    episodic_record(
        tenant_id="acme",
        case_id=1,
        title="Prior lateral movement via psexec from HR laptop",
        narrative=(
            "Six months ago, HR-42 ran psexec against PROD-DB-1; "
            "verdict was true_positive; root cause was reused contractor creds."
        ),
        verdict="true_positive",
        tags=["lateral-movement", "psexec", "smb"],
    )

    # 1b. Pretend an alert just landed and ingestion called autopop.
    alert = _make_alert()
    summary = populate_from_alert(alert)
    assert summary["errors"] == [], summary
    assert len(summary["nodes"]) >= 7, summary  # case, asset, user, IOCs, tool, techniques

    agent = _make_agent(tenant_id="acme", case_id=42)

    async def go() -> dict:
        # 1c. Investigator drops working hypothesis into the scratchpad.
        await agent.call_tool(
            "memory.scratchpad_set",
            {"key": "hypothesis", "value": "psexec lateral move; possible contractor creds reuse"},
        )

        # 1d. Recall similar prior cases via the episodic tool.
        recall = await agent.call_tool(
            "memory.episodic_recall",
            {"query": "psexec lateral movement reused credentials", "k": 3},
        )

        # 1e. Pivot from the case node and check we can see the blast
        #     radius autopop produced.
        neighbours = await agent.call_tool(
            "graph.neighbors",
            {"type": "case", "key": "42", "depth": 1},
        )

        # 1f. Closing verdict — record into episodic for future agents.
        record = await agent.call_tool(
            "memory.episodic_record",
            {
                "title": "Lateral movement WS-7 → srv-db-01",
                "narrative": "Confirmed psexec lateral move; revoked alice's session.",
                "verdict": "true_positive",
                "tags": ["lateral-movement", "psexec", "contractor"],
            },
        )

        # 1g. Read scratchpad back through the tool — must still hold our
        #     working note.
        note = await agent.call_tool("memory.scratchpad_get", {"key": "hypothesis"})

        return {
            "recall": recall,
            "neighbours": neighbours,
            "record": record,
            "note": note,
        }

    out = asyncio.run(go())

    # — episodic recall surfaced the prior case
    recall_hits = out["recall"].get("hits") or []
    assert recall_hits, out["recall"]
    top_titles = [h.get("title", "") for h in recall_hits]
    assert any("psexec" in t.lower() or "lateral" in t.lower() for t in top_titles), top_titles

    # — graph neighbours reached every entity autopop materialised
    neigh_keys = {h["node"]["key"] for h in (out["neighbours"].get("neighbors") or [])}
    must_reach = {"WS-7", "acme\\alice", "ip:10.0.0.7", "ip:203.0.113.66", "psexec.exe", "T1021.001"}
    missing = must_reach - neigh_keys
    assert not missing, f"missing blast-radius hops: {missing} (saw {neigh_keys})"

    # — new verdict landed in episodic
    assert out["record"].get("ok") is True, out["record"]

    # — scratchpad note round-tripped through the tool surface
    assert out["note"].get("found") is True
    assert "psexec" in out["note"].get("value", ""), out["note"]

    print(
        f"    ✓ recall={len(recall_hits)} prior hit(s); "
        f"graph reached {len(must_reach)} required entities; scratchpad held"
    )


# ── 2. Cross-tenant isolation through the full substrate ─────────────
def test_cross_tenant_isolation() -> None:
    print("\n[2] Cross-tenant isolation: globex sees zero of acme's substrate")
    _reset()
    import app.tools  # noqa: F401
    from app.memory import episodic_record, populate_from_alert, scratchpad

    # acme builds out its substrate.
    acme_alert = _make_alert(tenant_id="acme", external_id="ext-A", case_id=100)
    populate_from_alert(acme_alert)
    episodic_record(
        tenant_id="acme",
        case_id=100,
        title="acme private lateral move",
        narrative="acme private context — globex must never see this.",
        verdict="true_positive",
        tags=["acme-only"],
    )
    scratchpad.set(case_id=100, key="secret", value="acme private working note")

    # globex builds its own substrate.
    globex_alert = _make_alert(
        tenant_id="globex",
        external_id="ext-B",
        case_id=200,
        src_host="GLOBEX-WS-1",
        src_user="globex\\bob",
        src_ip="10.1.0.5",
        dst_ip="198.51.100.7",
        file_hash="b" * 64,
        mitre_techniques=["T1059.001"],
    )
    populate_from_alert(globex_alert)
    episodic_record(
        tenant_id="globex",
        case_id=200,
        title="globex private powershell exec",
        narrative="globex private context — acme must never see this.",
        verdict="true_positive",
        tags=["globex-only"],
    )
    scratchpad.set(case_id=200, key="secret", value="globex private working note")

    globex_agent = _make_agent(tenant_id="globex", case_id=200)

    async def go() -> dict:
        # Try to recall — globex should only see its own row.
        recall = await globex_agent.call_tool(
            "memory.episodic_recall",
            {"query": "private context lateral movement", "k": 5},
        )
        # Try to pivot off acme's case 100 — should return nothing because
        # tenant injection rewrites the lookup scope to globex.
        acme_pivot = await globex_agent.call_tool(
            "graph.neighbors",
            {"type": "case", "key": "100", "depth": 2},
        )
        # Try to peek at acme's scratchpad slot — the tool is tagged
        # ``needs:case`` so the injected case_id is globex's, and the
        # storage is tenant-keyed under the hood.
        peek = await globex_agent.call_tool(
            "memory.scratchpad_get", {"key": "secret"},
        )
        return {"recall": recall, "acme_pivot": acme_pivot, "peek": peek}

    out = asyncio.run(go())

    # Episodic recall: every hit must be globex's tenant.
    hits = out["recall"].get("hits") or []
    tenants = {h.get("tenant_id") for h in hits}
    assert tenants <= {"globex"}, tenants
    assert all("acme-only" not in (h.get("tags") or []) for h in hits), hits

    # Graph: globex cannot resolve acme's case node — neighbours must be empty.
    assert (out["acme_pivot"].get("neighbors") or []) == [], out["acme_pivot"]

    # Scratchpad: globex's lookup hits globex's own slot, not acme's.
    # Since injection rewrites case_id to globex's 200, we get globex's note.
    found_value = out["peek"].get("value", "")
    assert "acme private" not in found_value, out["peek"]

    print(f"    ✓ episodic tenants={sorted(tenants)}; cross-tenant pivot empty; scratchpad isolated")


# ── 3. Idempotent replay through the agent surface ───────────────────
def test_idempotent_replay_through_agent_surface() -> None:
    print("\n[3] Re-ingesting the same alert through autopop does not duplicate graph rows")
    _reset()
    import app.tools  # noqa: F401
    from app.memory import populate_from_alert
    from app.memory.graph import graph_find_nodes

    alert = _make_alert(case_id=77)
    populate_from_alert(alert)
    first_iocs = len(graph_find_nodes(tenant_id="acme", type="ioc"))
    first_assets = len(graph_find_nodes(tenant_id="acme", type="asset"))

    # Replay (simulates the same alert arriving twice — connector
    # at-least-once or operator manual replay).
    populate_from_alert(alert)
    populate_from_alert(alert)
    second_iocs = len(graph_find_nodes(tenant_id="acme", type="ioc"))
    second_assets = len(graph_find_nodes(tenant_id="acme", type="asset"))

    assert first_iocs == second_iocs, (first_iocs, second_iocs)
    assert first_assets == second_assets, (first_assets, second_assets)

    # And through the agent tool surface, the case still reaches the
    # same blast radius (no phantom duplicate edges either).
    agent = _make_agent(tenant_id="acme", case_id=77)

    async def go() -> dict:
        return await agent.call_tool(
            "graph.neighbors", {"type": "case", "key": "77", "depth": 1},
        )

    neighbours = asyncio.run(go())
    keys = [h["node"]["key"] for h in (neighbours.get("neighbors") or [])]
    # Each entity must appear exactly once even after the triple replay.
    assert len(keys) == len(set(keys)), keys
    print(f"    ✓ {first_iocs} IOC / {first_assets} asset rows stable across 3 replays; neighbours unique")


# ── 4. Failure isolation: a broken graph backend does not break ingestion ──
def test_graph_failure_does_not_break_ingestion() -> None:
    print("\n[4] populate_from_alert / populate_from_ioc are best-effort")
    _reset()
    import app.tools  # noqa: F401
    from app.memory import autopop as autopop_mod
    from app.memory import populate_from_alert, populate_from_ioc
    from app.models.ioc import IOC, IOCType

    # Monkey-patch the graph upsert *inside autopop* — that is where
    # populate_from_alert / populate_from_ioc resolve them after the
    # `from app.memory.graph import graph_upsert_node, graph_upsert_edge`
    # at the top of autopop.py. Patching app.memory.graph directly would
    # be a no-op because autopop already bound the originals into its
    # own namespace at import time.
    def _boom(*_a, **_kw):
        raise RuntimeError("graph backend exploded (simulated)")

    autopop_mod.graph_upsert_node = _boom  # type: ignore[assignment]
    autopop_mod.graph_upsert_edge = _boom  # type: ignore[assignment]

    alert = _make_alert(case_id=999, external_id="ext-broken")
    out_alert = populate_from_alert(alert)
    # Must NOT raise. Errors are surfaced in the summary so a caller
    # *could* log them, but the call itself succeeded.
    assert out_alert["errors"], out_alert  # we expect captured errors
    assert out_alert["nodes"] == [], out_alert
    assert out_alert["edges"] == [], out_alert

    ioc = IOC(
        tenant_id="acme",
        value="broken.example.com",
        type=IOCType.DOMAIN,
        threat_score=10,
    )
    out_ioc = populate_from_ioc(ioc)
    assert out_ioc["errors"], out_ioc
    assert out_ioc["nodes"] == [], out_ioc
    print(f"    ✓ broken graph backend → ingestion still returns cleanly")


def main() -> int:
    print("== Smoke: memory substrate end-to-end ==")
    tests = [
        test_e2e_happy_path,
        test_cross_tenant_isolation,
        test_idempotent_replay_through_agent_surface,
        test_graph_failure_does_not_break_ingestion,
    ]
    failures: list[str] = []
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001 — smoke harness
            import traceback

            print(f"  [FAIL] {t.__name__}: {exc}")
            traceback.print_exc()
            failures.append(t.__name__)
    if failures:
        print(f"\n✗ {len(failures)} failure(s): {failures}")
        return 1
    print("\n✓ All memory-substrate smoke tests passed.")
    return 0


if __name__ == "__main__":
    ROOT = Path(__file__).resolve().parents[1]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    sys.exit(main())
