"""Smoke test for the memory tool registration + context-injection (t1m-tools).

Covers:
1. Every memory tool (scratchpad, episodic, graph) is registered with the
   expected risk class and ``needs:tenant`` / ``needs:case`` tags.
2. ``BaseAgent.call_tool`` automatically injects ``tenant_id`` and
   ``case_id`` from the agent — *overriding* anything the LLM tried to
   pass — before the audit trace is written. This is the hard tenancy
   boundary for memory operations.
3. A scratchpad write/read cycle works through the tool surface.
4. A graph upsert + neighbours traversal works through the tool surface
   and the traversal respects the agent's tenant (so a second agent on
   a different tenant cannot read the first tenant's graph).
5. Episodic record + recall round-trips through the tool surface.

Run with:
    cd platform/backend
    python -m tests._check_memory_tools
"""
from __future__ import annotations

import asyncio
import importlib
import os
import sys
import tempfile
from pathlib import Path


def _reset(env: dict[str, str] | None = None) -> None:
    """Force a fresh ``Settings`` + clean SQLite DB so tests are isolated.

    Mirrors the helper in ``_check_graph.py`` — we deliberately do *not*
    reload ``app.models.*`` (SQLModel registers tables in shared
    ``MetaData`` and re-registering raises).
    """
    tmp = Path(tempfile.mkdtemp(prefix="aisoc-memtools-"))
    db_path = tmp / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_SEED_ON_STARTUP"] = "false"
    # Skip HITL gating so destructive tests run inline.
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_HITL_SLA_SECONDS"] = "2"
    # Force in-process fallbacks for every memory backend so this test
    # is hermetic.
    for k in (
        "AISOC_GRAPH_BACKEND",
        "AISOC_EPISODIC_BACKEND",
        "AISOC_SCRATCHPAD_BACKEND",
        "AISOC_NEO4J_URI",
        "AISOC_REDIS_URL",
        "AISOC_QDRANT_URL",
    ):
        os.environ.pop(k, None)
    for k, v in (env or {}).items():
        os.environ[k] = v
    for mod in [
        "app.memory",
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


# Stand-in agent: smallest viable BaseAgent subclass so we can exercise
# ``call_tool`` without spinning up a full investigation. We override
# ``trace`` to a no-op so we don't need a real DB session bound to the
# agent_traces table for the unit slice; the call_tool dispatch logic
# is what we're verifying.
def _make_agent(*, tenant_id: str, case_id: int):
    from sqlmodel import Session

    from app.agents.base import BaseAgent
    from app.models.trace import AgentTrace
    from app.db import engine

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
            # Capture detail for assertions, but skip writing to the DB
            # so the test stays insulated from trace persistence.
            self.traces.append({"step": step, "summary": summary, "detail": detail or {}})
            t = AgentTrace(
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
            return t

    session = Session(engine)
    return _Probe(db=session, case_id=case_id, tenant_id=tenant_id)


def test_registry_shape() -> None:
    print("\n[1] All memory tools are registered with correct tags + risk class")
    _reset()
    # Ensure app.tools is imported so registration side-effects fire.
    import app.tools  # noqa: F401
    from app.tools.registry import registry
    from app.models.tool_call import RiskClass

    expected = {
        # name → (risk, needs_tenant, needs_case)
        "memory.scratchpad_set":   (RiskClass.WRITE_REVERSIBLE, False, True),
        "memory.scratchpad_get":   (RiskClass.READ,             False, True),
        "memory.scratchpad_all":   (RiskClass.READ,             False, True),
        "memory.episodic_recall":  (RiskClass.READ,             True,  False),
        # episodic_record is WRITE_SIGNIFICANT (not REVERSIBLE) by design:
        # once indexed, a memory can already have influenced downstream
        # recalls/LLM turns — there is no clean inverse.
        "memory.episodic_record":  (RiskClass.WRITE_SIGNIFICANT, True,  True),
        # graph upserts are WRITE_SIGNIFICANT (not REVERSIBLE) by design:
        # they are idempotent/additive and may already have been traversed
        # by downstream `graph.neighbors` calls — there is no clean inverse.
        "graph.upsert_node":       (RiskClass.WRITE_SIGNIFICANT, True,  False),
        "graph.upsert_edge":       (RiskClass.WRITE_SIGNIFICANT, True,  False),
        "graph.neighbors":         (RiskClass.READ,             True,  False),
        "graph.find_nodes":        (RiskClass.READ,             True,  False),
    }
    for name, (risk, needs_tenant, needs_case) in expected.items():
        td = registry.get(name)
        assert td is not None, f"{name} not registered"
        assert td.risk_class == risk, f"{name}: risk {td.risk_class} != {risk}"
        assert ("needs:tenant" in td.tags) == needs_tenant, (name, td.tags)
        assert ("needs:case" in td.tags) == needs_case, (name, td.tags)
        assert td.integration == "aisoc-memory", (name, td.integration)
    print(f"    ✓ {len(expected)} memory tools registered with correct shape")


def test_injection_overrides_llm_supplied_values() -> None:
    print("\n[2] BaseAgent.call_tool overrides LLM-supplied tenant_id / case_id")
    _reset()
    import app.tools  # noqa: F401

    agent = _make_agent(tenant_id="acme", case_id=42)

    async def go() -> dict:
        # Pretend the LLM tried to set a bogus tenant + bogus case. The
        # injection MUST clobber both before the handler runs.
        return await agent.call_tool(
            "memory.scratchpad_set",
            {
                "tenant_id": "evil-tenant",  # should be overwritten
                "case_id": 9999,             # should be overwritten
                "key": "hypothesis",
                "value": "C2 beacon from HR-42",
            },
        )

    result = asyncio.run(go())
    assert result.get("ok") is True, result

    # Confirm the trace recorded the *injected* values, not the LLM's
    # attempt — this is what makes the audit log trustworthy.
    #
    # `memory.scratchpad_set` is tagged `needs:case` only, so:
    #   - `case_id`   → injected from agent (LLM's 9999 clobbered to 42)
    #   - `tenant_id` → rejected entirely (handler does not declare it AND
    #     the tool is not tagged `needs:tenant`). This is the stronger
    #     security guarantee: the LLM cannot smuggle in a param a tool did
    #     not opt into, even if it picks a "harmless" name like tenant_id.
    last = agent.traces[-1]
    detail_params = last["detail"]["params"]
    rejected = last["detail"].get("rejected_params", {})
    assert detail_params["case_id"] == 42, detail_params
    assert "tenant_id" not in detail_params, detail_params
    assert rejected.get("tenant_id") == "evil-tenant", rejected

    # And the side-effect landed in the right tenant/case slot.
    from app.memory import scratchpad
    assert scratchpad.get(42, "hypothesis") == "C2 beacon from HR-42"
    # Bogus case (9999) MUST be empty because injection clobbered it.
    assert scratchpad.get(9999, "hypothesis") is None
    print(f"    ✓ injection overrode case_id; rejected smuggled tenant_id; trace + side-effect aligned")


def test_scratchpad_roundtrip_via_tool() -> None:
    print("\n[3] Scratchpad set → get → all round-trip through the tool surface")
    _reset()
    import app.tools  # noqa: F401

    agent = _make_agent(tenant_id="acme", case_id=7)

    async def go() -> tuple[dict, dict, dict]:
        a = await agent.call_tool(
            "memory.scratchpad_set", {"key": "verdict", "value": "true_positive"},
        )
        b = await agent.call_tool("memory.scratchpad_get", {"key": "verdict"})
        c = await agent.call_tool("memory.scratchpad_all", {})
        return a, b, c

    set_r, get_r, all_r = asyncio.run(go())
    assert set_r["ok"] is True
    assert get_r["found"] is True and get_r["value"] == "true_positive", get_r
    assert all_r["case_id"] == 7
    assert all_r["entries"].get("verdict") == "true_positive", all_r
    print(f"    ✓ scratchpad tools work end-to-end")


def test_graph_via_tool_is_tenant_scoped() -> None:
    print("\n[4] Graph upsert/neighbours through tool surface stay tenant-scoped")
    _reset()
    import app.tools  # noqa: F401

    acme = _make_agent(tenant_id="acme", case_id=1)
    other = _make_agent(tenant_id="other", case_id=1)

    async def go() -> tuple[dict, dict]:
        # acme writes a small graph slice.
        await acme.call_tool(
            "graph.upsert_node",
            {"type": "ioc", "key": "8.8.8.8", "label": "DNS"},
        )
        await acme.call_tool(
            "graph.upsert_node",
            {"type": "asset", "key": "HR-42", "label": "HR laptop"},
        )
        await acme.call_tool(
            "graph.upsert_edge",
            {
                "src_type": "ioc", "src_key": "8.8.8.8",
                "dst_type": "asset", "dst_key": "HR-42",
                "type": "observed_on",
            },
        )
        # acme should see HR-42 from 8.8.8.8.
        acme_view = await acme.call_tool(
            "graph.neighbors", {"type": "ioc", "key": "8.8.8.8", "depth": 1},
        )
        # other should see *nothing* — different tenant.
        other_view = await other.call_tool(
            "graph.neighbors", {"type": "ioc", "key": "8.8.8.8", "depth": 1},
        )
        return acme_view, other_view

    acme_view, other_view = asyncio.run(go())
    assert any(n["node"]["key"] == "HR-42" for n in acme_view["neighbors"]), acme_view
    assert other_view["neighbors"] == [], other_view
    print(f"    ✓ graph tools enforce tenant scope via injected tenant_id")


def test_episodic_record_and_recall_via_tool() -> None:
    print("\n[5] Episodic record → recall round-trip through tool surface")
    _reset()
    import app.tools  # noqa: F401

    agent = _make_agent(tenant_id="acme", case_id=3)

    async def go() -> tuple[dict, dict]:
        rec = await agent.call_tool(
            "memory.episodic_record",
            {
                "title": "SMB lateral movement from HR laptop",
                "narrative": (
                    "Contractor-owned HR-42 originated SMB probes against "
                    "PROD-DB-1; correlated with stolen creds reuse."
                ),
                "verdict": "true_positive",
                "tags": ["lateral-movement", "smb"],
            },
        )
        rec_r = await agent.call_tool(
            "memory.episodic_recall",
            {"query": "lateral movement via SMB from contractor", "k": 3},
        )
        return rec, rec_r

    rec, rec_r = asyncio.run(go())
    assert rec["ok"] is True
    hits = rec_r["hits"]
    assert hits, rec_r
    assert any(
        "SMB" in h.get("title", "") or "smb" in h.get("tags", [])
        for h in hits
    ), hits
    print(f"    ✓ episodic record/recall reachable as agent tools")


def main() -> int:
    print("== Smoke: memory tools registration + agent injection ==")
    tests = [
        test_registry_shape,
        test_injection_overrides_llm_supplied_values,
        test_scratchpad_roundtrip_via_tool,
        test_graph_via_tool_is_tenant_scoped,
        test_episodic_record_and_recall_via_tool,
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
    print("\n✓ All memory-tool smoke tests passed.")
    return 0


if __name__ == "__main__":
    # Ensure `app` is importable when running this file directly.
    ROOT = Path(__file__).resolve().parents[1]
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    sys.exit(main())
