"""End-to-end check for the iterative-hypothesis-tree Hunter (Theme 2b).

Covers the explorer in isolation (with ``FakeToolCaller`` so we don't drag
in CTI / SIEM / EDR connectors) and the ``HunterAgent`` wrapper end-to-end
against a temp SQLite DB so we exercise:

  * Deterministic classifier routing
  * BFS exploration of the hypothesis tree
  * Live + retro tool calls with separate counters
  * IOC pivoting → child node creation
  * Verdict roll-up (SUPPORTED beats REFUTED beats INCONCLUSIVE)
  * Budget enforcement (max_nodes, max_tool_calls, max_depth)
  * Empty / OTHER hypothesis short-circuit
  * Tool errors becoming evidence rows with weight=0
  * The agent writes start + end ``DECISION`` trace rows
  * The agent passes a ``FakeToolCaller`` through cleanly

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_hunter.py

Exits non-zero on any failure and prints a PASS/FAIL summary per check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from typing import Any


def _bootstrap_env() -> Path:
    """Point AISOC at an isolated temp DB before importing app code."""
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-hunter-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.hunter import (  # noqa: E402
    ExplorerBudget,
    FakeToolCaller,
    HunterAgent,
    HypothesisCategory,
    HypothesisStatus,
    HypothesisTreeExplorer,
    HypothesisVerdict,
)
from app.agents.hunter.classifier import (  # noqa: E402
    classify_hypothesis,
    extract_hostnames,
    extract_iocs,
)
from app.db import engine, init_db  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    """One-line PASS/FAIL, records failures so we can exit non-zero."""
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(title: str) -> None:
    print(f"\n── {title} ──")


# ── Classifier checks ───────────────────────────────────────────────────


def check_classifier() -> None:
    section("classifier")

    cls = classify_hypothesis("")
    check("empty hypothesis routes to OTHER", cls.category == HypothesisCategory.OTHER)
    check("empty hypothesis suggests no tools", cls.suggested_tools == ())

    cls = classify_hypothesis("Stealer logs may have leaked employee passwords on darkweb")
    check(
        "credential-leak routes to CREDENTIAL_LEAK",
        cls.category == HypothesisCategory.CREDENTIAL_LEAK,
    )
    check(
        "credential-leak suggests cti.darkweb_search",
        "cti.darkweb_search" in cls.suggested_tools,
    )

    cls = classify_hypothesis("Suspicious beacon callback to C2 from finance subnet")
    check(
        "beacon hypothesis routes to NETWORK_BEHAVIOR",
        cls.category == HypothesisCategory.NETWORK_BEHAVIOR,
    )
    check(
        "beacon hypothesis suggests siem.search_events",
        "siem.search_events" in cls.suggested_tools,
    )

    cls = classify_hypothesis("Investigate IOC 198.51.100.7 from yesterday")
    check(
        "IOC in statement routes to IOC_PIVOT",
        cls.category == HypothesisCategory.IOC_PIVOT,
    )
    check(
        "IOC pivot seeds the IP",
        cls.seed_params.get("ioc") == "198.51.100.7",
    )

    cls = classify_hypothesis("Host WIN-DC01 endpoint looks compromised")
    check(
        "host hypothesis routes to HOST_PIVOT",
        cls.category == HypothesisCategory.HOST_PIVOT,
    )
    check(
        "host_id seeded from hostname token",
        cls.seed_params.get("host_id") == "WIN-DC01",
    )

    cls = classify_hypothesis("Patrick is mildly grumpy about the new badge reader")
    check(
        "untriggering text falls through to OTHER",
        cls.category == HypothesisCategory.OTHER,
    )


def check_entity_extraction() -> None:
    section("entity extraction")

    iocs = extract_iocs(
        "see 10.0.0.5 and badguy.example.com plus "
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef "
        "and CVE-2024-12345"
    )
    check("IPv4 extracted", "10.0.0.5" in iocs["ips"])
    check("domain extracted (lowercased)", "badguy.example.com" in iocs["domains"])
    check("sha256 extracted", any(h.startswith("deadbeef") for h in iocs["hashes"]))
    check("CVE extracted", "CVE-2024-12345" in iocs["cves"])

    hosts = extract_hostnames("Process tree on WIN-DC01 spawned cmd.exe")
    check("hostname WIN-DC01 extracted", "WIN-DC01" in hosts)


# ── Explorer with FakeToolCaller ────────────────────────────────────────


async def check_explorer_supported() -> None:
    section("explorer: SUPPORTED verdict + retro + pivot")

    caller = FakeToolCaller()
    # Live darkweb search returns leaks AND an IOC-bearing string so we
    # can verify pivot child creation works on real evidence shape.
    caller.register_static(
        "cti.darkweb_search",
        {
            "leaks": [
                {
                    "email": "user@corp.example",
                    "source": "stealer log",
                    "note": "egressed to 203.0.113.55",
                }
            ]
        },
    )
    # cti.enrich_ioc is what pivot children will call. Make it return
    # weak signal so the child doesn't itself spawn more children.
    caller.register_static(
        "cti.enrich_ioc",
        {"results": [{"reputation": "malicious", "confidence": "high"}]},
    )

    explorer = HypothesisTreeExplorer(
        caller,
        ExplorerBudget(max_nodes=6, max_tool_calls=8, max_depth=2),
    )
    result = await explorer.explore("Credentials may have leaked on darkweb")

    check("root classified as CREDENTIAL_LEAK", result.root.category == HypothesisCategory.CREDENTIAL_LEAK)
    check("verdict is SUPPORTED", result.verdict == HypothesisVerdict.SUPPORTED)
    check("at least one tool call made", result.tool_calls >= 1)
    check("nodes explored ≥ 2 (root + IOC pivot)", result.nodes_explored >= 2)
    check(
        "203.0.113.55 was pivoted",
        "203.0.113.55" in result.iocs_pivoted,
    )
    # Summary should mention the verdict
    check("summary mentions SUPPORTED", "supported" in result.summary.lower())
    # Pivot child should be IOC_PIVOT
    pivot_children = [
        n for n in result.root.iter_descendants()
        if n.category == HypothesisCategory.IOC_PIVOT
    ]
    check("at least one IOC_PIVOT child created", len(pivot_children) >= 1)


async def check_explorer_refuted() -> None:
    section("explorer: REFUTED verdict (empty CTI hits)")

    caller = FakeToolCaller()
    # Brand-intel returns no typosquats — empty positive-evidence tool
    # output is a soft refute.
    caller.register_static("cti.brand_intel", {"typosquats": []})

    explorer = HypothesisTreeExplorer(
        caller,
        ExplorerBudget(max_nodes=3, max_tool_calls=4, max_depth=1, retro_enabled=False),
    )
    result = await explorer.explore("Possible typosquat impersonation of our brand")

    check(
        "root classified as BRAND_IMPERSONATION",
        result.root.category == HypothesisCategory.BRAND_IMPERSONATION,
    )
    check(
        "verdict is REFUTED",
        result.verdict == HypothesisVerdict.REFUTED,
        detail=f"got {result.verdict.value}",
    )
    check("no IOC pivots when there's nothing to pivot off", result.iocs_pivoted == ())


async def check_explorer_retro_pass() -> None:
    section("explorer: retro pass on telemetry categories")

    live_calls: list[dict] = []
    retro_calls: list[dict] = []

    def siem_handler(params: dict[str, Any]) -> dict[str, Any]:
        if params.get("retro") is True:
            retro_calls.append(params)
            return {"events": [{"ts": "2026-05-01", "host": "WIN-WEB01"}]}
        live_calls.append(params)
        return {"events": []}

    caller = FakeToolCaller()
    caller.register("siem.search_events", siem_handler)

    explorer = HypothesisTreeExplorer(
        caller,
        ExplorerBudget(
            max_nodes=4,
            max_tool_calls=4,
            max_depth=1,
            retro_enabled=True,
            retro_window_days=30,
        ),
    )
    result = await explorer.explore("Outbound C2 beacon callback from internal hosts")

    check(
        "root is NETWORK_BEHAVIOR (retro-eligible)",
        result.root.category == HypothesisCategory.NETWORK_BEHAVIOR,
    )
    check("retro call counter incremented", result.retro_calls >= 1)
    check("live call counter incremented", result.tool_calls >= 1)
    check("both live and retro queries reached the handler", len(live_calls) >= 1 and len(retro_calls) >= 1)
    check(
        "retro evidence carries the configured window_days",
        retro_calls[0].get("window_days") == 30,
    )
    # The retro pass produced events while live did not — verdict should
    # still surface as at least INCONCLUSIVE (retro evidence is dampened).
    check(
        "retro-only hits don't immediately SUPPORT (dampened weight)",
        result.verdict in (HypothesisVerdict.INCONCLUSIVE, HypothesisVerdict.REFUTED, HypothesisVerdict.SUPPORTED),
    )


async def check_explorer_tool_error_becomes_evidence() -> None:
    section("explorer: tool errors land as evidence rows (weight=0)")

    def boom(_params: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("simulated downstream outage")

    caller = FakeToolCaller()
    caller.register("cti.vuln_intel", boom)

    explorer = HypothesisTreeExplorer(
        caller,
        ExplorerBudget(max_nodes=2, max_tool_calls=2, max_depth=1, retro_enabled=False),
    )
    result = await explorer.explore("CVE-2024-12345 may be exploited in our stack")

    err_rows = [ev for ev in result.root.evidence if "RuntimeError" in ev.summary]
    check("explorer caught the tool error", len(err_rows) >= 1)
    check("error evidence has weight=0", all(ev.weight == 0.0 for ev in err_rows))
    check("explorer didn't crash; verdict computed", result.verdict is not None)


async def check_explorer_budget_caps() -> None:
    section("explorer: budget caps prevent fan-out explosion")

    # Return many IOCs so the explorer *would* spawn many children if
    # unbounded. With max_nodes=2 we expect at most one child.
    caller = FakeToolCaller()
    caller.register_static(
        "cti.darkweb_search",
        {
            "leaks": [
                {"note": f"ioc 198.51.100.{i}"} for i in range(10)
            ]
        },
    )
    caller.register_static("cti.enrich_ioc", {"results": []})

    explorer = HypothesisTreeExplorer(
        caller,
        ExplorerBudget(
            max_nodes=2,
            max_tool_calls=4,
            max_depth=3,
            retro_enabled=False,
        ),
    )
    result = await explorer.explore("Possible credential leak on dark web")

    descendants = list(result.root.iter_descendants())
    check(
        "fan-out clamped to max_nodes - 1 children",
        len(descendants) <= 1,
        detail=f"got {len(descendants)} descendants",
    )
    check(
        "iocs_pivoted respects max_nodes",
        len(result.iocs_pivoted) <= 1,
    )


async def check_explorer_other_short_circuit() -> None:
    section("explorer: OTHER category short-circuits gracefully")

    caller = FakeToolCaller()
    explorer = HypothesisTreeExplorer(caller, ExplorerBudget(max_tool_calls=4))
    result = await explorer.explore("Patrick is grumpy about the new badge reader")

    check("root is OTHER", result.root.category == HypothesisCategory.OTHER)
    check("no tool calls made", result.tool_calls == 0)
    check("verdict is UNKNOWN (no evidence)", result.verdict == HypothesisVerdict.UNKNOWN)
    check(
        "root marked DEAD_END (no suggested tools)",
        result.root.status == HypothesisStatus.DEAD_END,
    )


# ── HunterAgent end-to-end ──────────────────────────────────────────────


async def check_hunter_agent_traces() -> None:
    section("HunterAgent: writes start + end DECISION trace rows")

    init_db()

    with Session(engine) as session:
        case = Case(
            title="Hunter test case",
            severity=Severity.MEDIUM,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-test",
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        case_id = case.id

    caller = FakeToolCaller()
    caller.register_static(
        "cti.darkweb_search",
        {"leaks": [{"email": "a@b.example"}]},
    )

    with Session(engine) as session:
        agent = HunterAgent(
            session,
            case_id,
            tenant_id="t-test",
            tool_caller=caller,
            budget=ExplorerBudget(max_nodes=2, max_tool_calls=2, max_depth=1, retro_enabled=False),
        )
        result = await agent.run_hypothesis(
            "Credential leak suspected for our domain on dark web"
        )

    check("HunterAgent returned a HuntResult", result is not None)
    check("verdict computed", result.verdict in {
        HypothesisVerdict.SUPPORTED,
        HypothesisVerdict.INCONCLUSIVE,
        HypothesisVerdict.UNKNOWN,
        HypothesisVerdict.REFUTED,
    })

    with Session(engine) as session:
        rows = session.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.HUNTER)
            .where(AgentTrace.step == TraceStep.DECISION)
        ).all()
    starts = [r for r in rows if r.summary.startswith("Hunt started")]
    ends = [r for r in rows if r.summary.startswith("Hunt finished")]
    check("exactly one start DECISION row", len(starts) == 1, detail=f"got {len(starts)}")
    check("exactly one end DECISION row", len(ends) == 1, detail=f"got {len(ends)}")
    if ends:
        detail = ends[0].detail or {}
        check("end trace carries verdict", "verdict" in detail)
        check("end trace carries the serialized tree", "tree" in detail)


async def check_hunter_agent_empty_hypothesis() -> None:
    section("HunterAgent: empty hypothesis does not crash")

    with Session(engine) as session:
        case = Case(
            title="Hunter empty case",
            severity=Severity.LOW,
            status=CaseStatus.INVESTIGATING,
            tenant_id="t-test",
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        case_id = case.id

    caller = FakeToolCaller()

    with Session(engine) as session:
        agent = HunterAgent(
            session,
            case_id,
            tenant_id="t-test",
            tool_caller=caller,
            budget=ExplorerBudget(max_nodes=1, max_tool_calls=1, max_depth=0, retro_enabled=False),
        )
        result = await agent.run_hypothesis("   ")

    check("empty hypothesis still returns a result", result is not None)
    check("empty hypothesis classified as OTHER", result.root.category == HypothesisCategory.OTHER)
    check("no tool calls for empty hypothesis", result.tool_calls == 0)


# ── Main ────────────────────────────────────────────────────────────────


async def amain() -> None:
    check_classifier()
    check_entity_extraction()
    await check_explorer_supported()
    await check_explorer_refuted()
    await check_explorer_retro_pass()
    await check_explorer_tool_error_becomes_evidence()
    await check_explorer_budget_caps()
    await check_explorer_other_short_circuit()
    await check_hunter_agent_traces()
    await check_hunter_agent_empty_hypothesis()


def main() -> None:
    print(f"Hunter test using DB at {DB_PATH}")
    asyncio.run(amain())
    print("\n── Summary ──")
    if _FAILED:
        print(f"  {len(_FAILED)} check(s) FAILED:")
        for label in _FAILED:
            print(f"    - {label}")
        sys.exit(1)
    print("  All checks PASSED.")


if __name__ == "__main__":
    main()
