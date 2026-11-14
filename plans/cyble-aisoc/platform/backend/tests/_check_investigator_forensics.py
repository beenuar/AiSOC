"""End-to-end smoke test for live-forensics escalation (Theme 2j).

Verifies that when the Investigator's deterministic fallback runs against a
Windows host whose EDR telemetry is shallow, the deep-forensics escalation
path fires and ``forensics.collect_artifact`` is invoked through the
``MockForensicsConnector``.

We intentionally test ``_deterministic_investigate`` directly rather than
the full ``run()`` loop because the mock LLM provider uses keyword routing
and will almost always emit *some* tool call — making the "LLM declines to
act" fallback hard to trigger from the outside. The deterministic playbook
*is* the deep-forensics escalation surface, and it's the one we ship as the
safety net when an LLM is unavailable, so it's the contract worth pinning.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_investigator_forensics.py

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
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-investigator-forensics-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.investigator import (  # noqa: E402
    InvestigatorAgent,
    _deterministic_investigate,
)
from app.db import engine, init_db  # noqa: E402
from app.memory.scratchpad import scratchpad  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.case import Case, CaseStatus, Severity  # noqa: E402
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402


# ── Tiny test harness ───────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(title: str) -> None:
    print(f"\n── {title} ──")


# ── Helpers ─────────────────────────────────────────────────────────────


def _make_case(tenant_id: str = "t-test") -> int:
    with Session(engine) as session:
        case = Case(
            title="Investigator forensics smoke",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id=tenant_id,
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        return case.id  # type: ignore[return-value]


def _make_alert(
    case_id: int,
    *,
    src_host: str,
    process_name: str | None = "powershell.exe",
    tenant_id: str = "t-test",
) -> Alert:
    return Alert(
        external_id=f"ext-{case_id}-{src_host}",
        tenant_id=tenant_id,
        source="sentinelone",
        title="Suspicious encoded PowerShell on critical host",
        description="Encoded command line, parent=winword.exe",
        severity="high",
        detection_rule="rule.powershell.encoded",
        src_user="alice",
        src_host=src_host,
        src_ip="10.0.0.44",
        dst_ip="185.220.101.5",
        process_name=process_name,
        case_id=case_id,
    )


def _tool_results(case_id: int) -> list[dict]:
    return scratchpad.get(case_id, "tool_results", []) or []


def _tool_calls_in_trace(case_id: int) -> list[dict]:
    with Session(engine) as session:
        rows = session.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.INVESTIGATOR)
            .where(AgentTrace.step == TraceStep.TOOL_CALL)
        ).all()
    return [r.detail or {} for r in rows]


# ── Checks ──────────────────────────────────────────────────────────────


async def check_deep_forensics_fires_on_story_host() -> None:
    section("deterministic path: deep forensics fires on _STORY_HOST")

    init_db()
    case_id = _make_case()
    # MockForensicsConnector._STORY_HOST is "WIN-FIN-0044" — that's the
    # host the mock returns a non-empty pslist for, *and* the mock EDR's
    # get_process_tree comes back shallow for, which is exactly the
    # condition we want the escalation to fire on.
    alert = _make_alert(case_id, src_host="WIN-FIN-0044")

    with Session(engine) as session:
        session.add(alert)
        session.commit()
        session.refresh(alert)
        primary = alert

        agent = InvestigatorAgent(session, case_id, tenant_id="t-test")
        await _deterministic_investigate(agent, primary)

    results = _tool_results(case_id)
    tool_names = [r["tool"] for r in results]
    trace_tools = [
        d.get("tool") for d in _tool_calls_in_trace(case_id) if d.get("tool")
    ]

    check(
        "edr.get_process_tree was called (shallow EDR check)",
        "edr.get_process_tree" in tool_names,
        detail=f"saw: {tool_names}",
    )
    check(
        "asset.get_context was called (criticality check)",
        "asset.get_context" in tool_names,
        detail=f"saw: {tool_names}",
    )
    check(
        "forensics.collect_artifact was called (deep escalation)",
        "forensics.collect_artifact" in tool_names,
        detail=f"saw: {tool_names}",
    )
    check(
        "forensics.collect_artifact also recorded in trace",
        "forensics.collect_artifact" in trace_tools,
        detail=f"trace tools: {trace_tools}",
    )

    forensics_calls = [
        r for r in results if r["tool"] == "forensics.collect_artifact"
    ]
    check(
        "forensics call targeted the right host",
        any(
            (c.get("params") or {}).get("host") == "WIN-FIN-0044"
            for c in forensics_calls
        )
        # params live on the trace row, not the scratchpad result. Pull
        # from the trace too:
        or any(
            (d.get("params") or {}).get("host") == "WIN-FIN-0044"
            for d in _tool_calls_in_trace(case_id)
            if d.get("tool") == "forensics.collect_artifact"
        ),
        detail="host param not found on forensics.collect_artifact call",
    )
    check(
        "forensics call requested Generic.System.Pslist artifact",
        any(
            (d.get("params") or {}).get("artifact") == "Generic.System.Pslist"
            for d in _tool_calls_in_trace(case_id)
            if d.get("tool") == "forensics.collect_artifact"
        ),
        detail="artifact param not set to Generic.System.Pslist",
    )

    # Mock connector returns a non-empty row set for the story host.
    if forensics_calls:
        res = forensics_calls[0]["result"]
        rows = (
            res.get("rows")
            or res.get("row_count")
            or res.get("results")
            or []
        )
        check(
            "mock forensics returned a non-empty result for story host",
            bool(rows),
            detail=f"result keys: {list(res.keys())}",
        )


async def check_deep_forensics_skipped_when_no_host() -> None:
    section("deterministic path: alert with no src_host skips forensics")

    case_id = _make_case()
    alert = _make_alert(case_id, src_host=None)  # type: ignore[arg-type]
    # Alert.src_host is Optional[str]; force-None to model alerts that
    # come in keyed only on a user (e.g. dark-web hit, identity alert).
    alert.src_host = None

    with Session(engine) as session:
        session.add(alert)
        session.commit()
        session.refresh(alert)
        primary = alert

        agent = InvestigatorAgent(session, case_id, tenant_id="t-test")
        await _deterministic_investigate(agent, primary)

    tool_names = [r["tool"] for r in _tool_results(case_id)]
    check(
        "no edr.get_process_tree without a host",
        "edr.get_process_tree" not in tool_names,
        detail=f"saw: {tool_names}",
    )
    check(
        "no forensics.collect_artifact without a host",
        "forensics.collect_artifact" not in tool_names,
        detail=f"saw: {tool_names}",
    )
    # User-keyed alerts should still get dark-web context.
    check(
        "cti.darkweb_search still ran on the user",
        "cti.darkweb_search" in tool_names,
        detail=f"saw: {tool_names}",
    )


async def check_deep_forensics_handles_no_primary() -> None:
    section("deterministic path: None primary is a no-op")

    case_id = _make_case()
    with Session(engine) as session:
        agent = InvestigatorAgent(session, case_id, tenant_id="t-test")
        await _deterministic_investigate(agent, None)

    check(
        "no tool results when primary is None",
        _tool_results(case_id) == [],
    )


# ── Main ────────────────────────────────────────────────────────────────


async def amain() -> None:
    await check_deep_forensics_fires_on_story_host()
    await check_deep_forensics_skipped_when_no_host()
    await check_deep_forensics_handles_no_primary()

    print("\n" + "=" * 60)
    if _FAILED:
        print(f"FAILED: {len(_FAILED)} check(s)")
        for label in _FAILED:
            print(f"  - {label}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(amain())
