"""End-to-end smoke test for the multi-modal Reporter v2 (Theme 2k).

Verifies that ``build_case_report``:

1. Produces a structurally valid :class:`CaseReport` from canonical case
   tables (Case + Alert + AgentTrace + ToolCall + HitlRequest).
2. Composes a chronological timeline that includes alerts, high-signal
   trace steps, tool calls (forward + rollback), and HITL events.
3. Builds an attack graph that links hosts, users, IOCs, and processes
   from EDR ``edr.get_process_tree`` tool calls.
4. Aggregates an ATT&CK heatmap of tactic → technique counts pulled
   from both alert-level and case-level technique tags.
5. Computes a blast-radius map (hosts/users/iocs/actions/score) that
   correctly down-weights rolled-back actions.
6. Refuses to emit a report when the supplied ``tenant_id`` does not
   match the case row (defense-in-depth tenant isolation).
7. End-to-end via :class:`ReporterAgent`: confirm that the report is
   cached on the scratchpad and that a ``Multi-modal report built``
   trace step is recorded with non-empty stats.

Run from ``platform/backend/``:

    PYTHONPATH=. python tests/_check_multimodal_report.py

Exits non-zero on any failed check.
"""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _bootstrap_env() -> Path:
    tmpdir = Path(tempfile.mkdtemp(prefix="aisoc-multimodal-report-test-"))
    db_path = tmpdir / "aisoc.db"
    os.environ["AISOC_DB_PATH"] = str(db_path)
    os.environ["AISOC_AUTONOMY_LEVEL"] = "autonomous"
    os.environ["AISOC_LLM_PROVIDER"] = "mock"
    return db_path


DB_PATH = _bootstrap_env()
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlmodel import Session, select  # noqa: E402

from app.agents.reporter import ReporterAgent  # noqa: E402
from app.db import engine, init_db  # noqa: E402
from app.memory.scratchpad import scratchpad  # noqa: E402
from app.models.alert import Alert  # noqa: E402
from app.models.case import Case, CaseStatus, Severity, Verdict  # noqa: E402
from app.models.hitl import HitlChannel, HitlRequest, HitlState  # noqa: E402
from app.models.tool_call import RiskClass, ToolCall  # noqa: E402
from app.models.trace import AgentName, AgentTrace, TraceStep  # noqa: E402
from app.reports import build_case_report  # noqa: E402


# ── tiny harness ────────────────────────────────────────────────────────


_FAILED: list[str] = []


def check(label: str, ok: bool, *, detail: str = "") -> None:
    if ok:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}" + (f"  -- {detail}" if detail else ""))
        _FAILED.append(label)


def section(title: str) -> None:
    print(f"\n── {title} ──")


# ── fixture builder ─────────────────────────────────────────────────────


TENANT = "t-test"


def _seed_case_with_evidence() -> int:
    """Build a rich case row + child rows that exercise every panel.

    Returns the case id.
    """
    now = datetime.now(timezone.utc)

    with Session(engine) as session:
        case = Case(
            title="Encoded PowerShell on WIN-FIN-0044",
            severity=Severity.HIGH,
            status=CaseStatus.INVESTIGATING,
            tenant_id=TENANT,
            mitre_techniques=["T1059.001", "T1003"],  # case-level tags
            affected_hosts=["WIN-FIN-0044"],
            affected_users=["alice"],
            iocs=["185.220.101.5"],
        )
        session.add(case)
        session.commit()
        session.refresh(case)
        case_id = case.id  # type: ignore[assignment]

        # Two alerts so the heatmap aggregates counts correctly.
        a1 = Alert(
            external_id="ext-1",
            tenant_id=TENANT,
            source="sentinelone",
            title="Encoded PowerShell",
            description="powershell.exe -enc",
            severity="high",
            detection_rule="rule.powershell.encoded",
            src_user="alice",
            src_host="WIN-FIN-0044",
            src_ip="10.0.0.44",
            dst_ip="185.220.101.5",
            process_name="powershell.exe",
            mitre_tactics=["Execution"],
            mitre_techniques=["T1059.001"],
            case_id=case_id,
            created_at=now,
        )
        a2 = Alert(
            external_id="ext-2",
            tenant_id=TENANT,
            source="crowdstrike",
            title="LSASS access",
            description="Suspicious handle to lsass.exe",
            severity="high",
            detection_rule="rule.lsass.access",
            src_user="alice",
            src_host="WIN-FIN-0044",
            mitre_tactics=["Credential Access"],
            # Both alerts tag T1059.001 to verify the heatmap counts collapse.
            mitre_techniques=["T1003", "T1059.001"],
            case_id=case_id,
            created_at=now + timedelta(seconds=10),
        )
        session.add(a1)
        session.add(a2)

        # Trace rows — only DECISION / HANDOFF / HITL_REQUEST / ERROR
        # should make it onto the timeline. THINK is noise.
        for i, (step, summary) in enumerate(
            [
                (TraceStep.THINK, "thinking..."),  # filtered out
                (TraceStep.DECISION, "Escalating to deep forensics"),
                (TraceStep.HANDOFF, "→ Responder"),
            ]
        ):
            session.add(
                AgentTrace(
                    case_id=case_id,
                    tenant_id=TENANT,
                    agent=AgentName.INVESTIGATOR,
                    step=step,
                    summary=summary,
                    detail={"i": i},
                    created_at=now + timedelta(seconds=20 + i),
                )
            )

        # Tool calls: a forward write + its rollback, plus a couple of reads
        # including an EDR process tree (drives the attack graph).
        proc_tree_result = {
            "host": "WIN-FIN-0044",
            "tree": [
                {
                    "pid": 100,
                    "name": "winword.exe",
                    "children": [
                        {
                            "pid": 200,
                            "name": "powershell.exe",
                            "children": [
                                {"pid": 300, "name": "rundll32.exe"},
                            ],
                        }
                    ],
                }
            ],
        }
        tc_read = ToolCall(
            case_id=case_id,
            tenant_id=TENANT,
            agent=AgentName.INVESTIGATOR,
            tool_name="edr.get_process_tree",
            integration="crowdstrike",
            params={"host": "WIN-FIN-0044"},
            result=proc_tree_result,
            success=True,
            risk_class=RiskClass.READ,
            duration_ms=42,
            created_at=now + timedelta(seconds=30),
        )
        session.add(tc_read)
        session.commit()
        session.refresh(tc_read)

        tc_write = ToolCall(
            case_id=case_id,
            tenant_id=TENANT,
            agent=AgentName.RESPONDER,
            tool_name="edr.isolate_host",
            integration="crowdstrike",
            params={"host": "WIN-FIN-0044"},
            result={"isolated": True},
            success=True,
            risk_class=RiskClass.WRITE_SIGNIFICANT,
            duration_ms=120,
            created_at=now + timedelta(seconds=40),
        )
        session.add(tc_write)
        session.commit()
        session.refresh(tc_write)

        tc_rollback = ToolCall(
            case_id=case_id,
            tenant_id=TENANT,
            agent=AgentName.RESPONDER,
            tool_name="edr.unisolate_host",
            integration="crowdstrike",
            params={"host": "WIN-FIN-0044"},
            result={"unisolated": True},
            success=True,
            risk_class=RiskClass.WRITE_SIGNIFICANT,
            rollback_of_id=tc_write.id,
            duration_ms=80,
            created_at=now + timedelta(seconds=60),
        )
        session.add(tc_rollback)
        # Mark the forward call as rolled back too.
        tc_write.rolled_back_at = now + timedelta(seconds=60)
        tc_write.rolled_back_by = "analyst@cyble"
        session.add(tc_write)

        # HITL: one approved request.
        session.add(
            HitlRequest(
                case_id=case_id,
                tenant_id=TENANT,
                agent="responder",
                tool_name="edr.isolate_host",
                integration="crowdstrike",
                params={"host": "WIN-FIN-0044"},
                rationale="Confirmed C2 beacon from host",
                blast_radius={"hosts": ["WIN-FIN-0044"]},
                state=HitlState.APPROVED,
                risk_class="WRITE-SIGNIFICANT",
                expires_at=now + timedelta(minutes=15),
                decided_at=now + timedelta(seconds=39),
                decided_by="analyst@cyble",
                decided_channel=HitlChannel.CONSOLE,
                decision_reason="confirmed",
                created_at=now + timedelta(seconds=35),
            )
        )

        session.commit()
        return case_id


# ── checks ──────────────────────────────────────────────────────────────


def check_builder_panels() -> int:
    section("builder: report panels assemble from canonical tables")

    init_db()
    case_id = _seed_case_with_evidence()

    with Session(engine) as session:
        report = build_case_report(session, case_id=case_id, tenant_id=TENANT)

    # Stats sanity.
    stats = report.stats
    check(
        "stats.alerts == 2",
        stats.get("alerts") == 2,
        detail=f"stats={stats}",
    )
    check(
        "stats.tool_calls == 3",
        stats.get("tool_calls") == 3,
        detail=f"stats={stats}",
    )
    check(
        "stats.hitl_requests == 1",
        stats.get("hitl_requests") == 1,
        detail=f"stats={stats}",
    )
    check(
        "stats.timeline_events > 0",
        (stats.get("timeline_events") or 0) > 0,
        detail=f"stats={stats}",
    )

    # Timeline: THINK step should be filtered, DECISION + HANDOFF kept.
    timeline_kinds = [e.kind for e in report.timeline]
    trace_summaries = [e.summary for e in report.timeline if e.kind == "trace"]
    check(
        "timeline contains alert + trace + tool_call + hitl events",
        {"alert", "trace", "tool_call", "hitl"} <= set(timeline_kinds),
        detail=f"saw kinds: {sorted(set(timeline_kinds))}",
    )
    check(
        "timeline filters THINK noise but keeps DECISION/HANDOFF",
        "thinking..." not in trace_summaries
        and "Escalating to deep forensics" in trace_summaries
        and "→ Responder" in trace_summaries,
        detail=f"trace summaries: {trace_summaries}",
    )

    # Timeline ordering: must be chronologically ascending.
    timestamps = [e.timestamp for e in report.timeline if e.timestamp]
    check(
        "timeline events are chronologically ordered",
        timestamps == sorted(timestamps),
        detail="timeline not sorted ascending",
    )

    # Rollback surfaces with a rollback_of_id reference on a tool_call event.
    has_rollback_event = any(
        e.kind == "tool_call" and (e.detail or {}).get("rollback_of_id")
        for e in report.timeline
    )
    check(
        "timeline surfaces rollback tool calls",
        has_rollback_event,
        detail="no tool_call event carried rollback_of_id",
    )

    # Attack graph: should include the host, the user, the dst IP IOC,
    # and the process chain from the EDR process tree.
    graph = report.attack_graph
    node_labels = {n.label for n in graph.nodes}
    node_types = {n.kind for n in graph.nodes}
    check(
        "attack graph includes host node",
        "WIN-FIN-0044" in node_labels,
        detail=f"labels: {sorted(node_labels)[:10]}",
    )
    check(
        "attack graph includes user node",
        "alice" in node_labels,
        detail=f"labels: {sorted(node_labels)[:10]}",
    )
    check(
        "attack graph includes IOC node",
        "185.220.101.5" in node_labels,
        detail=f"labels: {sorted(node_labels)[:10]}",
    )
    check(
        "attack graph includes process node(s) from EDR tree",
        "process" in node_types,
        detail=f"types: {sorted(node_types)}",
    )
    check(
        "attack graph has at least one edge",
        len(graph.edges) > 0,
        detail=f"edges={len(graph.edges)}",
    )

    # Heatmap: T1059.001 appears in case tags AND both alerts → count should
    # collapse to a single cell with count >= 2 (we keep cells unique per
    # tactic/technique pair).
    heatmap = report.attack_heatmap
    techniques = [c.technique for c in heatmap.cells]
    check(
        "heatmap includes T1059.001 (Execution)",
        "T1059.001" in techniques,
        detail=f"cells: {[(c.tactic, c.technique, c.count) for c in heatmap.cells]}",
    )
    check(
        "heatmap includes T1003 (Credential Access)",
        "T1003" in techniques,
        detail=f"cells: {[(c.tactic, c.technique, c.count) for c in heatmap.cells]}",
    )
    # Count for T1059.001 should reflect *multiple* sources (case row +
    # alert 1 + alert 2). Exact value depends on builder semantics; assert
    # it's >= 2 to avoid pinning to an implementation detail while still
    # catching the "always 1" regression.
    t1059_cells = [c for c in heatmap.cells if c.technique == "T1059.001"]
    check(
        "heatmap aggregates T1059.001 from multiple sources",
        any(c.count >= 2 for c in t1059_cells),
        detail=f"T1059.001 cells: {[(c.tactic, c.count) for c in t1059_cells]}",
    )

    # Blast radius: the host appears (we touched it), user appears
    # (alerted), action count includes both the isolate AND its rollback,
    # and the rollback is flagged on the forward action so the UI can
    # render "reverted".
    blast = report.blast_radius
    check(
        "blast_radius.hosts includes WIN-FIN-0044",
        "WIN-FIN-0044" in blast.hosts,
        detail=f"hosts: {blast.hosts}",
    )
    check(
        "blast_radius.users includes alice",
        "alice" in blast.users,
        detail=f"users: {blast.users}",
    )
    isolate_actions = [
        a for a in blast.actions if a.get("tool_name") == "edr.isolate_host"
    ]
    check(
        "blast_radius.actions includes the isolate forward call",
        len(isolate_actions) >= 1,
        detail=f"actions: {[a.get('tool_name') for a in blast.actions]}",
    )
    check(
        "blast_radius reflects rollback on the forward isolate action",
        any(a.get("rolled_back") for a in isolate_actions),
        detail=f"isolate actions: {isolate_actions}",
    )
    # Score: we had a WRITE_HIGH action against a single host → expect >=2
    # (one significant write OR small set of assets).
    check(
        "blast_radius.score >= 2 (write_high present)",
        blast.score >= 2,
        detail=f"score={blast.score}",
    )

    return case_id


def check_builder_rejects_cross_tenant(case_id: int) -> None:
    section("builder: cross-tenant tenant_id is rejected")
    with Session(engine) as session:
        try:
            build_case_report(session, case_id=case_id, tenant_id="t-other")
        except PermissionError as exc:
            check(
                "build_case_report raises PermissionError on tenant mismatch",
                True,
                detail=str(exc),
            )
            return
        except Exception as exc:  # pragma: no cover
            check(
                "build_case_report raises PermissionError on tenant mismatch",
                False,
                detail=f"got {type(exc).__name__}: {exc}",
            )
            return
    check(
        "build_case_report raises PermissionError on tenant mismatch",
        False,
        detail="no exception raised",
    )


def check_builder_handles_missing_case() -> None:
    section("builder: missing case raises LookupError")
    with Session(engine) as session:
        try:
            build_case_report(session, case_id=999_999, tenant_id=TENANT)
        except LookupError as exc:
            check(
                "build_case_report raises LookupError on missing case",
                True,
                detail=str(exc),
            )
            return
        except Exception as exc:  # pragma: no cover
            check(
                "build_case_report raises LookupError on missing case",
                False,
                detail=f"got {type(exc).__name__}: {exc}",
            )
            return
    check(
        "build_case_report raises LookupError on missing case",
        False,
        detail="no exception raised",
    )


def check_report_is_json_safe(case_id: int) -> None:
    section("builder: to_dict() produces JSON-serializable output")
    import json

    with Session(engine) as session:
        report = build_case_report(session, case_id=case_id, tenant_id=TENANT)
    blob = report.to_dict()
    try:
        s = json.dumps(blob, default=str)
    except Exception as exc:  # pragma: no cover
        check("report.to_dict() is JSON-serializable", False, detail=str(exc))
        return
    check(
        "report.to_dict() is JSON-serializable",
        len(s) > 0 and '"timeline"' in s and '"attack_graph"' in s,
        detail=f"serialized {len(s)} bytes",
    )


async def check_reporter_agent_wires_report(case_id: int) -> None:
    section("ReporterAgent caches report on scratchpad + emits trace step")

    # Clear any prior cache entry so we know the agent wrote it fresh.
    scratchpad.set(case_id, "case_report", None)

    with Session(engine) as session:
        agent = ReporterAgent(session, case_id, tenant_id=TENANT)
        await agent.run()

    cached = scratchpad.get(case_id, "case_report", None)
    check(
        "scratchpad['case_report'] populated by Reporter",
        isinstance(cached, dict) and "timeline" in cached,
        detail=f"cached type={type(cached).__name__}",
    )

    with Session(engine) as session:
        rows = session.exec(
            select(AgentTrace)
            .where(AgentTrace.case_id == case_id)
            .where(AgentTrace.agent == AgentName.REPORTER)
            .where(AgentTrace.step == TraceStep.DECISION)
        ).all()
    summaries = [r.summary for r in rows]
    matching = [
        r for r in rows if r.summary and "Multi-modal report built" in r.summary
    ]
    check(
        "Reporter recorded a 'Multi-modal report built' DECISION trace",
        len(matching) >= 1,
        detail=f"reporter decision summaries: {summaries}",
    )
    if matching:
        stats = (matching[-1].detail or {}).get("report_stats") or {}
        check(
            "Reporter trace carries non-empty report_stats",
            isinstance(stats, dict) and stats.get("alerts", 0) >= 1,
            detail=f"stats={stats}",
        )


# ── main ────────────────────────────────────────────────────────────────


async def amain() -> None:
    case_id = check_builder_panels()
    check_builder_rejects_cross_tenant(case_id)
    check_builder_handles_missing_case()
    check_report_is_json_safe(case_id)
    await check_reporter_agent_wires_report(case_id)

    print("\n" + "=" * 60)
    if _FAILED:
        print(f"FAILED: {len(_FAILED)} check(s)")
        for label in _FAILED:
            print(f"  - {label}")
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    asyncio.run(amain())
