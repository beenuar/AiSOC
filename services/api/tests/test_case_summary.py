"""Tests for WS-D2 — per-case auto-summary builder + HTML renderer.

Mirrors the structure of ``test_executive_digest`` so the two artefacts stay
consistent: pure builder gets exercised against deterministic input rows, and
the HTML renderer is verified end-to-end for structure + safe escaping.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.services.case_summary import (
    CaseSummaryInputs,
    SummaryCaseRow,
    SummaryCommentRow,
    SummaryTaskRow,
    _internal_helpers,
    build_summary_from_rows,
)
from app.services.case_summary_html import render_case_summary_html

OPENED = datetime(2026, 5, 2, 10, 0, tzinfo=UTC)
NOW = datetime(2026, 5, 9, 12, 0, tzinfo=UTC)
CASE_ID = uuid.uuid4()


def _case(
    *,
    severity: str = "high",
    status: str = "resolved",
    opened_at: datetime | None = None,
    triaged_at: datetime | None = None,
    resolved_at: datetime | None = None,
    closed_at: datetime | None = None,
    sla_due_at: datetime | None = None,
    title: str = "Suspected ransomware",
    description: str | None = "Initial ransomware indicators on FIN-LAPTOP-04",
    assignee: str | None = "alice@example.com",
    created_by: str | None = "alert-fusion",
    mitre_techniques: list[str] | None = None,
    alert_ids: list[str] | None = None,
    observable_graph: dict[str, object] | None = None,
    evidence_chain: list[object] | None = None,
    compliance_frameworks: list[str] | None = None,
    tags: dict[str, object] | None = None,
    case_number: str | None = "CASE-2026-0042",
) -> SummaryCaseRow:
    open_ts = opened_at or OPENED
    return SummaryCaseRow(
        id=CASE_ID,
        case_number=case_number,
        title=title,
        description=description,
        severity=severity,
        status=status,
        assignee=assignee,
        created_by=created_by,
        tags=tags or {},
        mitre_techniques=list(mitre_techniques or []),
        alert_ids=list(alert_ids or []),
        observable_graph=observable_graph or {},
        evidence_chain=list(evidence_chain or []),
        compliance_frameworks=list(compliance_frameworks or []),
        opened_at=open_ts,
        triaged_at=triaged_at,
        resolved_at=resolved_at,
        closed_at=closed_at,
        sla_due_at=sla_due_at,
        created_at=open_ts,
        updated_at=closed_at or resolved_at or triaged_at or open_ts,
    )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_hours_between_handles_missing_endpoints() -> None:
    fn = _internal_helpers["_hours_between"]
    assert fn(None, OPENED) is None
    assert fn(OPENED, None) is None
    assert fn(OPENED + timedelta(hours=3), OPENED) == 3.0


def test_bucket_techniques_groups_known_and_unknowns() -> None:
    fn = _internal_helpers["_bucket_techniques"]
    buckets = fn(["T1059.001", "T1059", "T1486", "T9999", "junk"])
    # Two execution entries (sub-tech + parent), one impact, two unknowns.
    assert buckets["Execution"] == 2
    assert buckets["Impact"] == 1
    assert buckets["Other"] == 2


def test_summarise_observables_counts_kinds() -> None:
    fn = _internal_helpers["_summarise_observables"]
    summary = fn(
        {
            "nodes": [
                {"kind": "host"},
                {"kind": "host"},
                {"kind": "user"},
                {"type": "ip"},  # tolerate "type" alias
                "garbage",  # tolerate junk
            ],
            "edges": [{"src": 1, "dst": 2}, {"src": 2, "dst": 3}],
        }
    )
    assert summary.total_nodes == 5
    assert summary.total_edges == 2
    assert summary.node_kind_counts["host"] == 2
    assert "ip" in summary.distinct_kinds


def test_summarise_evidence_counts_kinds() -> None:
    fn = _internal_helpers["_summarise_evidence"]
    summary = fn(
        [
            {"kind": "file_hash"},
            {"kind": "file_hash"},
            {"kind": "memory_dump"},
            "junk",
        ]
    )
    assert summary.total_items == 4
    assert summary.distinct_kinds == ["file_hash", "memory_dump"]


def test_summarise_tasks_handles_overdue_and_status_counts() -> None:
    fn = _internal_helpers["_summarise_tasks"]
    rows = [
        SummaryTaskRow(
            title="Contain host",
            status="todo",
            assignee=None,
            due_at=NOW - timedelta(hours=1),
            created_at=OPENED,
            updated_at=OPENED,
        ),
        SummaryTaskRow(
            title="Pull memory",
            status="in_progress",
            assignee=None,
            due_at=NOW + timedelta(hours=2),
            created_at=OPENED,
            updated_at=OPENED,
        ),
        SummaryTaskRow(
            title="Reset password",
            status="done",
            assignee=None,
            due_at=NOW - timedelta(hours=2),  # done tasks aren't overdue
            created_at=OPENED,
            updated_at=OPENED,
        ),
    ]
    summary = fn(rows, now=NOW)
    assert summary.total == 3
    assert summary.todo == 1
    assert summary.in_progress == 1
    assert summary.done == 1
    assert summary.overdue == 1


def test_summarise_comments_separates_system_and_authors() -> None:
    fn = _internal_helpers["_summarise_comments"]
    rows = [
        SummaryCommentRow(author="alice", body="Looking", is_system=False, created_at=OPENED),
        SummaryCommentRow(author="bob", body="Joining", is_system=False, created_at=OPENED),
        SummaryCommentRow(author=None, body="auto", is_system=True, created_at=OPENED),
    ]
    summary = fn(rows)
    assert summary.total == 3
    assert summary.analyst == 2
    assert summary.system == 1
    assert summary.distinct_authors == ["alice", "bob"]


def test_build_timeline_caps_to_limit_but_keeps_lifecycle() -> None:
    fn = _internal_helpers["_build_timeline"]
    case = _case(
        triaged_at=OPENED + timedelta(hours=1),
        resolved_at=OPENED + timedelta(hours=4),
        closed_at=OPENED + timedelta(hours=5),
    )
    comments = [
        SummaryCommentRow(
            author=f"a{i}",
            body=f"note {i}",
            is_system=False,
            created_at=OPENED + timedelta(minutes=i),
        )
        for i in range(50)
    ]
    timeline = fn(case, comments, [], limit=10)
    assert len(timeline) == 10
    # All 4 lifecycle events must survive truncation.
    lifecycle_kinds = sum(1 for e in timeline if e.kind == "case")
    assert lifecycle_kinds == 4


def test_build_recommendations_sla_breach_triggers_warning() -> None:
    fn = _internal_helpers["_build_recommendations"]
    from app.services.case_summary import (
        CaseLifecycleTimings,
        CommentBreakdown,
        CoverageSummary,
        TaskBreakdown,
    )

    case = _case(severity="critical")
    lifecycle = CaseLifecycleTimings(
        opened_at=OPENED,
        sla_due_at=OPENED + timedelta(hours=2),
        resolved_at=OPENED + timedelta(hours=5),
        sla_breached=True,
    )
    recs = fn(
        case,
        lifecycle,
        TaskBreakdown(),
        CommentBreakdown(),
        CoverageSummary(),
    )
    assert any("SLA" in r.title for r in recs)


# ---------------------------------------------------------------------------
# Pure top-level builder
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline_inputs() -> CaseSummaryInputs:
    case = _case(
        triaged_at=OPENED + timedelta(hours=1),
        resolved_at=OPENED + timedelta(hours=6),
        closed_at=OPENED + timedelta(hours=8),
        sla_due_at=OPENED + timedelta(hours=4),  # breach: resolved at +6h
        mitre_techniques=["T1486", "T1059.001", "T1003"],
        alert_ids=[str(uuid.uuid4()) for _ in range(3)],
        observable_graph={
            "nodes": [{"kind": "host"}, {"kind": "user"}, {"kind": "user"}],
            "edges": [{"src": 0, "dst": 1}],
        },
        evidence_chain=[{"kind": "file_hash"}, {"kind": "memory_dump"}],
        compliance_frameworks=["SOC2", "ISO27001"],
    )
    comments = [
        SummaryCommentRow(
            author="alice",
            body="Containing the host",
            is_system=False,
            created_at=OPENED + timedelta(minutes=15),
        ),
        SummaryCommentRow(
            author=None,
            body="Auto-triage routed to playbook PB-001",
            is_system=True,
            created_at=OPENED + timedelta(minutes=5),
        ),
    ]
    tasks = [
        SummaryTaskRow(
            title="Isolate host",
            status="done",
            assignee="alice",
            due_at=OPENED + timedelta(hours=1),
            created_at=OPENED,
            updated_at=OPENED + timedelta(hours=1),
        ),
        SummaryTaskRow(
            title="Reset credentials",
            status="todo",
            assignee=None,
            due_at=OPENED - timedelta(hours=1),  # already overdue
            created_at=OPENED,
            updated_at=OPENED,
        ),
    ]
    return CaseSummaryInputs(case=case, comments=comments, tasks=tasks)


def test_build_summary_basic_shape(baseline_inputs: CaseSummaryInputs) -> None:
    summary = build_summary_from_rows(baseline_inputs, now=NOW)

    assert summary.case.case_id == CASE_ID
    assert summary.case.case_number == "CASE-2026-0042"
    assert summary.case.severity == "high"

    # Lifecycle.
    assert summary.lifecycle.time_to_triage_hours == 1.0
    assert summary.lifecycle.time_to_resolve_hours == 6.0
    assert summary.lifecycle.time_to_close_hours == 8.0
    assert summary.lifecycle.sla_breached is True

    # Coverage.
    assert summary.coverage.mitre_techniques == ["T1486", "T1059.001", "T1003"]
    assert summary.coverage.compliance_frameworks == ["SOC2", "ISO27001"]
    # Tactic buckets should bucket T1486 → Impact, T1059.001 → Execution, T1003 → Credential Access.
    assert summary.coverage.mitre_tactic_buckets["Impact"] == 1
    assert summary.coverage.mitre_tactic_buckets["Execution"] == 1
    assert summary.coverage.mitre_tactic_buckets["Credential Access"] == 1

    # Activity counts.
    assert summary.tasks.total == 2
    assert summary.tasks.done == 1
    assert summary.tasks.todo == 1
    assert summary.tasks.overdue == 1
    assert summary.comments.analyst == 1
    assert summary.comments.system == 1

    # Alerts.
    assert summary.alerts["count"] == 3

    # Observables / evidence.
    assert summary.observables.total_nodes == 3
    assert summary.evidence.total_items == 2

    # Timeline non-empty + sorted.
    assert summary.timeline
    timestamps = [e.ts for e in summary.timeline]
    assert timestamps == sorted(timestamps)


def test_build_summary_recommends_when_sla_breached(baseline_inputs: CaseSummaryInputs) -> None:
    summary = build_summary_from_rows(baseline_inputs, now=NOW)
    titles = [r.title for r in summary.recommendations]
    assert any("SLA" in t for t in titles)
    assert any("overdue" in t.lower() for t in titles)


def test_build_summary_minimal_inputs_returns_neutral_recommendation() -> None:
    case = _case(
        status="closed",
        severity="low",
        triaged_at=OPENED + timedelta(minutes=5),
        resolved_at=OPENED + timedelta(minutes=20),
        closed_at=OPENED + timedelta(minutes=25),
        sla_due_at=None,
        mitre_techniques=["T1078"],
    )
    summary = build_summary_from_rows(CaseSummaryInputs(case=case), now=NOW)
    assert summary.recommendations
    # With nothing concerning, we get the neutral "case closed cleanly" rec.
    assert any("cleanly" in r.title.lower() for r in summary.recommendations)


def test_build_summary_is_deterministic(baseline_inputs: CaseSummaryInputs) -> None:
    a = build_summary_from_rows(baseline_inputs, now=NOW).model_dump_json()
    b = build_summary_from_rows(baseline_inputs, now=NOW).model_dump_json()
    assert a == b


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


def test_render_case_summary_html_contains_sections(baseline_inputs: CaseSummaryInputs) -> None:
    summary = build_summary_from_rows(baseline_inputs, now=NOW)
    html = render_case_summary_html(summary)

    assert "<!DOCTYPE html>" in html
    assert "AiSOC case auto-summary" in html
    assert "Lifecycle" in html
    assert "MITRE ATT&amp;CK techniques" in html
    assert "Compliance frameworks" in html
    assert "Evidence" in html
    assert "Activity" in html
    assert "Timeline" in html
    assert "Post-mortem" in html


def test_render_case_summary_html_escapes_user_data() -> None:
    case = _case(
        title="<script>alert('xss')</script>",
        description="<img src=x onerror=alert(1)>",
        severity="critical",
    )
    summary = build_summary_from_rows(CaseSummaryInputs(case=case), now=NOW)
    html = render_case_summary_html(summary)

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
    assert "<img src=x" not in html
