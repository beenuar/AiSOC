"""Tests for Stage 3 #21 — auto post-mortem builder + HTML renderer.

Mirrors ``test_case_summary.py`` so the two retrospectives stay siblings:
the pure builder is exercised against deterministic fixtures, then the HTML
renderer is verified end-to-end for structure + safe escaping.

The post-mortem is *blameless* — analyst names should never appear in the
rendered timeline or recommendation copy. Several tests guard that
property explicitly.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.services.case_postmortem import (
    CasePostmortem,
    PostmortemInputs,
    SummaryCaseRow,
    SummaryCommentRow,
    SummaryTaskRow,
    _internal_helpers,
    build_postmortem_from_rows,
)
from app.services.case_postmortem_html import render_case_postmortem_html

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
    assert fn(OPENED + timedelta(hours=2, minutes=30), OPENED) == 2.5


def test_bucket_response_action_classifies_keywords() -> None:
    fn = _internal_helpers["_bucket_response_action"]
    assert fn("Isolate the host immediately") == "containment"
    assert fn("Reset password for compromised user") == "eradication"
    assert fn("Restore the database from backup") == "recovery"
    assert fn("Notify the customer success team") == "communication"
    assert fn("Investigate the lateral movement path") == "investigation"
    # Empty / unknown → "other".
    assert fn("") == "other"
    assert fn("Send carrier pigeon") == "other"


def test_first_analyst_touch_skips_system_comments() -> None:
    fn = _internal_helpers["_first_analyst_touch"]
    rows = [
        SummaryCommentRow(
            author=None,
            body="auto-triage",
            is_system=True,
            created_at=OPENED + timedelta(minutes=1),
        ),
        SummaryCommentRow(
            author="alice",
            body="Looking",
            is_system=False,
            created_at=OPENED + timedelta(minutes=15),
        ),
        SummaryCommentRow(
            author="bob",
            body="Joining",
            is_system=False,
            created_at=OPENED + timedelta(minutes=30),
        ),
    ]
    assert fn(rows) == OPENED + timedelta(minutes=15)
    # No analyst comments at all → None.
    assert fn([rows[0]]) is None
    assert fn([]) is None


def test_summarise_response_buckets_and_overdue() -> None:
    fn = _internal_helpers["_summarise_response"]
    tasks = [
        SummaryTaskRow(
            title="Isolate FIN-LAPTOP-04",
            status="done",
            assignee="alice",
            due_at=OPENED + timedelta(hours=1),
            created_at=OPENED,
            updated_at=OPENED + timedelta(hours=1),
        ),
        SummaryTaskRow(
            title="Reset password for finance user",
            status="todo",
            assignee=None,
            due_at=NOW - timedelta(hours=1),  # overdue
            created_at=OPENED,
            updated_at=OPENED,
        ),
        SummaryTaskRow(
            title="Run containment playbook PB-014",
            status="done",
            assignee="alice",
            due_at=OPENED + timedelta(hours=2),
            created_at=OPENED,
            updated_at=OPENED + timedelta(hours=2),
        ),
    ]
    summary = fn(tasks, now=NOW)
    assert summary.total_actions == 3
    assert summary.completed == 2
    assert summary.open == 1
    assert summary.overdue == 1
    assert summary.automation_used is True  # "playbook" hit

    bucket_names = {a.bucket for a in summary.actions_by_bucket}
    assert "containment" in bucket_names
    assert "eradication" in bucket_names


def test_build_detection_flags_sla_breach_when_resolved_late() -> None:
    fn = _internal_helpers["_build_detection"]
    case = _case(
        sla_due_at=OPENED + timedelta(hours=2),
        resolved_at=OPENED + timedelta(hours=5),
        triaged_at=OPENED + timedelta(hours=1),
    )
    detection = fn(case, [], now=NOW)
    assert detection.sla_breached is True
    assert detection.time_to_triage_hours == 1.0
    assert detection.time_to_resolve_hours == 5.0


def test_build_detection_gaps_warns_on_slow_first_touch() -> None:
    fn = _internal_helpers["_build_detection_gaps"]
    case = _case(mitre_techniques=["T1059"])
    from app.services.case_postmortem import DetectionTiming

    detection = DetectionTiming(
        opened_at=OPENED,
        first_analyst_touch_at=OPENED + timedelta(hours=6),
        time_to_detect_hours=6.0,
        time_to_triage_hours=2.0,
        sla_breached=False,
    )
    gaps = fn(detection, case)
    assert any("First analyst touch" in g.title for g in gaps)
    # No SLA breach, so no critical-tier SLA gap.
    assert not any(g.severity == "critical" for g in gaps)


def test_build_timeline_strips_authors_and_keeps_lifecycle() -> None:
    fn = _internal_helpers["_build_timeline"]
    case = _case(
        triaged_at=OPENED + timedelta(hours=1),
        resolved_at=OPENED + timedelta(hours=4),
        closed_at=OPENED + timedelta(hours=5),
    )
    comments = [
        SummaryCommentRow(
            author="alice",
            body="Manually isolating the host",
            is_system=False,
            created_at=OPENED + timedelta(minutes=10),
        ),
        SummaryCommentRow(
            author=None,
            body="Auto-triage routed via PB-014",
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
            created_at=OPENED + timedelta(minutes=15),
            updated_at=OPENED + timedelta(hours=1),
        ),
    ]
    timeline = fn(case, comments, tasks, limit=30)

    assert timeline, "timeline should not be empty"
    timestamps = [e.ts for e in timeline]
    assert timestamps == sorted(timestamps)

    # Lifecycle anchors must all survive.
    labels = {e.label for e in timeline}
    assert "Case opened" in labels
    assert "Triaged" in labels
    assert "Resolved" in labels
    assert "Closed" in labels

    # Blameless: no author names anywhere in the rendered fields.
    blob = " ".join(e.label + " " + (e.detail or "") for e in timeline)
    assert "alice" not in blob.lower()


def test_build_timeline_caps_to_limit_but_keeps_lifecycle() -> None:
    fn = _internal_helpers["_build_timeline"]
    case = _case(
        triaged_at=OPENED + timedelta(hours=1),
        resolved_at=OPENED + timedelta(hours=4),
        closed_at=OPENED + timedelta(hours=5),
    )
    comments = [
        SummaryCommentRow(
            author=None,
            body=f"system note {i}",
            is_system=True,
            created_at=OPENED + timedelta(minutes=i + 10),
        )
        for i in range(50)
    ]
    timeline = fn(case, comments, [], limit=10)
    assert len(timeline) == 10
    # Lifecycle phases (4 events) must all survive truncation.
    lifecycle_phases = {"detection", "triage", "resolution", "closure"}
    survived = sum(1 for e in timeline if e.phase in lifecycle_phases)
    assert survived == 4


def test_build_went_well_rewards_fast_high_severity_resolution() -> None:
    fn = _internal_helpers["_build_went_well"]
    case = _case(severity="high")
    from app.services.case_postmortem import DetectionTiming, ResponseEffectiveness

    detection = DetectionTiming(
        opened_at=OPENED,
        first_analyst_touch_at=OPENED + timedelta(minutes=12),
        time_to_detect_hours=0.2,
        time_to_resolve_hours=2.0,
        sla_breached=False,
        sla_due_at=OPENED + timedelta(hours=4),
    )
    response = ResponseEffectiveness(
        total_actions=2,
        completed=2,
        open=0,
        overdue=0,
        automation_used=True,
    )
    items = fn(case, detection, response)
    titles = " ".join(i.title for i in items)
    assert "Fast first analyst engagement" in titles
    assert "Fast resolution" in titles
    assert "Automation engaged" in titles
    assert "All response actions closed" in titles
    assert "SLA met" in titles


def test_build_fell_short_calls_out_high_severity_with_no_analyst_note() -> None:
    fn = _internal_helpers["_build_fell_short"]
    case = _case(severity="critical")
    from app.services.case_postmortem import DetectionTiming, ResponseEffectiveness

    detection = DetectionTiming(opened_at=OPENED, sla_breached=False)
    response = ResponseEffectiveness()
    items = fn(case, detection, response, [])
    titles = " ".join(i.title for i in items)
    assert "No analyst narrative" in titles
    assert "No tracked response actions" in titles
    assert "MITRE ATT&CK coverage missing" in titles


def test_build_action_items_returns_neutral_when_clean() -> None:
    fn = _internal_helpers["_build_action_items"]
    case = _case(mitre_techniques=["T1078"])
    from app.services.case_postmortem import DetectionTiming, ResponseEffectiveness

    detection = DetectionTiming(
        opened_at=OPENED,
        time_to_detect_hours=0.1,
        time_to_triage_hours=0.5,
        time_to_resolve_hours=1.0,
        sla_breached=False,
    )
    response = ResponseEffectiveness(total_actions=2, completed=2, automation_used=True)
    items = fn(case, detection, response, [], [])
    assert len(items) == 1
    assert "No structural follow-ups" in items[0].title


# ---------------------------------------------------------------------------
# Pure top-level builder
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline_inputs() -> PostmortemInputs:
    case = _case(
        triaged_at=OPENED + timedelta(hours=1),
        resolved_at=OPENED + timedelta(hours=6),
        closed_at=OPENED + timedelta(hours=8),
        sla_due_at=OPENED + timedelta(hours=4),  # breach: resolved at +6h
        mitre_techniques=["T1486", "T1059.001"],
        alert_ids=[str(uuid.uuid4()) for _ in range(3)],
        observable_graph={
            "nodes": [
                {"kind": "host"},
                {"kind": "user"},
                {"kind": "user"},
                {"kind": "domain", "value": "evil.example.com"},
            ],
            "edges": [{"src": 0, "dst": 1}],
        },
        evidence_chain=[{"kind": "file_hash"}, {"kind": "memory_dump"}],
        compliance_frameworks=["SOC2"],
        tags={"team": "soc-1"},
    )
    comments = [
        SummaryCommentRow(
            author="alice",
            body="Confirmed encryption activity, isolating host",
            is_system=False,
            created_at=OPENED + timedelta(minutes=15),
        ),
        SummaryCommentRow(
            author=None,
            body="Auto-triage routed to playbook PB-014",
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
        SummaryTaskRow(
            title="Run containment playbook PB-014",
            status="done",
            assignee="alice",
            due_at=OPENED + timedelta(hours=2),
            created_at=OPENED,
            updated_at=OPENED + timedelta(hours=2),
        ),
    ]
    return PostmortemInputs(case=case, comments=comments, tasks=tasks)


def test_build_postmortem_basic_shape(baseline_inputs: PostmortemInputs) -> None:
    pm = build_postmortem_from_rows(baseline_inputs, now=NOW)

    assert pm.case.case_id == CASE_ID
    assert pm.case.case_number == "CASE-2026-0042"
    assert pm.case.severity == "high"

    # Detection.
    assert pm.detection.time_to_triage_hours == 1.0
    assert pm.detection.time_to_resolve_hours == 6.0
    assert pm.detection.sla_breached is True
    assert pm.detection.first_analyst_touch_at == OPENED + timedelta(minutes=15)
    assert pm.detection.time_to_detect_hours == 0.25

    # Overview blast radius.
    assert pm.overview.blast_radius_hosts == 1
    assert pm.overview.blast_radius_identities == 2
    assert pm.overview.blast_radius_alerts == 3
    assert pm.overview.affected_domains == ["evil.example.com"]

    # Response.
    assert pm.response.total_actions == 3
    assert pm.response.completed == 2
    assert pm.response.overdue == 1
    assert pm.response.automation_used is True

    # Detection gaps include the SLA breach.
    assert any(g.severity == "critical" and "SLA" in g.title for g in pm.detection_gaps)

    # Action items reflect the breach + overdue items.
    titles = " ".join(i.title for i in pm.action_items)
    assert "SLA" in titles
    assert "overdue" in titles.lower()

    # Timeline non-empty + sorted, no analyst names leaked.
    assert pm.timeline
    timestamps = [e.ts for e in pm.timeline]
    assert timestamps == sorted(timestamps)
    blob = " ".join(e.label + " " + (e.detail or "") for e in pm.timeline)
    assert "alice" not in blob.lower()


def test_build_postmortem_minimal_inputs_returns_neutral_recommendation() -> None:
    """When everything is clean, the action-item list still has one entry.

    The fallback neutral marker requires *no* gaps, *no* fell-short items,
    and *no* generated action items. We need an analyst comment (so detection
    doesn't surface a "no analyst touch" gap) and a tagged technique.
    """
    case = _case(
        status="closed",
        severity="low",
        triaged_at=OPENED + timedelta(minutes=5),
        resolved_at=OPENED + timedelta(minutes=20),
        closed_at=OPENED + timedelta(minutes=25),
        sla_due_at=None,
        mitre_techniques=["T1078"],
    )
    comments = [
        SummaryCommentRow(
            author="analyst",
            body="reviewed",
            is_system=False,
            created_at=OPENED + timedelta(minutes=2),
        ),
    ]
    pm = build_postmortem_from_rows(PostmortemInputs(case=case, comments=comments), now=NOW)
    assert pm.detection.sla_breached is False
    assert pm.detection_gaps == []
    assert pm.fell_short == []
    assert pm.action_items
    assert any("No structural follow-ups" in i.title for i in pm.action_items)


def test_build_postmortem_is_deterministic(baseline_inputs: PostmortemInputs) -> None:
    a = build_postmortem_from_rows(baseline_inputs, now=NOW).model_dump_json()
    b = build_postmortem_from_rows(baseline_inputs, now=NOW).model_dump_json()
    assert a == b


def test_build_postmortem_headline_includes_label_and_severity(
    baseline_inputs: PostmortemInputs,
) -> None:
    pm = build_postmortem_from_rows(baseline_inputs, now=NOW)
    assert "CASE-2026-0042" in pm.headline
    assert "HIGH" in pm.headline
    assert "SLA breached" in pm.headline


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


def test_render_case_postmortem_html_contains_all_sections(
    baseline_inputs: PostmortemInputs,
) -> None:
    pm = build_postmortem_from_rows(baseline_inputs, now=NOW)
    html = render_case_postmortem_html(pm)

    assert "<!DOCTYPE html>" in html
    assert "AiSOC" in html
    assert "post-mortem" in html.lower()
    # All major section headings should be present (case-insensitive — copy
    # may evolve, structure shouldn't).
    lowered = html.lower()
    assert "incident overview" in lowered
    assert "detection" in lowered
    assert "response" in lowered
    assert "timeline" in lowered
    assert "went well" in lowered
    assert "fell short" in lowered
    assert "action items" in lowered


def test_render_case_postmortem_html_escapes_user_data() -> None:
    case = _case(
        title="<script>alert('xss')</script>",
        description="<img src=x onerror=alert(1)>",
        severity="critical",
    )
    pm = build_postmortem_from_rows(PostmortemInputs(case=case), now=NOW)
    html = render_case_postmortem_html(pm)

    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
    assert "<img src=x" not in html


def test_render_case_postmortem_html_omits_analyst_names(
    baseline_inputs: PostmortemInputs,
) -> None:
    """Blameless retrospective: analyst usernames must not appear in the body.

    The case assignee is metadata and may legitimately appear in the header,
    but the timeline + action items must not surface comment authors.
    """
    pm = build_postmortem_from_rows(baseline_inputs, now=NOW)
    html = render_case_postmortem_html(pm)

    # Strip the case assignee line so we can assert the *narrative* sections
    # don't surface analyst names.
    assert "alice" not in pm.headline.lower()
    for item in pm.action_items:
        assert "alice" not in item.body.lower()
        assert "alice" not in item.title.lower()
    for entry in pm.timeline:
        assert "alice" not in entry.label.lower()
        if entry.detail:
            assert "alice" not in entry.detail.lower()

    # The rendered HTML must also be blameless — the assignee line is allowed
    # in the header but narrative sections (timeline / action items) must not
    # surface analyst handles.
    body_html = html.split("</header>", 1)[-1].lower() if "</header>" in html else html.lower()
    assert "alice" not in body_html


def test_postmortem_round_trips_through_pydantic_json(
    baseline_inputs: PostmortemInputs,
) -> None:
    pm = build_postmortem_from_rows(baseline_inputs, now=NOW)
    payload = pm.model_dump_json()
    restored = CasePostmortem.model_validate_json(payload)
    assert restored == pm
