"""Tests for WS-G2 — executive weekly digest builder + HTML renderer.

The digest service is split into a *pure* builder (``build_digest_from_rows``)
and a thin async DB orchestrator. We exercise the pure builder against
deterministic input rows and snapshot the HTML render to lock the contract
that downstream analyst tooling depends on.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.services.digest_html import render_digest_html
from app.services.executive_digest import (
    AlertRow,
    AutomationSummary,
    CaseRow,
    DigestInputs,
    GateLogRow,
    MttSummary,
    SeveritySplit,
    _internal_helpers,
    build_digest_from_rows,
)

PERIOD_START = datetime(2026, 5, 2, 0, 0, tzinfo=UTC)
PERIOD_END = datetime(2026, 5, 9, 0, 0, tzinfo=UTC)
TENANT_ID = uuid.uuid4()


def _alert(
    *,
    severity: str = "low",
    status: str = "open",
    created_at: datetime | None = None,
    resolved_at: datetime | None = None,
    first_seen_at: datetime | None = None,
    disposition: str | None = None,
    mitre_tactics: list[str] | None = None,
    connector_type: str | None = "edr-crowdstrike",
    ai_score: float | None = None,
    title: str = "Suspicious Activity",
    alert_id: str | None = None,
    event_time: datetime | None = None,
) -> AlertRow:
    """Builder that fills sensible defaults for a row."""
    created = created_at or PERIOD_START + timedelta(hours=1)
    return AlertRow(
        severity=severity,
        status=status,
        created_at=created,
        resolved_at=resolved_at,
        first_seen_at=first_seen_at,
        disposition=disposition,
        mitre_tactics=list(mitre_tactics or []),
        connector_type=connector_type,
        ai_score=ai_score,
        title=title,
        alert_id=alert_id or str(uuid.uuid4()),
        event_time=event_time or created,
    )


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_format_period_label_same_month() -> None:
    fmt = _internal_helpers["_format_period_label"]
    label = fmt(PERIOD_START, PERIOD_END)
    assert "May" in label
    assert "2026" in label


def test_severity_split_counts() -> None:
    split = _internal_helpers["_severity_split"](
        [
            _alert(severity="critical"),
            _alert(severity="critical"),
            _alert(severity="high"),
            _alert(severity="medium"),
            _alert(severity="low"),
            _alert(severity="info"),
        ]
    )
    assert isinstance(split, SeveritySplit)
    assert split.critical == 2
    assert split.high == 1
    assert split.medium == 1
    assert split.low == 1
    assert split.info == 1


def test_mean_hours_zero_or_empty_returns_none() -> None:
    mean = _internal_helpers["_mean_hours"]
    assert mean([]) is None
    assert mean([timedelta(hours=2), timedelta(hours=4)]) == 3.0


def test_compute_mtt_only_counts_valid_pairs() -> None:
    rows = [
        _alert(
            created_at=PERIOD_START,
            first_seen_at=PERIOD_START + timedelta(minutes=30),
            resolved_at=PERIOD_START + timedelta(hours=4),
            disposition="true_positive",
        ),
        _alert(
            created_at=PERIOD_START + timedelta(hours=1),
            first_seen_at=None,
            resolved_at=PERIOD_START + timedelta(hours=3),
            disposition="false_positive",
        ),
    ]
    mtt = _internal_helpers["_compute_mtt"](rows)
    assert isinstance(mtt, MttSummary)
    assert mtt.mttd_hours == 0.5  # only the first alert had first_seen_at
    assert mtt.mttr_hours is not None
    # MTTC only counts true positives
    assert mtt.mttc_hours == 4.0


def test_top_tactics_sorted_with_delta() -> None:
    current = [
        _alert(mitre_tactics=["initial_access", "execution"]),
        _alert(mitre_tactics=["initial_access"]),
        _alert(mitre_tactics=["lateral_movement"]),
    ]
    prior = [_alert(mitre_tactics=["initial_access"])]
    tactics = _internal_helpers["_top_tactics"](current, prior, limit=3)
    assert [t.tactic for t in tactics][0] == "initial_access"
    initial = next(t for t in tactics if t.tactic == "initial_access")
    assert initial.count == 2
    assert initial.delta_from_prior == 1


def test_top_sources_skips_blank_connectors() -> None:
    current = [
        _alert(connector_type="edr-crowdstrike"),
        _alert(connector_type="edr-crowdstrike"),
        _alert(connector_type="aws-cloudtrail"),
        _alert(connector_type=None),
    ]
    sources = _internal_helpers["_top_sources"](current, limit=5)
    assert sources[0].connector_type == "edr-crowdstrike"
    assert sources[0].count == 2
    assert {s.connector_type for s in sources} == {"edr-crowdstrike", "aws-cloudtrail"}


def test_high_risk_alerts_sorted_by_severity_then_score() -> None:
    rows = [
        _alert(severity="low", ai_score=0.99, title="Noisy Low"),
        _alert(severity="critical", ai_score=0.10, title="Sneaky Critical"),
        _alert(severity="high", ai_score=0.95, title="Real High"),
        _alert(severity="critical", ai_score=0.95, title="Loud Critical"),
    ]
    top = _internal_helpers["_high_risk_alerts"](rows, limit=3)
    assert [a.title for a in top] == ["Loud Critical", "Sneaky Critical", "Real High"]


def test_automation_summary_categorises_decisions() -> None:
    log = [
        GateLogRow(decision="auto"),
        GateLogRow(decision="auto"),
        GateLogRow(decision="review"),
        GateLogRow(decision="escalate"),
        GateLogRow(decision="something_unknown"),
    ]
    summary = _internal_helpers["_automation_summary"](log)
    assert isinstance(summary, AutomationSummary)
    assert summary.total_decisions == 5
    assert summary.auto_executed == 2
    assert summary.review_pending == 1
    assert summary.escalated == 1


def test_case_summary_filters_by_window() -> None:
    rows = [
        CaseRow(
            status="open",
            created_at=PERIOD_START + timedelta(hours=1),
            closed_at=None,
            sla_breached=False,
        ),
        CaseRow(
            status="closed",
            created_at=PERIOD_START + timedelta(hours=2),
            closed_at=PERIOD_START + timedelta(hours=4),
            sla_breached=True,
        ),
        CaseRow(
            status="open",
            created_at=PERIOD_START - timedelta(days=2),
            closed_at=None,
            sla_breached=False,
        ),
    ]
    summary = _internal_helpers["_case_summary"](rows, 12, PERIOD_START, PERIOD_END)
    assert summary.opened == 2
    assert summary.closed == 1
    assert summary.sla_breached == 1
    assert summary.open_at_period_end == 12


# ---------------------------------------------------------------------------
# Top-level pure builder
# ---------------------------------------------------------------------------


@pytest.fixture
def baseline_inputs() -> DigestInputs:
    """A realistic, deterministic input bundle that exercises every section."""
    return DigestInputs(
        tenant_id=TENANT_ID,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        current_alerts=[
            _alert(
                severity="critical",
                title="Ransomware exec on FIN-LAPTOP-04",
                created_at=PERIOD_START + timedelta(hours=2),
                first_seen_at=PERIOD_START + timedelta(hours=2, minutes=15),
                resolved_at=PERIOD_START + timedelta(hours=8),
                disposition="true_positive",
                mitre_tactics=["impact", "execution"],
                ai_score=0.96,
            ),
            _alert(
                severity="critical",
                title="LSASS memory access — SVR-DC-01",
                created_at=PERIOD_START + timedelta(hours=4),
                ai_score=0.91,
                mitre_tactics=["credential_access"],
            ),
            _alert(
                severity="high",
                title="OAuth grant from new IP",
                created_at=PERIOD_START + timedelta(days=1),
                resolved_at=PERIOD_START + timedelta(days=1, hours=6),
                disposition="false_positive",
                mitre_tactics=["initial_access"],
                connector_type="azure-ad",
            ),
            _alert(
                severity="medium",
                title="Suspicious DNS tunnelling",
                created_at=PERIOD_START + timedelta(days=2),
                mitre_tactics=["command_and_control"],
                connector_type="aws-vpc-flow",
            ),
            _alert(severity="low", title="Failed login spike"),
        ],
        prior_alerts=[
            _alert(mitre_tactics=["initial_access"]),
            _alert(mitre_tactics=["execution"]),
        ],
        cases=[
            CaseRow(
                status="open",
                created_at=PERIOD_START + timedelta(hours=2),
                closed_at=None,
                sla_breached=False,
            ),
            CaseRow(
                status="closed",
                created_at=PERIOD_START + timedelta(hours=3),
                closed_at=PERIOD_START + timedelta(hours=10),
                sla_breached=True,
            ),
        ],
        gate_log=[
            GateLogRow(decision="auto"),
            GateLogRow(decision="auto"),
            GateLogRow(decision="auto"),
            GateLogRow(decision="review"),
            GateLogRow(decision="escalate"),
        ],
        open_alerts_at_period_end=42,
        open_cases_at_period_end=7,
    )


def test_build_digest_basic_shape(baseline_inputs: DigestInputs) -> None:
    digest = build_digest_from_rows(baseline_inputs)

    assert digest.tenant_id == TENANT_ID
    assert digest.period.start == PERIOD_START
    assert digest.period.end == PERIOD_END
    assert "May" in digest.period.label

    assert digest.alerts.total == 5
    assert digest.alerts.severity.critical == 2
    assert digest.alerts.severity.high == 1
    assert digest.alerts.severity.medium == 1
    assert digest.alerts.severity.low == 1
    assert digest.alerts.open_at_period_end == 42

    assert digest.cases.opened == 2
    assert digest.cases.closed == 1
    assert digest.cases.sla_breached == 1
    assert digest.cases.open_at_period_end == 7

    assert digest.automation.total_decisions == 5
    assert digest.automation.auto_executed == 3

    assert len(digest.high_risk_alerts) >= 3
    # High-risk alerts should be ordered with criticals first.
    severities = [a.severity for a in digest.high_risk_alerts]
    assert severities[0] == "critical"


def test_build_digest_headline_and_recommendations(baseline_inputs: DigestInputs) -> None:
    digest = build_digest_from_rows(baseline_inputs)

    assert "alerts ingested" in digest.headline
    # We have an SLA breach in the inputs, so a warning rec must appear.
    titles = [r.title for r in digest.recommendations]
    assert any("SLA" in t for t in titles)


def test_build_digest_no_signals_falls_back_to_neutral_recommendation() -> None:
    inputs = DigestInputs(
        tenant_id=TENANT_ID,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
    )
    digest = build_digest_from_rows(inputs)
    assert digest.alerts.total == 0
    assert digest.cases.opened == 0
    assert digest.recommendations
    assert digest.recommendations[0].severity == "info"
    assert "No significant deviations" in digest.recommendations[0].title


def test_build_digest_is_deterministic(baseline_inputs: DigestInputs) -> None:
    """Same inputs must yield byte-identical outputs."""
    a = build_digest_from_rows(baseline_inputs).model_dump_json()
    b = build_digest_from_rows(baseline_inputs).model_dump_json()
    assert a == b


# ---------------------------------------------------------------------------
# HTML renderer
# ---------------------------------------------------------------------------


def test_render_digest_html_contains_sections(baseline_inputs: DigestInputs) -> None:
    digest = build_digest_from_rows(baseline_inputs)
    html = render_digest_html(digest)

    assert "<!DOCTYPE html>" in html
    assert "AiSOC weekly executive digest" in html
    assert digest.period.label in html
    assert "Headline metrics" in html
    assert "Severity distribution" in html
    assert "Top MITRE tactics" in html
    assert "High-risk alerts" in html
    assert "Automation" in html
    assert "Recommendations" in html


def test_render_digest_html_escapes_user_data() -> None:
    inputs = DigestInputs(
        tenant_id=TENANT_ID,
        period_start=PERIOD_START,
        period_end=PERIOD_END,
        current_alerts=[
            _alert(title="<script>alert('xss')</script>", severity="critical", ai_score=0.99),
        ],
    )
    digest = build_digest_from_rows(inputs)
    html = render_digest_html(digest)

    # Raw script tag must not appear; escaped form must.
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html
