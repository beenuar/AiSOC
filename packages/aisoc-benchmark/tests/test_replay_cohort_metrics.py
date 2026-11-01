"""Full-cohort accounting: every evaluated input lands in exactly one bucket.

What these cover, and the defect each one blocks
------------------------------------------------
**Full-cohort malicious recall.** The selective ``malicious_recall`` is
computed over labelled decisions that did not error, so a run that *crashed*
on half the malicious cases silently dropped them from the denominator and
the published recall described the half it managed to answer. The full-cohort
figure keeps every labelled malicious case in its denominator — abstained,
errored, all of it — and the two are published side by side because they
answer different questions ("how good are its answers" vs "how much of the
threat landed somewhere safe").

**Closure accounting.** ``auto_close_precision`` answers "of what it would
have closed, how much was right" and nothing else. These four answer the
questions a buyer actually asks: how much of the malicious cohort would have
been closed (the catastrophic direction), how contaminated the closed pile is,
how much benign volume the closure actually absorbs, and how much of the
closed pile has no truth label at all. All are **proposed** closures — replay
executes nothing, and the score says so in its own fields.

**Request reliability.** ``requested / attempted / completed / failed /
unattempted`` as five visible counts, so a run that stopped a third of the way
through cannot publish a headline over the two-thirds it never reached without
the gap showing.
"""

from __future__ import annotations

from typing import Any

from aisoc_benchmark.replay import format_replay_report, score_replay

MALICIOUS = "true_positive"
FP = "false_positive"
BENIGN = "benign"
BTP = "benign_true_positive"


def _decision(
    index: int,
    expected: str,
    verdict: str | None,
    *,
    confidence: float = 0.95,
    labelled: bool = True,
    error: str | None = None,
    severity: str = "high",
    attribution: dict[str, int] | None = None,
    llm_calls: int = 0,
) -> dict[str, Any]:
    return {
        "finding_id": f"F-{index:03d}",
        "vendor": "splunk",
        "rule_id": "rule-1",
        "closed_at": "2026-05-01T00:00:00+00:00",
        "expected_disposition": expected,
        "vendor_disposition": "disposition:1",
        "labelled": labelled,
        "verdict": verdict,
        "confidence": confidence,
        "tier": "llm",
        "findings": [],
        "confidence_basis": [],
        "evidence": {},
        "tokens": 0,
        "measured_usd": None,
        "estimated_usd": None,
        "unpriced_calls": 0,
        "latency_ms": 10,
        "resolved_models": [],
        "attribution_sources": attribution or {},
        "severity": severity,
        "llm_calls": llm_calls,
        "error": error,
    }


# --------------------------------------------------------------------------
# Full-cohort malicious recall keeps errored and abstained cases
# --------------------------------------------------------------------------


def test_full_cohort_recall_keeps_errored_malicious_in_the_denominator() -> None:
    """Ten malicious: 4 caught, 2 abstained, 2 called benign, 2 errored.

    Selective recall is over the 8 that did not error (4/8). Full-cohort
    recall is over all 10 (4/10), and the split of the other six is published
    as counts rather than vanishing.
    """
    rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(4)]
    rows += [_decision(10 + i, MALICIOUS, "needs_review") for i in range(2)]
    rows += [_decision(20 + i, MALICIOUS, BENIGN) for i in range(2)]
    rows += [_decision(30 + i, MALICIOUS, None, error="triage failed: boom") for i in range(2)]
    rows += [_decision(100 + i, FP, FP) for i in range(4)]

    score = score_replay(rows)

    assert score.malicious_support == 8  # selective: errored rows excluded
    assert score.malicious_recall == 4 / 8
    assert score.malicious_support_full == 10
    assert score.malicious_recall_full_cohort == 4 / 10
    assert score.malicious_abstained == 2
    assert score.malicious_errored == 2
    # Routed somewhere a human will look: abstentions and errors both retain
    # the alert. Misclassified-benign did NOT reach anyone — that is the
    # number the full-cohort view exists to surface.
    assert score.malicious_reached_review == 4
    assert score.malicious_closed_as_negative == 2


def test_full_cohort_equals_selective_when_nothing_errored() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(6)]
    rows += [_decision(100 + i, FP, FP) for i in range(4)]
    score = score_replay(rows)
    assert score.malicious_recall_full_cohort == score.malicious_recall == 1.0
    assert score.malicious_support_full == score.malicious_support == 6


# --------------------------------------------------------------------------
# The four closure metrics, over proposed closures
# --------------------------------------------------------------------------


def test_closure_metrics_report_all_four_cuts() -> None:
    """6 malicious (1 closed!), 8 benign-family (6 closed), 2 unlabeled closed.

    - malicious closure rate: 1/6 — the catastrophic direction.
    - contamination: among closures with known truth (7), 1 was malicious.
    - benign closure coverage: 6 of 8 benign-family items closed.
    - unknown share: 2 of 9 closures carry no truth label.
    """
    rows = [_decision(i, MALICIOUS, MALICIOUS, confidence=0.99) for i in range(5)]
    # The catastrophe: a malicious case the agent would have closed as benign.
    rows += [_decision(5, MALICIOUS, BENIGN, confidence=0.99)]
    rows += [_decision(10 + i, FP, FP, confidence=0.99) for i in range(3)]
    rows += [_decision(20 + i, BENIGN, BENIGN, confidence=0.99) for i in range(3)]
    # Benign-family items the agent escalated: not closed.
    rows += [_decision(30 + i, BTP, "needs_review") for i in range(2)]
    # Unlabeled items the agent would have closed.
    rows += [_decision(40 + i, "unlabeled", FP, confidence=0.99, labelled=False) for i in range(2)]

    score = score_replay(rows)

    assert score.closures_proposed == 9
    assert score.closures_executed == 0
    assert score.malicious_closure_rate == 1 / 6
    assert score.malicious_closed_count == 1
    assert score.closure_contamination == 1 / 7
    assert score.benign_closure_coverage == 6 / 8
    assert score.closure_unknown_share == 2 / 9


def test_no_proposed_closures_reports_not_measured_not_zero() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(3)]
    rows += [_decision(10 + i, FP, "needs_review") for i in range(3)]
    score = score_replay(rows)
    assert score.closures_proposed == 0
    assert score.closure_contamination is None
    assert score.closure_unknown_share is None
    # Malicious closure rate has a real denominator (3 malicious) and a true
    # zero numerator: nothing malicious was closed. That zero was counted.
    assert score.malicious_closure_rate == 0.0


# --------------------------------------------------------------------------
# Request reliability: five counts, nothing vanishes
# --------------------------------------------------------------------------


def test_reliability_counts_cover_every_requested_item() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(4)]
    rows += [_decision(10, FP, FP), _decision(11, FP, None, error="triage failed: x")]
    score = score_replay(rows, requested_total=10)
    assert score.requested_total == 10
    assert score.attempted == 6
    assert score.completed == 5
    assert score.failed == 1
    assert score.unattempted == 4


def test_unattempted_is_unknown_when_no_request_count_was_given() -> None:
    score = score_replay([_decision(0, MALICIOUS, MALICIOUS), _decision(1, FP, FP)])
    assert score.requested_total is None
    assert score.unattempted is None


# --------------------------------------------------------------------------
# Attribution aggregation and per-severity segmentation
# --------------------------------------------------------------------------


def test_attribution_sources_aggregate_across_decisions() -> None:
    rows = [
        _decision(0, MALICIOUS, MALICIOUS, attribution={"response_body": 1}, llm_calls=1),
        _decision(1, FP, FP, attribution={"response_body": 1}, llm_calls=1),
        _decision(2, FP, FP, llm_calls=1),  # placed a call nobody attributed
    ]
    score = score_replay(rows)
    assert score.attribution_sources == {"response_body": 2}
    assert score.llm_calls == 3


def test_per_severity_segments_are_reported() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS, severity="critical") for i in range(2)]
    rows += [_decision(10 + i, MALICIOUS, BENIGN, severity="low") for i in range(2)]
    rows += [_decision(20 + i, FP, FP, severity="low") for i in range(2)]
    score = score_replay(rows)
    by_key = {segment.key: segment for segment in score.per_severity}
    assert by_key["critical"].malicious_recall == 1.0
    assert by_key["low"].malicious_recall == 0.0


# --------------------------------------------------------------------------
# The renderer carries the new sections
# --------------------------------------------------------------------------


def test_report_renders_full_cohort_and_closure_sections() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS, confidence=0.99) for i in range(3)]
    rows += [_decision(10 + i, FP, FP, confidence=0.99) for i in range(3)]
    report = format_replay_report(score_replay(rows, requested_total=6))
    assert "Full cohort" in report
    assert "Proposed closures" in report
    assert "requested" in report.lower()
    # Proposed, never executed: the report says so in words.
    assert "proposed" in report.lower()
    assert "executed: 0" in report.lower()
