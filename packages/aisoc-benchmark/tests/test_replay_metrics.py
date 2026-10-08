"""Replay scoring: the numbers, and the ones it refuses to print.

Gap-closure Phase 1.3.
"""

from __future__ import annotations

from typing import Any

# The baseline gate runs mypy with `--no-site-packages`, so pytest is
# unresolvable there while pytest itself imports it without difficulty. The
# same finding is recorded against `tests/test_benchmark.py`; silenced here
# rather than added to the baseline, which may only shrink.
import pytest  # type: ignore[import-not-found]
from aisoc_benchmark.metrics import extract_checkable_indicators
from aisoc_benchmark.replay import (
    LATENCY_FIELDS,
    LATENCY_LINE_PREFIX,
    LATENCY_LINE_PREFIXES,
    MIN_MALICIOUS_FOR_HEADLINE,
    format_replay_report,
    score_replay,
    strip_latency,
)

MALICIOUS = "true_positive"
FP = "false_positive"


def _decision(
    index: int,
    expected: str,
    verdict: str | None,
    *,
    confidence: float = 0.8,
    labelled: bool = True,
    findings: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    error: str | None = None,
    rule_id: str = "rule-1",
    vendor: str = "splunk",
) -> dict[str, Any]:
    return {
        "finding_id": f"F-{index:03d}",
        "vendor": vendor,
        "rule_id": rule_id,
        "closed_at": "2026-05-01T00:00:00+00:00",
        "expected_disposition": expected,
        "vendor_disposition": "disposition:1",
        "labelled": labelled,
        "verdict": verdict,
        "confidence": confidence,
        "tier": "deterministic",
        "findings": findings or [],
        "confidence_basis": [],
        "evidence": evidence or {},
        "tokens": 0,
        "measured_usd": None,
        "estimated_usd": None,
        "unpriced_calls": 0,
        "latency_ms": 10,
        "resolved_models": [],
        "error": error,
    }


def _corpus(malicious: int, benign: int, *, hits: int | None = None) -> list[dict[str, Any]]:
    """``hits`` malicious cases the agent caught; the rest it called benign."""
    caught = malicious if hits is None else hits
    rows = [_decision(i, MALICIOUS, MALICIOUS if i < caught else FP) for i in range(malicious)]
    rows += [_decision(1000 + i, FP, FP) for i in range(benign)]
    return rows


# --------------------------------------------------------------------------
# The headline floor
# --------------------------------------------------------------------------


def test_a_thin_malicious_corpus_prints_no_headline_accuracy() -> None:
    score = score_replay(_corpus(malicious=5, benign=195))

    assert score.headline_accuracy is None
    assert score.headline_accuracy_ci is None
    assert "5 malicious case(s)" in (score.headline_withheld_reason or "")
    # Everything else is still reported. Withholding one figure is not an
    # excuse to withhold the ones that make the thin corpus visible.
    assert score.malicious_support == 5
    assert score.malicious_recall == 1.0


def test_the_headline_appears_once_the_floor_is_met() -> None:
    score = score_replay(_corpus(malicious=MIN_MALICIOUS_FOR_HEADLINE, benign=30))

    assert score.headline_withheld_reason is None
    assert score.headline_accuracy == pytest.approx(1.0)


def test_the_withheld_headline_renders_as_words_not_as_zero() -> None:
    """A reader must never see a number where a refusal belongs."""
    report = format_replay_report(score_replay(_corpus(malicious=2, benign=50)))

    assert "Withheld." in report
    # Sliced to the headline section alone. It used to run to "## Per class",
    # which stopped being the next heading when the scorecard sections landed
    # between them -- and one of those prints "100.0%", which *contains*
    # "0.0%", so the old window made this pass or fail on an unrelated
    # figure's digits.
    headline = report.split("## Against a constant answer")[0].split("## Headline accuracy")[1]
    assert "0.0%" not in headline


# --------------------------------------------------------------------------
# Per class, and absent versus zero
# --------------------------------------------------------------------------


def test_a_class_the_agent_never_predicted_reads_not_measured() -> None:
    score = score_replay(_corpus(malicious=10, benign=10))

    benign_true_positive = next(c for c in score.per_class if c.label == "benign_true_positive")
    assert benign_true_positive.support == 0
    assert benign_true_positive.precision is None
    assert benign_true_positive.recall is None
    assert "not measured" in format_replay_report(score)


def test_recall_counts_a_missed_malicious_case_against_the_agent() -> None:
    score = score_replay(_corpus(malicious=10, benign=0, hits=6))

    assert score.malicious_recall == pytest.approx(0.6)
    assert score.malicious_precision == pytest.approx(1.0)


def test_an_abstention_counts_against_malicious_recall() -> None:
    """An alert routed to a human was not caught by the agent."""
    rows = [_decision(i, MALICIOUS, "needs_review") for i in range(10)]

    score = score_replay(rows)

    assert score.abstained == 10
    assert score.graded == 0
    assert score.malicious_recall == 0.0
    assert score.abstention_rate == 1.0


def test_escalate_is_an_abstention_not_a_verdict() -> None:
    score = score_replay([_decision(i, MALICIOUS, "escalate") for i in range(4)])

    assert score.abstained == 4


# --------------------------------------------------------------------------
# Populations kept apart
# --------------------------------------------------------------------------


def test_unlabelled_findings_are_excluded_from_accuracy_and_counted() -> None:
    rows = _corpus(malicious=10, benign=10)
    rows += [_decision(2000 + i, "unlabeled", FP, labelled=False) for i in range(40)]

    score = score_replay(rows)

    assert score.decisions == 60
    assert score.labelled == 20
    assert score.unlabeled == 40
    assert score.graded == 20


def test_a_refusal_is_neither_an_answer_nor_an_abstention() -> None:
    rows = _corpus(malicious=4, benign=4)
    rows += [_decision(3000 + i, MALICIOUS, None, error="normalize failed") for i in range(3)]

    score = score_replay(rows)

    assert score.errored == 3
    assert score.labelled == 8
    assert score.abstained == 0


def test_a_verdict_outside_the_taxonomy_gets_its_own_column() -> None:
    """An unrecognised verdict is a finding about the product, not a rounding error."""
    rows = [_decision(i, MALICIOUS, "wildly_unexpected") for i in range(5)]

    score = score_replay(rows)

    assert score.confusion[MALICIOUS]["wildly_unexpected"] == 5


# --------------------------------------------------------------------------
# Calibration
# --------------------------------------------------------------------------


def test_a_perfectly_calibrated_agent_has_near_zero_calibration_error() -> None:
    # Eight of ten right, all claiming 0.8.
    rows = [_decision(i, MALICIOUS, MALICIOUS if i < 8 else FP, confidence=0.8) for i in range(10)]

    score = score_replay(rows)

    assert score.expected_calibration_error == pytest.approx(0.0, abs=1e-6)


def test_a_confidently_wrong_agent_has_a_large_calibration_error() -> None:
    rows = [_decision(i, MALICIOUS, FP, confidence=0.95) for i in range(10)]

    score = score_replay(rows)

    assert score.expected_calibration_error == pytest.approx(0.95, abs=1e-6)


def test_every_bin_is_emitted_so_an_unused_confidence_range_is_visible() -> None:
    score = score_replay(_corpus(malicious=10, benign=0))

    assert len(score.calibration) == 10
    assert any(b.count == 0 and b.accuracy is None for b in score.calibration)


# --------------------------------------------------------------------------
# Hallucination
# --------------------------------------------------------------------------


def test_an_indicator_absent_from_the_evidence_is_counted_as_hallucinated() -> None:
    rows = [
        _decision(
            0,
            MALICIOUS,
            MALICIOUS,
            findings=["Beaconing to 203.0.113.77 from 10.0.0.5"],
            evidence={"src_ip": "10.0.0.5"},
        )
    ]

    score = score_replay(rows)

    assert score.indicators_checked == 2
    assert score.hallucinated_total == 1
    assert score.hallucinated_examples == ["203.0.113.77"]
    assert score.hallucination_rate == pytest.approx(0.5)


def test_hallucination_is_graded_on_a_decision_that_errored() -> None:
    """An agent that invented an address before failing has still invented it."""
    rows = [_decision(0, MALICIOUS, None, findings=["saw 203.0.113.9"], error="triage failed")]

    score = score_replay(rows)

    assert score.hallucinated_total == 1


def test_extraction_uses_the_same_vocabulary_the_existing_grader_checks() -> None:
    found = extract_checkable_indicators("contacted evil.example.com at 198.51.100.4 twice")

    assert found == ["evil.example.com", "198.51.100.4"]


# --------------------------------------------------------------------------
# Breakdowns, intervals, determinism
# --------------------------------------------------------------------------


def test_per_rule_and_per_source_slices_report_their_own_sample_size() -> None:
    rows = [_decision(i, MALICIOUS, MALICIOUS, rule_id="rule-a", vendor="splunk") for i in range(6)]
    rows += [_decision(100 + i, MALICIOUS, FP, rule_id="rule-b", vendor="sentinel") for i in range(4)]

    score = score_replay(rows)

    by_rule = {s.key: s for s in score.per_rule}
    assert by_rule["rule-a"].graded == 6
    assert by_rule["rule-a"].malicious_recall == 1.0
    assert by_rule["rule-b"].malicious_recall == 0.0
    assert {s.key for s in score.per_source} == {"splunk", "sentinel"}


def test_a_finding_with_no_rule_id_is_grouped_rather_than_dropped() -> None:
    score = score_replay([_decision(0, MALICIOUS, MALICIOUS, rule_id="")])

    assert [s.key for s in score.per_rule] == ["unattributed"]


def test_an_interval_needs_more_than_a_handful_of_cases() -> None:
    score = score_replay(_corpus(malicious=3, benign=0))

    assert score.malicious_recall == 1.0
    assert score.malicious_recall_ci is None


def test_scoring_the_same_decisions_twice_gives_the_same_report() -> None:
    """The bootstrap is seeded, so the report reproduces byte for byte."""
    rows = _corpus(malicious=40, benign=60, hits=31)

    first = format_replay_report(score_replay(rows))
    second = format_replay_report(score_replay(rows))

    assert first == second
    assert "seed" in first


def test_a_different_seed_is_recorded_in_the_report() -> None:
    rows = _corpus(malicious=40, benign=60, hits=31)

    report = format_replay_report(score_replay(rows, bootstrap_seed=7, bootstrap_resamples=200))

    assert "200 resamples, seed 7" in report


def test_a_history_with_no_labels_at_all_says_so() -> None:
    rows = [_decision(i, "unlabeled", FP, labelled=False) for i in range(50)]

    score = score_replay(rows)

    assert score.headline_accuracy is None
    assert "nothing to grade against" in (score.headline_withheld_reason or "")
    assert score.unlabeled == 50


# --------------------------------------------------------------------------
# The reproducibility claim, stated precisely
# --------------------------------------------------------------------------
#
# Gap-closure Phase 1.4. Everything in this report is a property of the input
# and the code apart from the two wall-clock latency figures, and the claim is
# worth nothing if it is stated loosely. `strip_latency` is what produces the
# artefact the claim is about, so it is checked in both directions: it must
# remove the line the renderer emits, and it must remove nothing else.


def test_two_runs_differing_only_in_latency_are_identical_once_it_is_excluded() -> None:
    """The exact shape of what changes between two runs on one history.

    Latency is the only field that moves, and it moves every time. Everything
    downstream of that fact depends on this holding.
    """
    fast = _corpus(malicious=40, benign=60, hits=31)
    slow = [{**row, "latency_ms": row["latency_ms"] + 137} for row in fast]

    assert format_replay_report(score_replay(fast)) != format_replay_report(score_replay(slow))
    assert strip_latency(format_replay_report(score_replay(fast))) == strip_latency(format_replay_report(score_replay(slow)))


def test_stripping_latency_changes_exactly_one_line() -> None:
    report = format_replay_report(score_replay(_corpus(malicious=40, benign=60, hits=31)))

    stripped = strip_latency(report)

    original_lines = report.split("\n")
    stripped_lines = stripped.split("\n")
    # The line is replaced rather than dropped, so a diff of two reports
    # points at content rather than at an offset.
    assert len(original_lines) == len(stripped_lines)
    differing = [(a, b) for a, b in zip(original_lines, stripped_lines, strict=True) if a != b]
    # Asserted as a property rather than a count. The report carries more
    # than one host-measured line since the scorecard added "time to
    # verdict", and the guarantee worth keeping is that the stripper touches
    # *only* lines it declares -- not that there happens to be one of them.
    assert differing, "the stripper changed nothing, so it is a no-op that still claims to exclude latency"
    for before, _ in differing:
        assert before.startswith(LATENCY_LINE_PREFIXES), f"stripped a line it does not declare: {before!r}"


def test_the_renderer_emits_the_line_the_stripper_looks_for() -> None:
    """Both directions, because a prefix that drifted would silently strip nothing.

    The producer and the remover share one constant. This asserts the
    constant is actually what lands in the rendered report, so a renderer
    change that stopped using it fails here rather than leaving
    `--exclude-latency` a no-op that still claims to have excluded something.
    """
    report = format_replay_report(score_replay(_corpus(malicious=40, benign=60, hits=31)))

    assert sum(1 for line in report.split("\n") if line.startswith(LATENCY_LINE_PREFIX)) == 1


def test_prose_mentioning_latency_elsewhere_is_not_deleted() -> None:
    """Anchored on the line prefix, not on the word.

    A future section discussing latency must not be silently removed from an
    operator's export.
    """
    report = "## Cost and latency\n\n- Tokens: 0\n" + LATENCY_LINE_PREFIX + " 4 ms, p95 9 ms\n\nLatency is reported, not scored.\n"

    stripped = strip_latency(report)

    assert "## Cost and latency" in stripped
    assert "Latency is reported, not scored." in stripped
    assert "4 ms" not in stripped


def test_the_latency_fields_named_for_the_json_export_exist_on_the_score() -> None:
    score = score_replay(_corpus(malicious=40, benign=60, hits=31)).as_dict()

    for field in LATENCY_FIELDS:
        assert field in score
