"""A delta between two eval runs, and the four ways it lies if unguarded.

Parity 3.4. Three of the four failure modes produce a plausible figure
rather than an error, which is why each gets its own class.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from compare_eval_runs import (  # noqa: E402
    VERDICT_IMPROVED,
    VERDICT_NOT_COMPARABLE,
    VERDICT_REGRESSED,
    VERDICT_UNCHANGED,
    ComparisonRefused,
    compare,
    format_delta_report,
)


def _axis(deltas, name):
    return next(d for d in deltas if d.axis == name)


class TestTheOrdinaryCase:
    def test_an_improvement_is_called_an_improvement(self) -> None:
        deltas = compare({"accuracy": 0.80}, {"accuracy": 0.86})
        assert _axis(deltas, "accuracy").verdict == VERDICT_IMPROVED
        assert _axis(deltas, "accuracy").delta == pytest.approx(0.06)

    def test_a_regression_is_called_a_regression(self) -> None:
        assert _axis(compare({"accuracy": 0.86}, {"accuracy": 0.80}), "accuracy").verdict == VERDICT_REGRESSED

    def test_a_tiny_move_is_unchanged(self) -> None:
        """A bootstrap CI and a sampled corpus both drift between runs.
        A tool that called every 0.001 a regression would be ignored
        within a week."""
        assert _axis(compare({"accuracy": 0.800}, {"accuracy": 0.8009}), "accuracy").verdict == VERDICT_UNCHANGED


class TestNotMeasuredIsNotZero:
    """The failure that produces the most confident wrong answer."""

    def test_an_axis_that_stopped_being_measured_is_not_a_regression(self) -> None:
        deltas = compare({"malicious_recall": 0.62}, {"malicious_recall": None})
        axis = _axis(deltas, "malicious_recall")

        assert axis.verdict == VERDICT_NOT_COMPARABLE, (
            "0.62 -> not measured was reported as a regression; the agent did not get worse, nobody asked it"
        )
        assert axis.delta is None
        assert "absent is not zero" in axis.note

    def test_the_string_not_measured_is_handled_too(self) -> None:
        """Reports in this tree write the words as well as null."""
        assert _axis(compare({"accuracy": "not measured"}, {"accuracy": 0.9}), "accuracy").verdict == VERDICT_NOT_COMPARABLE

    def test_a_newly_measured_axis_is_not_an_improvement(self) -> None:
        deltas = compare({"groundedness": None}, {"groundedness": 0.81})
        assert _axis(deltas, "groundedness").verdict == VERDICT_NOT_COMPARABLE

    def test_an_axis_only_in_one_run_is_reported_not_dropped(self) -> None:
        """Silently omitting it is how a report shrinks without anyone
        noticing which axis went quiet."""
        deltas = compare({"accuracy": 0.9}, {"accuracy": 0.9, "mitre_accuracy": 0.4})
        assert _axis(deltas, "mitre_accuracy").verdict == VERDICT_NOT_COMPARABLE

    def test_a_boolean_is_not_a_measurement(self) -> None:
        """`True` would silently become 1.0 and compare against a real
        rate."""
        assert _axis(compare({"measured": True}, {"measured": False}), "measured").verdict == VERDICT_NOT_COMPARABLE


class TestAMeanWithoutItsDenominator:
    def test_a_materially_changed_support_is_called_out(self) -> None:
        """A precision of 1.00 over two predictions and over two hundred
        are the same number and different facts."""
        deltas = compare(
            {"accuracy": {"mean": 0.90, "scored_incidents": 200}},
            {"accuracy": {"mean": 0.95, "scored_incidents": 10}},
        )
        axis = _axis(deltas, "accuracy")
        assert axis.verdict == VERDICT_IMPROVED
        assert "support changed from 200 to 10" in axis.note

    def test_a_steady_support_needs_no_caveat(self) -> None:
        deltas = compare(
            {"accuracy": {"mean": 0.90, "scored_incidents": 200}},
            {"accuracy": {"mean": 0.95, "scored_incidents": 195}},
        )
        assert _axis(deltas, "accuracy").note == ""


class TestTwoRunsOnDifferentCorpora:
    def test_a_dataset_mismatch_is_refused_outright(self) -> None:
        """A delta between a 200-incident run and a 10-incident one
        measures the corpus, not the change."""
        with pytest.raises(ComparisonRefused, match="different datasets"):
            compare(
                {"dataset": "synthetic_incidents", "accuracy": 0.9},
                {"dataset": "mitre_engenuity_micro", "accuracy": 0.95},
            )

    def test_the_same_dataset_compares_normally(self) -> None:
        deltas = compare(
            {"dataset": "synthetic_incidents", "accuracy": 0.90},
            {"dataset": "synthetic_incidents", "accuracy": 0.95},
        )
        assert _axis(deltas, "accuracy").verdict == VERDICT_IMPROVED

    def test_runs_that_name_no_dataset_are_still_compared(self) -> None:
        """Refusing those would make the tool unusable on every report
        this tree already writes."""
        assert _axis(compare({"accuracy": 0.9}, {"accuracy": 0.95}), "accuracy").verdict == VERDICT_IMPROVED


class TestWallClockIsNotGraded:
    def test_latency_is_reported_but_never_a_regression(self) -> None:
        """It differs between two runs on one host, let alone two."""
        deltas = compare({"mean_latency_ms": 100.0}, {"mean_latency_ms": 900.0})
        axis = _axis(deltas, "mean_latency_ms")
        assert axis.verdict == VERDICT_NOT_COMPARABLE
        assert "machine" in axis.note


class TestTheReport:
    def test_it_spells_out_not_measured(self) -> None:
        report = format_delta_report(
            compare({"accuracy": 0.9, "malicious_recall": None}, {"accuracy": 0.9, "malicious_recall": None}),
            before_label="a.json",
            after_label="b.json",
        )
        assert "not measured" in report
        assert "| 0.0000 |" not in report, "an unmeasured axis was rendered as zero"

    def test_it_counts_regressions_explicitly(self) -> None:
        report = format_delta_report(compare({"accuracy": 0.9}, {"accuracy": 0.5}), before_label="a", after_label="b")
        assert "**Regressions: 1**" in report
        assert "accuracy" in report

    def test_it_is_deterministic(self) -> None:
        """A report a reviewer has to diff cannot carry a timestamp."""
        args = ({"accuracy": 0.9}, {"accuracy": 0.95})
        first = format_delta_report(compare(*args), before_label="a", after_label="b")
        second = format_delta_report(compare(*args), before_label="a", after_label="b")
        assert first == second
