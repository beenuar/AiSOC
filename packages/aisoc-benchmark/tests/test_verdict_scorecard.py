"""Scorecard metrics: the ones that survive an imbalanced corpus.

Depth plan 1.2. The existing report publishes headline accuracy, malicious
recall with a bootstrap interval, per-class precision and recall, and a
confusion matrix. On a real queue that is not enough to tell a classifier
from a constant, and the plan names exactly what is missing:

* **balanced accuracy and the Matthews correlation coefficient, always next
  to the majority-class baseline.** Plain accuracy on a queue that is 90%
  false positive is 0.90 for an agent that reads nothing. Balanced accuracy
  is 0.50 for that agent and MCC is 0.0, which is the whole point -- but
  only if the baseline travels with them, so no number is ever read without
  what a constant answer would have scored.
* **a Wilson interval on malicious recall.** The bootstrap interval already
  there is resample-based; Wilson is closed-form, deterministic for a given
  (successes, trials), and does not collapse to a zero-width interval at
  0 or 1 the way a percentile bootstrap does. That degenerate case is not
  hypothetical: an agent that catches every malicious case in a small
  corpus gets `[1.0, 1.0]` from the bootstrap, which reads as certainty
  earned by sample size that does not exist.
* **auto-close precision at the closure threshold, and escalation rate.**
  The question an operator is actually deciding is "if I let it close
  things at confidence >= X, what fraction of what it closed was really
  closable?" -- which is not any existing field.
* **time to verdict at p50 and p95, labelled with hardware and never
  graded.** Reported beside the scores, never inside them.

Every test here fails on the pre-1.2 tree because the field does not exist.
"""

from __future__ import annotations

from typing import Any

import pytest  # type: ignore[import-not-found]
from aisoc_benchmark.replay import score_replay

MALICIOUS = "true_positive"
FP = "false_positive"
BENIGN = "benign"


def _decision(
    index: int,
    expected: str,
    verdict: str | None,
    *,
    confidence: float = 0.8,
    latency_ms: float = 10.0,
) -> dict[str, Any]:
    return {
        "finding_id": f"F-{index:03d}",
        "vendor": "splunk",
        "rule_id": "rule-1",
        "closed_at": "2026-05-01T00:00:00+00:00",
        "expected_disposition": expected,
        "labelled": True,
        "verdict": verdict,
        "confidence": confidence,
        "tier": "deterministic",
        "findings": [],
        "confidence_basis": [],
        "evidence": {},
        "tokens": 0,
        "measured_usd": None,
        "estimated_usd": None,
        "unpriced_calls": 0,
        "latency_ms": latency_ms,
        "resolved_models": [],
        "error": None,
    }


def _skewed_queue(malicious: int, benign: int, *, verdict_for_all: str = FP) -> list[dict[str, Any]]:
    """A queue mostly of false positives, and an agent that says so to everything.

    The constant-answer agent, which is the thing plain accuracy cannot see.
    """
    rows = [_decision(i, MALICIOUS, verdict_for_all) for i in range(malicious)]
    rows += [_decision(1000 + i, FP, verdict_for_all) for i in range(benign)]
    return rows


class TestBalancedAccuracyAndMCC:
    def test_a_constant_answer_scores_half_on_balanced_accuracy(self) -> None:
        """Plain accuracy would read 0.90 here. Balanced accuracy reads 0.50."""
        score = score_replay(_skewed_queue(malicious=40, benign=360))

        assert score.balanced_accuracy == pytest.approx(0.5, abs=1e-9)

    def test_a_constant_answer_scores_zero_on_mcc(self) -> None:
        """MCC is 0 for a predictor with no relationship to the label.

        The coefficient is the one headline number that cannot be bought
        with the base rate.
        """
        score = score_replay(_skewed_queue(malicious=40, benign=360))

        assert score.matthews_corrcoef == pytest.approx(0.0, abs=1e-9)

    def test_the_majority_baseline_travels_with_them(self) -> None:
        """Neither figure may be published without what a constant would score.

        This is the plan's wording and it is load-bearing: a reader given
        0.74 alone cannot tell whether the agent is good or the queue is.
        """
        score = score_replay(_skewed_queue(malicious=40, benign=360))

        assert score.majority_class_accuracy == pytest.approx(0.9, abs=1e-9)
        assert score.majority_class_label == FP

    def test_a_perfect_agent_scores_one_on_both(self) -> None:
        rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(40)]
        rows += [_decision(1000 + i, FP, FP) for i in range(360)]

        score = score_replay(rows)

        assert score.balanced_accuracy == pytest.approx(1.0, abs=1e-9)
        assert score.matthews_corrcoef == pytest.approx(1.0, abs=1e-9)

    def test_balanced_accuracy_averages_recall_over_present_classes_only(self) -> None:
        """A class with no support must not be averaged in as a zero.

        Dividing by four when the corpus holds two classes would cap the
        score at 0.5 for a perfect agent, which is a scoring bug that reads
        as a model failure.
        """
        rows = [_decision(i, MALICIOUS, MALICIOUS) for i in range(10)]
        rows += [_decision(100 + i, BENIGN, BENIGN) for i in range(10)]

        score = score_replay(rows)

        assert score.balanced_accuracy == pytest.approx(1.0, abs=1e-9)


class TestWilsonInterval:
    def test_recall_carries_a_wilson_interval(self) -> None:
        score = score_replay(_skewed_queue(malicious=40, benign=360, verdict_for_all=MALICIOUS))

        interval = score.malicious_recall_wilson
        assert interval is not None
        low, high = interval
        assert 0.0 <= low <= 1.0 and 0.0 <= high <= 1.0

    def test_a_perfect_run_still_has_width(self) -> None:
        """The failure a percentile bootstrap has at the boundary.

        40 for 40 is not proof of a 100% recall rate; Wilson says so and a
        bootstrap over an all-ones vector cannot.
        """
        score = score_replay(_skewed_queue(malicious=40, benign=360, verdict_for_all=MALICIOUS))

        interval = score.malicious_recall_wilson
        assert interval is not None
        low, high = interval
        assert high == pytest.approx(1.0, abs=1e-9)
        assert low < 0.95, f"a 40/40 run should not claim a lower bound of {low}"

    def test_a_smaller_sample_gives_a_wider_interval(self) -> None:
        """The property that makes the interval worth publishing at all."""
        wide = score_replay(_skewed_queue(malicious=10, benign=90, verdict_for_all=MALICIOUS))
        narrow = score_replay(_skewed_queue(malicious=200, benign=200, verdict_for_all=MALICIOUS))

        wide_interval, narrow_interval = wide.malicious_recall_wilson, narrow.malicious_recall_wilson
        assert wide_interval is not None and narrow_interval is not None
        assert (wide_interval[1] - wide_interval[0]) > (narrow_interval[1] - narrow_interval[0])

    def test_it_is_deterministic(self) -> None:
        """Closed form, so two runs over one corpus cannot disagree."""
        rows = _skewed_queue(malicious=37, benign=211, verdict_for_all=MALICIOUS)

        assert score_replay(rows).malicious_recall_wilson == score_replay(rows).malicious_recall_wilson


class TestAutoCloseAndEscalation:
    def test_auto_close_precision_counts_only_what_would_have_closed(self) -> None:
        """Of the rows the policy would auto-close, how many were closable?

        One malicious case above the threshold is a missed attack that the
        platform would have closed by itself, which is the outcome this
        number exists to price.
        """
        rows = [
            _decision(1, FP, FP, confidence=0.95),
            _decision(2, FP, FP, confidence=0.95),
            _decision(3, FP, FP, confidence=0.95),
            # Above the threshold and wrong: the agent would have closed a
            # real attack.
            _decision(4, MALICIOUS, FP, confidence=0.95),
            # Below the threshold: not auto-closed, so not counted either way.
            _decision(5, MALICIOUS, FP, confidence=0.10),
        ]

        score = score_replay(rows, auto_close_threshold=0.9)

        assert score.auto_close_considered == 4
        assert score.auto_close_precision == pytest.approx(0.75, abs=1e-9)
        assert score.auto_close_threshold == pytest.approx(0.9, abs=1e-9)

    def test_nothing_above_the_threshold_reports_none_not_zero(self) -> None:
        """`0.0` would read as "it closed things and got them all wrong"."""
        score = score_replay([_decision(1, FP, FP, confidence=0.2)], auto_close_threshold=0.9)

        assert score.auto_close_considered == 0
        assert score.auto_close_precision is None

    def test_escalation_rate_is_the_share_routed_to_a_human(self) -> None:
        rows = [_decision(i, FP, FP) for i in range(6)]
        rows += [_decision(100 + i, MALICIOUS, "escalate") for i in range(2)]
        rows += [_decision(200 + i, MALICIOUS, "needs_review") for i in range(2)]

        score = score_replay(rows)

        assert score.escalation_rate == pytest.approx(0.4, abs=1e-9)


class TestTimeToVerdict:
    def test_p50_and_p95_are_reported(self) -> None:
        rows = [_decision(i, FP, FP, latency_ms=float(i)) for i in range(1, 101)]

        score = score_replay(rows)

        assert score.time_to_verdict_p50_ms == pytest.approx(50.0, abs=1.0)
        assert score.time_to_verdict_p95_ms == pytest.approx(95.0, abs=1.0)

    def test_it_is_never_graded(self) -> None:
        """Latency is hardware, so it must not move a score.

        Two runs identical but for latency must score identically, or the
        scoreboard would rank a faster laptop as a better agent.
        """
        slow = [_decision(i, FP, FP, latency_ms=9000.0) for i in range(50)]
        fast = [_decision(i, FP, FP, latency_ms=1.0) for i in range(50)]

        a, b = score_replay(slow), score_replay(fast)

        assert a.balanced_accuracy == b.balanced_accuracy
        assert a.matthews_corrcoef == b.matthews_corrcoef
        assert a.time_to_verdict_p50_ms != b.time_to_verdict_p50_ms
