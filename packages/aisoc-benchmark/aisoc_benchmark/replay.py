"""Scoring for replay evaluation: the agent against a customer's own analysts.

Gap-closure Phase 1.3.

This extends the benchmark package rather than standing beside it. The
hallucination machinery is :func:`aisoc_benchmark.metrics.is_checkable_indicator`
and :func:`~aisoc_benchmark.metrics.extract_checkable_indicators`, unchanged, so
an indicator counted here is one the synthetic-corpus grader would also have
counted. A second grader would eventually disagree with the first about what
"hallucinated" means, and the published numbers would stop being comparable
while still looking like they were.

What replay measures that the synthetic corpus cannot
------------------------------------------------------
The synthetic corpus has balanced classes by construction. A real queue does
not: most closed findings are false positives, and a handful are the ones that
mattered. Three consequences shape this module.

**Headline accuracy is withheld on a thin corpus.** Below
:data:`MIN_MALICIOUS_FOR_HEADLINE` true positives the report prints the count
and refuses the number. Accuracy over 200 findings of which three were
malicious is 98% for an agent that calls everything benign, and publishing
that figure would be actively misleading in the direction that sells.

**Recall on malicious leads.** It is the number an operator is actually
deciding on, and it is the one an imbalanced corpus hides. :class:`ReplayScore`
puts it first and the renderers keep that order.

**Every mean travels with the count it was computed over.** A precision of
1.00 across two predictions is not a precision of 1.00 across two hundred, and
a table that prints only the ratio has thrown away the distinction.

Absent is not zero
------------------
A rate with no denominator is ``None`` and renders as "not measured". This is
not fussiness: ``0.0`` in a precision column reads as "the agent got every one
of these wrong", and "the agent never predicted this class" is a different
fact with a different remedy.

Determinism
-----------
Bootstrap confidence intervals resample, so they need a source of randomness,
and a report that has to reproduce byte for byte cannot have an unseeded one.
:data:`BOOTSTRAP_SEED` fixes it, :class:`ReplayScore` records the seed and the
resample count it used, and :func:`score_replay` takes both as arguments so a
caller who wants a different interval can ask for one and have the report say
so.
"""

from __future__ import annotations

import json
import random
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .metrics import extract_checkable_indicators

__all__ = [
    "ABSTENTION_VERDICTS",
    "BOOTSTRAP_RESAMPLES",
    "BOOTSTRAP_SEED",
    "CALIBRATION_BINS",
    "GRADED_DISPOSITIONS",
    "LATENCY_FIELDS",
    "LATENCY_LINE_PREFIX",
    "LATENCY_LINE_PREFIXES",
    "MALICIOUS",
    "MIN_MALICIOUS_FOR_HEADLINE",
    "UNLABELED",
    "CalibrationBin",
    "ClassScore",
    "ReplayScore",
    "SegmentScore",
    "format_replay_report",
    "score_replay",
    "strip_latency",
]

#: The one line of the rendered report that measures the host rather than the
#: agent. Declared here, used by :func:`format_replay_report` to emit it and
#: by :func:`strip_latency` to remove it, so the producer and the remover
#: cannot drift into disagreeing about which line that is.
LATENCY_LINE_PREFIX = "- Mean latency:"

#: Every other rendered line that measures the host. The "time to verdict"
#: section reports the same measurements under the name an operator uses,
#: so it is wall clock too and must be strippable for the same reason: the
#: reproducibility claim is "byte for byte apart from the host figures", and
#: a figure the stripper does not know about silently falsifies it.
LATENCY_LINE_PREFIXES: tuple[str, ...] = (LATENCY_LINE_PREFIX, "- p50:", "- p95:")

#: The matching fields in :meth:`ReplayScore.as_dict`, for the JSON export.
LATENCY_FIELDS: tuple[str, ...] = (
    "mean_latency_ms",
    "p95_latency_ms",
    "time_to_verdict_p50_ms",
    "time_to_verdict_p95_ms",
)

#: The canonical disposition that means "this was a real threat". Written once
#: because "malicious recall" has to mean the same thing in the metric, the
#: renderer and the promotion gate Phase 2 builds on top of it.
MALICIOUS = "true_positive"

#: The four canonical dispositions an analyst can close a finding as. Mirrors
#: ``CANONICAL_DISPOSITIONS`` in ``services/actions``; this package does not
#: import from a service, and ``scripts/check_replay_contract_parity.py``
#: keeps the two in step in both directions.
GRADED_DISPOSITIONS: tuple[str, ...] = (
    MALICIOUS,
    "benign_true_positive",
    "false_positive",
    "benign",
)

#: An analyst who declined to classify. Excluded from accuracy, never guessed.
UNLABELED = "unlabeled"

#: The confidence at which auto-close precision is reported when a caller
#: names no tenant policy. Not a recommendation and not a default the
#: product applies -- closure is governed per tenant by the autonomy policy.
#: It exists so the figure is comparable across runs that did not state one.
DEFAULT_AUTO_CLOSE_THRESHOLD = 0.9

#: Verdicts a closure policy can act on without a human. `true_positive` is
#: absent deliberately: a confirmed attack escalates, it is never closed,
#: which is the rule `siem_writeback` already follows.
_AUTO_CLOSABLE_VERDICTS: frozenset[str] = frozenset({"false_positive", "benign", "benign_true_positive"})

#: Agent outputs that are a refusal to decide rather than a decision. These are
#: abstentions: scored as neither right nor wrong, and counted separately so
#: accuracy and abstention cannot be traded off invisibly. ``escalate`` belongs
#: here for the same reason ``needs_review`` does: both route the alert to a
#: human, which is a decision about who decides, not about what happened.
ABSTENTION_VERDICTS: frozenset[str] = frozenset({"needs_review", "escalate", "unknown", ""})

#: Below this many malicious cases in the test window, no headline accuracy is
#: printed. Set by the plan.
MIN_MALICIOUS_FOR_HEADLINE = 30

#: Reliability-diagram bin edges. Ten equal-width bins over [0, 1].
CALIBRATION_BINS = 10

BOOTSTRAP_RESAMPLES = 1000
BOOTSTRAP_SEED = 20260926


@dataclass(frozen=True)
class ClassScore:
    """Precision and recall for one disposition, with the counts behind them."""

    label: str
    #: Ground-truth occurrences. The denominator of recall.
    support: int
    #: Times the agent predicted this class. The denominator of precision.
    predicted: int
    correct: int
    precision: float | None
    recall: float | None
    f1: float | None


@dataclass(frozen=True)
class CalibrationBin:
    """One reliability bin: how often the agent was right when this sure."""

    lower: float
    upper: float
    count: int
    mean_confidence: float | None
    accuracy: float | None


@dataclass(frozen=True)
class SegmentScore:
    """A per-rule or per-source slice. Small slices are reported, not hidden."""

    key: str
    graded: int
    correct: int
    accuracy: float | None
    malicious_support: int
    malicious_recall: float | None


@dataclass
class ReplayScore:
    """The report. Field order is the reading order the renderers follow."""

    # ---- what was graded -------------------------------------------------
    decisions: int = 0
    labelled: int = 0
    unlabeled: int = 0
    errored: int = 0
    graded: int = 0
    abstained: int = 0

    # ---- the number an operator is deciding on ---------------------------
    malicious_support: int = 0
    malicious_recall: float | None = None
    malicious_recall_ci: tuple[float, float] | None = None
    malicious_precision: float | None = None
    #: Malicious cases the agent did not call malicious, as a count and a
    #: rate. Derivable from the confusion matrix and from `1 - recall`,
    #: and published as its own field anyway: a false negative is a
    #: missed attack, and a reader should not have to compute the number
    #: that matters most from the one that reads best.
    false_negatives: int = 0
    false_negative_rate: float | None = None
    #: What the agent said instead, counted. "It abstained on 40" and
    #: "it called 40 benign" are different failures with different fixes.
    false_negative_verdicts: dict[str, int] = field(default_factory=dict)

    # ---- headline, withheld on a thin corpus -----------------------------
    headline_accuracy: float | None = None
    headline_accuracy_ci: tuple[float, float] | None = None
    headline_withheld_reason: str | None = None

    # ---- the figures that survive an imbalanced corpus -------------------
    #
    # Plain accuracy on a queue that is 90% false positive is 0.90 for an
    # agent that reads nothing. These three are published together, always,
    # because the first two are only interpretable against the third: a
    # reader given 0.74 alone cannot tell whether the agent is good or the
    # queue is.
    #
    # Balanced accuracy is the unweighted mean recall over the classes the
    # corpus actually holds. Averaging over all four canonical dispositions
    # would cap a perfect agent at 0.5 on a two-class corpus, which is a
    # scoring bug that reads as a model failure.
    balanced_accuracy: float | None = None
    #: Matthews correlation. The one headline figure the base rate cannot
    #: buy: 0.0 for any predictor with no relationship to the label, +1 for
    #: perfect agreement, -1 for perfect disagreement. Computed over the
    #: multi-class confusion matrix, so it covers all four dispositions
    #: rather than collapsing them to malicious/not.
    matthews_corrcoef: float | None = None
    majority_class_accuracy: float | None = None
    majority_class_label: str | None = None

    #: Wilson score interval on malicious recall, beside the bootstrap one.
    #:
    #: Closed-form rather than resampled, for two reasons. It is
    #: deterministic for a given (successes, trials), so two runs over one
    #: corpus cannot disagree; and it keeps width at the boundary, where a
    #: percentile bootstrap over an all-ones vector returns [1.0, 1.0] and
    #: claims a certainty the sample size does not support.
    malicious_recall_wilson: tuple[float, float] | None = None

    #: "If the tenant let the agent close at confidence >= threshold, what
    #: share of what it closed was really closable?" A malicious case above
    #: the threshold is an attack the platform would have closed by itself,
    #: which is the outcome this number exists to price. `None` rather than
    #: 0.0 when nothing crossed the threshold: 0.0 reads as "it closed
    #: things and got them all wrong".
    auto_close_threshold: float | None = None
    auto_close_considered: int = 0
    auto_close_correct: int = 0
    auto_close_precision: float | None = None
    #: Share of labelled decisions the agent routed to a human instead of
    #: deciding. The same population as `abstention_rate`, named the way an
    #: operator sizing a queue thinks about it.
    escalation_rate: float | None = None

    # ---- time to verdict: reported, never graded -------------------------
    #
    # Latency is a property of the hardware the run happened on, so it must
    # not move a score -- a scoreboard that graded it would rank a faster
    # laptop as a better agent. Published beside the figures and labelled
    # with the hardware by the caller, never inside them.
    time_to_verdict_p50_ms: float | None = None
    time_to_verdict_p95_ms: float | None = None

    # ---- the rest --------------------------------------------------------
    abstention_rate: float | None = None
    per_class: list[ClassScore] = field(default_factory=list)
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    calibration: list[CalibrationBin] = field(default_factory=list)
    expected_calibration_error: float | None = None
    hallucination_rate: float | None = None
    hallucinated_total: int = 0
    indicators_checked: int = 0
    hallucinated_examples: list[str] = field(default_factory=list)
    per_rule: list[SegmentScore] = field(default_factory=list)
    per_source: list[SegmentScore] = field(default_factory=list)

    # ---- cost and latency, reported not scored ---------------------------
    total_tokens: int = 0
    measured_usd: float | None = None
    estimated_usd: float | None = None
    unpriced_calls: int = 0
    mean_latency_ms: float | None = None
    p95_latency_ms: float | None = None
    models: list[str] = field(default_factory=list)

    # ---- provenance ------------------------------------------------------
    bootstrap_resamples: int = BOOTSTRAP_RESAMPLES
    bootstrap_seed: int = BOOTSTRAP_SEED
    min_malicious_for_headline: int = MIN_MALICIOUS_FOR_HEADLINE

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _ratio(numerator: int, denominator: int) -> float | None:
    """A rate, or ``None`` when there was nothing to divide by."""
    return (numerator / denominator) if denominator else None


def _f1(precision: float | None, recall: float | None) -> float | None:
    if precision is None or recall is None or (precision + recall) == 0:
        return None
    return 2 * precision * recall / (precision + recall)


def _wilson_interval(successes: int, trials: int, *, z: float = 1.959963984540054) -> tuple[float, float] | None:
    """Wilson score interval at 95%, clamped to [0, 1].

    `z` is the two-sided 97.5th percentile of the standard normal, written
    out rather than imported so this package keeps no numeric dependency.

    The interval is centred on a shrunk estimate rather than on the raw
    proportion, which is exactly why it keeps width at 0 and 1 where the
    normal approximation and a percentile bootstrap both collapse.
    """
    if trials <= 0:
        return None
    phat = successes / trials
    denom = 1.0 + z * z / trials
    centre = (phat + z * z / (2 * trials)) / denom
    margin = (z / denom) * ((phat * (1.0 - phat) / trials + z * z / (4 * trials * trials)) ** 0.5)
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def _matthews(matrix: dict[str, dict[str, int]], labels: list[str]) -> float | None:
    """Multi-class Matthews correlation over the confusion matrix.

    The K-class generalisation (Gorodkin), which reduces to the familiar
    2x2 formula when K is 2. Abstentions are excluded by the caller: an
    alert routed to a human is not a wrong prediction, and counting it as
    one would make an appropriately humble agent look like a bad one.

    Two different zeros, kept apart:

    * **no rows at all** -> `None`. Nothing was measured, and 0.0 would
      read as "measured, and no relationship".
    * **rows, but the predictor or the labels are constant** -> `0.0`.
      The denominator is zero here too, but the answer is not unknown: a
      predictor that says one thing to everything has exactly zero
      correlation with the label, which is the finding this coefficient
      exists to surface. Returning `None` would hide the constant-answer
      agent behind "not measurable", and that agent is the whole reason
      plain accuracy was not enough.
    """
    total = sum(matrix[t].get(p, 0) for t in labels for p in labels)
    if total == 0:
        return None
    correct = sum(matrix[label].get(label, 0) for label in labels)
    actual = {label: sum(matrix[label].get(p, 0) for p in labels) for label in labels}
    predicted = {label: sum(matrix[t].get(label, 0) for t in labels) for label in labels}

    cov_xy = correct * total - sum(actual[label] * predicted[label] for label in labels)
    cov_xx = total * total - sum(predicted[label] ** 2 for label in labels)
    cov_yy = total * total - sum(actual[label] ** 2 for label in labels)
    denom = (cov_xx * cov_yy) ** 0.5
    if denom == 0:
        return 0.0
    return cov_xy / denom


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def _bootstrap_ci(
    outcomes: list[int],
    *,
    resamples: int,
    seed: int,
    confidence: float = 0.95,
) -> tuple[float, float] | None:
    """Percentile bootstrap over a list of 0/1 outcomes.

    Returns ``None`` below five observations. An interval over three samples
    is arithmetic, not evidence, and printing one invites a reader to treat a
    handful of cases as a measurement.
    """
    if len(outcomes) < 5 or resamples <= 0:
        return None
    rng = random.Random(seed)
    n = len(outcomes)
    means: list[float] = []
    for _ in range(resamples):
        total = 0
        for _ in range(n):
            total += outcomes[rng.randrange(n)]
        means.append(total / n)
    means.sort()
    tail = (1.0 - confidence) / 2.0
    low = means[min(len(means) - 1, int(tail * len(means)))]
    high = means[min(len(means) - 1, int((1.0 - tail) * len(means)))]
    return (round(low, 6), round(high, 6))


def _evidence_text(decision: dict[str, Any]) -> str:
    """Everything the agent was given, flattened, for the hallucination check."""
    return repr(decision.get("evidence") or {}).lower()


def _reasoning_text(decision: dict[str, Any]) -> str:
    parts = [*(decision.get("findings") or []), *(decision.get("confidence_basis") or [])]
    return " ".join(str(p) for p in parts)


def _segment(
    decisions: list[dict[str, Any]],
    key_name: str,
) -> list[SegmentScore]:
    """Group graded decisions by a field and score each group."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for decision in decisions:
        key = str(decision.get(key_name) or "unattributed")
        groups.setdefault(key, []).append(decision)

    scores: list[SegmentScore] = []
    for key in sorted(groups):
        rows = groups[key]
        answered = [d for d in rows if not _is_abstention(d)]
        correct = sum(1 for d in answered if _is_correct(d))
        malicious = [d for d in rows if d.get("expected_disposition") == MALICIOUS]
        malicious_hit = sum(1 for d in malicious if d.get("verdict") == MALICIOUS)
        scores.append(
            SegmentScore(
                key=key,
                graded=len(answered),
                correct=correct,
                accuracy=_ratio(correct, len(answered)),
                malicious_support=len(malicious),
                malicious_recall=_ratio(malicious_hit, len(malicious)),
            )
        )
    return scores


def _is_abstention(decision: dict[str, Any]) -> bool:
    return str(decision.get("verdict") or "") in ABSTENTION_VERDICTS


def _is_correct(decision: dict[str, Any]) -> bool:
    return decision.get("verdict") == decision.get("expected_disposition")


def score_replay(
    decisions: list[dict[str, Any]],
    *,
    bootstrap_resamples: int = BOOTSTRAP_RESAMPLES,
    bootstrap_seed: int = BOOTSTRAP_SEED,
    auto_close_threshold: float = DEFAULT_AUTO_CLOSE_THRESHOLD,
) -> ReplayScore:
    """Grade a replay run's decisions against the analysts' own labels.

    ``decisions`` are :meth:`app.replay.runner.ReplayDecision.as_dict`
    payloads. Plain dicts rather than an imported type, because this package
    must stay installable without a service on the path: a vendor grading
    their own agent against their own history should not need ``services/``.

    Three populations, kept apart on purpose:

    * **errored** - triage refused the finding. Neither a verdict nor an
      abstention. Folding these into abstentions would let a run that crashed
      on every hard case look appropriately humble.
    * **unlabeled** - the analyst declined to classify. Excluded from
      accuracy entirely, and counted so a customer whose history is mostly
      unlabeled sees that rather than a confident number over a remnant.
    * **graded** - everything else, split into answered and abstained.
    """
    score = ReplayScore(
        decisions=len(decisions),
        bootstrap_resamples=bootstrap_resamples,
        bootstrap_seed=bootstrap_seed,
    )

    errored = [d for d in decisions if d.get("error")]
    usable = [d for d in decisions if not d.get("error")]
    labelled = [d for d in usable if d.get("labelled") and d.get("expected_disposition") in GRADED_DISPOSITIONS]
    score.errored = len(errored)
    score.unlabeled = len(usable) - len(labelled)
    score.labelled = len(labelled)

    # Hallucination spans every decision that produced reasoning, answered or
    # not, and errored or not: an agent that invented an address before
    # failing has still invented it.
    checked = 0
    hallucinated: list[str] = []
    for decision in decisions:
        corpus = _evidence_text(decision)
        for indicator in extract_checkable_indicators(_reasoning_text(decision)):
            checked += 1
            if indicator.lower() not in corpus:
                hallucinated.append(indicator)
    score.indicators_checked = checked
    score.hallucinated_total = len(hallucinated)
    score.hallucination_rate = _ratio(len(hallucinated), checked)
    score.hallucinated_examples = sorted(set(hallucinated))[:20]

    # Cost and latency describe the whole run, including the decisions that
    # are not graded: they were still paid for.
    score.total_tokens = sum(int(d.get("tokens") or 0) for d in decisions)
    measured = [float(d["measured_usd"]) for d in decisions if d.get("measured_usd") is not None]
    estimated = [float(d["estimated_usd"]) for d in decisions if d.get("estimated_usd") is not None]
    score.measured_usd = round(sum(measured), 6) if measured else None
    score.estimated_usd = round(sum(estimated), 6) if estimated else None
    score.unpriced_calls = sum(int(d.get("unpriced_calls") or 0) for d in decisions)
    latencies = [float(d.get("latency_ms") or 0.0) for d in decisions]
    score.mean_latency_ms = (sum(latencies) / len(latencies)) if latencies else None
    score.p95_latency_ms = _percentile(latencies, 0.95)
    # Named for what an operator calls it. Same measurements as the two
    # fields above; published under the plan's own term so the scorecard
    # and the page agree about which number is "time to verdict".
    score.time_to_verdict_p50_ms = _percentile(latencies, 0.50)
    score.time_to_verdict_p95_ms = score.p95_latency_ms
    score.models = sorted({str(m) for d in decisions for m in (d.get("resolved_models") or [])})

    if not labelled:
        score.headline_withheld_reason = (
            "No finding in the test window carried an analyst disposition this platform can name, so there is nothing to grade against."
        )
        return score

    answered = [d for d in labelled if not _is_abstention(d)]
    score.abstained = len(labelled) - len(answered)
    score.graded = len(answered)
    score.abstention_rate = _ratio(score.abstained, len(labelled))

    # ---- confusion matrix, over labelled decisions including abstentions --
    matrix: dict[str, dict[str, int]] = {
        expected: dict.fromkeys([*GRADED_DISPOSITIONS, "abstained"], 0) for expected in GRADED_DISPOSITIONS
    }
    for decision in labelled:
        expected = str(decision.get("expected_disposition"))
        predicted = "abstained" if _is_abstention(decision) else str(decision.get("verdict") or "")
        if predicted not in matrix[expected]:
            # A verdict outside the taxonomy. Recorded under its own column
            # rather than dropped, because a column nobody expected is a
            # finding about the agent.
            for row in matrix.values():
                row.setdefault(predicted, 0)
        matrix[expected][predicted] += 1
    score.confusion = matrix

    # ---- per class, precision over answered only -------------------------
    support = Counter(str(d.get("expected_disposition")) for d in labelled)
    predicted_counts = Counter(str(d.get("verdict") or "") for d in answered)
    for label in GRADED_DISPOSITIONS:
        correct = sum(1 for d in answered if d.get("verdict") == label and _is_correct(d))
        precision = _ratio(correct, predicted_counts.get(label, 0))
        recall = _ratio(correct, support.get(label, 0))
        score.per_class.append(
            ClassScore(
                label=label,
                support=support.get(label, 0),
                predicted=predicted_counts.get(label, 0),
                correct=correct,
                precision=precision,
                recall=recall,
                f1=_f1(precision, recall),
            )
        )

    malicious_rows = [d for d in labelled if d.get("expected_disposition") == MALICIOUS]
    score.malicious_support = len(malicious_rows)
    malicious_class = next(c for c in score.per_class if c.label == MALICIOUS)
    score.malicious_recall = malicious_class.recall
    score.malicious_precision = malicious_class.precision
    # Recall's outcomes are per malicious case: did the agent call it
    # malicious? An abstention counts against recall, because an alert routed
    # to a human was not caught by the agent.
    score.malicious_recall_ci = _bootstrap_ci(
        [1 if d.get("verdict") == MALICIOUS else 0 for d in malicious_rows],
        resamples=bootstrap_resamples,
        seed=bootstrap_seed,
    )

    # False negatives, named. Every one is an attack the agent let
    # through, which is the outcome an operator is actually buying
    # against, and `1 - recall` is a worse way to say it.
    missed = [d for d in malicious_rows if d.get("verdict") != MALICIOUS]
    score.false_negatives = len(missed)
    score.false_negative_rate = _ratio(len(missed), len(malicious_rows))
    verdicts: dict[str, int] = {}
    for d in missed:
        key = str(d.get("verdict") or "") or "(empty)"
        verdicts[key] = verdicts.get(key, 0) + 1
    score.false_negative_verdicts = dict(sorted(verdicts.items()))

    score.malicious_recall_wilson = _wilson_interval(
        sum(1 for d in malicious_rows if d.get("verdict") == MALICIOUS),
        len(malicious_rows),
    )

    # ---- figures that survive an imbalanced corpus ------------------------
    #
    # Over `answered` only, matching per-class precision above: an
    # abstention is a decision to involve a human, not a wrong prediction.
    # It is still visible, as `escalation_rate` directly below.
    present = [label for label in GRADED_DISPOSITIONS if support.get(label, 0) > 0]
    recalls = [c.recall for c in score.per_class if c.label in present and c.recall is not None]
    score.balanced_accuracy = (sum(recalls) / len(recalls)) if recalls else None

    answered_matrix: dict[str, dict[str, int]] = {expected: dict.fromkeys(GRADED_DISPOSITIONS, 0) for expected in GRADED_DISPOSITIONS}
    for decision in answered:
        expected = str(decision.get("expected_disposition"))
        predicted = str(decision.get("verdict") or "")
        if expected in answered_matrix and predicted in answered_matrix[expected]:
            answered_matrix[expected][predicted] += 1
    score.matthews_corrcoef = _matthews(answered_matrix, list(GRADED_DISPOSITIONS))

    # The number every other number has to be read against.
    if support:
        majority = max(support, key=lambda label: support[label])
        score.majority_class_label = majority
        score.majority_class_accuracy = _ratio(support[majority], len(labelled))

    # ---- auto-close precision at the closure threshold --------------------
    score.auto_close_threshold = auto_close_threshold
    closable = [
        d for d in answered if d.get("verdict") in _AUTO_CLOSABLE_VERDICTS and float(d.get("confidence") or 0.0) >= auto_close_threshold
    ]
    score.auto_close_considered = len(closable)
    score.auto_close_correct = sum(1 for d in closable if _is_correct(d))
    score.auto_close_precision = _ratio(score.auto_close_correct, len(closable))

    score.escalation_rate = score.abstention_rate

    # ---- calibration ------------------------------------------------------
    score.calibration, score.expected_calibration_error = _calibration(answered)

    # ---- headline, withheld below the floor -------------------------------
    if score.malicious_support < MIN_MALICIOUS_FOR_HEADLINE:
        score.headline_withheld_reason = (
            f"The test window holds {score.malicious_support} malicious case(s), below the "
            f"{MIN_MALICIOUS_FOR_HEADLINE} this report requires before printing a headline accuracy. "
            f"On a queue where almost everything is a false positive, an agent that calls everything "
            f"benign scores well, so the figure would describe the queue rather than the agent. "
            f"Per-class recall and the confusion matrix below are reported in full."
        )
    elif answered:
        correct = sum(1 for d in answered if _is_correct(d))
        score.headline_accuracy = correct / len(answered)
        score.headline_accuracy_ci = _bootstrap_ci(
            [1 if _is_correct(d) else 0 for d in answered],
            resamples=bootstrap_resamples,
            seed=bootstrap_seed,
        )

    score.per_rule = _segment(labelled, "rule_id")
    score.per_source = _segment(labelled, "vendor")
    return score


def _pct(value: float | None) -> str:
    """A rate as a percentage, or the words that mean there was no denominator.

    "not measured" rather than ``0.0`` everywhere. A zero in a recall column
    says the agent missed every malicious case; no denominator says it was
    never asked. Printing the first when the second is true is the single most
    misleading thing a report of this kind can do.
    """
    return "not measured" if value is None else f"{value * 100:.1f}%"


def _interval(bounds: tuple[float, float] | None) -> str:
    return "not measured" if bounds is None else f"{bounds[0] * 100:.1f}% to {bounds[1] * 100:.1f}%"


def _number(value: float | None) -> str:
    """A bare coefficient, for the figures that are not rates.

    Matthews correlation runs -1 to +1 and the closure threshold is a
    confidence, so neither is a percentage. Same "not measured" rule as
    `_pct`.
    """
    return "not measured" if value is None else f"{value:.2f}"


def _ms(value: float | None) -> str:
    return "not measured" if value is None else f"{value:,.0f} ms"


def format_replay_report(score: ReplayScore, *, method: dict[str, Any] | None = None) -> str:
    """Render the report as Markdown, malicious recall first.

    Deterministic by construction: no timestamps, no host names, no dict
    iteration that is not sorted. A report that reproduces byte for byte is
    the phase's acceptance test, and the easiest way to fail it is a renderer
    that prints "generated at".
    """
    lines: list[str] = ["# Replay evaluation", ""]

    lines += [
        "## What was graded",
        "",
        f"- Decisions replayed: {score.decisions}",
        f"- Carried an analyst label: {score.labelled}",
        f"- Unlabelled, excluded from accuracy: {score.unlabeled}",
        f"- Refused by triage, scored as neither: {score.errored}",
        f"- Answered: {score.graded}. Abstained: {score.abstained} ({_pct(score.abstention_rate)})",
        "",
        "## Recall on malicious",
        "",
        f"- Malicious cases in the test window: {score.malicious_support}",
        f"- Recall: {_pct(score.malicious_recall)} (95% CI {_interval(score.malicious_recall_ci)})",
        f"- Recall, Wilson 95% interval: {_interval(score.malicious_recall_wilson)}",
        f"- Precision: {_pct(score.malicious_precision)}",
        "",
        "## Headline accuracy",
        "",
    ]
    if score.headline_accuracy is None:
        lines += [f"Withheld. {score.headline_withheld_reason}", ""]
    else:
        lines += [
            f"{_pct(score.headline_accuracy)} over {score.graded} answered decisions (95% CI {_interval(score.headline_accuracy_ci)}).",
            "",
        ]

    # Printed immediately under the headline, and never without the
    # baseline. Plain accuracy on a queue that is 90% false positive is
    # 0.90 for an agent that reads nothing; a reader who sees the headline
    # without what a constant would have scored cannot tell the two apart.
    lines += [
        "## Against a constant answer",
        "",
        f"- Majority-class baseline: {_pct(score.majority_class_accuracy)} (always answering `{score.majority_class_label}`)",
        f"- Balanced accuracy: {_pct(score.balanced_accuracy)}",
        f"- Matthews correlation: {_number(score.matthews_corrcoef)}",
        "",
        "Balanced accuracy is the unweighted mean recall over the classes this",
        "corpus holds, so a constant answer scores 0.50 however skewed the queue",
        "is. Matthews correlation is 0.00 for any predictor with no relationship",
        "to the label, which is the one headline figure the base rate cannot buy.",
        "",
        "## Auto-close and escalation",
        "",
        f"- Auto-close precision at confidence >= {_number(score.auto_close_threshold)}:"
        f" {_pct(score.auto_close_precision)}"
        f" over {score.auto_close_considered} decision(s) the policy would have closed",
        f"- Escalation rate: {_pct(score.escalation_rate)}",
        "",
        "A malicious case above the threshold is an attack the platform would",
        "have closed by itself. Nothing above the threshold reports no figure",
        "rather than a zero, which would read as closing things and getting",
        "them all wrong.",
        "",
        "## Time to verdict",
        "",
        f"- p50: {_ms(score.time_to_verdict_p50_ms)}",
        f"- p95: {_ms(score.time_to_verdict_p95_ms)}",
        "",
        "Reported, never graded: latency is a property of the hardware the run",
        "happened on, and a scoreboard that graded it would rank a faster",
        "machine as a better agent.",
        "",
    ]

    lines += ["## Per class", "", "| Disposition | Support | Predicted | Precision | Recall | F1 |", "|---|---|---|---|---|---|"]
    for row in score.per_class:
        lines.append(f"| {row.label} | {row.support} | {row.predicted} | {_pct(row.precision)} | {_pct(row.recall)} | {_pct(row.f1)} |")

    lines += ["", "## Confusion matrix", "", "Rows are the analyst's label, columns the agent's verdict.", ""]
    columns = sorted({column for row in score.confusion.values() for column in row})
    lines.append("| analyst \\ agent | " + " | ".join(columns) + " |")
    lines.append("|---" * (len(columns) + 1) + "|")
    for expected in sorted(score.confusion):
        cells = " | ".join(str(score.confusion[expected].get(column, 0)) for column in columns)
        lines.append(f"| {expected} | {cells} |")

    lines += [
        "",
        "## Calibration",
        "",
        f"Expected calibration error: {_pct(score.expected_calibration_error)}",
        "",
        "| Confidence bin | Decisions | Mean confidence | Accuracy |",
        "|---|---|---|---|",
    ]
    for cbin in score.calibration:
        lines.append(f"| {cbin.lower:.1f} to {cbin.upper:.1f} | {cbin.count} | {_pct(cbin.mean_confidence)} | {_pct(cbin.accuracy)} |")

    lines += [
        "",
        "## Hallucination",
        "",
        f"- Checkable indicators cited: {score.indicators_checked}",
        f"- Absent from the evidence: {score.hallucinated_total} ({_pct(score.hallucination_rate)})",
    ]
    if score.hallucinated_examples:
        lines.append(f"- Examples: {', '.join(score.hallucinated_examples[:10])}")

    breakdowns: tuple[tuple[str, list[SegmentScore]], ...] = (
        ("Per rule", score.per_rule),
        ("Per source", score.per_source),
    )
    for title, segments in breakdowns:
        lines += ["", f"## {title}", "", "| Key | Answered | Accuracy | Malicious | Malicious recall |", "|---|---|---|---|---|"]
        for segment in segments:
            lines.append(
                f"| {segment.key} | {segment.graded} | {_pct(segment.accuracy)} | "
                f"{segment.malicious_support} | {_pct(segment.malicious_recall)} |"
            )

    measured = "not measured" if score.measured_usd is None else f"${score.measured_usd:.6f}"
    estimated = "not measured" if score.estimated_usd is None else f"${score.estimated_usd:.6f}"
    lines += [
        "",
        "## Cost and latency",
        "",
        f"- Tokens: {score.total_tokens}",
        f"- Measured spend: {measured} (list-price estimate for unbilled calls: {estimated}; "
        f"calls with no price at all: {score.unpriced_calls})",
        f"{LATENCY_LINE_PREFIX} {'not measured' if score.mean_latency_ms is None else f'{score.mean_latency_ms:.0f} ms'}, "
        f"p95 {'not measured' if score.p95_latency_ms is None else f'{score.p95_latency_ms:.0f} ms'}",
        f"- Models: {', '.join(score.models) if score.models else 'none, no model call was placed'}",
        "",
        "## Method",
        "",
        f"- Confidence intervals: percentile bootstrap, {score.bootstrap_resamples} resamples, seed {score.bootstrap_seed}.",
        f"- Headline accuracy requires at least {score.min_malicious_for_headline} malicious cases.",
    ]
    if method:
        for key in sorted(method):
            lines.append(f"- {key}: {json.dumps(method[key], sort_keys=True)}")
    lines.append("")
    return "\n".join(lines)


def strip_latency(report: str) -> str:
    """Return the report without the two wall-clock latency figures.

    Everything else in this report is a property of the input and the code,
    so two runs over one pinned window reproduce it byte for byte. Mean and
    p95 latency are not: they measure the machine the replay ran on, and they
    will differ between two runs on the same host, let alone two hosts.

    So the reproducibility claim is stated precisely rather than loosely. The
    report reproduces byte for byte **apart from these two figures**, and this
    function is what produces the artefact that claim is about. It removes the
    line :data:`LATENCY_LINE_PREFIX` names rather than matching on the word
    "latency" anywhere, because a future section that discusses latency in
    prose must not be silently deleted from an operator's export.

    The line is replaced rather than dropped, so the surrounding structure and
    the line count are unchanged and a diff of two reports points at content
    rather than at an offset.
    """

    def _strip(line: str) -> str:
        for prefix in LATENCY_LINE_PREFIXES:
            if line.startswith(prefix):
                return f"{prefix} excluded from this export (wall clock, not reproducible)"
        return line

    return "\n".join(_strip(line) for line in report.split("\n"))


def _calibration(answered: list[dict[str, Any]]) -> tuple[list[CalibrationBin], float | None]:
    """Reliability bins and expected calibration error.

    ECE is the support-weighted mean gap between confidence and accuracy
    across the bins. Empty bins contribute nothing and are still emitted, so
    the diagram shows where an agent never expressed a confidence rather than
    silently closing the gap.
    """
    if not answered:
        return [], None

    width = 1.0 / CALIBRATION_BINS
    bins: list[CalibrationBin] = []
    weighted_gap = 0.0
    for index in range(CALIBRATION_BINS):
        lower = index * width
        upper = lower + width
        # The last bin is closed at 1.0 so a confidence of exactly 1.0 lands
        # somewhere rather than being dropped.
        members = [
            d
            for d in answered
            if lower <= float(d.get("confidence") or 0.0) < upper
            or (index == CALIBRATION_BINS - 1 and float(d.get("confidence") or 0.0) == 1.0)
        ]
        if members:
            mean_conf = sum(float(d.get("confidence") or 0.0) for d in members) / len(members)
            accuracy = sum(1 for d in members if _is_correct(d)) / len(members)
            weighted_gap += len(members) * abs(mean_conf - accuracy)
        else:
            mean_conf = None
            accuracy = None
        bins.append(
            CalibrationBin(
                lower=round(lower, 4),
                upper=round(upper, 4),
                count=len(members),
                mean_confidence=(round(mean_conf, 6) if mean_conf is not None else None),
                accuracy=(round(accuracy, 6) if accuracy is not None else None),
            )
        )
    return bins, round(weighted_gap / len(answered), 6)
