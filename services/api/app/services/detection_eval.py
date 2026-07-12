"""Candidate detection-rule evaluation (Phase 4 — de-circularise the DAC gate).

The Phase 0 reality audit's #1 circular gate: the detection-proposal promote
path shelled out to ``scripts/run_evals.py`` **without ever passing the proposed
rule body**. "Passed" meant the repo's global substrate MITRE accuracy did not
regress — a value entirely independent of the rule under review. A rule that
matches nothing (blind) or matches everything (noisy) sailed through its own
exam.

This module closes that hole. It evaluates the **candidate rule body itself**
against caller-supplied positive and negative fixtures using the *real* runtime
engine (:func:`app.services.rule_engine.execute_rule`) — the same code that runs
the rule in production. The contract is the one every detection must satisfy:

* it MUST fire on every positive fixture (a rule that misses the attack it
  claims to catch is worthless), and
* it MUST stay silent on every negative fixture (a rule that fires on the
  benign near-miss is a false-positive factory).

The proposal approve-gate now requires this verdict to pass, so a bad rule is
rejected on its own merits rather than on an unrelated global metric.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.rule_engine import execute_rule


@dataclass(frozen=True)
class FixtureOutcome:
    """Per-fixture result: did the candidate rule fire, and was that expected?"""

    index: int
    kind: str  # "positive" | "negative"
    fired: bool
    expected_fire: bool
    ok: bool
    error: str | None = None


@dataclass(frozen=True)
class CandidateEvalResult:
    """Outcome of evaluating a candidate rule against its fixtures."""

    passed: bool
    positives_total: int
    positives_fired: int
    negatives_total: int
    negatives_fired: int
    outcomes: list[FixtureOutcome] = field(default_factory=list)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "positives_total": self.positives_total,
            "positives_fired": self.positives_fired,
            "negatives_total": self.negatives_total,
            "negatives_fired": self.negatives_fired,
            "reason": self.reason,
            "outcomes": [
                {
                    "index": o.index,
                    "kind": o.kind,
                    "fired": o.fired,
                    "expected_fire": o.expected_fire,
                    "ok": o.ok,
                    "error": o.error,
                }
                for o in self.outcomes
            ],
        }


def _fires(rule_language: str, rule_body: str, event: dict[str, Any]) -> tuple[bool, str | None]:
    """Run the candidate rule against a single event via the real engine."""
    match = execute_rule(
        rule_id="candidate",
        rule_name="candidate",
        rule_language=rule_language,
        rule_body=rule_body,
        severity="medium",
        events=[event],
    )
    return bool(match.matched), match.error


def evaluate_candidate_rule(
    *,
    rule_language: str,
    rule_body: str,
    positive_fixtures: list[dict[str, Any]],
    negative_fixtures: list[dict[str, Any]],
) -> CandidateEvalResult:
    """Evaluate a candidate rule against its own positive/negative fixtures.

    Returns a :class:`CandidateEvalResult`. ``passed`` is True only when the
    rule fired on *every* positive fixture, stayed silent on *every* negative
    fixture, and at least one positive fixture was supplied (a rule with no
    positive fixture has proven nothing — the gate would be vacuous).
    """
    outcomes: list[FixtureOutcome] = []

    if not positive_fixtures:
        return CandidateEvalResult(
            passed=False,
            positives_total=0,
            positives_fired=0,
            negatives_total=len(negative_fixtures),
            negatives_fired=0,
            reason="no positive fixtures supplied — cannot prove the rule catches anything",
        )

    positives_fired = 0
    for i, event in enumerate(positive_fixtures):
        fired, err = _fires(rule_language, rule_body, event)
        if fired:
            positives_fired += 1
        outcomes.append(FixtureOutcome(index=i, kind="positive", fired=fired, expected_fire=True, ok=fired, error=err))

    negatives_fired = 0
    for i, event in enumerate(negative_fixtures):
        fired, err = _fires(rule_language, rule_body, event)
        if fired:
            negatives_fired += 1
        outcomes.append(FixtureOutcome(index=i, kind="negative", fired=fired, expected_fire=False, ok=not fired, error=err))

    fired_on_all_positives = positives_fired == len(positive_fixtures)
    silent_on_all_negatives = negatives_fired == 0
    passed = fired_on_all_positives and silent_on_all_negatives

    n_pos = len(positive_fixtures)
    n_neg = len(negative_fixtures)
    if passed:
        reason = "rule fired on all positives and stayed silent on all negatives"
    elif not fired_on_all_positives and not silent_on_all_negatives:
        reason = f"rule is both blind ({positives_fired}/{n_pos} positives) and noisy ({negatives_fired}/{n_neg} negatives fired)"
    elif not fired_on_all_positives:
        reason = f"rule is blind: fired on only {positives_fired}/{n_pos} positive fixtures"
    else:
        reason = f"rule is noisy: fired on {negatives_fired}/{n_neg} negative fixtures (must be 0)"

    return CandidateEvalResult(
        passed=passed,
        positives_total=len(positive_fixtures),
        positives_fired=positives_fired,
        negatives_total=len(negative_fixtures),
        negatives_fired=negatives_fired,
        outcomes=outcomes,
        reason=reason,
    )
