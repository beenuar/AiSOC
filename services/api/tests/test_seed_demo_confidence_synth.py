"""Contract tests for ``_synthesise_confidence`` in the demo seeder.

The demo seeder doesn't run a live fusion service, so it mirrors the
``services/fusion`` ``ConfidenceScorer`` math inline. These tests pin the
mirror so it can't drift silently — if someone rebalances the real scorer
without updating the seeder (or vice versa), the demo would start showing
confidence values that the API contract rejects.

The contract we're guarding:

1. Output shape: ``(int 0-100, label, list[ConfidenceFactor-shaped dict])``.
2. ``label`` is one of ``{"low", "medium", "high"}`` — same strings the
   fusion ``ConfidenceLabel`` enum emits.
3. Each rationale entry has the keys the UI's confidence pill expects
   (``factor``, ``label``, ``value``, ``contribution``, ``weight``).
4. Rationale is sorted by absolute impact descending, so the top driver
   shows up first in the explainability list.
5. Severity dominates: a ``critical`` alert with strong signals scores
   strictly higher than the same alert downgraded to ``info``.

These tests are pure — no DB, no asyncio, no fixtures. They execute the
helper directly.
"""

from __future__ import annotations

import pytest
from app.scripts.seed_demo import _synthesise_confidence

_REQUIRED_KEYS = {"factor", "label", "value", "contribution", "weight"}


# ─── Output shape ─────────────────────────────────────────────────────────────


def test_synthesise_returns_int_label_list_triple() -> None:
    """Top-level shape: ``(int 0-100, label, list)``."""
    score, label, rationale = _synthesise_confidence(
        severity="high",
        ai_score=0.75,
        n_techniques=2,
        n_iocs=3,
        has_threat_intel=True,
    )

    assert isinstance(score, int)
    assert 0 <= score <= 100
    assert label in {"low", "medium", "high"}
    assert isinstance(rationale, list)
    assert len(rationale) >= 1


def test_each_rationale_entry_carries_confidence_factor_keys() -> None:
    """Every rationale row must be ConfidenceFactor-shaped for the UI."""
    _, _, rationale = _synthesise_confidence(
        severity="medium",
        ai_score=0.6,
        n_techniques=1,
        n_iocs=2,
        has_threat_intel=False,
    )

    for entry in rationale:
        missing = _REQUIRED_KEYS - entry.keys()
        assert not missing, f"missing keys in rationale: {missing}"
        assert isinstance(entry["contribution"], int | float)
        assert isinstance(entry["weight"], int | float)
        # Weights are normalised in [0, 1]; contributions in [-1, +1].
        assert 0 <= entry["weight"] <= 1
        assert -1.0 <= entry["contribution"] <= 1.0


def test_rationale_sorted_by_absolute_impact() -> None:
    """Top driver shows up first — UI relies on this ordering."""
    _, _, rationale = _synthesise_confidence(
        severity="critical",
        ai_score=0.9,
        n_techniques=3,
        n_iocs=5,
        has_threat_intel=True,
    )

    impacts = [abs(f["contribution"] * f["weight"]) for f in rationale]
    assert impacts == sorted(impacts, reverse=True)


# ─── Score semantics ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_synthesise_accepts_all_five_severity_tiers(severity: str) -> None:
    """All v1.5 severity tiers must produce a valid score — including info."""
    score, label, rationale = _synthesise_confidence(
        severity=severity,
        ai_score=0.5,
        n_techniques=1,
        n_iocs=1,
        has_threat_intel=False,
    )

    assert 0 <= score <= 100
    assert label in {"low", "medium", "high"}
    # The severity row must surface in the rationale verbatim.
    severity_entries = [f for f in rationale if f["factor"] == "severity"]
    assert len(severity_entries) == 1
    assert severity_entries[0]["value"] == severity


def test_critical_beats_info_when_other_signals_equal() -> None:
    """A critical alert should out-score the same alert downgraded to info.

    Severity is one of seven factors but it's the largest single driver of
    confidence at the extremes of the ladder, so this asymmetry must hold.
    If a refactor flips the sign on ``_SEVERITY_CONTRIBUTION``, this test
    catches it.
    """
    common = {
        "ai_score": 0.7,
        "n_techniques": 2,
        "n_iocs": 3,
        "has_threat_intel": True,
    }
    crit_score, _, _ = _synthesise_confidence(severity="critical", **common)
    info_score, _, _ = _synthesise_confidence(severity="info", **common)
    assert crit_score > info_score


def test_threat_intel_match_lifts_score_over_no_match() -> None:
    """TI match must be a positive driver — same alert, different TI signal."""
    common = {
        "severity": "high",
        "ai_score": 0.6,
        "n_techniques": 2,
        "n_iocs": 2,
    }
    with_ti, _, _ = _synthesise_confidence(has_threat_intel=True, **common)
    without_ti, _, _ = _synthesise_confidence(has_threat_intel=False, **common)
    assert with_ti > without_ti
