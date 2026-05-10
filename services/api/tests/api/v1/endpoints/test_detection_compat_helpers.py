"""Pure-function tests for the WS-B3 detection-compat helpers.

The Detections UI relies on three helper functions:

* :func:`detection_compat._build_coverage` – MITRE coverage heatmap
* :func:`detection_compat._build_drift`    – drift inbox
* :func:`detection_compat._build_confidence` – confidence trends panel

All three are intentionally pure — they take a list of in-memory
``DetectionRule`` instances and return a Pydantic response model — so we
can lock in the contract without spinning up a DB. These tests are the
behavioural backstop for the API → frontend bridge.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from app.api.v1.endpoints.detection_compat import (
    DRIFT_FP_RATE_THRESHOLD,
    DRIFT_LOW_CONFIDENCE_THRESHOLD,
    DRIFT_STALE_DAYS,
    _build_confidence,
    _build_coverage,
    _build_drift,
)
from app.models.detection_rule import DetectionRule


def _make_rule(
    *,
    name: str = "Rule",
    status: str = "active",
    confidence: int = 50,
    fp_rate: float = 0.0,
    severity: str = "medium",
    tactics: list[str] | None = None,
    techniques: list[str] | None = None,
    last_triggered: datetime | None = None,
    rule_id: uuid.UUID | None = None,
) -> DetectionRule:
    """Build an in-memory ``DetectionRule`` with sensible defaults.

    We construct via the SQLAlchemy mapped class but never persist — these
    helpers operate on plain Python objects, so attribute access is enough.
    """
    rule = DetectionRule(
        id=rule_id or uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        name=name,
        rule_language="sigma",
        rule_body="title: x",
        category="custom",
        status=status,
        severity=severity,
        confidence=confidence,
        mitre_tactics=tactics or [],
        mitre_techniques=techniques or [],
        fp_rate=fp_rate,
        suppression_config={},
        threshold_config={},
        total_hits=0,
        last_triggered=last_triggered,
        tags=[],
        is_builtin=False,
        version=1,
        provenance={},
    )
    return rule


# ─── _build_confidence ──────────────────────────────────────────────────────


def test_confidence_empty_library_returns_zero_summary_and_empty_buckets() -> None:
    """An empty rule library still returns 4 zero-filled histogram buckets.

    The frontend assumes a fixed four-bucket layout, so we always return
    that shape — even when there's nothing to plot — to avoid an empty
    array conditional in the UI.
    """
    resp = _build_confidence([])

    assert resp.summary.totalRules == 0
    assert resp.summary.activeRules == 0
    assert resp.summary.avgConfidence == 0.0
    assert resp.summary.medianConfidence == 0
    assert resp.summary.lowConfidence == 0
    assert [b.label for b in resp.buckets] == ["0–25", "26–50", "51–75", "76–100"]
    assert all(b.count == 0 and b.activeCount == 0 for b in resp.buckets)
    assert resp.tactics == []
    assert resp.lowest == []
    assert resp.highest == []


def test_confidence_buckets_assign_rules_to_correct_band() -> None:
    """Rules must land in inclusive [floor, ceil] buckets."""
    rules = [
        _make_rule(name="floor", confidence=0),
        _make_rule(name="band1-mid", confidence=20),
        _make_rule(name="band1-edge", confidence=25),
        _make_rule(name="band2-edge", confidence=26),
        _make_rule(name="band3", confidence=70),
        _make_rule(name="band4", confidence=100),
    ]
    resp = _build_confidence(rules)

    by_label = {b.label: b for b in resp.buckets}
    assert by_label["0–25"].count == 3  # 0, 20, 25
    assert by_label["26–50"].count == 1  # 26
    assert by_label["51–75"].count == 1  # 70
    assert by_label["76–100"].count == 1  # 100


def test_confidence_active_count_only_includes_active_rules() -> None:
    """Disabled rules count toward ``count`` but not ``activeCount``.

    This drives the "tall but pale" histogram bars in the UI, which signal
    "lots of rules in this band but most are disabled — clean them up".
    """
    rules = [
        _make_rule(name="enabled-low", status="active", confidence=10),
        _make_rule(name="disabled-low", status="testing", confidence=10),
        _make_rule(name="disabled-low2", status="archived", confidence=10),
    ]
    resp = _build_confidence(rules)

    low_band = next(b for b in resp.buckets if b.label == "0–25")
    assert low_band.count == 3
    assert low_band.activeCount == 1


def test_confidence_summary_averages_match_reference_math() -> None:
    """Average confidences are population means rounded to 2dp."""
    rules = [
        _make_rule(name="a", status="active", confidence=80),
        _make_rule(name="b", status="active", confidence=60),
        _make_rule(name="c", status="testing", confidence=20),
    ]
    resp = _build_confidence(rules)

    # Overall mean = (80 + 60 + 20) / 3 = 53.3333… → 53.33
    assert resp.summary.avgConfidence == 53.33
    # Active mean = (80 + 60) / 2 = 70.0
    assert resp.summary.avgConfidenceActive == 70.0


def test_confidence_median_uses_lower_midpoint_for_even_n() -> None:
    """Even-length lists use ``(lower + upper) // 2`` so result stays int."""
    rules = [
        _make_rule(confidence=10),
        _make_rule(confidence=20),
        _make_rule(confidence=40),
        _make_rule(confidence=80),
    ]
    resp = _build_confidence(rules)
    # sorted = [10, 20, 40, 80] → (20 + 40) // 2 = 30
    assert resp.summary.medianConfidence == 30


def test_confidence_low_count_uses_drift_threshold() -> None:
    """``lowConfidence`` mirrors the drift heuristic for the same threshold.

    Keeping the cutoff in lockstep with the drift inbox means the UI's
    "below trust gate" badge and the drift "low confidence" chip refer to
    the same set of rules — analysts shouldn't have to translate.
    """
    rules = [
        _make_rule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD - 1),  # under
        _make_rule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD),  # at threshold = OK
        _make_rule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD + 10),  # over
    ]
    resp = _build_confidence(rules)
    assert resp.summary.lowConfidence == 1


def test_confidence_per_tactic_drops_unmapped_rules() -> None:
    """Rules without a primary tactic don't pollute the per-tactic chart."""
    rules = [
        _make_rule(name="exec1", confidence=80, tactics=["execution"]),
        _make_rule(name="exec2", confidence=40, tactics=["execution"]),
        _make_rule(name="unmapped", confidence=10, tactics=[]),
    ]
    resp = _build_confidence(rules)

    assert [t.tactic for t in resp.tactics] == ["execution"]
    assert resp.tactics[0].rules == 2
    assert resp.tactics[0].avgConfidence == 60.0


def test_confidence_per_tactic_sorted_worst_first_then_alpha() -> None:
    """Tactics sort by avg ASC so the UI doesn't have to re-sort."""
    rules = [
        _make_rule(name="exec", confidence=90, tactics=["execution"]),
        _make_rule(name="exfil", confidence=20, tactics=["exfiltration"]),
        _make_rule(name="cred", confidence=20, tactics=["credential-access"]),
    ]
    resp = _build_confidence(rules)
    # 20 < 90, ties broken alphabetically
    assert [t.tactic for t in resp.tactics] == [
        "credential-access",
        "exfiltration",
        "execution",
    ]


def test_confidence_lowest_and_highest_lists_are_capped_and_ordered() -> None:
    """Worst rules listed asc, best listed desc, both capped at top_n."""
    rules = [_make_rule(name=f"rule-{c:03d}", confidence=c) for c in range(0, 100, 10)]
    resp = _build_confidence(rules, top_n=3)

    assert [e.confidence for e in resp.lowest] == [0, 10, 20]
    assert [e.confidence for e in resp.highest] == [90, 80, 70]


def test_confidence_lowest_uses_stable_secondary_sort_by_name() -> None:
    """Identical scores must be ordered deterministically by name.

    Without this, two consecutive ``GET /confidence`` calls could reorder
    rules with the same confidence, causing the worst-offenders list to
    flicker in the UI.
    """
    rules = [
        _make_rule(name="zeta", confidence=10),
        _make_rule(name="alpha", confidence=10),
        _make_rule(name="mu", confidence=10),
    ]
    resp = _build_confidence(rules, top_n=3)

    assert [e.name for e in resp.lowest] == ["alpha", "mu", "zeta"]


def test_confidence_handles_none_confidence_as_zero() -> None:
    """``rule.confidence`` is non-null in the schema, but defensive.

    The model has a default of 50, but ORM round-trips can return None
    in edge cases (e.g. fresh objects before flush). The helper coerces
    to 0 so the histogram math doesn't blow up.
    """
    r = _make_rule(name="null-conf")
    r.confidence = None  # type: ignore[assignment]
    resp = _build_confidence([r])

    assert resp.summary.avgConfidence == 0.0
    assert resp.summary.medianConfidence == 0
    assert resp.buckets[0].count == 1  # 0 falls in the 0–25 band


# ─── _build_drift ───────────────────────────────────────────────────────────


def test_drift_clean_library_returns_empty_inbox() -> None:
    """A library with no FP / confidence / staleness issues is empty."""
    fresh = datetime.now(UTC) - timedelta(days=1)
    rules = [
        _make_rule(
            name="healthy",
            status="active",
            confidence=80,
            fp_rate=0.05,
            last_triggered=fresh,
        ),
    ]
    resp = _build_drift(rules)

    assert resp.entries == []
    assert resp.summary.total == 0


def test_drift_active_rule_with_no_triggers_marked_stale() -> None:
    """Active rules without any trigger history are stale by definition."""
    rules = [
        _make_rule(name="silent-active", status="active", confidence=80, fp_rate=0.01),
    ]
    resp = _build_drift(rules)

    assert resp.summary.stale == 1
    assert resp.entries[0].issues == ["stale"]
    assert resp.entries[0].daysSinceTriggered is None


def test_drift_disabled_rule_is_not_stale_but_other_issues_still_flag() -> None:
    """Disabled rules aren't expected to fire, so absence of triggers != drift.

    But a disabled rule with bad FP / confidence is still surfaced so an
    analyst can clean it up rather than leave dead weight in the library.
    """
    rules = [
        _make_rule(
            name="disabled-noisy",
            status="testing",
            confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD - 5,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.1,
            last_triggered=None,
        ),
    ]
    resp = _build_drift(rules)

    assert resp.summary.stale == 0
    assert resp.summary.lowConfidence == 1
    assert resp.summary.highFpRate == 1
    assert set(resp.entries[0].issues) == {"high_fp_rate", "low_confidence"}


def test_drift_orders_worst_offenders_first() -> None:
    """Sort priority is issues desc → severity desc → fp_rate desc → name asc."""
    fresh = datetime.now(UTC) - timedelta(days=1)
    rules = [
        # 1 issue, low severity
        _make_rule(
            name="a-low-issue",
            status="active",
            confidence=10,
            fp_rate=0.05,
            severity="low",
            last_triggered=fresh,
        ),
        # 3 issues, critical severity
        _make_rule(
            name="b-many-issues",
            status="active",
            confidence=10,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.5,
            severity="critical",
            last_triggered=datetime.now(UTC) - timedelta(days=DRIFT_STALE_DAYS + 5),
        ),
    ]
    resp = _build_drift(rules)

    assert resp.entries[0].name == "b-many-issues"
    assert resp.entries[1].name == "a-low-issue"


# ─── _build_coverage ────────────────────────────────────────────────────────


def test_coverage_counts_rules_with_and_without_techniques() -> None:
    """Unmapped rules count in totals but not in technique cells."""
    rules = [
        _make_rule(
            name="mapped",
            status="active",
            tactics=["execution"],
            techniques=["T1059"],
        ),
        _make_rule(name="unmapped", status="active", tactics=[], techniques=[]),
    ]
    resp = _build_coverage(rules)

    assert resp.summary.totalRules == 2
    assert resp.summary.activeRules == 2
    # Coverage is technique-keyed, so unmapped rules don't appear in cells.
    technique_ids = {cell.techniqueId for cell in resp.cells}
    assert technique_ids == {"T1059"}
