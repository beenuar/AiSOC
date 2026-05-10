"""Tests for WS-B3 — Detection management UI backend.

These tests pin the contract the analyst console relies on for:

* ``GET /api/v1/detection/coverage``  — rule-centric MITRE heatmap
* ``POST /api/v1/detection/rules/bulk-toggle`` — bulk enable/disable
* ``GET /api/v1/detection/drift``     — rules that need attention

The HTTP wrappers are thin DB queries that defer all interesting logic to
``_build_coverage``, ``_build_drift``, and ``_coerce_uuid``. Testing the
pure helpers gives full coverage of the heuristics without needing
Postgres or the full FastAPI app, which keeps these tests fast and
trivially runnable in CI on every push.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import pytest
from app.api.v1.endpoints.detection_compat import (
    DRIFT_FP_RATE_THRESHOLD,
    DRIFT_LOW_CONFIDENCE_THRESHOLD,
    DRIFT_STALE_DAYS,
    _build_confidence,
    _build_coverage,
    _build_drift,
    _coerce_uuid,
    _primary_tactic,
)

# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


@dataclass
class FakeRule:
    """Minimal stand-in for ``DetectionRule`` rows.

    The pure helpers only read attributes — they never persist — so a
    plain dataclass with the right field names is enough. We use this
    instead of ``DetectionRule`` directly so tests don't drag in the ORM
    machinery.
    """

    id: uuid.UUID = field(default_factory=uuid.uuid4)
    name: str = "Rule"
    severity: str = "medium"
    status: str = "active"  # "active" | "inactive" | "testing"
    confidence: int = 50
    fp_rate: float = 0.0
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    last_triggered: datetime | None = None


# ---------------------------------------------------------------------------
# _primary_tactic
# ---------------------------------------------------------------------------


class TestPrimaryTactic:
    """We deterministically pick the first declared tactic for plotting."""

    def test_picks_first_tactic(self):
        rule = FakeRule(mitre_tactics=["execution", "initial-access"])
        assert _primary_tactic(rule) == "execution"

    def test_returns_none_when_no_tactics(self):
        rule = FakeRule(mitre_tactics=[])
        assert _primary_tactic(rule) is None

    def test_handles_falsy_first_entry(self):
        rule = FakeRule(mitre_tactics=["", "execution"])
        assert _primary_tactic(rule) is None


# ---------------------------------------------------------------------------
# _build_coverage
# ---------------------------------------------------------------------------


class TestBuildCoverage:
    """Coverage heatmap should reflect the enabled-rule distribution."""

    def test_empty_library(self):
        cov = _build_coverage([])
        assert cov.tactics == []
        assert cov.cells == []
        assert cov.summary.totalRules == 0
        assert cov.summary.activeRules == 0
        assert cov.summary.coveredTechniques == 0

    def test_single_active_rule_one_technique(self):
        rule = FakeRule(
            status="active",
            mitre_tactics=["execution"],
            mitre_techniques=["T1059"],
        )
        cov = _build_coverage([rule])
        assert cov.tactics == ["execution"]
        assert len(cov.cells) == 1
        cell = cov.cells[0]
        assert cell.techniqueId == "T1059"
        assert cell.tactic == "execution"
        assert cell.activeRules == 1
        assert cell.inactiveRules == 0
        assert cell.totalRules == 1
        assert cov.summary.activeRules == 1
        assert cov.summary.coveredTechniques == 1

    def test_inactive_rule_does_not_count_as_covered(self):
        # A disabled rule shouldn't paint a technique as "covered" — that's
        # the whole point of the heatmap surfacing tuning gaps.
        rule = FakeRule(
            status="inactive",
            mitre_tactics=["execution"],
            mitre_techniques=["T1059"],
        )
        cov = _build_coverage([rule])
        assert len(cov.cells) == 1
        assert cov.cells[0].activeRules == 0
        assert cov.cells[0].inactiveRules == 1
        # The technique appears in the grid (so analysts can re-enable
        # it) but coveredTechniques is 0.
        assert cov.summary.coveredTechniques == 0
        assert cov.summary.techniques == 1

    def test_multiple_rules_same_technique_aggregate(self):
        rules = [
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="inactive", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
        ]
        cov = _build_coverage(rules)
        assert len(cov.cells) == 1
        cell = cov.cells[0]
        assert cell.activeRules == 2
        assert cell.inactiveRules == 1
        assert cell.totalRules == 3

    def test_unmapped_rules_count_in_summary_but_not_in_cells(self):
        # Rules without a technique mapping shouldn't appear on the
        # heatmap (we have nothing to plot), but they still count toward
        # totalRules so the analyst sees the right library size.
        rules = [
            FakeRule(status="active", mitre_techniques=[]),
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
        ]
        cov = _build_coverage(rules)
        assert cov.summary.totalRules == 2
        assert cov.summary.activeRules == 2
        assert len(cov.cells) == 1  # only the mapped technique
        assert cov.summary.techniques == 1

    def test_skips_blank_technique_strings(self):
        # JSONB columns occasionally contain stray empty strings; they
        # shouldn't end up as their own grid cell.
        rule = FakeRule(
            status="active",
            mitre_techniques=["", "T1059", "  "],
            mitre_tactics=["execution"],
        )
        cov = _build_coverage([rule])
        assert [c.techniqueId for c in cov.cells] == ["T1059"]

    def test_cells_sorted_for_stable_rendering(self):
        # Heatmap cells must be returned in a stable order so the UI
        # doesn't shuffle rows on every refresh.
        rules = [
            FakeRule(status="active", mitre_techniques=["T1059"], mitre_tactics=["execution"]),
            FakeRule(status="active", mitre_techniques=["T1003"], mitre_tactics=["credential-access"]),
            FakeRule(status="active", mitre_techniques=["T1566"], mitre_tactics=["initial-access"]),
        ]
        cov = _build_coverage(rules)
        # First by tactic alphabetical, then by technique id.
        tactics_in_order = [c.tactic for c in cov.cells]
        assert tactics_in_order == sorted(tactics_in_order)


# ---------------------------------------------------------------------------
# _build_drift
# ---------------------------------------------------------------------------


class TestBuildDrift:
    """Drift inbox surfaces rules that need analyst attention."""

    NOW = datetime(2026, 5, 9, tzinfo=UTC)

    def test_empty_library(self):
        out = _build_drift([], now=self.NOW)
        assert out.entries == []
        assert out.summary.total == 0

    def test_clean_rule_does_not_appear(self):
        # Active, low FP, recently triggered, decent confidence → nothing
        # to flag.
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.05,
            last_triggered=self.NOW - timedelta(days=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.entries == []
        assert out.summary.total == 0

    def test_high_fp_rate_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.05,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "high_fp_rate" in out.entries[0].issues
        assert out.summary.highFpRate == 1

    def test_low_confidence_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD - 1,
            fp_rate=0.0,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "low_confidence" in out.entries[0].issues
        assert out.summary.lowConfidence == 1

    def test_stale_active_rule_flags_rule(self):
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.0,
            last_triggered=self.NOW - timedelta(days=DRIFT_STALE_DAYS + 1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "stale" in out.entries[0].issues
        assert out.entries[0].daysSinceTriggered == DRIFT_STALE_DAYS + 1

    def test_active_rule_never_triggered_is_stale(self):
        # A rule that's been enabled long enough to expect a trigger but
        # has none recorded — likely broken or noisy syntax.
        rule = FakeRule(status="active", confidence=80, fp_rate=0.0, last_triggered=None)
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "stale" in out.entries[0].issues
        assert out.entries[0].daysSinceTriggered is None

    def test_inactive_rule_is_never_stale(self):
        # A disabled rule with no recent triggers is *expected* — don't
        # nag analysts about it.
        rule = FakeRule(
            status="inactive",
            confidence=80,
            fp_rate=0.0,
            last_triggered=None,
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.entries == []

    def test_inactive_rule_with_high_fp_still_flagged(self):
        # …but a disabled rule with a bad FP history still surfaces so
        # someone can clean it up rather than letting it rot in the DB.
        rule = FakeRule(
            status="inactive",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.1,
            last_triggered=None,
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        assert "high_fp_rate" in out.entries[0].issues
        assert "stale" not in out.entries[0].issues
        assert out.entries[0].enabled is False

    def test_multiple_issues_aggregated(self):
        rule = FakeRule(
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
        )
        out = _build_drift([rule], now=self.NOW)
        assert len(out.entries) == 1
        issues = set(out.entries[0].issues)
        assert issues == {"high_fp_rate", "low_confidence", "stale"}

    def test_entries_sorted_worst_first(self):
        # 3-issue rule beats 1-issue rule; within the same issue count,
        # higher severity wins.
        rule_a = FakeRule(
            name="aa",
            status="active",
            confidence=80,
            fp_rate=DRIFT_FP_RATE_THRESHOLD + 0.05,
            last_triggered=self.NOW - timedelta(hours=1),
        )
        rule_b = FakeRule(
            name="bb",
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
            severity="critical",
        )
        rule_c = FakeRule(
            name="cc",
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=90),
            severity="medium",
        )
        out = _build_drift([rule_a, rule_b, rule_c], now=self.NOW)
        names_in_order = [e.name for e in out.entries]
        assert names_in_order == ["bb", "cc", "aa"]

    def test_summary_counts_each_issue_independently(self):
        # A rule with 2 issues contributes to 2 counters, not just 1.
        rule = FakeRule(
            status="active",
            confidence=10,
            fp_rate=0.5,
            last_triggered=self.NOW - timedelta(days=1),
        )
        out = _build_drift([rule], now=self.NOW)
        assert out.summary.total == 1  # one entry…
        assert out.summary.highFpRate == 1
        assert out.summary.lowConfidence == 1
        assert out.summary.stale == 0  # …recent trigger so not stale.

    def test_handles_naive_datetime(self):
        # Some DB drivers return naive datetimes — make sure we don't
        # blow up on tz-mixing.
        rule = FakeRule(
            status="active",
            confidence=80,
            fp_rate=0.0,
            last_triggered=datetime(2026, 5, 1),  # naive
        )
        out = _build_drift([rule], now=self.NOW)
        # 8 days ago → not stale at default threshold.
        assert out.entries == []


# ---------------------------------------------------------------------------
# _coerce_uuid
# ---------------------------------------------------------------------------


class TestCoerceUuid:
    """Bulk-toggle mustn't 422 on a single bad ID — bad IDs go to ``skipped``."""

    def test_valid_uuid_string(self):
        u = uuid.uuid4()
        assert _coerce_uuid(str(u)) == u

    def test_garbage_returns_none(self):
        assert _coerce_uuid("not-a-uuid") is None

    def test_empty_string_returns_none(self):
        assert _coerce_uuid("") is None

    def test_none_input_returns_none(self):
        # The frontend technically can't send ``None``, but defensive
        # coding because pydantic's coercion can produce surprises.
        assert _coerce_uuid(None) is None  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _build_confidence (WS-B3.1 — confidence trends panel)
# ---------------------------------------------------------------------------


class TestBuildConfidence:
    """Histogram + per-tactic averages + worst/best leaderboards.

    The confidence panel is the analyst's "what's brittle in my library?"
    view — it has to be deterministic across calls so the UI doesn't
    flicker when nothing changed, and it has to handle edge cases
    (empty library, all-active, no MITRE coverage) without raising.
    """

    NOW = datetime(2026, 5, 9, tzinfo=UTC)

    def test_empty_library_returns_zeroed_buckets(self):
        # Empty library should still emit all 4 buckets so the UI doesn't
        # have to special-case "no data" — it just renders zeros.
        out = _build_confidence([], now=self.NOW)
        assert out.summary.totalRules == 0
        assert out.summary.activeRules == 0
        assert out.summary.avgConfidence == 0.0
        assert out.summary.medianConfidence == 0
        assert out.summary.lowConfidence == 0
        assert len(out.buckets) == 4
        assert [b.label for b in out.buckets] == ["0–25", "26–50", "51–75", "76–100"]
        assert all(b.count == 0 and b.activeCount == 0 for b in out.buckets)
        assert out.tactics == []
        assert out.lowest == []
        assert out.highest == []

    def test_histogram_bins_inclusively(self):
        # Bucket bounds are inclusive on both sides — 25 lands in 0–25,
        # 26 lands in 26–50. This test pins that contract.
        rules = [
            FakeRule(name="r0", confidence=0),
            FakeRule(name="r25", confidence=25),
            FakeRule(name="r26", confidence=26),
            FakeRule(name="r50", confidence=50),
            FakeRule(name="r51", confidence=51),
            FakeRule(name="r75", confidence=75),
            FakeRule(name="r76", confidence=76),
            FakeRule(name="r100", confidence=100),
        ]
        out = _build_confidence(rules, now=self.NOW)
        counts = {b.label: b.count for b in out.buckets}
        assert counts == {"0–25": 2, "26–50": 2, "51–75": 2, "76–100": 2}

    def test_active_only_count_is_separate(self):
        # The histogram tracks both total and active counts so the UI can
        # render a "active vs disabled" stacked bar without a second call.
        rules = [
            FakeRule(name="active_low", confidence=10, status="active"),
            FakeRule(name="disabled_low", confidence=10, status="inactive"),
            FakeRule(name="active_high", confidence=90, status="active"),
        ]
        out = _build_confidence(rules, now=self.NOW)
        low_bucket = next(b for b in out.buckets if b.label == "0–25")
        high_bucket = next(b for b in out.buckets if b.label == "76–100")
        assert low_bucket.count == 2
        assert low_bucket.activeCount == 1
        assert high_bucket.count == 1
        assert high_bucket.activeCount == 1

    def test_summary_avg_and_median(self):
        rules = [
            FakeRule(confidence=20),
            FakeRule(confidence=40),
            FakeRule(confidence=60),
            FakeRule(confidence=80),
        ]
        out = _build_confidence(rules, now=self.NOW)
        # avg = 50, median (even count) = (40+60)//2 = 50
        assert out.summary.avgConfidence == pytest.approx(50.0)
        assert out.summary.medianConfidence == 50

    def test_median_with_odd_count(self):
        rules = [FakeRule(confidence=c) for c in (10, 30, 50, 70, 90)]
        out = _build_confidence(rules, now=self.NOW)
        assert out.summary.medianConfidence == 50

    def test_low_confidence_count_uses_drift_threshold(self):
        # ``lowConfidence`` is gated on ``DRIFT_LOW_CONFIDENCE_THRESHOLD``
        # so the confidence panel and the drift inbox agree on what "low"
        # means. If the threshold ever changes, both views move together.
        rules = [
            FakeRule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD - 1),
            FakeRule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD),
            FakeRule(confidence=DRIFT_LOW_CONFIDENCE_THRESHOLD + 1),
        ]
        out = _build_confidence(rules, now=self.NOW)
        # Strictly below the threshold counts as low; at-or-above does not.
        assert out.summary.lowConfidence == 1

    def test_active_avg_excludes_disabled(self):
        # Average across all rules vs. active-only should diverge once a
        # disabled rule pulls the overall average down.
        rules = [
            FakeRule(confidence=100, status="active"),
            FakeRule(confidence=100, status="active"),
            FakeRule(confidence=0, status="inactive"),
        ]
        out = _build_confidence(rules, now=self.NOW)
        assert out.summary.avgConfidence == pytest.approx(200 / 3, abs=0.01)
        assert out.summary.avgConfidenceActive == pytest.approx(100.0)

    def test_per_tactic_averages_sorted_worst_first(self):
        # Multiple tactics → worst-average first so the UI can render the
        # chart without re-sorting on the client.
        rules = [
            FakeRule(confidence=20, mitre_tactics=["exfiltration"]),
            FakeRule(confidence=30, mitre_tactics=["exfiltration"]),
            FakeRule(confidence=80, mitre_tactics=["execution"]),
            FakeRule(confidence=90, mitre_tactics=["execution"]),
        ]
        out = _build_confidence(rules, now=self.NOW)
        assert [t.tactic for t in out.tactics] == ["exfiltration", "execution"]
        ex = next(t for t in out.tactics if t.tactic == "exfiltration")
        assert ex.rules == 2
        assert ex.avgConfidence == pytest.approx(25.0)

    def test_rules_without_tactic_skipped_in_per_tactic(self):
        # A rule with no MITRE tactic still contributes to the histogram
        # and summary, but shouldn't show up in the per-tactic view —
        # we'd be inventing a "no-tactic" pseudo-tactic otherwise.
        rules = [
            FakeRule(confidence=10, mitre_tactics=[]),
            FakeRule(confidence=90, mitre_tactics=["execution"]),
        ]
        out = _build_confidence(rules, now=self.NOW)
        assert out.summary.totalRules == 2
        assert [t.tactic for t in out.tactics] == ["execution"]

    def test_lowest_and_highest_leaderboards(self):
        # ``lowest`` / ``highest`` are top-N by confidence, ascending /
        # descending. We use top_n=2 here so the assertion is tight.
        rules = [
            FakeRule(name="a", confidence=10),
            FakeRule(name="b", confidence=20),
            FakeRule(name="c", confidence=80),
            FakeRule(name="d", confidence=95),
        ]
        out = _build_confidence(rules, now=self.NOW, top_n=2)
        assert [e.name for e in out.lowest] == ["a", "b"]
        assert [e.name for e in out.highest] == ["d", "c"]

    def test_lowest_stable_secondary_sort(self):
        # Tied confidence → stable, alphabetical secondary sort so the
        # leaderboard doesn't flicker between calls.
        rules = [
            FakeRule(name="zebra", confidence=10),
            FakeRule(name="apple", confidence=10),
            FakeRule(name="mango", confidence=10),
        ]
        out = _build_confidence(rules, now=self.NOW, top_n=3)
        assert [e.name for e in out.lowest] == ["apple", "mango", "zebra"]

    def test_top_n_clamped_to_library_size(self):
        # A small library shouldn't crash when top_n is larger than the
        # number of rules — we just return everything.
        rules = [FakeRule(name="only", confidence=50)]
        out = _build_confidence(rules, now=self.NOW, top_n=10)
        assert len(out.lowest) == 1
        assert len(out.highest) == 1

    def test_none_confidence_treated_as_zero(self):
        # ``confidence`` is non-null in the schema but the helper guards
        # against ``None`` defensively (DB drivers can return ``None``
        # for newly inserted rows before the default kicks in).
        rule = FakeRule(name="r", confidence=None)  # type: ignore[arg-type]
        out = _build_confidence([rule], now=self.NOW)
        assert out.summary.avgConfidence == 0.0
        assert out.summary.lowConfidence == 1


# ---------------------------------------------------------------------------
# Threshold sanity (catches accidental regressions in product behavior)
# ---------------------------------------------------------------------------


def test_thresholds_are_documented_constants():
    """Catch accidental changes to the drift thresholds.

    Tuning the thresholds is a product decision; this test exists so that
    if someone tightens them they have to update this assertion *and*
    docs, not silently change the inbox volume.
    """
    assert DRIFT_FP_RATE_THRESHOLD == pytest.approx(0.2)
    assert DRIFT_LOW_CONFIDENCE_THRESHOLD == 40
    assert DRIFT_STALE_DAYS == 30
