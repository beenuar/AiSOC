"""Characterisation tests for the UEBA scoring core.

`_welford_update`, `compute_z_score`, `_composite_score` and `_risk_level` are
the whole detection path for personal baselines, and none of them were covered
by a test — CI's own comment claims "config loader + risk scoring core" but all
six existing cases live in `test_config.py`.

A baseline that *cannot* be scored — unknown feature, fewer than
`min_baseline_samples` observations, or zero variance — must return `None`, not
`0.0`. `0.0` is indistinguishable from an observation sitting exactly on its own
mean, so the RSS composite read "no signal" as "all clear"; service accounts,
batch jobs and automation users converge on a constant stream and could never
raise an anomaly.
"""
from __future__ import annotations

import math

import pytest
from app.services.baseline import _welford_update, compute_z_score
from app.services.scoring import (
    _composite_score,
    _risk_level,
    _unscoreable_features,
)


def _feed(values: list[float], feature: str = "f") -> dict[str, dict[str, float]]:
    """Replay *values* through the online updater, as the service does per event."""
    stats: dict[str, dict[str, float]] = {}
    for v in values:
        stats = _welford_update(stats, feature, v)
    return stats


def _scored(*z_scores: float) -> dict[str, dict[str, float]]:
    """Build a `score_features`-shaped payload carrying the given z-scores."""
    return {
        f"feature_{i}": {"value": 0.0, "mean": 0.0, "std": 1.0, "z_score": z}
        for i, z in enumerate(z_scores)
    }


class TestWelfordUpdate:
    """The online mean/variance itself is correct — this must not regress."""

    def test_first_observation_has_no_variance_yet(self):
        # n=1: the n-1 denominator is undefined, so the code yields 0.0.
        stats = _feed([10.0])["f"]
        assert stats["count"] == 1
        assert stats["mean"] == pytest.approx(10.0)
        assert stats["M2"] == pytest.approx(0.0)
        assert stats["std"] == pytest.approx(0.0)

    def test_mean_and_sample_std_match_textbook_values(self):
        # sample std of [2,4,4,4,5,5,7,9] is sqrt(32/7) with the n-1 denominator
        stats = _feed([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0])["f"]
        assert stats["count"] == 8
        assert stats["mean"] == pytest.approx(5.0)
        assert stats["std"] == pytest.approx(math.sqrt(32.0 / 7.0))

    def test_constant_stream_keeps_std_at_zero(self):
        # A service account doing the same thing every day drives std -> 0.
        stats = _feed([100.0] * 200)["f"]
        assert stats["count"] == 200
        assert stats["mean"] == pytest.approx(100.0)
        assert stats["std"] == pytest.approx(0.0)

    def test_features_are_tracked_independently(self):
        stats: dict[str, dict[str, float]] = {}
        stats = _welford_update(stats, "bytes_out", 1.0)
        stats = _welford_update(stats, "hosts_touched", 50.0)
        stats = _welford_update(stats, "bytes_out", 3.0)
        assert stats["bytes_out"]["count"] == 2
        assert stats["hosts_touched"]["count"] == 1
        assert stats["bytes_out"]["mean"] == pytest.approx(2.0)


class TestComputeZScoreEstablishedBaseline:
    """The healthy path — an established baseline with real variance.

    These fixtures hold five observations and pass ``min_samples=5`` so they
    exercise the scoring arithmetic rather than the sample-count gate, which
    has its own tests below.
    """

    def test_scores_value_against_baseline(self):
        stats = _feed([10.0, 12.0, 14.0, 11.0, 13.0])
        s = stats["f"]
        assert compute_z_score(stats, "f", 20.0, min_samples=5) == pytest.approx(
            abs(20.0 - s["mean"]) / s["std"]
        )

    def test_deviation_is_absolute_in_both_directions(self):
        stats = _feed([10.0, 12.0, 14.0, 11.0, 13.0])
        assert compute_z_score(stats, "f", 0.0, min_samples=5) > 0.0
        assert compute_z_score(stats, "f", 24.0, min_samples=5) > 0.0

    def test_value_at_the_mean_scores_zero(self):
        # A genuinely normal observation still scores 0.0 — this is the value
        # that must stay distinct from the unscoreable None below.
        stats = _feed([10.0, 12.0, 14.0, 11.0, 13.0])
        assert compute_z_score(
            stats, "f", stats["f"]["mean"], min_samples=5
        ) == pytest.approx(0.0)

    def test_defaults_to_the_configured_sample_gate(self):
        # Thirty observations clear settings.min_baseline_samples unaided.
        stats = _feed([10.0, 12.0, 14.0, 11.0, 13.0] * 6)
        assert compute_z_score(stats, "f", 40.0) is not None


class TestComputeZScoreUnscoreable:
    """Every path that cannot produce a score must return None, not 0.0."""

    def test_never_seen_feature_is_unscoreable(self):
        # No baseline at all for this feature — nothing to deviate from.
        stats = _feed([10.0, 12.0, 14.0] * 10)
        assert compute_z_score(stats, "never_observed", 9999.0) is None

    def test_missing_std_key_is_unscoreable(self):
        # _welford_update seeds {mean, M2, count} and writes "std" at the end,
        # so a partially-initialised entry is reachable.
        stats = {"f": {"mean": 10.0, "M2": 0.0, "count": 100}}
        assert compute_z_score(stats, "f", 9999.0) is None

    def test_too_few_observations_is_unscoreable(self):
        # Cold start: the sample variance carries no information yet.
        stats = _feed([10.0, 12.0, 14.0])
        assert compute_z_score(stats, "f", 9999.0, min_samples=30) is None

    def test_single_observation_is_unscoreable(self):
        # n=1 gives variance 0.0 via the n-1 denominator, so this would have
        # been silently scored as normal even with no sample gate.
        stats = _feed([10.0])
        assert compute_z_score(stats, "f", 9999.0, min_samples=1) is None

    def test_constant_baseline_is_unscoreable_for_extreme_value(self):
        # 50x the established mean over a long, entirely uniform history —
        # the shape a service account produces.
        stats = _feed([100.0] * 200)
        assert compute_z_score(stats, "f", 5000.0) is None

    def test_zero_sample_gate_does_not_make_zero_variance_informative(self):
        # The sample gate and the variance check are independent: disabling the
        # former must not resurrect the degenerate path.
        assert compute_z_score(_feed([7.0]), "f", 8.0, min_samples=0) is None

    def test_unscoreable_is_distinct_from_normal(self):
        """The regression this change exists to prevent."""
        degenerate = _feed([100.0] * 200)
        healthy = _feed([10.0, 12.0, 14.0, 11.0, 13.0] * 6)
        assert compute_z_score(degenerate, "f", 5000.0) is None
        assert compute_z_score(healthy, "f", healthy["f"]["mean"]) == 0.0


class TestCompositeScore:
    """Root-sum-of-squares, capped at 10, with no per-feature denominator."""

    def test_empty_input_returns_zero(self):
        assert _composite_score({}) == 0.0

    def test_is_root_sum_of_squares(self):
        assert _composite_score(_scored(3.0, 4.0)) == pytest.approx(5.0)

    def test_is_capped_at_ten(self):
        assert _composite_score(_scored(20.0, 20.0)) == 10.0

    def test_zero_scored_features_contribute_nothing(self):
        # Why dropping unscoreable features later is numerically neutral:
        # RSS has no denominator, and 0**2 adds nothing to the sum.
        assert _composite_score(_scored(3.0, 4.0)) == pytest.approx(
            _composite_score(_scored(3.0, 4.0, 0.0, 0.0))
        )

    def test_only_unscoreable_features_score_zero(self):
        assert _composite_score({"a": {"z_score": None}, "b": {"z_score": None}}) == 0.0

    def test_unscoreable_features_are_excluded_not_counted(self):
        mixed = {"a": {"z_score": 3.0}, "b": {"z_score": None}}
        assert _composite_score(mixed) == pytest.approx(3.0)

    def test_is_not_normalised_by_feature_count(self):
        # Ten mild deviations outrank three identical ones.
        assert _composite_score(_scored(*([2.0] * 10))) > _composite_score(
            _scored(2.0, 2.0, 2.0)
        )


class TestUnscoreableFeatures:
    """The helper that feeds the operator-visible log line."""

    def test_returns_only_unscoreable_names_sorted(self):
        scored = {
            "zeta": {"z_score": None},
            "alpha": {"z_score": 0.0},
            "mu": {"z_score": None},
        }
        assert _unscoreable_features(scored) == ["mu", "zeta"]

    def test_returns_empty_when_every_feature_scored(self):
        assert _unscoreable_features({"a": {"z_score": 1.5}}) == []


class TestRiskLevel:
    """`critical` and `high` are hard-coded; only `medium` follows settings."""

    @pytest.mark.parametrize(
        "score,expected",
        [
            (9.9, "critical"),
            (6.0, "critical"),
            (5.9, "high"),
            (4.0, "high"),
            (3.9, "medium"),
            (3.0, "medium"),
            (2.9, "low"),
            (0.0, "low"),
        ],
    )
    def test_boundaries(self, score, expected):
        assert _risk_level(score) == expected
