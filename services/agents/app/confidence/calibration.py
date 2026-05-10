"""Calibration math for agent confidence scores.

Two primitives:

- :func:`brier_score` — mean squared error between predicted probabilities and
  binary outcomes. Lower is better; ``0.0`` is perfect, ``0.25`` is the
  "always 0.5" baseline. The eval-harness Brier-score gate uses this.
- :func:`reliability_curve` — bucketed (mean predicted, empirical positive rate,
  count) tuples used to render a reliability diagram and compute Expected
  Calibration Error.

Both functions are pure and dependency-free so they can run in CI without
pulling numpy/sklearn.
"""

from __future__ import annotations

from collections.abc import Sequence


def brier_score(predictions: Sequence[float], outcomes: Sequence[int]) -> float:
    """Return the Brier score for binary outcomes.

    ``predictions`` are floats in ``[0, 1]``. ``outcomes`` are ``0`` or ``1``.

    Raises ``ValueError`` on length mismatch or empty input so the eval suite
    fails loudly instead of silently scoring 0.
    """

    if len(predictions) != len(outcomes):
        raise ValueError(f"predictions/outcomes length mismatch: {len(predictions)} vs {len(outcomes)}")
    if not predictions:
        raise ValueError("brier_score requires at least one sample")

    total = 0.0
    for p, y in zip(predictions, outcomes, strict=True):
        if not 0.0 <= p <= 1.0:
            raise ValueError(f"prediction {p!r} outside [0, 1]")
        if y not in (0, 1):
            raise ValueError(f"outcome {y!r} must be 0 or 1")
        total += (p - y) ** 2
    return total / len(predictions)


def reliability_curve(
    predictions: Sequence[float],
    outcomes: Sequence[int],
    n_buckets: int = 10,
) -> list[tuple[float, float, int]]:
    """Return ``(mean_predicted, empirical_rate, count)`` per probability bucket.

    Buckets are equal-width over ``[0, 1]``. Empty buckets are omitted so
    consumers get a clean reliability diagram.

    A perfectly calibrated classifier produces points along ``y = x``.
    """

    if n_buckets < 1:
        raise ValueError("n_buckets must be >= 1")
    if len(predictions) != len(outcomes):
        raise ValueError("predictions/outcomes length mismatch")

    buckets: list[list[tuple[float, int]]] = [[] for _ in range(n_buckets)]
    for p, y in zip(predictions, outcomes, strict=True):
        idx = min(int(p * n_buckets), n_buckets - 1)
        buckets[idx].append((p, y))

    curve: list[tuple[float, float, int]] = []
    for bucket in buckets:
        if not bucket:
            continue
        mean_pred = sum(p for p, _ in bucket) / len(bucket)
        empirical = sum(y for _, y in bucket) / len(bucket)
        curve.append((mean_pred, empirical, len(bucket)))
    return curve


def expected_calibration_error(
    predictions: Sequence[float],
    outcomes: Sequence[int],
    n_buckets: int = 10,
) -> float:
    """Return Expected Calibration Error (ECE).

    ECE is the weighted-by-bucket-count mean of ``|mean_pred - empirical_rate|``.
    Useful as a single-number calibration headline.
    """

    curve = reliability_curve(predictions, outcomes, n_buckets=n_buckets)
    if not curve:
        return 0.0
    total_count = sum(count for _, _, count in curve)
    if total_count == 0:
        return 0.0
    return sum(abs(mean_pred - empirical) * count for mean_pred, empirical, count in curve) / total_count
