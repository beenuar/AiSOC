"""Improvement telemetry — verdict precision over time.

Charts how a tenant's verdict precision improves as institutional memory
accumulates ("your AiSOC is 11% more accurate than at install"). Given a
chronological verdict/override history, we bucket by window and compute
precision per window, then the lift from the first window to the last.

The aggregate anonymized improvement curve (opt-in, via the mesh plumbing) is
published on the benchmark page; per-tenant curves render on the SOC metrics
dashboard.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WindowPrecision:
    window: int
    total: int
    correct: int
    precision: float


@dataclass(frozen=True)
class ImprovementCurve:
    windows: list[WindowPrecision] = field(default_factory=list)
    baseline_precision: float = 0.0
    latest_precision: float = 0.0
    lift: float = 0.0  # latest - baseline (absolute)
    lift_pct: float = 0.0  # relative to baseline

    def to_json(self) -> dict:
        return {
            "windows": [{"window": w.window, "precision": w.precision, "total": w.total} for w in self.windows],
            "baseline_precision": self.baseline_precision,
            "latest_precision": self.latest_precision,
            "lift": self.lift,
            "lift_pct": self.lift_pct,
        }


def precision_over_time(history: list[dict], *, window_size: int = 20) -> ImprovementCurve:
    """Compute precision per window from a chronological history.

    Each row: ``{predicted, actual}`` where a verdict is "correct" when the
    predicted disposition matches the analyst's ground truth. History must be in
    chronological order.
    """
    windows: list[WindowPrecision] = []
    for i in range(0, len(history), window_size):
        chunk = history[i : i + window_size]
        if not chunk:
            continue
        correct = sum(1 for r in chunk if str(r.get("predicted")) == str(r.get("actual")))
        precision = round(correct / len(chunk), 4)
        windows.append(WindowPrecision(window=len(windows), total=len(chunk), correct=correct, precision=precision))

    if not windows:
        return ImprovementCurve()

    baseline = windows[0].precision
    latest = windows[-1].precision
    lift = round(latest - baseline, 4)
    lift_pct = round((lift / baseline) * 100, 1) if baseline > 0 else 0.0
    return ImprovementCurve(
        windows=windows,
        baseline_precision=baseline,
        latest_precision=latest,
        lift=lift,
        lift_pct=lift_pct,
    )
