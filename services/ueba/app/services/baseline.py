"""Baseline computation service.

Maintains a rolling Welford online-statistics baseline per entity.
On each call to ``update_baseline`` the running mean and variance are
updated without having to re-read the full window of historical events.
"""

from __future__ import annotations

import math
import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ueba import EntityBaseline

# ---------------------------------------------------------------------------
# Welford online statistics helpers
# ---------------------------------------------------------------------------


def _welford_update(
    stats: dict[str, dict[str, float]],
    feature: str,
    value: float,
) -> dict[str, dict[str, float]]:
    """Update incremental mean/variance for *feature* with new *value*.

    Uses Welford's online algorithm:
      n  ← n + 1
      δ  ← x - mean
      mean ← mean + δ/n
      δ2 ← x - mean
      M2 ← M2 + δ·δ2
      variance = M2 / (n−1) for n > 1
    """
    if feature not in stats:
        stats[feature] = {"mean": 0.0, "M2": 0.0, "count": 0}

    s = stats[feature]
    s["count"] += 1
    n = s["count"]
    delta = value - s["mean"]
    s["mean"] += delta / n
    delta2 = value - s["mean"]
    s["M2"] += delta * delta2

    # Compute std from M2
    variance = s["M2"] / (n - 1) if n > 1 else 0.0
    s["std"] = math.sqrt(variance)

    return stats


def compute_z_score(
    stats: dict[str, dict[str, float]],
    feature: str,
    value: float,
) -> float:
    """Return the z-score of *value* given the baseline stats for *feature*."""
    if feature not in stats:
        return 0.0
    s = stats[feature]
    std = s.get("std", 0.0)
    if std < 1e-9:
        return 0.0
    return abs(value - s["mean"]) / std


# ---------------------------------------------------------------------------
# DB-backed baseline service
# ---------------------------------------------------------------------------


class BaselineService:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    async def get_or_create(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
    ) -> EntityBaseline:
        result = await self._db.execute(
            select(EntityBaseline).where(
                EntityBaseline.tenant_id == tenant_id,
                EntityBaseline.entity_type == entity_type,
                EntityBaseline.entity_id == entity_id,
            )
        )
        row = result.scalar_one_or_none()
        if row is None:
            now = datetime.now(UTC)
            row = EntityBaseline(
                tenant_id=tenant_id,
                entity_type=entity_type,
                entity_id=entity_id,
                feature_stats={},
                window_start=now - timedelta(days=settings.baseline_window_days),
                window_end=now,
            )
            self._db.add(row)
            await self._db.flush()
        return row

    async def update(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
        features: dict[str, float],
    ) -> EntityBaseline:
        """Incrementally update the baseline with new feature observations."""
        baseline = await self.get_or_create(tenant_id, entity_type, entity_id)
        stats = dict(baseline.feature_stats)  # copy so SQLAlchemy detects mutation

        for feature, value in features.items():
            stats = _welford_update(stats, feature, value)

        baseline.feature_stats = stats
        baseline.window_end = datetime.now(UTC)
        await self._db.flush()
        return baseline

    async def score_features(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
        features: dict[str, float],
    ) -> dict[str, dict[str, float]]:
        """Return per-feature z-scores (does not mutate the baseline)."""
        baseline = await self.get_or_create(tenant_id, entity_type, entity_id)
        stats = baseline.feature_stats

        scored: dict[str, dict[str, float]] = {}
        for feature, value in features.items():
            z = compute_z_score(stats, feature, value)
            feat_stats = stats.get(feature, {})
            scored[feature] = {
                "value": value,
                "mean": feat_stats.get("mean", 0.0),
                "std": feat_stats.get("std", 0.0),
                "z_score": z,
            }
        return scored
