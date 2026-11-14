"""Anomaly scoring engine.

Combines per-feature z-scores into a composite risk score and classifies
events as low / medium / high / critical anomalies.
"""

from __future__ import annotations

import math
import uuid

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.ueba import UEBAAnomaly
from app.services.baseline import BaselineService
from app.services.peer_group import PeerGroupService

logger = structlog.get_logger(__name__)


def _risk_level(score: float) -> str:
    if score >= 6.0:
        return "critical"
    if score >= 4.0:
        return "high"
    if score >= settings.anomaly_threshold:
        return "medium"
    return "low"


def _unscoreable_features(scored_features: dict[str, dict[str, float | None]]) -> list[str]:
    """Names of features whose baseline could not produce a z-score."""
    return sorted(f for f, s in scored_features.items() if s.get("z_score") is None)


def _composite_score(scored_features: dict[str, dict[str, float | None]]) -> float:
    """Root-sum-of-squares of individual z-scores (capped at 10).

    Features with a ``None`` z-score are excluded rather than counted as zero.
    RSS has no per-feature denominator and ``0.0 ** 2`` adds nothing, so this
    leaves every existing composite unchanged; it only stops an unscoreable
    feature from being *reported* as a normal one.
    """
    z_scores: list[float] = []
    for stats in scored_features.values():
        z = stats.get("z_score")
        if z is not None:
            z_scores.append(z)
    if not z_scores:
        return 0.0
    rss = math.sqrt(sum(z**2 for z in z_scores))
    return min(rss, 10.0)


class ScoringService:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session
        self._baseline = BaselineService(session)
        self._peer = PeerGroupService(session)

    async def score_event(
        self,
        tenant_id: uuid.UUID,
        entity_type: str,
        entity_id: str,
        event_type: str,
        features: dict[str, float],
        source_event_id: str | None = None,
        peer_group_id: str | None = None,
    ) -> UEBAAnomaly | None:
        """Score an event.  Returns a persisted ``UEBAAnomaly`` if anomalous, else None."""

        # 1. Score against personal baseline
        scored = await self._baseline.score_features(tenant_id, entity_type, entity_id, features)
        composite = _composite_score(scored)

        # An entity whose baseline cannot be scored produces no anomaly and,
        # before this, no record of any kind — it simply never appeared. Say so
        # once per event so the gap is visible to an operator instead of
        # looking like a clean result.
        unscoreable = _unscoreable_features(scored)
        if unscoreable:
            logger.info(
                "ueba.features_unscoreable",
                tenant_id=str(tenant_id),
                entity_type=entity_type,
                entity_id=entity_id,
                features=unscoreable,
                scored_count=len(scored) - len(unscoreable),
                hint=(
                    "baseline has zero variance or fewer than "
                    f"{settings.min_baseline_samples} samples; automation and service "
                    "accounts converge here and cannot be scored by deviation"
                ),
            )

        # 2. Update baseline with this event
        await self._baseline.update(tenant_id, entity_type, entity_id, features)

        # 3. Peer-group deviation
        peer_dev: float | None = None
        if peer_group_id:
            peer_dev = await self._peer.deviation_score(tenant_id, peer_group_id, features)
            # Blend peer deviation into composite
            if peer_dev is not None:
                composite = (composite + peer_dev) / 2

        risk = _risk_level(composite)

        if composite < settings.anomaly_threshold:
            return None  # not anomalous

        anomaly = UEBAAnomaly(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_id=entity_id,
            source_event_id=source_event_id,
            event_type=event_type,
            anomaly_score=composite,
            risk_level=risk,
            features=scored,
            peer_group_id=peer_group_id,
            peer_deviation_score=peer_dev,
        )
        self._db.add(anomaly)
        await self._db.flush()
        return anomaly
