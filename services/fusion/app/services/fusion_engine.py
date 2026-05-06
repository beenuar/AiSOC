"""
Core fusion engine: orchestrates deduplication → correlation → ML scoring.
"""

from __future__ import annotations

from uuid import UUID

import structlog

from app.models.alert import FusedAlert, FusionDecision, RawAlert
from app.services.confidence import ConfidenceScorer
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.entity_risk import EntityRiskEngine
from app.services.ml_scorer import MLScorer

logger = structlog.get_logger()


class FusionEngine:
    """Orchestrates the full alert fusion pipeline."""

    def __init__(
        self,
        deduplicator: Deduplicator,
        correlator: Correlator,
        ml_scorer: MLScorer | None = None,
        entity_risk: EntityRiskEngine | None = None,
        confidence_scorer: ConfidenceScorer | None = None,
    ) -> None:
        self._dedup = deduplicator
        self._correlator = correlator
        self._ml_scorer = ml_scorer or MLScorer()
        self._entity_risk = entity_risk
        # Confidence + explainability is intrinsic to a fused alert — every
        # alert leaves the engine with a high/med/low label and an evidence
        # chain. The scorer is pure / stateless so we instantiate a default.
        self._confidence_scorer = confidence_scorer or ConfidenceScorer()

    async def process(self, alert: RawAlert) -> FusedAlert:
        """
        Process a raw alert through the full fusion pipeline.

        Pipeline:
          1. Deduplication: suppress exact/near-exact duplicates
          2. Correlation: group into an existing or new incident
          3. ML scoring: anomaly_score (Isolation Forest) + priority_score (LightGBM)
        """
        # --- Step 1: Deduplication ---
        is_dup, original_id = await self._dedup.is_duplicate(alert)
        if is_dup:
            logger.info(
                "Alert suppressed as duplicate",
                alert_id=str(alert.id),
                original_id=original_id,
            )
            return FusedAlert(
                id=alert.id,
                tenant_id=alert.tenant_id,
                incident_id=None,
                fusion_decision=FusionDecision.DUPLICATE,
                duplicate_of=UUID(original_id) if original_id else None,
                alert=alert,
            )

        # Register fingerprint to dedup future duplicates
        await self._dedup.register(alert)

        # --- Step 2: Correlation ---
        correlated, incident = await self._correlator.correlate(alert)

        decision = FusionDecision.CORRELATED if correlated else FusionDecision.NEW_INCIDENT

        fused = FusedAlert(
            id=alert.id,
            tenant_id=alert.tenant_id,
            incident_id=incident.id,
            fusion_decision=decision,
            duplicate_of=None,
            alert=alert,
        )

        # --- Step 3: ML scoring ---
        try:
            fused = await self._ml_scorer.score(fused)
        except Exception as exc:
            logger.warning("ML scoring failed; using defaults", error=str(exc))

        # --- Step 3b: Detection confidence + explainability ---
        # Pure, synchronous projection of the values already on ``fused``.
        # Runs after ML scoring so the rationale picks up anomaly / priority.
        try:
            fused = self._confidence_scorer.score(fused)
        except Exception as exc:
            logger.warning("confidence_scoring_failed", error=str(exc))

        # --- Step 4: Risk-Based Alerting (entity rollup) ---
        # RBA accumulates points on the entities this alert touches and may
        # promote one or more of them to an entity-incident. Failures here
        # never block the alert pipeline — RBA is additive signal, not
        # the primary correlation path.
        if self._entity_risk is not None and self._entity_risk.enabled:
            try:
                promotions = await self._entity_risk.observe(alert)
                if promotions:
                    logger.info(
                        "rba_promotions",
                        alert_id=str(alert.id),
                        promoted=[f"{p.entity_type}:{p.entity_value}" for p in promotions],
                    )
            except Exception as exc:
                logger.warning("rba_observation_failed", error=str(exc))

        logger.info(
            "Alert fusion complete",
            alert_id=str(alert.id),
            decision=decision,
            incident_id=str(incident.id),
            incident_alert_count=incident.alert_count,
            anomaly_score=fused.anomaly_score,
            priority_score=fused.priority_score,
            confidence=fused.confidence_label.value,
        )

        return fused

    @property
    def ml_scorer(self) -> MLScorer:
        return self._ml_scorer

    @property
    def entity_risk(self) -> EntityRiskEngine | None:
        return self._entity_risk

    @property
    def confidence_scorer(self) -> ConfidenceScorer:
        return self._confidence_scorer
