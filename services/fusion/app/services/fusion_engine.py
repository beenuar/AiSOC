"""
Core fusion engine: orchestrates deduplication → correlation → enrichment enrichment trigger.
"""
from uuid import UUID

import structlog

from app.models.alert import FusedAlert, FusionDecision, RawAlert
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator

logger = structlog.get_logger()


class FusionEngine:
    """Orchestrates the full alert fusion pipeline."""

    def __init__(self, deduplicator: Deduplicator, correlator: Correlator) -> None:
        self._dedup = deduplicator
        self._correlator = correlator

    async def process(self, alert: RawAlert) -> FusedAlert:
        """
        Process a raw alert through the full fusion pipeline.

        Pipeline:
          1. Deduplication: suppress exact/near-exact duplicates
          2. Correlation: group into an existing or new incident
          3. Return a FusedAlert with decision metadata
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

        decision = (
            FusionDecision.CORRELATED if correlated else FusionDecision.NEW_INCIDENT
        )

        logger.info(
            "Alert fusion complete",
            alert_id=str(alert.id),
            decision=decision,
            incident_id=str(incident.id),
            incident_alert_count=incident.alert_count,
        )

        return FusedAlert(
            id=alert.id,
            tenant_id=alert.tenant_id,
            incident_id=incident.id,
            fusion_decision=decision,
            duplicate_of=None,
            alert=alert,
        )
