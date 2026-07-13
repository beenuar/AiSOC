"""
Core fusion engine: orchestrates deduplication → correlation → ML scoring.
"""

from __future__ import annotations

from uuid import UUID

import structlog

from app.core.config import settings
from app.models.alert import (
    ConfidenceFactor,
    FusedAlert,
    FusionDecision,
    IncidentSummary,
    RawAlert,
)
from app.services.confidence import ConfidenceScorer
from app.services.correlator import Correlator
from app.services.deduplicator import Deduplicator
from app.services.entity_risk import EntityRiskEngine, EntityRiskRecord
from app.services.ml_scorer import MLScorer
from app.services.narrative import (
    NarrativeFactor,
    NarrativeInputs,
    build_narrative,
)
from app.services.ueba_signal import UebaSignalCache, alert_entities, apply_ueba_boost
from app.services.vuln_boost import apply_vuln_boost

logger = structlog.get_logger()


def _to_narrative_inputs(
    fused: FusedAlert,
    incident: IncidentSummary,
    top_promotion: EntityRiskRecord | None,
) -> NarrativeInputs:
    """Project a fully-scored ``FusedAlert`` into ``NarrativeInputs``.

    This is the only place in the fusion service that knows how to map the
    domain model onto the narrative builder's contract. The builder itself
    stays decoupled (it takes a dataclass and returns a string), which is
    what lets us mirror it byte-for-byte into ``services/api/app/_vendor/``
    and reuse it for the API's lazy-fill path.

    The shape is intentionally narrow: we surface only the fields the
    InvestigationRail actually renders. New signals (UEBA z-score, vuln
    severity, …) are added by extending ``NarrativeInputs`` first, then
    plumbing them through here — never by bypassing the dataclass.
    """
    raw = fused.alert

    rationale_factors: tuple[NarrativeFactor, ...] = tuple(
        NarrativeFactor(
            label=row.label,
            value=row.value,
            contribution=row.contribution,
            weight=row.weight,
        )
        for row in fused.confidence_rationale
        if isinstance(row, ConfidenceFactor)
    )

    # The fusion service speaks ``FusionDecision`` enums. The narrative builder
    # only needs to know whether the alert opened a new incident or attached
    # to an existing one — the duplicate path returns earlier and never
    # reaches this adapter.
    if fused.fusion_decision == FusionDecision.CORRELATED:
        correlation_decision: str | None = "correlated"
    elif fused.fusion_decision == FusionDecision.NEW_INCIDENT:
        correlation_decision = "new_incident"
    else:
        correlation_decision = None

    rba_entity: str | None = None
    rba_score: float | None = None
    if top_promotion is not None:
        rba_entity = f"{top_promotion.entity_type}:{top_promotion.entity_value}"
        rba_score = top_promotion.score

    # ``confidence_score`` is on [0, 1]; the narrative surfaces a /100 number
    # so the rail prose reads naturally ("Confidence: high (78/100)").
    confidence_pct: int | None = round(max(0.0, min(1.0, fused.confidence_score)) * 100) if fused.confidence_score is not None else None

    return NarrativeInputs(
        severity=raw.severity.value,  # type: ignore[arg-type]
        title=raw.title,
        confidence=confidence_pct,
        confidence_label=fused.confidence_label.value,  # type: ignore[arg-type]
        rationale=rationale_factors,
        src_ip=raw.src_ip,
        dst_ip=raw.dst_ip,
        hostname=raw.hostname,
        username=raw.username,
        file_hash=raw.file_hash,
        domain=raw.domain,
        url=raw.url,
        mitre_tactics=tuple(raw.mitre_tactics),
        mitre_techniques=tuple(raw.mitre_techniques),
        incident_alert_count=incident.alert_count,
        correlation_decision=correlation_decision,
        rba_entity=rba_entity,
        rba_score=rba_score,
        exploit_in_wild=fused.exploit_in_wild,
        source=raw.source,
        tags=tuple(raw.tags),
    )


class FusionEngine:
    """Orchestrates the full alert fusion pipeline."""

    def __init__(
        self,
        deduplicator: Deduplicator,
        correlator: Correlator,
        ml_scorer: MLScorer | None = None,
        entity_risk: EntityRiskEngine | None = None,
        confidence_scorer: ConfidenceScorer | None = None,
        ueba_cache: UebaSignalCache | None = None,
    ) -> None:
        self._dedup = deduplicator
        self._correlator = correlator
        self._ml_scorer = ml_scorer or MLScorer()
        self._entity_risk = entity_risk
        # Phase A4 — behavioral-model signal (optional; None = no UEBA fusion).
        self._ueba_cache = ueba_cache
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

        # --- Step 3c: Exploit-in-wild boost (Tier 3.5) ---
        # Inspects enrichments for exploited CVEs and raises confidence when present.
        if settings.vuln_boost_enabled:
            try:
                fused = apply_vuln_boost(fused)
            except Exception as exc:
                logger.warning("vuln_boost_failed", error=str(exc))

        # --- Step 3d: Behavioral-model fusion (Phase A4) ---
        # Fold the alert's entities' latest UEBA anomaly into confidence +
        # anomaly score. Best-effort: a Redis miss/outage is a no-op.
        if self._ueba_cache is not None:
            try:
                signal = await self._ueba_cache.lookup(str(alert.tenant_id), alert_entities(alert))
                fused = apply_ueba_boost(fused, signal)
            except Exception as exc:
                logger.warning("ueba_boost_failed", error=str(exc))

        # --- Step 4: Risk-Based Alerting (entity rollup) ---
        # RBA accumulates points on the entities this alert touches and may
        # promote one or more of them to an entity-incident. Failures here
        # never block the alert pipeline — RBA is additive signal, not
        # the primary correlation path.
        top_promotion: EntityRiskRecord | None = None
        if self._entity_risk is not None and self._entity_risk.enabled:
            try:
                promotions = await self._entity_risk.observe(alert)
                if promotions:
                    # Pick the highest-scoring promoted entity as the rail's
                    # headline for the RBA call-out. Ties break on score then
                    # entity_value for determinism (sorted is stable).
                    top_promotion = max(
                        promotions,
                        key=lambda r: (r.score, r.entity_value),
                    )
                    logger.info(
                        "rba_promotions",
                        alert_id=str(alert.id),
                        promoted=[f"{p.entity_type}:{p.entity_value}" for p in promotions],
                    )
            except Exception as exc:
                logger.warning("rba_observation_failed", error=str(exc))

        # --- Step 5: Correlation narrative ---
        # Deterministic, Markdown-light prose composed from the values already
        # on ``fused`` plus the RBA promotion (if any) and incident roll-up.
        # The narrative is cached on the ``alerts`` row so the API and the
        # InvestigationRail never have to round-trip an LLM to show "why".
        # Failures here are never fatal — the API will recompute on first read
        # via the same builder (vendored in ``services/api/app/_vendor/``).
        try:
            fused.narrative = build_narrative(_to_narrative_inputs(fused, incident, top_promotion))
        except Exception as exc:
            logger.warning("narrative_build_failed", alert_id=str(alert.id), error=str(exc))

        logger.info(
            "Alert fusion complete",
            alert_id=str(alert.id),
            decision=decision,
            incident_id=str(incident.id),
            incident_alert_count=incident.alert_count,
            anomaly_score=fused.anomaly_score,
            priority_score=fused.priority_score,
            confidence=fused.confidence_label.value,
            narrative_present=fused.narrative is not None,
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
