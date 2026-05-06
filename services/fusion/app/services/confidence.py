"""
Detection confidence + explainability surface.

Wave 1 of the AiSOC v6 capability roadmap. Every fused alert leaves the
fusion service with a high/medium/low confidence label and an ordered
evidence chain (``ConfidenceFactor[]``) that the UI renders in the alert
detail drawer. The label is **derived**, not assigned — analysts can
reproduce the score from the rationale alone.

Contribution model
==================

The score lives in [0.0, 1.0]. Each factor contributes a signed amount in
[-1.0, +1.0] weighted by its relative importance. The final score is

    score = sum(w_i * c_i) + 0.5

clamped to [0, 1]. Bands map to labels:

    score ≥ 0.70 → HIGH      (action this without further verification)
    0.40–0.70   → MEDIUM    (analyst review recommended)
    score < 0.40 → LOW       (likely noise, suppress or downgrade)

Factors and weights
-------------------

================== ====== ==========================================
factor              w     signal
================== ====== ==========================================
severity           0.20   alert severity (critical / high / med / low)
ml_anomaly         0.18   IsolationForest anomaly_score (0–1)
ml_priority        0.18   LightGBM priority_score (0–1)
mitre_coverage     0.14   number of mapped MITRE techniques
threat_intel       0.16   enrichment hits (TI feed match)
upstream_risk      0.08   raw_alert.risk_score (0–1, vendor-provided)
ioc_density        0.06   distinct populated IOC fields
================== ====== ==========================================

Sum of weights = 1.0. The factor list is *also* what's persisted on the
``FusedAlert`` so the UI can render the same evidence chain that the
score was derived from — no magic numbers.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import structlog

from app.models.alert import (
    AlertSeverity,
    ConfidenceFactor,
    ConfidenceLabel,
    FusedAlert,
)

logger = structlog.get_logger()


# ─── Constants ───────────────────────────────────────────────────────────────

# Score bands → label. Tuned so that "high" requires multiple positive
# signals together (severity alone is not enough) and "low" is reserved for
# alerts whose rationale is mostly noise.
HIGH_THRESHOLD = 0.70
LOW_THRESHOLD = 0.40

# Factor weights — keep summing to 1.0 if you tweak.
WEIGHT_SEVERITY = 0.20
WEIGHT_ML_ANOMALY = 0.18
WEIGHT_ML_PRIORITY = 0.18
WEIGHT_MITRE = 0.14
WEIGHT_THREAT_INTEL = 0.16
WEIGHT_UPSTREAM_RISK = 0.08
WEIGHT_IOC_DENSITY = 0.06

_SEVERITY_CONTRIBUTION = {
    AlertSeverity.CRITICAL: 1.0,
    AlertSeverity.HIGH: 0.6,
    AlertSeverity.MEDIUM: 0.0,
    AlertSeverity.LOW: -0.5,
    AlertSeverity.INFO: -1.0,
}


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _band(score: float) -> ConfidenceLabel:
    if score >= HIGH_THRESHOLD:
        return ConfidenceLabel.HIGH
    if score < LOW_THRESHOLD:
        return ConfidenceLabel.LOW
    return ConfidenceLabel.MEDIUM


def _ml_contribution(value: float) -> float:
    """ML scores are already in [0, 1]. Centre on 0.5 → contribution in [-1, +1]."""
    return max(-1.0, min(1.0, (value - 0.5) * 2.0))


def _mitre_contribution(num_techniques: int) -> float:
    """0 techniques → mild negative; 1 → neutral; 3+ → strongly positive."""
    if num_techniques == 0:
        return -0.4
    if num_techniques == 1:
        return 0.0
    if num_techniques == 2:
        return 0.4
    return min(1.0, 0.4 + (num_techniques - 2) * 0.2)


def _ti_contribution(enrichments: dict | None) -> tuple[float, str]:
    """Threat-intel hits are the strongest binary signal we have."""
    if not enrichments:
        return -0.3, "no TI match"
    hits = 0
    sources: list[str] = []
    for source in ("misp", "otx", "taxii", "kev", "virustotal"):
        match = enrichments.get(source)
        if isinstance(match, dict) and (match.get("hit") or match.get("matches")):
            hits += 1
            sources.append(source.upper())
        elif isinstance(match, list) and match:
            hits += 1
            sources.append(source.upper())
    if hits == 0:
        return -0.3, "no TI match"
    if hits == 1:
        return 0.6, sources[0]
    return 1.0, " + ".join(sources)


def _ioc_density_contribution(alert) -> tuple[float, int]:
    """More populated IOC fields → more concrete signal."""
    fields = [
        alert.src_ip,
        alert.dst_ip,
        alert.hostname,
        alert.username,
        alert.file_hash,
        alert.domain,
        alert.url,
    ]
    populated = sum(1 for f in fields if f)
    if populated == 0:
        contribution = -0.6
    elif populated <= 2:
        contribution = 0.0
    elif populated <= 4:
        contribution = 0.5
    else:
        contribution = 1.0
    return contribution, populated


# ─── ConfidenceScorer ────────────────────────────────────────────────────────


class ConfidenceScorer:
    """Pure, stateless scorer — safe to share across requests.

    The contract is intentionally synchronous: confidence is a *projection*
    of values already present on the ``FusedAlert``, not an asynchronous
    enrichment step. If new signals are added (e.g. UEBA z-score, RBA
    entity score) extend ``score`` and add a row to the rationale.

    The scorer carries an ``enabled`` flag so the capability can be feature-
    flagged at the deployment level (``AISOC_FEATURE_CONFIDENCE``) without
    having to pass ``None`` through the pipeline. When disabled, ``score``
    returns the alert unchanged — the model defaults (MEDIUM / 0.5 / [])
    keep the API and UI rendering safely.
    """

    def __init__(self, enabled: bool = True) -> None:
        self._enabled = enabled

    @property
    def enabled(self) -> bool:
        return self._enabled

    def score(self, fused: FusedAlert) -> FusedAlert:
        if not self._enabled:
            # Break-glass path. Leave the model defaults in place so the
            # frontend can degrade gracefully (no chip, no rationale panel)
            # without raising on missing fields.
            return fused

        """Attach ``confidence_label`` / ``confidence_score`` /
        ``confidence_rationale`` to the fused alert and return it."""
        alert = fused.alert
        rationale: list[ConfidenceFactor] = []

        # 1. Severity
        sev_contribution = _SEVERITY_CONTRIBUTION.get(alert.severity, 0.0)
        rationale.append(
            ConfidenceFactor(
                factor="severity",
                label="Alert severity",
                value=alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                contribution=sev_contribution,
                weight=WEIGHT_SEVERITY,
            )
        )

        # 2. ML anomaly score
        anomaly_contribution = _ml_contribution(fused.anomaly_score)
        rationale.append(
            ConfidenceFactor(
                factor="ml_anomaly",
                label="ML anomaly score",
                value=f"{fused.anomaly_score:.2f}",
                contribution=anomaly_contribution,
                weight=WEIGHT_ML_ANOMALY,
            )
        )

        # 3. ML priority score
        priority_contribution = _ml_contribution(fused.priority_score)
        rationale.append(
            ConfidenceFactor(
                factor="ml_priority",
                label="ML priority rank",
                value=f"{fused.priority_score:.2f}",
                contribution=priority_contribution,
                weight=WEIGHT_ML_PRIORITY,
            )
        )

        # 4. MITRE coverage
        n_tech = len(alert.mitre_techniques)
        mitre_contribution = _mitre_contribution(n_tech)
        rationale.append(
            ConfidenceFactor(
                factor="mitre_coverage",
                label="MITRE technique coverage",
                value=f"{n_tech} techniques" if n_tech != 1 else "1 technique",
                contribution=mitre_contribution,
                weight=WEIGHT_MITRE,
            )
        )

        # 5. Threat-intel
        ti_contribution, ti_value = _ti_contribution(fused.enrichments)
        rationale.append(
            ConfidenceFactor(
                factor="threat_intel",
                label="Threat-intel match",
                value=ti_value,
                contribution=ti_contribution,
                weight=WEIGHT_THREAT_INTEL,
            )
        )

        # 6. Upstream vendor risk score
        upstream = max(0.0, min(1.0, alert.risk_score or 0.0))
        upstream_contribution = _ml_contribution(upstream)
        rationale.append(
            ConfidenceFactor(
                factor="upstream_risk",
                label="Upstream vendor risk score",
                value=f"{upstream:.2f}",
                contribution=upstream_contribution,
                weight=WEIGHT_UPSTREAM_RISK,
            )
        )

        # 7. IOC density
        ioc_contribution, populated = _ioc_density_contribution(alert)
        rationale.append(
            ConfidenceFactor(
                factor="ioc_density",
                label="IOC density",
                value=f"{populated} populated fields",
                contribution=ioc_contribution,
                weight=WEIGHT_IOC_DENSITY,
            )
        )

        # Combine: score = 0.5 + Σ(w_i * c_i), clamped to [0, 1]
        delta = sum(f.contribution * f.weight for f in rationale)
        # Map [-0.5, +0.5] possible range onto a full [0, 1] using the same
        # sigmoid-like recentring; the test suite verifies the bands.
        raw = 0.5 + delta
        score = max(0.0, min(1.0, raw))
        label = _band(score)

        fused.confidence_score = round(score, 4)
        fused.confidence_label = label
        # Sort rationale by absolute contribution, descending — UI shows the
        # most-impactful evidence first.
        fused.confidence_rationale = sorted(rationale, key=lambda f: abs(f.contribution * f.weight), reverse=True)

        logger.debug(
            "confidence_scored",
            alert_id=str(fused.id),
            label=label.value,
            score=fused.confidence_score,
        )
        return fused
