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

================== ======= ==========================================
factor              w      signal
================== ======= ==========================================
severity           0.1692  alert severity (critical / high / med / low)
ml_anomaly         0.1598  IsolationForest anomaly_score (0–1)
ml_priority        0.1598  LightGBM priority_score (0–1)
threat_intel       0.1410  enrichment hits (TI feed match)
mitre_coverage     0.1316  number of mapped MITRE techniques
upstream_risk      0.0752  raw_alert.risk_score (0–1, vendor-provided)
identity_privilege 0.0600  actor's privilege + tags at event time
asset_criticality  0.0564  tenant asset inventory (fuse-time stamp)
ioc_density        0.0470  distinct populated IOC fields
================== ======= ==========================================

Sum of weights = 1.0. The factor list is *also* what's persisted on the
``FusedAlert`` so the UI can render the same evidence chain that the
score was derived from — no magic numbers.

Where the four-decimal weights come from
----------------------------------------
``identity_privilege`` (depth plan wave 2, 1.1) was added at 0.06 — the same
weight ``asset_criticality`` carries, because it answers the matching
question about the actor rather than the asset — and the eight pre-existing
weights were scaled by 0.94 so the total is still exactly 1.0. Scaling,
rather than taking the new weight out of one neighbour, keeps every existing
factor's share of the model unchanged relative to the others: the only thing
that moved is that all of them together now account for 94% instead of 100%.

That does shift every alert's score slightly, which is a real change and is
measured rather than waved at. It does **not** reorder two alerts that
differ only in pre-existing factors, because a common positive scale factor
preserves the ordering of ``Σ(w·c)``.

AiSOC — open-source AI Security Operations Center (MIT License)
"""

from __future__ import annotations

import structlog

from app.memory.distill import SignaturePrior, signature_key
from app.memory.stage import MEMORY_CAP, memory_contribution
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
# `test_weights_sum_to_one` holds this, and it is not decoration: the score
# is `0.5 + Σ(w·c)` with contributions in [-1, +1], so a total above 1.0
# lets a single all-positive alert clamp at the ceiling and a total below it
# makes `HIGH` unreachable.
WEIGHT_SEVERITY = 0.1692
WEIGHT_ML_ANOMALY = 0.1598
WEIGHT_ML_PRIORITY = 0.1598
WEIGHT_MITRE = 0.1316
WEIGHT_THREAT_INTEL = 0.1410
WEIGHT_UPSTREAM_RISK = 0.0752
WEIGHT_IOC_DENSITY = 0.0470
WEIGHT_ASSET_CRITICALITY = 0.0564
#: Depth plan wave 2, 1.1. Deliberately the same magnitude as asset
#: criticality: both are context about *what the alert is about* rather than
#: evidence that it happened, and letting either outweigh the detection
#: itself is how a prioritisation scheme gets switched off.
WEIGHT_IDENTITY_PRIVILEGE = 0.0600

# What the asset the alert landed on contributes. Unknown — no inventory, no
# match — is exactly 0.0: the absence of a CMDB row is not evidence in either
# direction, and the factor row says "unknown" rather than being omitted,
# because "we do not know what this host is" is a fact an analyst needs.
_ASSET_CRITICALITY_CONTRIBUTION = {
    "critical": 1.0,
    "high": 0.5,
    "medium": 0.0,
    "low": -0.3,
    "none": -0.5,
}

# What the actor's privilege contributes. Same shape and same reasoning as
# the asset table above: `unknown` is exactly 0.0, because "no posture has
# been collected for this provider" is not evidence in either direction, and
# the factor row still appears so an analyst sees that the platform could not
# answer rather than seeing nothing at all.
#
# `standard` is mildly negative for the same reason `low` criticality is: an
# ordinary account doing something is less interesting than an administrator
# doing it, and a scheme where context can only ever increase a score stops
# being able to deprioritise anything.
_PRIVILEGE_TIER_CONTRIBUTION = {
    "domain_admin": 1.0,
    "admin": 0.7,
    "elevated": 0.3,
    "standard": -0.2,
    "unknown": 0.0,
}

#: Each tag that is *true* adds this much, capped below. Tags are evidence
#: about reach, and reach compounds: an identity that can escalate AND
#: reaches another account is worse than either alone. The cap stops four
#: tags from making the tier irrelevant.
_PRIVILEGE_TAG_STEP = 0.2
_PRIVILEGE_TAG_CAP = 0.6

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


#: The key `services/fusion/app/services/identity_privilege_context.py`
#: writes. Imported as a literal rather than from that module so the scorer
#: keeps no import of the thing that opens a database connection.
_PRIVILEGE_STAMP_KEY = "identity_privilege"


def _privilege_contribution(stamp: object) -> tuple[float, str]:
    """Tier plus capped tag steps, and the sentence the UI renders.

    Returns ``(contribution, value)``. The value string is what an analyst
    reads in the evidence chain, so it says "unknown" in words whenever the
    contribution is zero for lack of data — a 0.00 with no explanation is
    indistinguishable from a measured neutral.
    """
    if not isinstance(stamp, dict):
        return 0.0, "unknown (no posture collected)"

    tier = str(stamp.get("tier") or "unknown").lower()
    if tier == "unknown":
        reason = str(stamp.get("reason") or "no posture snapshot covers this event")
        return 0.0, f"unknown ({reason})"

    contribution = _PRIVILEGE_TIER_CONTRIBUTION.get(tier, 0.0)

    tags = stamp.get("tags_set")
    if not isinstance(tags, list):
        raw_tags = stamp.get("tags")
        tags = [k for k, v in raw_tags.items() if v is True] if isinstance(raw_tags, dict) else []
    tag_bonus = min(_PRIVILEGE_TAG_CAP, len(tags) * _PRIVILEGE_TAG_STEP)

    contribution = max(-1.0, min(1.0, contribution + tag_bonus))
    value = tier if not tags else f"{tier} ({', '.join(sorted(tags))})"
    if stamp.get("snapshot_partial"):
        value = f"{value} — snapshot incomplete"
    return contribution, value


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

    def score(self, fused: FusedAlert, priors: dict[str, SignaturePrior] | None = None) -> FusedAlert:
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

        # 8. Asset criticality (business-context plan, PR-3). Read from the
        # fuse-time stamp (`enrichments["asset_context"]`), never queried
        # here — the scorer stays a pure projection.
        asset_ctx = (fused.enrichments or {}).get("asset_context")
        criticality = str(asset_ctx.get("criticality", "")).lower() if isinstance(asset_ctx, dict) else ""
        asset_contribution = _ASSET_CRITICALITY_CONTRIBUTION.get(criticality, 0.0)
        rationale.append(
            ConfidenceFactor(
                factor="asset_criticality",
                label="Asset criticality",
                value=(criticality or "unknown (no inventory match)"),
                contribution=asset_contribution,
                weight=WEIGHT_ASSET_CRITICALITY,
            )
        )

        # 9. Actor privilege at event time (depth 2 wave 2, 1.1). Read from
        # the fuse-time stamp (`enrichments["identity_privilege"]`), never
        # queried here — the scorer stays a pure projection, same contract
        # as the asset factor above.
        privilege_contribution, privilege_value = _privilege_contribution(
            (fused.enrichments or {}).get(_PRIVILEGE_STAMP_KEY)
        )
        rationale.append(
            ConfidenceFactor(
                factor="identity_privilege",
                label="Actor privilege at event time",
                value=privilege_value,
                contribution=privilege_contribution,
                weight=WEIGHT_IDENTITY_PRIVILEGE,
            )
        )

        # 10. Institutional memory nudge (Wave 1) — a bounded ±MEMORY_CAP
        # adjustment from the distilled per-signature prior. A signature the
        # analysts have repeatedly corrected to benign pulls new alerts of that
        # signature down; one repeatedly confirmed nudges up. Unknown
        # signatures contribute nothing (no factor added).
        if priors:
            sig = signature_key(
                category="",
                connector_type=(alert.connector_type or ""),
                primary_technique=(alert.mitre_techniques[0] if alert.mitre_techniques else ""),
            )
            mem = memory_contribution(sig, priors)
            if mem.sample_count > 0:
                rationale.append(
                    ConfidenceFactor(
                        factor="institutional_memory",
                        label="Institutional memory",
                        value=mem.basis,
                        # contribution*weight == mem.delta (bounded ±MEMORY_CAP).
                        contribution=round(mem.delta / MEMORY_CAP, 4) if MEMORY_CAP else 0.0,
                        weight=MEMORY_CAP,
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
