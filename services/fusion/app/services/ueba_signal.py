"""Fuse the UEBA behavioral model into fused-alert scoring (Phase A4).

`services/ueba` continuously scores every entity (user / device / ip) and emits
``ueba.anomalies`` messages, but fusion never consumed them — so the platform's
"three-model" story (Semantic graph / Behavioral UEBA / Knowledge LLM) was only
two models in production. This module closes that: fusion caches the latest
per-entity behavioral anomaly and folds it into an alert's confidence + anomaly
score at fuse time.

Flow:

* The fusion consumer subscribes to ``ueba.anomalies`` and calls
  :meth:`UebaSignalCache.record`, which stores the latest score/risk per
  ``(tenant, entity_type, entity_id)`` in Redis with a TTL (behavioral signal
  is time-decaying — a week-old anomaly shouldn't boost today's alert).
* During ``FusionEngine.process`` an alert looks up the highest behavioral
  anomaly across its own entities (username, hostname, src/dst IP) via
  :meth:`UebaSignalCache.lookup` and :func:`apply_ueba_boost` raises the
  alert's confidence + anomaly score and records an explainable factor.

Everything is fail-soft: a Redis miss/outage or a malformed UEBA message
degrades to "no behavioral boost", never an error into the pipeline.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import structlog

from app.models.alert import ConfidenceFactor, ConfidenceLabel, FusedAlert

logger = structlog.get_logger()

# UEBA risk_level -> normalized behavioral weight in [0, 1] and the confidence
# nudge it earns. Kept conservative: even a critical behavioral anomaly is a
# supporting signal, not a verdict on its own.
_RISK_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.45, "low": 0.2}
_RISK_BOOST = {"critical": 0.20, "high": 0.14, "medium": 0.07, "low": 0.0}

_CONF_HIGH = 0.70
_CONF_MEDIUM = 0.40


def _label_for(score: float) -> ConfidenceLabel:
    if score >= _CONF_HIGH:
        return ConfidenceLabel.HIGH
    if score >= _CONF_MEDIUM:
        return ConfidenceLabel.MEDIUM
    return ConfidenceLabel.LOW


@dataclass(frozen=True)
class UebaSignal:
    entity_type: str
    entity_id: str
    anomaly_score: float
    risk_level: str

    @property
    def normalized(self) -> float:
        return _RISK_WEIGHT.get(self.risk_level.lower(), 0.0)


def _key(tenant_id: str, entity_type: str, entity_id: str) -> str:
    return f"ueba:anom:{tenant_id}:{entity_type.lower()}:{entity_id.lower()}"


def alert_entities(alert: Any) -> list[tuple[str, str]]:
    """(entity_type, entity_id) pairs the UEBA cache is keyed by, for an alert.

    UEBA entity types are user / device / ip (see services/ueba). We map the
    alert's username -> user, hostname -> device, src/dst IP -> ip.
    """
    out: list[tuple[str, str]] = []
    if getattr(alert, "username", None):
        out.append(("user", str(alert.username)))
    if getattr(alert, "hostname", None):
        out.append(("device", str(alert.hostname)))
    for ip in (getattr(alert, "src_ip", None), getattr(alert, "dst_ip", None)):
        if ip:
            out.append(("ip", str(ip)))
    return out


class UebaSignalCache:
    """Redis-backed latest-anomaly-per-entity cache. Fail-soft on every op."""

    def __init__(self, redis_client: Any, ttl_seconds: int = 86400) -> None:
        self._redis = redis_client
        self._ttl = ttl_seconds

    async def record(self, message: dict[str, Any]) -> bool:
        """Store one ``ueba.anomalies`` message. Returns True if cached."""
        try:
            tenant = str(message.get("tenant_id") or "")
            etype = str(message.get("entity_type") or "")
            eid = str(message.get("entity_id") or "")
            if not (tenant and etype and eid):
                return False
            payload = json.dumps(
                {
                    "anomaly_score": float(message.get("anomaly_score") or 0.0),
                    "risk_level": str(message.get("risk_level") or "low"),
                    "entity_type": etype,
                    "entity_id": eid,
                }
            )
            await self._redis.set(_key(tenant, etype, eid), payload.encode("utf-8"), ex=self._ttl)
            return True
        except Exception as exc:  # noqa: BLE001 — behavioral cache is best-effort
            logger.debug("ueba_signal.record_failed", error=str(exc))
            return False

    async def lookup(self, tenant_id: str, entities: list[tuple[str, str]]) -> UebaSignal | None:
        """Return the highest-scoring cached behavioral signal for the alert's
        entities, or ``None`` if none is cached."""
        best: UebaSignal | None = None
        for etype, eid in entities:
            try:
                raw = await self._redis.get(_key(tenant_id, etype, eid))
            except Exception as exc:  # noqa: BLE001
                logger.debug("ueba_signal.lookup_failed", error=str(exc))
                continue
            if not raw:
                continue
            try:
                data = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
                sig = UebaSignal(
                    entity_type=data.get("entity_type", etype),
                    entity_id=data.get("entity_id", eid),
                    anomaly_score=float(data.get("anomaly_score", 0.0)),
                    risk_level=str(data.get("risk_level", "low")),
                )
            except (ValueError, TypeError):
                continue
            if best is None or sig.normalized > best.normalized:
                best = sig
        return best


def apply_ueba_boost(fused: FusedAlert, signal: UebaSignal | None) -> FusedAlert:
    """Fold a behavioral anomaly into the alert's confidence + anomaly score.

    Appends an explainable ``ueba_anomaly`` factor, nudges confidence by the
    risk-scaled amount (and recomputes the label so it stays consistent), and
    raises ``anomaly_score`` to at least the behavioral signal — so a benign-
    looking alert on a wildly anomalous entity is surfaced, not buried.
    """
    if signal is None:
        return fused
    boost = _RISK_BOOST.get(signal.risk_level.lower(), 0.0)
    normalized = signal.normalized

    fused.confidence_rationale.append(
        ConfidenceFactor(
            factor="ueba_anomaly",
            label="Behavioral anomaly (UEBA)",
            value=f"{signal.entity_type}:{signal.entity_id} risk={signal.risk_level} score={signal.anomaly_score:.2f}",
            contribution=+min(0.3, normalized * 0.3),
            weight=0.12,
        )
    )
    if boost > 0.0:
        fused.confidence_score = min(1.0, (fused.confidence_score or 0.0) + boost)
        fused.confidence_label = _label_for(fused.confidence_score)
    if fused.anomaly_score is None or normalized > fused.anomaly_score:
        fused.anomaly_score = normalized

    logger.info(
        "ueba_boost_applied",
        alert_id=str(fused.id),
        entity=f"{signal.entity_type}:{signal.entity_id}",
        risk=signal.risk_level,
    )
    return fused
