"""
Risk-Based Alerting (RBA) — entity rollup with time-decayed risk scores.

The Splunk-pioneered RBA pattern: alerts contribute *points* to the entities
they touch (user, host, src_ip, domain). Points decay exponentially with a
half-life so stale signal naturally drops out. Once an entity's score crosses
``rba_promotion_threshold`` AiSOC promotes the entity to an incident with the
contributing alerts attached — and the entity-centric queue surfaces the
top-N highest-risk entities to the analyst, not raw alerts.

Why entity-first
----------------
The 2026 buyer-side scoring bar mandates ``alert-to-incident ratio ≥ 50:1``
(SANS 2025 + AI-SOC 30-item checklist). Per-alert correlation alone caps
collapse at the entity boundary; entity-rollup compounds across detections
so one user with five medium signals lands above one with a single
high-severity false positive.

Storage
-------
Redis hashes per entity, namespaced by tenant. Cheap, atomic, and TTLs match
``rba_window_seconds`` so cold entities self-evict. Two ZSETs keep top-N
entities sorted (by score, by last_seen) for O(log N) queue reads. All
keys are RLS-safe because the tenant_id is part of the key prefix and the
API service re-checks tenant on read.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

import redis.asyncio as aioredis
import structlog

from app.core.config import settings
from app.models.alert import AlertSeverity, RawAlert

logger = structlog.get_logger()

# Key layout (all prefixed by tenant for RLS at the cache layer):
#   aisoc:fusion:rba:entity:{tenant}:{entity_type}:{entity_value}  →  hash
#   aisoc:fusion:rba:topn:{tenant}                                  →  zset (score)
#   aisoc:fusion:rba:promoted:{tenant}                              →  zset (last seen)
_ENTITY_PREFIX = "aisoc:fusion:rba:entity:"
_TOPN_KEY = "aisoc:fusion:rba:topn:"
_PROMOTED_KEY = "aisoc:fusion:rba:promoted:"

ENTITY_TYPES: tuple[str, ...] = ("user", "host", "src_ip", "domain")


@dataclass(frozen=True)
class EntitySignal:
    """A single alert's contribution to one entity."""

    entity_type: str
    entity_value: str
    points: float
    alert_id: str
    severity: str
    detection: str
    occurred_at: datetime


@dataclass
class EntityRiskRecord:
    """The current decayed risk picture for one entity."""

    tenant_id: str
    entity_type: str
    entity_value: str
    score: float
    alert_count: int
    last_seen: datetime
    contributing_alerts: list[str]
    severities: dict[str, int]
    promoted_at: datetime | None
    contributors: list[dict] | None = None

    def to_dict(self) -> dict:
        return {
            "tenant_id": self.tenant_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "score": round(self.score, 2),
            "alert_count": self.alert_count,
            "last_seen": self.last_seen.isoformat() + "Z",
            "contributing_alerts": self.contributing_alerts,
            "severities": self.severities,
            "promoted_at": (self.promoted_at.isoformat() + "Z") if self.promoted_at else None,
            "contributors": self.contributors or [],
        }


class EntityRiskEngine:
    """Time-decaying entity risk accumulator + entity-centric queue."""

    def __init__(self, redis_client: aioredis.Redis) -> None:
        self._redis = redis_client
        self._enabled = settings.rba_enabled
        self._threshold = settings.rba_promotion_threshold
        self._window = settings.rba_window_seconds
        self._half_life = max(60, settings.rba_decay_half_life_seconds)
        self._max_top = max(10, settings.rba_max_top_entities)
        self._weights: dict[AlertSeverity, float] = {
            AlertSeverity.CRITICAL: settings.rba_severity_weights_critical,
            AlertSeverity.HIGH: settings.rba_severity_weights_high,
            AlertSeverity.MEDIUM: settings.rba_severity_weights_medium,
            AlertSeverity.LOW: settings.rba_severity_weights_low,
            AlertSeverity.INFO: settings.rba_severity_weights_info,
        }

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def threshold(self) -> float:
        return self._threshold

    # ------------------------------------------------------------------
    # Ingest path
    # ------------------------------------------------------------------
    async def observe(self, alert: RawAlert) -> list[EntityRiskRecord]:
        """
        Apply ``alert`` against every entity it touches.

        Returns the list of entity records that crossed the promotion
        threshold *as a result of this alert*. The fusion engine uses the
        return value to log promotions and emit downstream signals.
        """
        if not self._enabled:
            return []

        signals = self._build_signals(alert)
        if not signals:
            return []

        promoted: list[EntityRiskRecord] = []
        for sig in signals:
            record = await self._apply_signal(alert.tenant_id, sig)
            if record.score >= self._threshold and record.promoted_at is None:
                record = await self._promote(alert.tenant_id, record)
                promoted.append(record)

        return promoted

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------
    async def top_entities(
        self,
        tenant_id: UUID | str,
        *,
        limit: int = 25,
        promoted_only: bool = False,
    ) -> list[EntityRiskRecord]:
        """Return the top-N entities by current decayed score."""
        key = _TOPN_KEY + str(tenant_id)
        raw = await self._redis.zrevrange(key, 0, max(0, limit - 1), withscores=True)
        records: list[EntityRiskRecord] = []
        for member, _zscore in raw:
            entity = member.decode() if isinstance(member, (bytes, bytearray)) else member
            entity_type, _, entity_value = entity.partition("::")
            rec = await self._load(str(tenant_id), entity_type, entity_value)
            if rec is None:
                continue
            if promoted_only and rec.promoted_at is None:
                continue
            records.append(rec)
        return records

    async def get(self, tenant_id: UUID | str, entity_type: str, entity_value: str) -> EntityRiskRecord | None:
        return await self._load(str(tenant_id), entity_type, entity_value)

    async def stats(self, tenant_id: UUID | str) -> dict:
        """Return queue-level metrics for the dashboard."""
        topn_key = _TOPN_KEY + str(tenant_id)
        promoted_key = _PROMOTED_KEY + str(tenant_id)
        total = await self._redis.zcard(topn_key)
        promoted = await self._redis.zcard(promoted_key)
        # Score histogram (≥80, 50–80, 20–50, <20).
        bands = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        members = await self._redis.zrevrange(topn_key, 0, self._max_top - 1, withscores=True)
        for _m, score in members:
            if score >= 80:
                bands["critical"] += 1
            elif score >= 50:
                bands["high"] += 1
            elif score >= 20:
                bands["medium"] += 1
            else:
                bands["low"] += 1
        return {
            "tracked_entities": total,
            "promoted_entities": promoted,
            "score_bands": bands,
            "threshold": self._threshold,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_signals(self, alert: RawAlert) -> list[EntitySignal]:
        weight = self._weights.get(alert.severity, self._weights[AlertSeverity.MEDIUM])
        # Detection-confidence boost: higher upstream risk_score amplifies points.
        confidence_factor = 1.0 + min(max(alert.risk_score, 0.0), 1.0)
        points = round(weight * confidence_factor, 2)
        detection = alert.title or alert.source
        occurred = alert.event_time or alert.created_at

        candidates: list[tuple[str, str | None]] = [
            ("user", alert.username),
            ("host", alert.hostname),
            ("src_ip", alert.src_ip),
            ("domain", alert.domain),
        ]
        signals: list[EntitySignal] = []
        for entity_type, value in candidates:
            if not value:
                continue
            signals.append(
                EntitySignal(
                    entity_type=entity_type,
                    entity_value=str(value),
                    points=points,
                    alert_id=str(alert.id),
                    severity=alert.severity.value,
                    detection=detection,
                    occurred_at=occurred,
                )
            )
        return signals

    async def _apply_signal(self, tenant_id: UUID, sig: EntitySignal) -> EntityRiskRecord:
        record = await self._load(str(tenant_id), sig.entity_type, sig.entity_value)
        now = datetime.utcnow()

        if record is None:
            record = EntityRiskRecord(
                tenant_id=str(tenant_id),
                entity_type=sig.entity_type,
                entity_value=sig.entity_value,
                score=0.0,
                alert_count=0,
                last_seen=now,
                contributing_alerts=[],
                severities={},
                promoted_at=None,
                contributors=[],
            )

        record.score = self._decay(record.score, record.last_seen, now) + sig.points
        record.alert_count += 1
        record.last_seen = now
        if sig.alert_id not in record.contributing_alerts:
            record.contributing_alerts.append(sig.alert_id)
            # Cap contributing list to keep payload small in the queue UI.
            if len(record.contributing_alerts) > 50:
                record.contributing_alerts = record.contributing_alerts[-50:]
        record.severities[sig.severity] = record.severities.get(sig.severity, 0) + 1
        contributors = record.contributors or []
        contributors.append(
            {
                "alert_id": sig.alert_id,
                "severity": sig.severity,
                "detection": sig.detection,
                "points": sig.points,
                "at": sig.occurred_at.isoformat() + "Z",
            }
        )
        if len(contributors) > 25:
            contributors = contributors[-25:]
        record.contributors = contributors

        await self._save(record)
        return record

    def _decay(self, prior: float, prior_seen: datetime, now: datetime) -> float:
        if prior <= 0:
            return 0.0
        elapsed = max(0.0, (now - prior_seen).total_seconds())
        if elapsed <= 0:
            return prior
        decay = math.pow(0.5, elapsed / float(self._half_life))
        decayed = prior * decay
        return decayed if decayed > 0.05 else 0.0

    async def _promote(self, tenant_id: UUID, record: EntityRiskRecord) -> EntityRiskRecord:
        record.promoted_at = datetime.utcnow()
        await self._save(record)
        promoted_key = _PROMOTED_KEY + str(tenant_id)
        await self._redis.zadd(promoted_key, {self._member(record): time.time()})
        await self._redis.expire(promoted_key, self._window)
        logger.info(
            "rba_entity_promoted",
            tenant_id=str(tenant_id),
            entity_type=record.entity_type,
            entity_value=record.entity_value,
            score=round(record.score, 2),
            alert_count=record.alert_count,
            contributing_alerts=record.contributing_alerts[-10:],
        )
        return record

    @staticmethod
    def _member(record: EntityRiskRecord) -> str:
        return f"{record.entity_type}::{record.entity_value}"

    async def _save(self, record: EntityRiskRecord) -> None:
        key = _ENTITY_PREFIX + f"{record.tenant_id}:{record.entity_type}:{record.entity_value}"
        payload = {
            "score": str(record.score),
            "alert_count": str(record.alert_count),
            "last_seen": record.last_seen.isoformat(),
            "contributing_alerts": json.dumps(record.contributing_alerts),
            "severities": json.dumps(record.severities),
            "promoted_at": record.promoted_at.isoformat() if record.promoted_at else "",
            "contributors": json.dumps(record.contributors or []),
        }
        await self._redis.hset(key, mapping=payload)
        await self._redis.expire(key, self._window)
        topn_key = _TOPN_KEY + record.tenant_id
        await self._redis.zadd(topn_key, {self._member(record): record.score})
        await self._redis.zremrangebyrank(topn_key, 0, -(self._max_top + 1))
        await self._redis.expire(topn_key, self._window)

    async def _load(self, tenant_id: str, entity_type: str, entity_value: str) -> EntityRiskRecord | None:
        key = _ENTITY_PREFIX + f"{tenant_id}:{entity_type}:{entity_value}"
        data = await self._redis.hgetall(key)
        if not data:
            return None
        decoded = {
            (k.decode() if isinstance(k, (bytes, bytearray)) else k): (v.decode() if isinstance(v, (bytes, bytearray)) else v)
            for k, v in data.items()
        }
        promoted_at = None
        if decoded.get("promoted_at"):
            try:
                promoted_at = datetime.fromisoformat(decoded["promoted_at"])
            except ValueError:
                promoted_at = None
        try:
            last_seen = datetime.fromisoformat(decoded["last_seen"])
        except (KeyError, ValueError):
            last_seen = datetime.utcnow()
        return EntityRiskRecord(
            tenant_id=tenant_id,
            entity_type=entity_type,
            entity_value=entity_value,
            score=float(decoded.get("score", "0")),
            alert_count=int(decoded.get("alert_count", "0")),
            last_seen=last_seen,
            contributing_alerts=json.loads(decoded.get("contributing_alerts", "[]")),
            severities=json.loads(decoded.get("severities", "{}")),
            promoted_at=promoted_at,
            contributors=json.loads(decoded.get("contributors", "[]")),
        )
