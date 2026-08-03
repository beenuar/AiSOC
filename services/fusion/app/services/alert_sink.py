"""Persist fused alerts into the Postgres ``alerts`` table.

Phase 3.1 (world-class program) closed the second spine gap the reality audit
exposed: fusion published fused alerts to ``aisoc.alerts.fused`` and — before
this module — **nothing wrote them to the alert store**. The only writers were
the API's manual ``POST /alerts/submit`` endpoint and the demo seeder, so a
raw event could never become an alert row without a human in the loop.

Design constraints:

* **Fail-soft.** Fusion ran for months without a database; a Postgres outage
  must degrade to "fused alerts still stream over Kafka/WS, persistence
  resumes when the DB returns" — never crash the consumer.
* **Idempotent.** The insert is guarded by the alert's dedup fingerprint per
  tenant, so replaying a Kafka batch (consumer-group rebalance, restart
  mid-batch) cannot produce duplicate rows.
* **Duplicates are not persisted.** Fusion publishes DUPLICATE decisions
  downstream for observability, but they must not become new alert rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

import asyncpg
import structlog

from app.models.alert import FusedAlert, FusionDecision

logger = structlog.get_logger()


class PersistOutcome(str, Enum):
    """Distinguishable outcomes of a persist attempt (issue #568).

    The old sink collapsed "inserted", "already-existed", "DB down", and
    "insert errored" all into ``None``, so the caller could not tell a real
    duplicate from an outage it should retry. Each state is now explicit.
    """

    INSERTED = "inserted"  # a new row was written; alert_id is the row id
    DUPLICATE = "duplicate"  # already existed (dedup hit or id conflict)
    UNAVAILABLE = "unavailable"  # DB unreachable — retryable, NOT a duplicate
    FAILED = "failed"  # insert errored (bad tenant, SQL error) — observable


@dataclass(frozen=True)
class PersistResult:
    """Outcome of :meth:`AlertSink.persist` plus the canonical alert id."""

    outcome: PersistOutcome
    alert_id: str | None = None

    @property
    def persisted(self) -> bool:
        return self.outcome is PersistOutcome.INSERTED

    @property
    def durable(self) -> bool:
        """True when the alert is known to exist in the store (new or dup)."""
        return self.outcome in (PersistOutcome.INSERTED, PersistOutcome.DUPLICATE)


_INSERT_SQL = """
INSERT INTO alerts (
    id, tenant_id, title, description, severity, status,
    mitre_tactics, mitre_techniques, iocs, entities, raw_event,
    dedup_hash, confidence, confidence_label, confidence_rationale,
    narrative, anomaly_score, event_time,
    connector_id, connector_type, source_event_ids, ocsf_class_uid,
    rule_id, rule_name
)
SELECT
    $1, $2, $3, $4, $5, 'new',
    $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb,
    $11::text, $12, $13, $14::jsonb,
    $15, $16, COALESCE($17, NOW()),
    $18, $19, $20::jsonb, $21,
    $22, $23
WHERE NOT EXISTS (
    SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11::text
)
ON CONFLICT (id) DO NOTHING
RETURNING id
"""
# Two idempotency guards, complementary (issue #568):
#   * WHERE NOT EXISTS (tenant_id, dedup_hash) — content dedup; also protects
#     legacy rows written before ids were deterministic (random id, same hash).
#   * ON CONFLICT (id) DO NOTHING — exact-replay idempotency on the canonical
#     deterministic UUID (RawAlert.deterministic_id()).
# NB: $11 (dedup_hash) is cast ::text in BOTH the INSERT target and the WHERE.
# `dedup_hash` is VARCHAR(64); a varchar/text mismatch makes asyncpg's prepare
# fail to unify parameter $11 ("inconsistent types deduced"), silently dropping
# every write. Pinning both uses to ::text makes the deduction unambiguous.


def _asyncpg_dsn(url: str) -> str:
    """Strip the SQLAlchemy driver suffix — asyncpg wants plain postgresql://."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _iocs(fused: FusedAlert) -> list[dict[str, str]]:
    alert = fused.alert
    out: list[dict[str, str]] = []
    for ioc_type, value in (
        ("ip", alert.src_ip),
        ("ip", alert.dst_ip),
        ("hash", alert.file_hash),
        ("domain", alert.domain),
        ("url", alert.url),
    ):
        if value:
            out.append({"type": ioc_type, "value": value})
    return out


def _entities(fused: FusedAlert) -> list[dict[str, str]]:
    alert = fused.alert
    out: list[dict[str, str]] = []
    if alert.hostname:
        out.append({"type": "host", "value": alert.hostname})
    if alert.username:
        out.append({"type": "user", "value": alert.username})
    return out


class AlertSink:
    """asyncpg-backed writer from the fusion pipeline into the alert store."""

    def __init__(self, database_url: str, pool_size: int = 2) -> None:
        self._dsn = _asyncpg_dsn(database_url)
        self._pool_size = pool_size
        self._pool: asyncpg.Pool | None = None
        self._connect_failed_logged = False

    async def start(self) -> None:
        """Open the pool. Failure is logged, not raised (fail-soft)."""
        try:
            self._pool = await asyncpg.create_pool(self._dsn, min_size=1, max_size=self._pool_size, timeout=10)
            logger.info("alert_sink.started")
        except Exception as exc:  # noqa: BLE001 — degrade, never crash the worker
            self._pool = None
            logger.error("alert_sink.connect_failed", error=str(exc))

    async def stop(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _ensure_pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            # One reconnect attempt per persist call — cheap when the DB is
            # down (fast connect error) and self-healing when it returns.
            await self.start()
        return self._pool

    async def persist(self, fused: FusedAlert) -> PersistResult:
        """Insert one fused alert, returning a structured :class:`PersistResult`.

        The canonical alert id is ``fused.id`` (deterministic — issue #568), so
        even a duplicate / outage carries the id the row resolves to once the
        DB is reachable.
        """
        canonical_id = str(fused.id)
        if fused.fusion_decision == FusionDecision.DUPLICATE:
            return PersistResult(PersistOutcome.DUPLICATE, canonical_id)

        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            return PersistResult(PersistOutcome.UNAVAILABLE, canonical_id)
        self._connect_failed_logged = False

        alert = fused.alert
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    _INSERT_SQL,
                    fused.id,
                    alert.tenant_id,
                    alert.title[:500],
                    alert.description or None,
                    alert.severity.value,
                    json.dumps(alert.mitre_tactics),
                    json.dumps(alert.mitre_techniques),
                    json.dumps(_iocs(fused)),
                    json.dumps(_entities(fused)),
                    json.dumps(alert.raw_event, default=str),
                    alert.fingerprint(),
                    int(round(fused.confidence_score * 100)),
                    fused.confidence_label.value,
                    json.dumps([f.model_dump() for f in fused.confidence_rationale]),
                    fused.narrative,
                    fused.anomaly_score,
                    alert.event_time,
                    alert.connector_id,
                    alert.connector_type,
                    json.dumps(alert.source_event_ids),
                    alert.ocsf_class_uid,
                    alert.rule_id,
                    alert.rule_name,
                )
            if row is None:
                logger.debug("alert_sink.dedup_skip", fingerprint=alert.fingerprint())
                return PersistResult(PersistOutcome.DUPLICATE, canonical_id)
            return PersistResult(PersistOutcome.INSERTED, str(row["id"]))
        except asyncpg.ForeignKeyViolationError:
            # Unknown tenant — a mis-provisioned connector, not a pipeline bug.
            # Distinct from a duplicate so it is observable, not silently masked.
            logger.warning("alert_sink.unknown_tenant", tenant_id=str(alert.tenant_id))
            return PersistResult(PersistOutcome.FAILED, None)
        except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the consumer
            logger.error("alert_sink.persist_failed", error=str(exc))
            return PersistResult(PersistOutcome.FAILED, None)
