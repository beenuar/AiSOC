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

import asyncpg
import structlog

from app.models.alert import FusedAlert, FusionDecision

logger = structlog.get_logger()

_INSERT_SQL = """
INSERT INTO alerts (
    tenant_id, title, description, severity, status,
    mitre_tactics, mitre_techniques, iocs, entities, raw_event,
    dedup_hash, confidence, confidence_label, confidence_rationale,
    narrative, anomaly_score, event_time
)
SELECT
    $1, $2, $3, $4, 'new',
    $5::jsonb, $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb,
    $10::text, $11, $12, $13::jsonb,
    $14, $15, COALESCE($16, NOW())
WHERE NOT EXISTS (
    SELECT 1 FROM alerts WHERE tenant_id = $1 AND dedup_hash = $10::text
)
RETURNING id
"""
# NB: $10 (dedup_hash) is cast to ::text in BOTH the INSERT target and the
# WHERE. `dedup_hash` is VARCHAR(64), and varchar comparisons resolve through
# text operators — so `WHERE dedup_hash = $10` deduces $10 as text while the
# INSERT target deduces it as varchar. asyncpg's prepare cannot unify the two
# ("inconsistent types deduced for parameter $10: text versus character
# varying") and the persist fails silently, so no alert row is ever written.
# Pinning both uses to ::text makes the deduction unambiguous.


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

    async def persist(self, fused: FusedAlert) -> str | None:
        """Insert one fused alert. Returns the new row id, or ``None`` when
        skipped (duplicate decision, dedup hit, or DB unavailable)."""
        if fused.fusion_decision == FusionDecision.DUPLICATE:
            return None

        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            return None
        self._connect_failed_logged = False

        alert = fused.alert
        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(
                    _INSERT_SQL,
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
                )
            if row is None:
                logger.debug("alert_sink.dedup_skip", fingerprint=alert.fingerprint())
                return None
            return str(row["id"])
        except asyncpg.ForeignKeyViolationError:
            # Unknown tenant — a mis-provisioned connector, not a pipeline bug.
            logger.warning("alert_sink.unknown_tenant", tenant_id=str(alert.tenant_id))
            return None
        except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the consumer
            logger.error("alert_sink.persist_failed", error=str(exc))
            return None
