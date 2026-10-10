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
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

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
    rule_id, rule_name, external_id,
    affected_hosts, affected_users, affected_ips
)
SELECT
    $1, $2, $3, $4, $5, 'new',
    $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb,
    $11::text, $12, $13, $14::jsonb,
    $15, $16, COALESCE($17, NOW()),
    $18, $19, $20::jsonb, $21,
    $22, $23, $24,
    $25::jsonb, $26::jsonb, $27::jsonb
WHERE NOT EXISTS (
    SELECT 1 FROM alerts WHERE tenant_id = $2 AND dedup_hash = $11::text
)
ON CONFLICT (id) DO NOTHING
RETURNING id
"""
# The three entity columns are appended rather than inserted beside
# `entities`, where they belong semantically, so that every existing
# positional index into `_insert_args` keeps its meaning. Renumbering 24
# placeholders to make a list read nicely is how a confidence score ends up
# in a narrative column.

#: Record a raw event that deduplicated onto an alert that already exists.
#:
#: Issue #1244. `source_event_ids` is "the raw events that produced this
#: alert" and the funnel's Correlation Instances tile counts the alerts where
#: it holds two or more. The only writer appended exactly one id *before* the
#: insert, and a deduplicated event's insert is filtered out by the
#: `WHERE NOT EXISTS` above — so the second, third and five-hundredth event to
#: fold onto an alert left no trace, the predicate could never be satisfied,
#: and the tile read zero on a pipeline that was deduplicating the whole time.
#:
#: One id per statement, with the `@>` guard making a replay a no-op rather
#: than a second entry — a consumer-group rebalance re-delivers the same event
#: and the provenance list must not grow on it. `$4` caps the array because a
#: hot dedup key would otherwise grow one row without bound; past the cap the
#: alert still exists and still deduplicates, only the list stops growing.
#: jsonb containment accepts a scalar against an array element, so
#: ``'["evt-1"]'::jsonb @> '"evt-1"'::jsonb`` is the membership test.
_DEDUP_SOURCE_EVENT_SQL = """
UPDATE alerts
   SET source_event_ids = source_event_ids || to_jsonb($3::text)
 WHERE tenant_id = $1
   AND dedup_hash = $2::text
   AND NOT (source_event_ids @> to_jsonb($3::text))
   AND jsonb_array_length(source_event_ids) < $4
"""

#: Ceiling on `source_event_ids` per alert. 200 ids is ~8 KB of JSONB, and the
#: question the column answers ("did more than one event produce this?") is
#: settled by the second entry.
_MAX_SOURCE_EVENT_IDS = 200

# The reconciliation row the two-way SIEM loop reads. Written here rather than
# from the API because fusion is the only place that holds the alert id, the
# connector instance and the vendor finding id at the same moment — asking the
# API to rediscover the link later would mean re-deriving the vendor from a
# string the promoter already parsed.
#
# `executed` is FALSE on insert and has no default in the schema: a link that
# has never been written back must not read as one that has.
_LINK_SQL = """
INSERT INTO alert_source_links (
    tenant_id, alert_id, vendor, external_id, connector_instance_id, executed
) VALUES ($1, $2, $3, $4, $5, FALSE)
ON CONFLICT (alert_id, vendor, external_id) DO NOTHING
"""

#: connector_type -> live-actions vendor id, for the SIEMs a disposition can
#: be written back to. A connector absent from this map still produces alerts;
#: it just has no return leg, which is the honest state for most sources.
_WRITEBACK_VENDOR_BY_CONNECTOR: dict[str, str] = {
    "splunk": "splunk",
    "splunk_enterprise": "splunk",
    "elastic": "elastic",
    "elasticsearch": "elastic",
    "elastic_security": "elastic",
    "microsoft_sentinel": "sentinel",
    "azure_sentinel": "sentinel",
    "sentinel": "sentinel",
    "qradar": "qradar",
    "ibm_qradar": "qradar",
    "defender": "defender",
    "microsoft_defender": "defender",
    "azure_defender": "defender",
}


def writeback_vendor(connector_type: str | None) -> str | None:
    """The vendor id a disposition would be written back to, if any."""
    if not connector_type:
        return None
    return _WRITEBACK_VENDOR_BY_CONNECTOR.get(connector_type.strip().lower())


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


def _affected(fused: FusedAlert) -> tuple[list[str], list[str], list[str]]:
    """The denormalized `affected_hosts` / `affected_users` / `affected_ips`.

    Issue #1244. These three columns have existed since migration 042, the
    ORM maps them, `GET /alerts/{id}` serialises them, and `feedback.py`,
    `rule_tuning.py`, `business_context.py`, `cases.py` and the GraphQL
    resolver all read them — but the production INSERT never named them, so
    the only rows that ever had a value were the ones `seed_demo.py` wrote.
    Every reader saw `[]` on a real alert and a populated list on a seeded
    one.

    Derived from the same fields `_entities` and `_iocs` already use rather
    than from a second source, so the row cannot disagree with itself.
    `entities` stays exactly as it was: it is the shape the Investigation
    Rail reads and these columns are the shape the filters read.
    """
    alert = fused.alert
    hosts = [alert.hostname] if alert.hostname else []
    users = [alert.username] if alert.username else []
    ips = [ip for ip in (alert.src_ip, alert.dst_ip) if ip]
    return hosts, users, ips


def _insert_args(fused: FusedAlert) -> tuple[Any, ...]:
    """The positional arguments `_INSERT_SQL` takes, in order.

    One definition, used by both the single and the batch path. They
    were two copies of a 25-element tuple, which is the kind of pair
    that drifts by one column and inserts a confidence score into a
    narrative without anything failing.
    """
    alert = fused.alert
    hosts, users, ips = _affected(fused)
    return (
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
        alert.external_id,
        json.dumps(hosts),
        json.dumps(users),
        json.dumps(ips),
    )


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
        alert = fused.alert
        if fused.fusion_decision == FusionDecision.DUPLICATE:
            # Fusion has already decided: there is no row to write, and a
            # database outage cannot change that verdict. The folded-away
            # event is still part of the surviving alert's provenance, so
            # record it when there is a pool — best-effort, never a reconnect
            # attempt, and never a different outcome.
            if self._pool is not None:
                try:
                    async with self._pool.acquire() as conn:
                        await self._record_deduplicated_event(conn, alert)
                except Exception as exc:  # noqa: BLE001 — provenance is not worth the verdict
                    logger.warning("alert_sink.dedup_provenance_failed", error=str(exc))
            return PersistResult(PersistOutcome.DUPLICATE, canonical_id)

        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            return PersistResult(PersistOutcome.UNAVAILABLE, canonical_id)
        self._connect_failed_logged = False

        try:
            async with pool.acquire() as conn:
                row = await conn.fetchrow(_INSERT_SQL, *_insert_args(fused))
                if row is None:
                    logger.debug("alert_sink.dedup_skip", fingerprint=alert.fingerprint())
                    await self._record_deduplicated_event(conn, alert)
                    return PersistResult(PersistOutcome.DUPLICATE, canonical_id)
            await self._link_source_finding(pool, alert, alert_id=row["id"])
            return PersistResult(PersistOutcome.INSERTED, str(row["id"]))
        except asyncpg.ForeignKeyViolationError:
            # Unknown tenant — a mis-provisioned connector, not a pipeline bug.
            # Distinct from a duplicate so it is observable, not silently masked.
            logger.warning("alert_sink.unknown_tenant", tenant_id=str(alert.tenant_id))
            return PersistResult(PersistOutcome.FAILED, None)
        except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the consumer
            logger.error("alert_sink.persist_failed", error=str(exc))
            return PersistResult(PersistOutcome.FAILED, None)

    async def persist_many(self, fused_batch: Sequence[FusedAlert]) -> list[PersistResult]:
        """Insert a batch of fused alerts over one connection.

        Gap-closure wave 7. `persist` acquires a pooled connection and
        makes a round trip **per alert**, so a deployment taking 200
        alerts/s makes 200 acquisitions and 200 round trips a second,
        and the alert path spends most of its time waiting rather than
        working.

        Three things are deliberately preserved, because a faster path
        that changes semantics is a different feature:

        * **One result per input, in order.** Callers already branch on
          `PersistOutcome`, and a batch that returned a summary would
          make a duplicate indistinguishable from an insert.
        * **One bad row does not take the batch.** Each insert is
          attempted inside the shared connection and a failure is
          recorded against that row alone — the same contract as the
          single path, where a malformed alert must not wedge the
          consumer.
        * **The dedup behaviour is the database's, not ours.** The
          `SELECT ... WHERE NOT EXISTS` in `_INSERT_SQL` still decides,
          so batching cannot introduce a duplicate the single path
          would have caught.

        Not a transaction spanning the batch: one rollback would then
        discard every alert in the window because of one bad row, which
        trades a per-row failure for a whole-window one.
        """
        if not fused_batch:
            return []

        results: list[PersistResult] = []
        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            return [PersistResult(PersistOutcome.UNAVAILABLE, str(f.id)) for f in fused_batch]
        self._connect_failed_logged = False

        async with pool.acquire() as conn:
            for fused in fused_batch:
                canonical_id = str(fused.id)
                if fused.fusion_decision == FusionDecision.DUPLICATE:
                    await self._record_deduplicated_event(conn, fused.alert)
                    results.append(PersistResult(PersistOutcome.DUPLICATE, canonical_id))
                    continue
                try:
                    row = await conn.fetchrow(_INSERT_SQL, *_insert_args(fused))
                except asyncpg.ForeignKeyViolationError:
                    logger.warning("alert_sink.unknown_tenant", tenant_id=str(fused.alert.tenant_id))
                    results.append(PersistResult(PersistOutcome.FAILED, None))
                    continue
                except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the batch
                    logger.error("alert_sink.persist_failed", error=str(exc))
                    results.append(PersistResult(PersistOutcome.FAILED, None))
                    continue

                if row is None:
                    await self._record_deduplicated_event(conn, fused.alert)
                    results.append(PersistResult(PersistOutcome.DUPLICATE, canonical_id))
                    continue
                results.append(PersistResult(PersistOutcome.INSERTED, str(row["id"])))

        # Source links after the inserts, on their own connections. They
        # are best-effort and a slow vendor lookup must not hold the
        # batch's connection open.
        for fused, result in zip(fused_batch, results, strict=True):
            if result.outcome is PersistOutcome.INSERTED and result.alert_id:
                await self._link_source_finding(pool, fused.alert, alert_id=result.alert_id)

        return results

    async def _record_deduplicated_event(self, conn: Any, alert: Any) -> None:
        """Attach a folded-away event's id to the alert it deduplicated onto.

        Best-effort, for the same reason `_link_source_finding` is: the
        provenance entry is worth one statement, never the verdict the caller
        is about to return. A failure here must not turn a correct DUPLICATE
        into a FAILED.
        """
        ids = [i for i in (alert.source_event_ids or []) if i]
        if not ids:
            return
        fingerprint = alert.fingerprint()
        try:
            for source_event_id in ids:
                await conn.execute(
                    _DEDUP_SOURCE_EVENT_SQL,
                    alert.tenant_id,
                    fingerprint,
                    str(source_event_id),
                    _MAX_SOURCE_EVENT_IDS,
                )
        except Exception as exc:  # noqa: BLE001 — provenance is not worth the alert
            logger.warning("alert_sink.dedup_provenance_failed", error=str(exc))

    async def _link_source_finding(self, pool: asyncpg.Pool, alert: Any, *, alert_id: Any) -> None:
        """Record which vendor finding produced this alert, when there is one.

        Best-effort by design. A missing link costs a writeback; raising here
        would cost the alert, and the alert is the thing that matters. Silent
        skips are the common case (most sources are not a SIEM whose findings
        AiSOC can write to), so they log at debug and a genuine failure at
        warning.
        """
        vendor = writeback_vendor(alert.connector_type)
        if not vendor or not alert.external_id:
            logger.debug(
                "alert_sink.no_source_link",
                connector_type=alert.connector_type,
                has_external_id=bool(alert.external_id),
            )
            return
        try:
            async with pool.acquire() as conn:
                await conn.execute(
                    _LINK_SQL,
                    alert.tenant_id,
                    alert_id,
                    vendor,
                    alert.external_id,
                    alert.connector_id,
                )
            logger.info("alert_sink.source_linked", vendor=vendor, alert_id=str(alert_id))
        except Exception as exc:  # noqa: BLE001 — never fail an alert over its link row
            logger.warning("alert_sink.source_link_failed", vendor=vendor, error=str(exc))
