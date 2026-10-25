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

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

import asyncpg
import structlog

from app.core.config import settings
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
    """Outcome of :meth:`AlertSink.persist` plus the canonical alert id.

    ``retryable`` distinguishes an outage from a bad row. The outcome alone
    cannot: a connection reset and a foreign-key violation both used to be
    ``FAILED``, and the consumer treated both the same way — either committing
    the offset (loss) or retrying a permanently bad alert forever.

    ``verified`` says the caller may trust the outcome as durable evidence.
    A ``DUPLICATE`` verdict with an unreachable database is a correct *fusion*
    verdict but not a verified store state: the surviving row might itself
    never have been written. The consumer must not commit until it is verified
    or repaired.
    """

    outcome: PersistOutcome
    alert_id: str | None = None
    retryable: bool = False
    verified: bool = True

    @property
    def persisted(self) -> bool:
        return self.outcome is PersistOutcome.INSERTED

    @property
    def durable(self) -> bool:
        """True when the alert is known to exist in the store (new or dup).

        Unverified duplicates are deliberately *not* durable. That distinction
        is the difference between "fusion remembers seeing this" (a Redis hint
        that may predate a crash) and "the row is in Postgres".
        """
        return self.verified and self.outcome in (PersistOutcome.INSERTED, PersistOutcome.DUPLICATE)


_INSERT_SQL = """
INSERT INTO alerts (
    id, tenant_id, title, description, severity, status,
    mitre_tactics, mitre_techniques, iocs, entities, raw_event,
    dedup_hash, confidence, confidence_label, confidence_rationale,
    narrative, anomaly_score, event_time,
    connector_id, connector_type, source_event_ids, ocsf_class_uid,
    rule_id, rule_name, external_id,
    affected_hosts, affected_users, affected_ips,
    session_id, session_key_kind, originating_human
)
SELECT
    $1, $2, $3, $4, $5, 'new',
    $6::jsonb, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb,
    $11::text, $12, $13, $14::jsonb,
    $15, $16, COALESCE($17, NOW()),
    $18, $19, $20::jsonb, $21,
    $22, $23, $24,
    $25::jsonb, $26::jsonb, $27::jsonb,
    $28, $29, $30
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

#: The reconciliation read for a fusion ``DUPLICATE`` verdict.
#:
#: Fusion registers a dedup fingerprint in Redis *before* the row is durable.
#: If the process dies (or Postgres rejects the insert) in that window, the
#: re-delivered message is still classified ``DUPLICATE`` and the old sink
#: returned without writing anything: the event was permanently lost while the
#: consumer committed its offset. The dedup hint is therefore treated as a
#: claim to verify, not a fact. If no row carries this ``(tenant, dedup_hash)``
#: pair, the redelivered alert is inserted under its deterministic id.
_SURVIVING_ALERT_SQL = """
SELECT id
  FROM alerts
 WHERE tenant_id = $1
   AND dedup_hash = $2::text
 LIMIT 1
"""

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


# Three layers of idempotency, complementary (issue #568):
#   * WHERE NOT EXISTS (tenant_id, dedup_hash) — content dedup; also protects
#     legacy rows written before ids were deterministic (random id, same hash).
#   * ON CONFLICT (id) DO NOTHING — exact-replay idempotency on the canonical
#     deterministic UUID (RawAlert.deterministic_id()).
#   * uq_alerts_tenant_dedup (migration 120) — the database-level guarantee for
#     two concurrent writers that supply different ids but the same fingerprint.
#     Under READ COMMITTED both can pass WHERE NOT EXISTS; the partial unique
#     index makes the second INSERT raise UniqueViolationError instead of
#     writing a second visible alert. `_persist_on_conn` resolves that
#     violation to the winner's row (see `_DEDUP_UNIQUE_INDEX`).
# NB: $11 (dedup_hash) is cast ::text in BOTH the INSERT target and the WHERE.
# `dedup_hash` is VARCHAR(64); a varchar/text mismatch makes asyncpg's prepare
# fail to unify parameter $11 ("inconsistent types deduced"), silently dropping
# every write. Pinning both uses to ::text makes the deduction unambiguous.

#: The partial unique index created by
#: ``services/api/migrations/120_alerts_tenant_dedup_unique.sql``. A unique
#: violation carrying this constraint name is the concurrent-dedup race, not a
#: malformed row: the loser must resolve the winner's row rather than fail (or
#: insert a second alert).
_DEDUP_UNIQUE_INDEX = "uq_alerts_tenant_dedup"


def _asyncpg_dsn(url: str) -> str:
    """Strip the SQLAlchemy driver suffix — asyncpg wants plain postgresql://."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


def _is_retryable_db_error(exc: BaseException) -> bool:
    """Whether re-running the statement could plausibly succeed.

    Transient: the connection was lost, the server was shutting down, a
    statement was cancelled by a timeout, or the pool was exhausted. Permanent:
    a constraint violation, an unknown tenant, invalid SQL. The two classes
    need different handling at the consumer: retry (and do not commit) versus
    dead-letter and move on.
    """
    if isinstance(
        exc,
        (
            asyncpg.PostgresConnectionError,
            asyncpg.InterfaceError,
            asyncpg.QueryCanceledError,
            asyncpg.DeadlockDetectedError,
            asyncpg.TooManyConnectionsError,
            TimeoutError,
            OSError,
        ),
    ):
        return True
    text = str(exc).lower()
    return any(
        marker in text
        for marker in (
            "connection",
            "connect",
            "server closed",
            "connection reset",
            "connection refused",
            "timed out",
            "timeout",
            "pool",
            "too many clients",
            "starting up",
            "shutting down",
            "not yet accepting",
        )
    )


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
        fused.session_id,
        fused.session_key_kind,
        fused.originating_human,
    )


class AlertSink:
    """asyncpg-backed writer from the fusion pipeline into the alert store."""

    def __init__(self, database_url: str, pool_size: int = 2) -> None:
        self._dsn = _asyncpg_dsn(database_url)
        self._pool_size = pool_size
        self._pool: asyncpg.Pool | None = None
        self._connect_failed_logged = False
        self._operation_timeout = float(getattr(settings, "alert_sink_operation_timeout_seconds", 10.0))
        self._start_lock = asyncio.Lock()

    async def start(self) -> None:
        """Open the pool. Failure is logged, not raised (fail-soft)."""
        async with self._start_lock:
            if self._pool is not None:
                return
            try:
                self._pool = await asyncpg.create_pool(
                    self._dsn,
                    min_size=1,
                    max_size=self._pool_size,
                    timeout=10,
                    command_timeout=self._operation_timeout,
                )
                logger.info("alert_sink.started")
            except Exception as exc:  # noqa: BLE001 — degrade, never crash the worker
                self._pool = None
                logger.error("alert_sink.connect_failed", error=str(exc))

    async def stop(self) -> None:
        await self._invalidate_pool()

    async def _invalidate_pool(self) -> None:
        """Forget a pool that just proved unusable.

        ``_ensure_pool`` used to reconnect only when ``_pool is None``. A pool
        whose server went away stayed non-None, so every later persist raised
        from ``acquire()`` and returned ``FAILED`` forever even after Postgres
        came back: recovery required a fusion restart. Dropping the handle on a
        connection-level failure lets the next attempt rebuild it.
        """
        pool, self._pool = self._pool, None
        if pool is not None:
            try:
                await pool.close()
            except Exception as exc:  # noqa: BLE001 — the pool is already broken
                logger.debug("alert_sink.pool_close_failed", error=str(exc))

    async def _ensure_pool(self) -> asyncpg.Pool | None:
        if self._pool is None:
            # One reconnect attempt per persist call — cheap when the DB is
            # down (fast connect error) and self-healing when it returns.
            await self.start()
        return self._pool

    async def ensure_pool(self) -> asyncpg.Pool | None:
        """Rebuild the pool if it was invalidated.

        Public because the dead-letter queue shares this pool: during a
        recovery hold no alert is being persisted, so nothing else would
        reconnect and the hold would never end after Postgres returns.
        """
        return await self._ensure_pool()

    async def invalidate_pool(self) -> None:
        """Drop a pool that just proved unusable, so the next call reconnects."""
        await self._invalidate_pool()

    async def persist(self, fused: FusedAlert) -> PersistResult:
        """Insert one fused alert, returning a structured :class:`PersistResult`.

        The canonical alert id is ``fused.id`` (deterministic — issue #568), so
        even a duplicate / outage carries the id the row resolves to once the
        DB is reachable.

        A fusion ``DUPLICATE`` is *reconciled* rather than trusted: the dedup
        fingerprint lives in Redis and is written before the row, so it can
        outlive a crash that prevented the insert. When no row carries the
        fingerprint, the redelivered alert is persisted, repairing the loss
        instead of confirming it.
        """
        canonical_id = str(fused.id)
        is_duplicate = fused.fusion_decision == FusionDecision.DUPLICATE
        try:
            result = await asyncio.wait_for(self._persist_once(fused), timeout=self._operation_timeout)
        except TimeoutError as exc:
            await self._invalidate_pool()
            logger.error("alert_sink.persist_timeout", error=str(exc), duplicate=is_duplicate)
            return PersistResult(
                PersistOutcome.DUPLICATE if is_duplicate else PersistOutcome.UNAVAILABLE,
                canonical_id,
                retryable=True,
                verified=False,
            )
        except asyncpg.ForeignKeyViolationError:
            # Unknown tenant — a mis-provisioned connector, not a pipeline bug.
            # Distinct from a duplicate so it is observable, not silently masked.
            logger.warning("alert_sink.unknown_tenant", tenant_id=str(fused.alert.tenant_id))
            return PersistResult(PersistOutcome.FAILED, None)
        except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the consumer
            retryable = _is_retryable_db_error(exc)
            if retryable:
                await self._invalidate_pool()
            logger.error("alert_sink.persist_failed", error=str(exc), retryable=retryable, duplicate=is_duplicate)
            if retryable and is_duplicate:
                # Fusion's verdict stands, but the surviving row is unverified.
                return PersistResult(PersistOutcome.DUPLICATE, canonical_id, retryable=True, verified=False)
            return PersistResult(PersistOutcome.FAILED, None, retryable=retryable)

        if result.outcome is PersistOutcome.INSERTED and result.alert_id:
            await self._link_source_finding_safely(fused, alert_id=result.alert_id)
        return result

    async def _persist_once(self, fused: FusedAlert) -> PersistResult:
        pool = await self._ensure_pool()
        if pool is None:
            if not self._connect_failed_logged:
                logger.error("alert_sink.unavailable_dropping_persistence")
                self._connect_failed_logged = True
            if fused.fusion_decision == FusionDecision.DUPLICATE:
                # Cannot verify; the consumer must retry rather than commit a
                # duplicate whose surviving row may never have been written.
                return PersistResult(PersistOutcome.DUPLICATE, str(fused.id), retryable=True, verified=False)
            return PersistResult(PersistOutcome.UNAVAILABLE, str(fused.id), retryable=True)
        self._connect_failed_logged = False
        async with pool.acquire() as conn:
            return await self._persist_on_conn(conn, fused)

    async def _persist_on_conn(self, conn: Any, fused: FusedAlert) -> PersistResult:
        """Persist one alert over an already-acquired connection.

        Shared by the single and batch paths so the duplicate-reconciliation
        rule cannot drift between them.
        """
        canonical_id = str(fused.id)
        alert = fused.alert
        is_duplicate = fused.fusion_decision == FusionDecision.DUPLICATE

        if is_duplicate:
            existing_id = await self._surviving_alert_id(conn, alert)
            if existing_id is not None:
                await self._record_deduplicated_event(conn, alert)
                return PersistResult(PersistOutcome.DUPLICATE, str(existing_id))

        try:
            row = await conn.fetchrow(_INSERT_SQL, *_insert_args(fused))
        except asyncpg.UniqueViolationError as exc:
            # Two writers with different ids can both pass the WHERE NOT EXISTS
            # guard under READ COMMITTED. The partial unique index from
            # migration 120 is the authority that stops the second row; this
            # writer lost the race and must resolve the winner's row rather
            # than report a failure (which would dead-letter an alert that is
            # already durable) or retry blindly (which would do the same).
            #
            # Both call sites (``persist`` and ``persist_many``) run each
            # statement in autocommit, so the failed INSERT does not leave a
            # transaction aborted and the reconciliation read below is valid.
            # Nothing in services/fusion opens a transaction around persist;
            # asyncpg's pool release also resets (ROLLBACKs) a leaked one. If a
            # caller ever wraps this in a transaction, run the INSERT inside a
            # nested ``conn.transaction()`` (a savepoint) so the error is
            # rolled back before this read, or it will fail with "current
            # transaction is aborted".
            #
            # Only this index is handled here. Any other *named* unique
            # violation is a schema/code disagreement and falls through to the
            # caller's existing failure path, so a database error is never
            # converted into a duplicate verdict. A driver that does not name
            # the index (constraint_name is None) still falls through to the
            # surviving-row read: if a row with this tenant and hash exists,
            # the alert is durable regardless of which constraint reported it.
            constraint = getattr(exc, "constraint_name", None)
            if constraint is not None and constraint != _DEDUP_UNIQUE_INDEX:
                raise
            existing_id = await self._surviving_alert_id(conn, alert)
            if existing_id is not None:
                logger.info(
                    "alert_sink.concurrent_dedup_resolved",
                    tenant_id=str(alert.tenant_id),
                    fingerprint=alert.fingerprint(),
                )
                await self._record_deduplicated_event(conn, alert)
                return PersistResult(PersistOutcome.DUPLICATE, str(existing_id))
            # The winner's row is not visible: it was rolled back, deleted, or
            # the read is looking at a different snapshot. Do not claim
            # durability; the consumer retries.
            logger.error(
                "alert_sink.dedup_conflict_unverified",
                tenant_id=str(alert.tenant_id),
                fingerprint=alert.fingerprint(),
            )
            return PersistResult(PersistOutcome.FAILED, canonical_id, retryable=True, verified=False)

        if row is None:
            # The `WHERE NOT EXISTS` guard filtered the insert. Resolve the row
            # that filtered it, so the returned id is the durable one (which
            # may predate deterministic ids).
            existing_id = await self._surviving_alert_id(conn, alert)
            if existing_id is not None:
                logger.debug("alert_sink.dedup_skip", fingerprint=alert.fingerprint())
                await self._record_deduplicated_event(conn, alert)
                return PersistResult(PersistOutcome.DUPLICATE, str(existing_id))
            if is_duplicate:
                # The hint said duplicate, but neither row nor insert exists.
                # Do not report durability: a retry can settle the race.
                logger.error(
                    "alert_sink.duplicate_unverified",
                    tenant_id=str(alert.tenant_id),
                    fingerprint=alert.fingerprint(),
                )
                return PersistResult(PersistOutcome.FAILED, canonical_id, retryable=True, verified=False)
            # A concurrent writer may have inserted the same id between the
            # two statements; retrying the message will re-read it.
            logger.warning("alert_sink.insert_filtered", alert_id=canonical_id)
            return PersistResult(PersistOutcome.FAILED, None, retryable=True)

        return PersistResult(PersistOutcome.INSERTED, str(row["id"]))

    async def _surviving_alert_id(self, conn: Any, alert: Any) -> Any | None:
        row = await conn.fetchrow(_SURVIVING_ALERT_SQL, alert.tenant_id, alert.fingerprint())
        return row["id"] if row is not None else None

    async def _link_source_finding_safely(self, fused: FusedAlert, *, alert_id: Any) -> None:
        # getattr rather than direct access: the batch-path tests construct the
        # sink with __new__ and replace this method, so there is no pool yet.
        pool = getattr(self, "_pool", None)
        if pool is not None:
            await self._link_source_finding(pool, fused.alert, alert_id=alert_id)

    @staticmethod
    def _unavailable_result(fused: FusedAlert) -> PersistResult:
        """A non-durable result that preserves the fusion verdict.

        A duplicate stays a duplicate (observable), but ``verified=False``
        tells the consumer it cannot commit yet.
        """
        duplicate = fused.fusion_decision == FusionDecision.DUPLICATE
        return PersistResult(
            PersistOutcome.DUPLICATE if duplicate else PersistOutcome.UNAVAILABLE,
            str(fused.id),
            retryable=True,
            verified=False,
        )

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
            return [self._unavailable_result(f) for f in fused_batch]
        self._connect_failed_logged = False

        connection_lost = False
        try:
            async with pool.acquire() as conn:
                for fused in fused_batch:
                    if connection_lost:
                        results.append(self._unavailable_result(fused))
                        continue
                    try:
                        results.append(await self._persist_on_conn(conn, fused))
                    except asyncpg.ForeignKeyViolationError:
                        logger.warning("alert_sink.unknown_tenant", tenant_id=str(fused.alert.tenant_id))
                        results.append(PersistResult(PersistOutcome.FAILED, None))
                    except Exception as exc:  # noqa: BLE001 — one bad row must not wedge the batch
                        retryable = _is_retryable_db_error(exc)
                        logger.error("alert_sink.persist_failed", error=str(exc), retryable=retryable)
                        if retryable:
                            # The connection is no longer trustworthy. Stop
                            # using it for the rest of the batch, but keep the
                            # results already obtained: those rows are durable.
                            connection_lost = True
                        duplicate = fused.fusion_decision == FusionDecision.DUPLICATE
                        results.append(
                            PersistResult(
                                PersistOutcome.DUPLICATE if duplicate else PersistOutcome.FAILED,
                                str(fused.id) if duplicate else None,
                                retryable=retryable,
                                verified=False,
                            )
                        )
        except Exception as exc:  # noqa: BLE001 — acquire/context failure is not a row failure
            retryable = _is_retryable_db_error(exc)
            if retryable:
                await self._invalidate_pool()
            logger.error("alert_sink.batch_failed", error=str(exc), retryable=retryable)
            done = len(results)
            results.extend(self._unavailable_result(f) for f in fused_batch[done:])
        else:
            if connection_lost:
                await self._invalidate_pool()

        # Source links after the inserts, on their own connections. They
        # are best-effort and a slow vendor lookup must not hold the
        # batch's connection open.
        for fused, result in zip(fused_batch, results, strict=True):
            if result.outcome is PersistOutcome.INSERTED and result.alert_id:
                await self._link_source_finding_safely(fused, alert_id=result.alert_id)

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
