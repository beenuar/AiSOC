"""Durable record of a fused alert that still owes its Kafka notification.

The window this closes
----------------------
``_fuse_and_persist`` persists the alert row first and publishes second, so a
downstream consumer never sees a row id that does not exist. Publication and
the input-offset commit cannot be made atomic, so two orderings have to be
accounted for, and only one of them was:

* **The process dies between the durable row and the publish.** The input
  offset was never committed, so Kafka re-delivers the record, the sink
  answers ``DUPLICATE`` (verified against the row that survived), and the
  publish is retried. Re-delivery is the recovery mechanism and it works.

* **The publish fails until the retry budget is gone.** The consumer then
  dead-letters the message and *commits the offset* — correctly, because the
  dead letter is a durable capture. But the alert row exists, the offset has
  moved past the source event, and nothing will ever publish the envelope.
  A dead letter is a triage record, not a delivery queue: nothing re-drives
  it. That alert is in Postgres and invisible to auto-triage forever.

This module is the recovery record for the second case. It is deliberately
**not** a transactional outbox: nothing is written on the happy path, because
the first case is already covered by an offset that has not moved, and making
every alert pay for an extra INSERT and DELETE to cover a window re-delivery
already covers would be a cost with no reader. A row is written only once a
publish has definitively failed, and it is written *before* the consumer is
allowed to acknowledge the message — which is the property that matters: an
acknowledged message never leaves an unpublished alert without a record of it.

What it guarantees, stated plainly
----------------------------------
Delivery of a fused alert is **at-least-once**, and this is what makes the
"at least" true rather than aspirational. It is not exactly-once and must not
be described as such: the relay can publish an envelope that an inline retry
had already delivered, and a broker acknowledgement that arrives after the
publisher stopped waiting is indistinguishable from one that never arrived.
Every published record is keyed by its canonical alert id so a consumer can
collapse the duplicates.

Rows are *deleted* when they are delivered rather than flagged, so the table
is exactly the set of alerts that still owe a notification and the backlog is
``COUNT(*)`` rather than a filtered scan over history.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

#: One pending notification per alert. A second failure for the same alert
#: updates the attempt counter instead of adding a row, so a long outage
#: cannot turn a bounded backlog into an unbounded one.
_RECORD_SQL = """
INSERT INTO fusion_alert_outbox (tenant_id, alert_id, topic, dedupe_key, payload, attempts, last_error)
VALUES ($1::uuid, $2::uuid, $3, $4, $5::jsonb, 1, $6)
ON CONFLICT (tenant_id, alert_id) DO UPDATE
SET attempts = fusion_alert_outbox.attempts + 1,
    last_error = EXCLUDED.last_error,
    payload = EXCLUDED.payload
"""

_CLEAR_SQL = "DELETE FROM fusion_alert_outbox WHERE tenant_id = $1::uuid AND alert_id = $2::uuid"


@dataclass(frozen=True)
class PendingNotification:
    """One fused alert whose envelope has not reached the broker."""

    id: int
    tenant_id: str
    alert_id: str
    topic: str
    key: str
    payload: dict[str, Any]
    attempts: int


class AlertNotificationOutbox:
    """Postgres-backed journal of undelivered fused-alert notifications.

    Shares the alert sink's connection pool, for the reason the dead-letter
    queue and the AI-asset recorder share it: one pool per service, opened by
    ``sink.start()`` during ``worker.start()``. The pool therefore arrives as
    a callable, because capturing it eagerly captures ``None``.

    Every method is fail-soft and says so in its return type. A journal that
    raises into the consumer would turn a Kafka blip into a stalled partition,
    which is worse than the gap it is recording. ``record`` returning ``False``
    is the one answer a caller must act on: it means the notification is *not*
    recoverable, so the message must not be acknowledged.
    """

    def __init__(self, pool_factory: Callable[[], Any], *, ensure_pool: Callable[[], Any] | None = None) -> None:
        self._pool_factory = pool_factory
        self._ensure_pool = ensure_pool
        #: Latched after the first "relation does not exist", so a deployment
        #: that has not run the migration logs once rather than per alert.
        #: Not auto-created: a CREATE TABLE here would swallow a permissions
        #: failure into a log line and leave the service reporting healthy
        #: with no journal at all.
        self._schema_missing = False

    @property
    def available(self) -> bool:
        """Whether the journal can record. False once the table is known absent."""
        return not self._schema_missing

    async def _pool(self) -> Any | None:
        pool = self._pool_factory()
        if pool is None and self._ensure_pool is not None:
            pool = await self._ensure_pool()
        return pool

    @staticmethod
    def _is_missing_schema(exc: BaseException) -> bool:
        # asyncpg raises UndefinedTableError; matching the SQLSTATE rather
        # than the class keeps this working if the driver is swapped.
        return getattr(exc, "sqlstate", None) == "42P01"

    def _note_missing_schema(self) -> None:
        if self._schema_missing:
            return
        self._schema_missing = True
        logger.error(
            "fusion.outbox_schema_missing",
            table="fusion_alert_outbox",
            detail=(
                "migration 121 has not been applied; an alert whose publish fails until the retry "
                "budget is exhausted has no recovery record and will not be delivered"
            ),
        )

    async def record(self, *, tenant_id: str, alert_id: str, topic: str, key: str, payload: dict[str, Any], error: str) -> bool:
        """Journal one undelivered notification. False means it was not recorded.

        The caller must treat ``False`` as "this alert is not recoverable" and
        keep the Kafka offset uncommitted, because committing it is what makes
        the gap permanent.
        """
        if self._schema_missing:
            return False
        pool = await self._pool()
        if pool is None:
            return False
        try:
            async with pool.acquire() as conn:
                await conn.execute(_RECORD_SQL, tenant_id, alert_id, topic, key, json.dumps(payload, default=str), error[:2000])
            return True
        except Exception as exc:  # noqa: BLE001 — never raise into the consumer
            if self._is_missing_schema(exc):
                self._note_missing_schema()
            else:
                logger.error("fusion.outbox_record_failed", alert_id=alert_id, error=str(exc))
            return False

    async def clear(self, *, tenant_id: str, alert_id: str) -> None:
        """Drop a journal row once the alert has been published inline.

        Called only when the sink answered ``DUPLICATE``, which is the one
        outcome that says "this alert already existed", and therefore the only
        path on which a journal row from an earlier attempt can be pending. On
        the ``INSERTED`` path the row is new and nothing can have journalled
        it, so the happy path pays nothing.
        """
        if self._schema_missing:
            return
        pool = await self._pool()
        if pool is None:
            return
        try:
            async with pool.acquire() as conn:
                await conn.execute(_CLEAR_SQL, tenant_id, alert_id)
        except Exception as exc:  # noqa: BLE001
            if self._is_missing_schema(exc):
                self._note_missing_schema()
            else:
                # A stale row republishes later. That is a duplicate, which
                # the delivery contract already allows, so this is a warning
                # and not a failure the caller has to handle.
                logger.warning("fusion.outbox_clear_failed", alert_id=alert_id, error=str(exc))

    async def claim(self, *, limit: int, lease_seconds: float, grace_seconds: float) -> list[PendingNotification]:
        """Lease up to ``limit`` pending notifications for this replica."""
        if self._schema_missing:
            return []
        pool = await self._pool()
        if pool is None:
            return []
        # Claim with a lease, in one statement. ``FOR UPDATE SKIP LOCKED`` is what
        # makes two replicas safe to run: the second one's sub-select steps over the
        # rows the first has locked instead of blocking on them. The lease (rather
        # than a lock held for the duration of the publish) is what makes a relay
        # that dies mid-publish recoverable — the rows become claimable again when
        # it expires, instead of being stranded behind a connection that is gone.
        #
        # ``created_at < now() - grace`` gives the consumer's own inline retry budget
        # first refusal. Without it the relay would race the retry that is already
        # in progress and publish a duplicate for every transient broker blip.
        claim_sql = """
UPDATE fusion_alert_outbox AS o
SET claimed_until = now() + make_interval(secs => $1::double precision),
    last_attempt_at = now()
WHERE o.id IN (
    SELECT c.id FROM fusion_alert_outbox AS c
    WHERE (c.claimed_until IS NULL OR c.claimed_until < now())
      AND c.created_at < now() - make_interval(secs => $2::double precision)
    ORDER BY c.created_at
    FOR UPDATE SKIP LOCKED
    LIMIT $3::int
)
RETURNING o.id, o.tenant_id, o.alert_id, o.topic, o.dedupe_key, o.payload, o.attempts
"""
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(claim_sql, float(lease_seconds), float(grace_seconds), int(limit))
        except Exception as exc:  # noqa: BLE001
            if self._is_missing_schema(exc):
                self._note_missing_schema()
            else:
                logger.warning("fusion.outbox_claim_failed", error=str(exc))
            return []
        claimed: list[PendingNotification] = []
        for row in rows:
            payload = row["payload"]
            if isinstance(payload, str):  # asyncpg returns jsonb as text without a codec
                try:
                    payload = json.loads(payload)
                except ValueError:
                    logger.error("fusion.outbox_payload_unreadable", outbox_id=row["id"])
                    continue
            claimed.append(
                PendingNotification(
                    id=int(row["id"]),
                    tenant_id=str(row["tenant_id"]),
                    alert_id=str(row["alert_id"]),
                    topic=str(row["topic"]),
                    key=str(row["dedupe_key"]),
                    payload=payload,
                    attempts=int(row["attempts"]),
                )
            )
        return claimed

    async def resolve(self, delivered: list[PendingNotification]) -> None:
        """Delete the rows this replica has now delivered.

        Takes the claims rather than bare ids so the delete carries a tenant
        predicate. The relay spans tenants by construction -- it drains
        whatever is owed -- but that is a reason for the *claim* to be
        unscoped, not for every statement after it: a delete keyed on an id
        alone would reach any row in the table if the id were ever wrong,
        and the pairing costs nothing because the claim already returned it.
        """
        if self._schema_missing or not delivered:
            return
        pool = await self._pool()
        if pool is None:
            return
        resolve_sql = """
DELETE FROM fusion_alert_outbox
WHERE (tenant_id, id) IN (SELECT * FROM unnest($1::uuid[], $2::bigint[]))
"""
        try:
            async with pool.acquire() as conn:
                await conn.execute(resolve_sql, [item.tenant_id for item in delivered], [item.id for item in delivered])
        except Exception as exc:  # noqa: BLE001
            # The lease expires and the row is re-claimed, so the cost of
            # this failing is a duplicate publication, not a lost alert.
            logger.warning("fusion.outbox_resolve_failed", count=len(delivered), error=str(exc))

    async def record_attempt_failed(self, pending: PendingNotification, error: str) -> None:
        """Release the lease early so a transient failure retries sooner.

        Scoped on the tenant the claim returned, for the reason
        :meth:`resolve` is.
        """
        if self._schema_missing:
            return
        pool = await self._pool()
        if pool is None:
            return
        fail_sql = """
UPDATE fusion_alert_outbox
SET attempts = attempts + 1, last_error = $3, claimed_until = NULL
WHERE id = $1::bigint AND tenant_id = $2::uuid
"""
        try:
            async with pool.acquire() as conn:
                await conn.execute(fail_sql, pending.id, pending.tenant_id, error[:2000])
        except Exception as exc:  # noqa: BLE001
            logger.warning("fusion.outbox_attempt_update_failed", outbox_id=pending.id, error=str(exc))

    async def backlog(self) -> tuple[int | None, float | None, dict[str, int]]:
        """``(pending rows, age of the oldest in seconds, per-tenant counts)``.

        ``None`` for either number means it could not be read, which is
        deliberately not zero: an unreadable backlog reported as no backlog
        is how a stuck relay looks healthy. The age rides along because a
        count alone cannot tell a backlog that is draining from one that is
        stuck -- ten rows ten seconds old and ten three days old read
        identically.

        Grouped by tenant rather than summed in SQL. On a deployment serving
        several tenants the useful question is *whose* notifications are
        stuck, and a single number cannot answer it; the totals the metrics
        route renders are folded from these rows.
        """
        if self._schema_missing:
            return None, None, {}
        pool = await self._pool()
        if pool is None:
            return None, None, {}
        backlog_sql = """
SELECT tenant_id, count(*) AS n, extract(epoch FROM now() - min(created_at)) AS age
FROM fusion_alert_outbox
GROUP BY tenant_id
"""
        try:
            async with pool.acquire() as conn:
                rows = await conn.fetch(backlog_sql)
        except Exception as exc:  # noqa: BLE001
            if self._is_missing_schema(exc):
                self._note_missing_schema()
            else:
                logger.warning("fusion.outbox_backlog_unreadable", error=str(exc))
            return None, None, {}
        per_tenant = {str(row["tenant_id"]): int(row["n"]) for row in rows}
        oldest = max((float(row["age"]) for row in rows if row["age"] is not None), default=None)
        return sum(per_tenant.values()), oldest, per_tenant


class NotificationRelay:
    """Drains the journal: claims pending notifications and publishes them.

    Runs as a background task beside the consume loop rather than as its own
    service, because it needs exactly the two things the worker already holds
    — the Kafka producer and the alert sink's pool — and a separate process
    would be a component CORE does not start, which is the deployment most
    likely to be running without one.

    ``publish`` is injected rather than the producer, so the relay delivers
    through the same awaited-acknowledgement path as the inline publish. A
    relay with its own send would be a second definition of "delivered", and
    the one that drifts is always the one with no traffic on it.
    """

    def __init__(
        self,
        outbox: AlertNotificationOutbox,
        publish: Callable[[dict[str, Any], str], Awaitable[None]],
        *,
        interval_seconds: float = 15.0,
        batch_size: int = 50,
        lease_seconds: float = 60.0,
        grace_seconds: float = 120.0,
    ) -> None:
        self._outbox = outbox
        self._publish = publish
        self._interval = max(1.0, interval_seconds)
        self._batch = max(1, batch_size)
        self._lease = max(1.0, lease_seconds)
        #: Head start for the consumer's own inline retries. Set above the
        #: retry budget (8 attempts, 30 s cap) so the relay is the recovery
        #: for a message that has been acknowledged, never a competitor to a
        #: retry that is still running.
        self._grace = max(0.0, grace_seconds)
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()
        self.recovered = 0
        self.failures = 0

    def start(self) -> None:
        if self._task is not None:  # pragma: no cover — start() is called once
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None

    async def _run(self) -> None:
        try:
            while not self._stop.is_set():
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                if self._stop.is_set():
                    return
                try:
                    await self.drain_once()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001 — a relay must not die on one sweep
                    logger.error("fusion.relay_sweep_failed", error=str(exc), exc_info=True)
        except asyncio.CancelledError:  # pragma: no cover — shutdown path
            pass

    async def drain_once(self) -> int:
        """Publish one batch of pending notifications. Returns how many landed."""
        pending = await self._outbox.claim(limit=self._batch, lease_seconds=self._lease, grace_seconds=self._grace)
        if not pending:
            return 0
        delivered: list[PendingNotification] = []
        for item in pending:
            try:
                await self._publish(item.payload, item.key)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.failures += 1
                logger.warning(
                    "fusion.relay_publish_failed",
                    alert_id=item.alert_id,
                    attempts=item.attempts,
                    error=str(exc),
                )
                await self._outbox.record_attempt_failed(item, str(exc))
                # Stop the sweep rather than walking the rest of the batch
                # into the same unreachable broker. The remaining rows keep
                # their lease and are re-claimed once it expires.
                break
            delivered.append(item)
        if delivered:
            self.recovered += len(delivered)
            await self._outbox.resolve(delivered)
            logger.info("fusion.notifications_recovered", count=len(delivered))
        return len(delivered)
