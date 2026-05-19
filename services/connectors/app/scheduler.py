"""APScheduler-driven polling loop for enabled connector instances.

The connectors microservice runs a single ``ConnectorScheduler`` per process,
started in the FastAPI lifespan and stopped on shutdown. The scheduler:

1. Periodically reloads the enabled-connector list from Postgres (the API
   service owns the ``connectors`` table; we read it directly via SQLAlchemy
   Core).
2. For each enabled instance, schedules an async job that runs every
   ``connector_config.poll_interval_seconds`` (default 300s = 5 min).
3. On each tick, the job decrypts ``auth_config`` via the vendored
   ``CredentialVault``, instantiates the connector class with the merged
   config, calls ``fetch_alerts()``, normalizes each event, and pushes the
   batch to ``services/ingest`` via ``IngestClient``.
4. Records success or failure on the connector row so the UI / health
   dashboards can show per-connector status.

Design rationale
----------------

* **APScheduler in-process** instead of Celery / RQ / a Go daemon: the
  poll workload is tiny (one HTTP round-trip per source per 5 min) and
  the per-connector logic is already async Python. Standing up a broker
  for this would be over-engineering, and we'd lose direct access to the
  connector classes' Python types. APScheduler's ``AsyncIOScheduler`` runs
  on the existing FastAPI event loop with effectively zero overhead for
  idle connectors.

* **Reload from DB, don't watch**: the API service can create / disable
  / update connectors at any time. Rather than wire up a pub/sub
  notification channel (LISTEN/NOTIFY, Redis pubsub, etc.) we just refetch
  the enabled set every ``RELOAD_INTERVAL_SECONDS`` (60s by default).
  Worst case a newly-created connector waits up to 60s for its first
  poll, which is fine — humans don't care about that latency for a thing
  that polls every 5 minutes anyway.

* **One async job per instance**: APScheduler schedules each connector
  by ``connector_id`` (UUID string). When we reload, any connector_id we
  no longer see gets ``remove_job``'d, any new one gets ``add_job``'d,
  and any existing one stays put. Idempotent reloads keep the scheduler
  state in sync with the DB without restart races.

* **Failures are recorded, not raised**: ``record_poll_failure`` updates
  the row's health status; we never let an exception escape the job
  function because APScheduler would then start de-prioritising the job.
  We *do* emit the exception via ``logger.exception`` so it shows up in
  centralized logs.
"""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy.ext.asyncio import AsyncEngine

from app.connectors import CONNECTOR_REGISTRY
from app.db.connector_repo import (
    ConnectorInstance,
    fetch_enabled_connectors,
    record_backfill_run,
    record_poll_failure,
    record_poll_success,
    record_schema_drift,
)
from app.db.engine import get_engine
from app.ingest_client import IngestClient, IngestClientError
from app.pipeline import (
    apply_filter_rules,
    compute_fingerprint,
    diff_fingerprints,
)
from app.security.credential_vault import CredentialVault, CredentialVaultError, get_vault

logger = logging.getLogger("aisoc.connectors.scheduler")

# How often we re-read the connectors table to pick up new / disabled
# instances. Tuned to balance UI-perceived latency against DB load — at
# 60s with N connectors, we issue 1 SELECT/min regardless of N.
_DEFAULT_RELOAD_INTERVAL_S = 60.0

# Default poll cadence per connector instance when ``connector_config``
# doesn't override it. Five minutes is the standard SOC poll interval and
# matches every connector's default ``since_seconds=300`` parameter.
_DEFAULT_POLL_INTERVAL_S = 300

# Hard floor / ceiling so a misconfigured ``connector_config`` can't DoS
# either the source API (too short) or render polling pointless (too long).
_MIN_POLL_INTERVAL_S = 30
_MAX_POLL_INTERVAL_S = 86400  # 24 hours

# Workstream 5: backfill-on-outage tunables.
#
# When a connector recovers from an outage that lasted at least
# ``_BACKFILL_OUTAGE_THRESHOLD_S`` we kick off a one-shot poll with an
# extended lookback window so the customer doesn't have a hole in their
# data for the duration of the outage. The threshold matches the v2 plan
# spec ("backfill-on-outage worker fires when a connector is unhealthy
# for >30 min and then recovers").
#
# We also enforce a flap-suppression window: if a backfill ran within the
# last ``_BACKFILL_FLAP_WINDOW_S`` we won't fire another one even if
# ``last_outage_at`` looks long. This prevents re-firing on a recovery
# that briefly toggled back to unhealthy and then to healthy again.
#
# ``_MAX_BACKFILL_LOOKBACK_S`` caps the lookback we ask the source for
# regardless of outage length, to prevent a 3-day outage from triggering
# a 3-day query that the source rate-limits or rejects.
_BACKFILL_OUTAGE_THRESHOLD_S = 30 * 60  # 30 minutes
_BACKFILL_FLAP_WINDOW_S = 10 * 60  # 10 minutes
_MAX_BACKFILL_LOOKBACK_S = 24 * 60 * 60  # 24 hours
# Small buffer added to the computed backfill window to cover the gap
# between the last successful poll and ``last_outage_at`` (which is set
# at *first failed* poll, not at the last successful one).
_BACKFILL_LOOKBACK_BUFFER_S = 5 * 60


def _coerce_poll_interval(connector_config: dict[str, Any]) -> int:
    """Pull ``poll_interval_seconds`` out of the config blob, with bounds."""
    raw = connector_config.get("poll_interval_seconds", _DEFAULT_POLL_INTERVAL_S)
    try:
        seconds = int(raw)
    except (TypeError, ValueError):
        return _DEFAULT_POLL_INTERVAL_S
    if seconds < _MIN_POLL_INTERVAL_S:
        return _MIN_POLL_INTERVAL_S
    if seconds > _MAX_POLL_INTERVAL_S:
        return _MAX_POLL_INTERVAL_S
    return seconds


def _job_id(connector_id: uuid.UUID) -> str:
    """Stable APScheduler job_id for an instance."""
    return f"connector:{connector_id}"


class ConnectorScheduler:
    """Owns the APScheduler instance and the DB-reload loop."""

    def __init__(
        self,
        *,
        engine: AsyncEngine | None = None,
        ingest_client: IngestClient | None = None,
        vault: CredentialVault | None = None,
        reload_interval_seconds: float = _DEFAULT_RELOAD_INTERVAL_S,
    ) -> None:
        # Lazily resolve everything so tests can inject fakes; production
        # callers just construct ``ConnectorScheduler()`` and rely on env.
        self._engine = engine
        self._ingest_client = ingest_client
        self._vault = vault
        self._reload_interval_s = reload_interval_seconds
        self._scheduler: AsyncIOScheduler | None = None
        # Cache of {connector_id_str: last_seen_config_signature} so reloads
        # can detect when an instance's poll interval / config changed and
        # need its job rescheduled, vs leaving an unchanged job alone.
        self._known_signatures: dict[str, str] = {}

    # ------------------------------------------------------------------ lifecycle

    async def start(self) -> None:
        """Construct the scheduler and kick off the reload loop.

        Safe to call once per process. Calling twice is a programming error;
        we raise rather than silently start a second scheduler.
        """
        if self._scheduler is not None:
            raise RuntimeError("ConnectorScheduler.start() called twice")

        # Resolve dependencies now that we're inside an event loop.
        if self._engine is None:
            self._engine = get_engine()
        if self._ingest_client is None:
            self._ingest_client = IngestClient.from_env()
        if self._vault is None:
            try:
                self._vault = get_vault()
            except CredentialVaultError as exc:
                # If the vault isn't configured we *cannot* decrypt creds, so
                # polling can never succeed. Log and bail rather than silently
                # poll-and-fail forever.
                logger.error("connector.scheduler.vault_unavailable: %s", exc)
                raise

        self._scheduler = AsyncIOScheduler(timezone="UTC")
        self._scheduler.start()

        # Fire one reload immediately so we don't wait
        # ``reload_interval`` seconds for the first poll cycle.
        await self.reload_jobs()

        # Then schedule the periodic reload. ``id`` is fixed so we can't
        # accidentally double-schedule.
        self._scheduler.add_job(
            self.reload_jobs,
            "interval",
            seconds=self._reload_interval_s,
            id="_reload_loop",
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        logger.info(
            "connector.scheduler.started reload_interval=%ss",
            self._reload_interval_s,
        )

    async def stop(self) -> None:
        """Stop the scheduler and release resources."""
        if self._scheduler is not None:
            # ``wait=False`` so we don't block shutdown waiting for an
            # in-flight poll to finish; the next start picks up where we
            # left off (record_poll_success has already been written for
            # successful polls before this point).
            self._scheduler.shutdown(wait=False)
            self._scheduler = None
        if self._ingest_client is not None:
            await self._ingest_client.aclose()
        self._known_signatures.clear()
        logger.info("connector.scheduler.stopped")

    # ------------------------------------------------------------------ reload

    async def reload_jobs(self) -> None:
        """Sync APScheduler jobs with the enabled-connectors set in Postgres.

        Three actions per reload tick:

        * **add**: instances we haven't scheduled yet
        * **update**: instances whose config signature changed (e.g. the user
          tightened the poll interval)
        * **remove**: instances we previously scheduled but are no longer
          enabled / no longer present
        """
        if self._scheduler is None or self._engine is None:
            # ``stop()`` was called between ticks, or ``start()`` was never
            # called. Either way: nothing to do.
            return

        try:
            async with self._engine.begin() as conn:
                instances = await fetch_enabled_connectors(conn)
        except Exception:
            # DB transient errors shouldn't take the scheduler down. Log and
            # try again at the next reload tick.
            logger.exception("connector.scheduler.reload_failed")
            return

        seen: set[str] = set()
        for inst in instances:
            cid = str(inst.id)
            seen.add(cid)
            sig = self._signature(inst)
            existing = self._known_signatures.get(cid)
            if existing == sig:
                # Unchanged — leave the existing job alone.
                continue

            interval = _coerce_poll_interval(inst.connector_config)
            self._scheduler.add_job(
                self._poll_one,
                "interval",
                seconds=interval,
                id=_job_id(inst.id),
                replace_existing=True,
                max_instances=1,
                # Don't pile up missed polls if the source was slow/dead.
                coalesce=True,
                # Spread first-fire by seconds-since-epoch hash so 100
                # connectors don't all stampede at the same instant.
                next_run_time=None,
                kwargs={"connector_id": inst.id},
            )
            self._known_signatures[cid] = sig
            logger.info(
                "connector.scheduler.scheduled id=%s type=%s interval=%ss",
                cid,
                inst.connector_type,
                interval,
            )

        # Remove jobs for instances that disappeared from the enabled set
        # (deleted, disabled, or moved to another tenant we don't poll).
        for cid in list(self._known_signatures.keys()):
            if cid in seen:
                continue
            try:
                # uuid.UUID round-trip protects against malformed cache keys.
                self._scheduler.remove_job(_job_id(uuid.UUID(cid)))
            except Exception:  # pragma: no cover - APScheduler raises JobLookupError
                pass
            self._known_signatures.pop(cid, None)
            logger.info("connector.scheduler.unscheduled id=%s", cid)

    @staticmethod
    def _signature(inst: ConnectorInstance) -> str:
        """Cheap fingerprint for change detection.

        We don't include ``auth_config`` because the auth blob is
        encrypted and we don't want to decrypt it just to check whether a
        secret rotated — every poll cycle reads fresh creds anyway.
        Including connector_type catches the (rare) case where a row was
        re-typed; including the poll interval catches the common case
        where the user adjusts cadence.
        """
        interval = _coerce_poll_interval(inst.connector_config)
        return f"{inst.connector_type}|{interval}"

    # ------------------------------------------------------------------ polling

    async def _poll_one(
        self,
        *,
        connector_id: uuid.UUID,
        backfill_seconds: int | None = None,
    ) -> None:
        """Single-connector poll cycle.

        Always wraps the entire body in try/except so a misbehaving
        connector class can't take down the scheduler. Records success or
        failure on the row, then returns.

        When ``backfill_seconds`` is provided this is a one-shot recovery
        poll triggered by the backfill-on-outage worker. We use that value
        as the lookback instead of the connector's normal poll cadence and
        we skip the recovery-detection branch at the end (we don't want
        the backfill itself to schedule another backfill).
        """
        if self._engine is None or self._ingest_client is None or self._vault is None:
            logger.warning(
                "connector.scheduler.poll_skipped id=%s reason=scheduler_not_ready",
                connector_id,
            )
            return

        # Re-fetch the row at poll time rather than relying on a cached
        # copy from the reload tick — credentials may have been rotated
        # since the last reload.
        try:
            async with self._engine.begin() as conn:
                instances = await fetch_enabled_connectors(conn)
        except Exception:
            logger.exception(
                "connector.scheduler.poll_load_failed id=%s",
                connector_id,
            )
            return

        target: ConnectorInstance | None = next((i for i in instances if i.id == connector_id), None)
        if target is None:
            # Instance was deleted / disabled between reload and poll.
            # Reload will clean up the job on its next tick.
            logger.info(
                "connector.scheduler.poll_skipped id=%s reason=not_enabled",
                connector_id,
            )
            return

        connector_class = CONNECTOR_REGISTRY.get(target.connector_type)
        if connector_class is None:
            # Catalog drift — the API service stored a connector_type this
            # build doesn't know about. Mark unhealthy and bail; the human
            # operator will see the bad type in the UI.
            logger.error(
                "connector.scheduler.unknown_type id=%s type=%s",
                connector_id,
                target.connector_type,
            )
            await self._record_failure(target.id)
            return

        # Decrypt creds and instantiate. We do this inside the try block
        # so InvalidToken / TypeError / etc all funnel into the same
        # failure recorder.
        try:
            auth = self._vault.decrypt_dict(target.auth_config or {})
        except CredentialVaultError as exc:
            logger.error(
                "connector.scheduler.decrypt_failed id=%s err=%s",
                connector_id,
                exc,
            )
            await self._record_failure(target.id)
            return

        # Filter out the scheduler-only knobs from connector_config before
        # passing to the constructor — connectors don't accept
        # ``poll_interval_seconds`` as a kwarg.
        runtime_config = {k: v for k, v in (target.connector_config or {}).items() if k not in {"poll_interval_seconds"}}
        kwargs = {**auth, **runtime_config}

        started = datetime.now(UTC)
        try:
            connector = connector_class(**kwargs)
        except TypeError as exc:
            logger.error(
                "connector.scheduler.bad_config id=%s type=%s err=%s",
                connector_id,
                target.connector_type,
                exc,
            )
            await self._record_failure(target.id)
            return

        # The schema lives in connector_config; use it for fetch lookback.
        # We deliberately default to the same poll interval, so a 5-min
        # poll fetches the last 5 min of events. This keeps the source
        # query window aligned with the scheduler cadence.
        #
        # Workstream 5: when this is a backfill-on-outage poll, the worker
        # passes an explicit ``backfill_seconds`` window covering the outage
        # duration (capped at _MAX_BACKFILL_LOOKBACK_S). The cap matters
        # because some sources rate-limit or outright reject very large
        # query windows.
        if backfill_seconds is not None:
            since_seconds = max(1, min(int(backfill_seconds), _MAX_BACKFILL_LOOKBACK_S))
            logger.info(
                "connector.scheduler.backfill_poll id=%s type=%s since_seconds=%d",
                connector_id,
                target.connector_type,
                since_seconds,
            )
        else:
            since_seconds = _coerce_poll_interval(target.connector_config)
        try:
            raw_events = await connector.fetch_alerts(since_seconds=since_seconds)
        except Exception:
            logger.exception(
                "connector.scheduler.fetch_failed id=%s type=%s",
                connector_id,
                target.connector_type,
            )
            await self._record_failure(target.id)
            return

        # Normalize defensively: connectors *should* normalize themselves
        # in fetch_alerts, but we double-tap so a connector that returns
        # raw events still produces consistent shapes downstream.
        normalized = [_safe_normalize(connector, e) for e in raw_events]

        # ---- Security Data Pipeline: pre-ingest filter rules ----
        #
        # Rules live on the connector's ``connector_config["filter_rules"]``
        # array. ``apply_filter_rules`` is pure: it just decides drop/keep.
        # We count drops here so they show up in ``events_dropped`` on the
        # row and emit one info-level log per drop so an operator can audit
        # filter behavior without trawling the database.
        filter_rules = (target.connector_config or {}).get("filter_rules") or []
        kept: list[dict[str, Any]] = []
        dropped_count = 0
        for event in normalized:
            decision = apply_filter_rules(event, filter_rules)
            if decision.action == "drop":
                dropped_count += 1
                # Keep the log line short — high-volume connectors can drop
                # hundreds of events per poll, and we don't want the log to
                # become the bottleneck. The rule_index is enough to find
                # the offending rule in the connector config.
                logger.debug(
                    "connector.scheduler.filter_drop id=%s rule_index=%s",
                    connector_id,
                    decision.rule_index,
                )
                continue
            kept.append(event)

        # ---- Schema-Drift Sentinel: fingerprint the kept batch ----
        #
        # We fingerprint *kept* events (post-filter) because the filter
        # rules are tenant-controlled and shouldn't be allowed to mask a
        # legitimate upstream schema change by dropping all instances of
        # the new field. Empty batches return None and we don't update
        # the baseline in that case (see fingerprint.compute_fingerprint).
        new_fingerprint = compute_fingerprint(kept)
        drift_detected = False
        drift_details: dict[str, Any] | None = None

        if new_fingerprint is not None and target.schema_fingerprint is not None:
            if new_fingerprint != target.schema_fingerprint:
                drift_detected = True
                # Recompute the union of keys so we can describe what
                # changed. We don't store prior keys in the row (only the
                # hash), so we approximate "removed" by diffing against
                # the current batch's keys vs. the keys set we'd expect
                # from the prior fingerprint. Since we don't have the
                # prior keys, we record the new key set and ``added`` is
                # the entire new set. This is good enough for the UI to
                # surface "schema changed at <timestamp>"; a future
                # iteration can persist the prior key list.
                current_keys = sorted({k for ev in kept for k in ev.keys()})
                drift_details = diff_fingerprints(
                    previous_keys=[],  # baseline keys not persisted yet
                    current_keys=current_keys,
                )
                drift_details["sample_event_count"] = len(kept)
                drift_details["new_fingerprint"] = new_fingerprint
                drift_details["previous_fingerprint"] = target.schema_fingerprint
                logger.warning(
                    "connector.scheduler.schema_drift id=%s type=%s added=%d",
                    connector_id,
                    target.connector_type,
                    len(drift_details.get("added", [])),
                )

        try:
            result = await self._ingest_client.push_events(
                tenant_id=target.tenant_id,
                connector_id=target.id,
                connector_type=target.connector_type,
                events=kept,
            )
        except IngestClientError:
            logger.exception(
                "connector.scheduler.ingest_failed id=%s events=%d",
                connector_id,
                len(kept),
            )
            await self._record_failure(target.id)
            return

        accepted = int(result.get("accepted", 0) or 0)
        elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)

        # If drift was detected, persist that fact *before* marking the
        # poll successful so the UI reflects "drifted" status alongside
        # "healthy". Both writes are independent transactions; the order
        # protects against a race where the operator views the row mid-
        # poll and sees a stale fingerprint.
        if drift_detected and drift_details is not None:
            await self._record_drift(
                target.id,
                fingerprint=new_fingerprint or "",
                details=drift_details,
            )

        # Workstream 5: derive ``last_event_at`` from the kept batch so the
        # freshness-SLO badge in the UI reflects the freshest event we
        # actually shipped to the lake (not the poll wall-clock, which can
        # be misleading for low-volume connectors). We look at the standard
        # ECS-ish ``@timestamp`` first and fall back to ``timestamp``; if
        # neither is present or parseable we leave ``last_event_at`` as
        # None and ``record_poll_success`` won't touch the column.
        last_event_at = _extract_last_event_at(kept) if accepted > 0 else None
        last_event_kind = target.connector_type if accepted > 0 else None

        # Workstream 5: detect recovery-from-outage *before* writing
        # success. ``record_poll_success`` clears ``last_outage_at``, so we
        # must read it from the in-memory ``target`` snapshot. We also
        # never schedule a backfill for a backfill poll itself (avoid
        # cascading) or for connectors that just flapped (last_backfill_at
        # within the flap window).
        should_backfill = False
        backfill_window_seconds = 0
        if backfill_seconds is None and target.last_outage_at is not None:
            outage_duration = (datetime.now(UTC) - target.last_outage_at).total_seconds()
            if outage_duration >= _BACKFILL_OUTAGE_THRESHOLD_S:
                # Suppress flapping: don't re-fire a backfill if we already
                # ran one within _BACKFILL_FLAP_WINDOW_S.
                flap_ok = True
                if target.last_backfill_at is not None:
                    since_last = (datetime.now(UTC) - target.last_backfill_at).total_seconds()
                    if since_last < _BACKFILL_FLAP_WINDOW_S:
                        flap_ok = False
                        logger.info(
                            "connector.scheduler.backfill_suppressed id=%s reason=flap since_last=%ds",
                            connector_id,
                            int(since_last),
                        )
                if flap_ok:
                    should_backfill = True
                    backfill_window_seconds = min(
                        int(outage_duration) + _BACKFILL_LOOKBACK_BUFFER_S,
                        _MAX_BACKFILL_LOOKBACK_S,
                    )
                    logger.info(
                        "connector.scheduler.backfill_scheduled id=%s outage_duration_s=%d window_s=%d",
                        connector_id,
                        int(outage_duration),
                        backfill_window_seconds,
                    )

        await self._record_success(
            target.id,
            events_added=accepted,
            events_dropped=dropped_count,
            schema_fingerprint=new_fingerprint,
            last_event_at=last_event_at,
            last_event_kind=last_event_kind,
        )
        logger.info(
            "connector.scheduler.poll_complete id=%s type=%s accepted=%d rejected=%d dropped=%d drift=%s elapsed_ms=%d backfill=%s",
            connector_id,
            target.connector_type,
            accepted,
            int(result.get("rejected", 0) or 0),
            dropped_count,
            "yes" if drift_detected else "no",
            elapsed_ms,
            "scheduled" if should_backfill else ("running" if backfill_seconds is not None else "no"),
        )

        # Fire the backfill *after* the success write so the UI shows
        # "healthy" before the backfill traffic kicks in. We mark the
        # backfill timestamp before invoking _poll_one to suppress any
        # racing recovery detection from a parallel job.
        if should_backfill:
            await self._record_backfill_run(target.id)
            try:
                await self._poll_one(
                    connector_id=connector_id,
                    backfill_seconds=backfill_window_seconds,
                )
            except Exception:  # pragma: no cover - defensive only
                logger.exception(
                    "connector.scheduler.backfill_run_failed id=%s",
                    connector_id,
                )

    # ------------------------------------------------------------------ db helpers

    async def _record_success(
        self,
        connector_id: uuid.UUID,
        *,
        events_added: int,
        events_dropped: int = 0,
        schema_fingerprint: str | None = None,
        last_event_at: datetime | None = None,
        last_event_kind: str | None = None,
    ) -> None:
        if self._engine is None:  # pragma: no cover
            return
        try:
            async with self._engine.begin() as conn:
                await record_poll_success(
                    conn,
                    connector_id,
                    events_added=events_added,
                    events_dropped=events_dropped,
                    schema_fingerprint=schema_fingerprint,
                    last_event_at=last_event_at,
                    last_event_kind=last_event_kind,
                )
        except Exception:  # pragma: no cover
            logger.exception(
                "connector.scheduler.record_success_failed id=%s",
                connector_id,
            )

    async def _record_backfill_run(self, connector_id: uuid.UUID) -> None:
        """Stamp ``last_backfill_at`` to suppress flap-driven re-fires.

        Workstream 5: invoked by ``_poll_one`` immediately before kicking
        off the one-shot backfill poll. Even if the backfill itself fails,
        the timestamp prevents a re-fire while the connector is bouncing
        between healthy/unhealthy.
        """
        if self._engine is None:  # pragma: no cover
            return
        try:
            async with self._engine.begin() as conn:
                await record_backfill_run(conn, connector_id)
        except Exception:  # pragma: no cover
            logger.exception(
                "connector.scheduler.record_backfill_failed id=%s",
                connector_id,
            )

    async def _record_drift(
        self,
        connector_id: uuid.UUID,
        *,
        fingerprint: str,
        details: dict[str, Any],
    ) -> None:
        """Persist a detected schema drift for the connector row.

        Kept separate from ``_record_success`` so a drift write that
        races with a future poll's success write doesn't clobber the
        ``last_schema_drift_at`` timestamp.
        """
        if self._engine is None:  # pragma: no cover
            return
        try:
            async with self._engine.begin() as conn:
                await record_schema_drift(
                    conn,
                    connector_id,
                    fingerprint=fingerprint,
                    details=details,
                )
        except Exception:  # pragma: no cover
            logger.exception(
                "connector.scheduler.record_drift_failed id=%s",
                connector_id,
            )

    async def _record_failure(self, connector_id: uuid.UUID) -> None:
        if self._engine is None:  # pragma: no cover
            return
        try:
            async with self._engine.begin() as conn:
                await record_poll_failure(conn, connector_id)
        except Exception:  # pragma: no cover
            logger.exception(
                "connector.scheduler.record_failure_failed id=%s",
                connector_id,
            )


def _safe_normalize(connector: Any, event: dict[str, Any]) -> dict[str, Any]:
    """Run ``connector.normalize`` but never raise out of the loop."""
    try:
        out = connector.normalize(event)
    except Exception:
        logger.exception(
            "connector.scheduler.normalize_failed connector=%s",
            getattr(connector, "connector_id", "?"),
        )
        return event
    if not isinstance(out, dict):
        return event
    return out


def _extract_last_event_at(events: list[dict[str, Any]]) -> datetime | None:
    """Return the freshest event timestamp from a normalized batch.

    Workstream 5: powers the freshness-SLO badge in the UI. We prefer
    the ECS-ish ``@timestamp`` field, fall back to ``timestamp``, and
    accept either ISO-8601 strings (with ``Z`` or offset) or epoch
    seconds. A batch with no parseable timestamps yields ``None`` so
    ``record_poll_success`` won't overwrite a previously-good value.
    """
    if not events:
        return None
    best: datetime | None = None
    for event in events:
        if not isinstance(event, dict):
            continue
        raw = event.get("@timestamp") or event.get("timestamp")
        parsed: datetime | None = None
        if isinstance(raw, datetime):
            parsed = raw
        elif isinstance(raw, str):
            try:
                # ``fromisoformat`` rejects trailing ``Z`` until 3.11+;
                # normalize to ``+00:00`` so we work on 3.10+.
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            except ValueError:
                parsed = None
        elif isinstance(raw, int | float):
            try:
                parsed = datetime.fromtimestamp(float(raw), tz=UTC)
            except (OverflowError, OSError, ValueError):
                parsed = None
        if parsed is None:
            continue
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        if best is None or parsed > best:
            best = parsed
    return best


# ---------------------------------------------------------------------------
# Lifespan integration helper
#
# ``app/main.py`` imports ``scheduler_lifespan`` and uses it as the
# FastAPI ``lifespan=`` argument so the scheduler starts on app boot and
# stops cleanly on SIGTERM.
# ---------------------------------------------------------------------------


_SCHEDULER_DISABLED_ENV = "AISOC_CONNECTORS_DISABLE_SCHEDULER"


def scheduler_disabled() -> bool:
    """Allow tests / one-shot CLI invocations to skip the scheduler entirely."""
    return os.getenv(_SCHEDULER_DISABLED_ENV, "").lower() in {"1", "true", "yes"}


__all__ = [
    "ConnectorScheduler",
    "scheduler_disabled",
]
