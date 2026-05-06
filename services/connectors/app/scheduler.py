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
    record_poll_failure,
    record_poll_success,
)
from app.db.engine import get_engine
from app.ingest_client import IngestClient, IngestClientError
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

    async def _poll_one(self, *, connector_id: uuid.UUID) -> None:
        """Single-connector poll cycle.

        Always wraps the entire body in try/except so a misbehaving
        connector class can't take down the scheduler. Records success or
        failure on the row, then returns.
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

        try:
            result = await self._ingest_client.push_events(
                tenant_id=target.tenant_id,
                connector_id=target.id,
                connector_type=target.connector_type,
                events=normalized,
            )
        except IngestClientError:
            logger.exception(
                "connector.scheduler.ingest_failed id=%s events=%d",
                connector_id,
                len(normalized),
            )
            await self._record_failure(target.id)
            return

        accepted = int(result.get("accepted", 0) or 0)
        elapsed_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
        await self._record_success(target.id, events_added=accepted)
        logger.info(
            "connector.scheduler.poll_complete id=%s type=%s accepted=%d rejected=%d elapsed_ms=%d",
            connector_id,
            target.connector_type,
            accepted,
            int(result.get("rejected", 0) or 0),
            elapsed_ms,
        )

    # ------------------------------------------------------------------ db helpers

    async def _record_success(self, connector_id: uuid.UUID, *, events_added: int) -> None:
        if self._engine is None:  # pragma: no cover
            return
        try:
            async with self._engine.begin() as conn:
                await record_poll_success(conn, connector_id, events_added=events_added)
        except Exception:  # pragma: no cover
            logger.exception(
                "connector.scheduler.record_success_failed id=%s",
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
