"""The consumer for ``NEW_IOC``, which nothing had.

Gap-closure Phase 8.1.

``services/threatintel/app/feeds/pipeline.py`` has emitted a ``NEW_IOC``
event for every newly-seen indicator since the pipeline was written, and a
grep for the string across this repository returns the emit site and nothing
else. This module is the other end.

Two things about the topic, because both are the kind of mistake that reports
success while doing nothing:

**The topic name in the pipeline's signature is not the topic in use.**
``ThreatIntelPipeline.__init__`` defaults ``kafka_topic`` to
``threat-intel-events``, and ``services/threatintel``'s lifespan passes
``settings.KAFKA_TOPIC_THREAT_INTEL``, which is ``aisoc.threat_intel``. The
constructor default is therefore unreachable in any running deployment. A
consumer written against it would subscribe to a topic no producer writes,
consume nothing, log nothing, and keep a container healthy indefinitely.
``scripts/check_ioc_lake_mapping.py`` compares the two settings so they cannot
drift apart again.

**A consumer that cannot reach its topic must say which kind of problem it
has.** The rule this service already follows elsewhere: a transient fault
retries with backoff, a permanent one stops the loop and names the operator
action, and a poison message is skipped without penalising a working
subscription. The failure that motivated the rule was a consumer with no
``except`` at all, which exited its ``async for`` and left the container
``running`` with ``/health`` answering 200 while it was subscribed to nothing.

The work itself is deliberately not done here. This module owns the
subscription, the decode, the routing decision and the per-tenant fan-out;
:mod:`app.services.retro_hunt.service` owns what a sweep is worth doing and
what it opens. That split is what lets the sweep be tested without a broker.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text

from app.core.config import settings
from app.core.kafka_security import kafka_client_kwargs
from app.db.cross_tenant import assert_cross_tenant_session
from app.db.database import AsyncSessionLocal
from app.services.retro_hunt.intel_types import route_feed_type
from app.services.retro_hunt.kev_exposure import handle_kev_entry
from app.services.retro_hunt.service import (
    IntelIndicator,
    TenantSweepReport,
    opted_in_tenants,
    sweep_tenant,
)
from app.workers._tick_failures import TickFailures

logger = logging.getLogger(__name__)

#: Seconds to wait before reconnecting after a transient broker fault.
_RECONNECT_BACKOFF_SECONDS = 5.0

#: Ceiling on the backoff so a long outage does not stretch to hours.
_MAX_BACKOFF_SECONDS = 120.0


class PermanentConsumerFault(RuntimeError):
    """A condition no retry will clear. Stops the loop and names the fix."""


def _enabled() -> bool:
    return bool(getattr(settings, "RETRO_HUNT_ENABLED", False))


def parse_intel_event(raw: bytes | str) -> dict[str, Any] | None:
    """Decode one message from the intel topic, or ``None`` if it is not one.

    Returns ``None`` rather than raising for anything malformed, because a
    single undecodable message must not stop a working subscription. The
    caller counts these and moves on.
    """
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("event_type") != "NEW_IOC":
        # The topic carries more than one event type. Anything else is
        # somebody else's message, not a fault.
        return None
    data = payload.get("data")
    if not isinstance(data, dict):
        return None
    return payload


def _first_seen(data: dict[str, Any], envelope_ts: Any) -> datetime | None:
    """When the publishing feed first saw this indicator.

    Feeds disagree about the field name and about the format, and a value
    that cannot be parsed becomes ``None`` rather than ``now``: stamping the
    current time would turn "the feed did not say" into "the feed saw this
    today", which is a claim about somebody else's data.
    """
    for key in ("first_seen", "date_added", "created", "first_seen_at", "timestamp"):
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            with contextlib.suppress(ValueError):
                return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
    if isinstance(envelope_ts, str) and envelope_ts.strip():
        with contextlib.suppress(ValueError):
            return datetime.fromisoformat(envelope_ts.replace("Z", "+00:00")).astimezone(UTC)
    return None


def cve_from_event(payload: dict[str, Any]) -> tuple[str, str, datetime | None] | None:
    """Pull a CVE out of a ``NEW_IOC`` that routes to the exposure check.

    Returns ``(cve_id, feed_source, first_seen)`` or ``None``. A CVE takes a
    different path from every other indicator because it never appears in
    event telemetry: sweeping the lake for one would return zero on every
    tenant while looking exactly like a sweep that worked. See
    :mod:`app.services.retro_hunt.kev_exposure`.
    """
    data = payload.get("data") or {}
    value = str(data.get("value") or "").strip()
    if not value:
        return None
    if not route_feed_type(str(data.get("type") or "")).is_vulnerability:
        return None
    source = str(payload.get("source") or data.get("source") or "unknown feed")
    return value, source, _first_seen(data, payload.get("timestamp"))


async def handle_kev_indicator(cve_id: str, feed_source: str, first_seen: datetime | None) -> list[TenantSweepReport]:
    """Fan one KEV entry out to every tenant that opted in.

    Same session and tenant-binding shape as :func:`handle_indicator`: the
    read of who opted in is genuinely cross-tenant, and every write after it
    rebinds the tenant so the case and task inserts are RLS-enforced.
    """
    reports: list[TenantSweepReport] = []
    async with AsyncSessionLocal() as db:
        await assert_cross_tenant_session(db, "retro-hunt KEV fan-out")
        tenants = await opted_in_tenants(db)
        if not tenants:
            return reports

        for settings_row in tenants:
            try:
                await db.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": str(settings_row.tenant_id)},
                )
                result = await handle_kev_entry(
                    db,
                    settings_row=settings_row,
                    cve_id=cve_id,
                    feed_source=feed_source,
                    intel_first_seen_at=first_seen,
                )
            except Exception as exc:  # noqa: BLE001 - one tenant must not stop the rest
                logger.exception(
                    "retro_hunt.kev_check_failed tenant=%s err=%s",
                    settings_row.tenant_id,
                    type(exc).__name__,
                )
                reports.append(
                    TenantSweepReport(
                        tenant_id=settings_row.tenant_id,
                        outcome="failed",
                        detail=type(exc).__name__,
                    )
                )
                continue

            reports.append(
                TenantSweepReport(
                    tenant_id=settings_row.tenant_id,
                    outcome="swept" if result.checked else "skipped_unsupported",
                    matched=result.exposed,
                    deduplicated=result.deduplicated,
                    detail=(
                        result.unavailable_reason
                        or (
                            f"{result.exposed_asset_count} exposed asset(s); case task opened."
                            if result.exposed
                            else "No unremediated findings for this CVE."
                        )
                    ),
                )
            )
        await db.commit()
    return reports


def indicator_from_event(payload: dict[str, Any]) -> IntelIndicator | None:
    """Turn one decoded ``NEW_IOC`` into a typed indicator, or refuse it.

    ``None`` means the event was understood and is not something to sweep: an
    unroutable type, a CVE (which the KEV exposure path handles), or an empty
    value. Each of those is logged with its reason by the caller so a feed
    publishing a type AiSOC does not handle is visible rather than silent.
    """
    data = payload.get("data") or {}
    value = str(data.get("value") or "").strip()
    if not value:
        return None

    routing = route_feed_type(str(data.get("type") or ""))
    if routing.indicator_type is None:
        return None

    return IntelIndicator(
        indicator_type=routing.indicator_type,
        value=value,
        feed_source=str(payload.get("source") or data.get("source") or "unknown feed"),
        first_seen_at=_first_seen(data, payload.get("timestamp")),
        description=str(data.get("description") or "")[:500],
    )


async def handle_indicator(indicator: IntelIndicator) -> list[TenantSweepReport]:
    """Fan one indicator out to every tenant that opted in.

    Opens its own session and commits once at the end. The read of who opted
    in is genuinely cross-tenant; every write after it rebinds the tenant so
    the alert insert is RLS-enforced, which is the same shape as the hunt
    scheduler's sweep and for the same reason.
    """
    reports: list[TenantSweepReport] = []
    async with AsyncSessionLocal() as db:
        await assert_cross_tenant_session(db, "retro-hunt intel fan-out")
        tenants = await opted_in_tenants(db)
        if not tenants:
            return reports

        for settings_row in tenants:
            try:
                await db.execute(
                    text("SELECT set_config('app.current_tenant_id', :t, true)"),
                    {"t": str(settings_row.tenant_id)},
                )
                reports.append(
                    await sweep_tenant(
                        db,
                        tenant_id=settings_row.tenant_id,
                        indicator=indicator,
                        settings_row=settings_row,
                    )
                )
            except Exception as exc:  # noqa: BLE001 - one tenant must not stop the rest
                logger.exception(
                    "retro_hunt.tenant_sweep_failed tenant=%s err=%s",
                    settings_row.tenant_id,
                    type(exc).__name__,
                )
                reports.append(
                    TenantSweepReport(
                        tenant_id=settings_row.tenant_id,
                        outcome="failed",
                        detail=type(exc).__name__,
                    )
                )
        await db.commit()
    return reports


async def _build_consumer() -> Any:
    """Construct and start the aiokafka consumer, or fail permanently.

    A missing ``aiokafka`` and an unset broker list are both conditions no
    amount of retrying fixes, so they raise :class:`PermanentConsumerFault`
    with the setting to change rather than joining the backoff loop.
    """
    try:
        from aiokafka import AIOKafkaConsumer  # noqa: PLC0415
    except ImportError as exc:  # pragma: no cover - environment-specific
        raise PermanentConsumerFault(
            "aiokafka is not installed, so the retro-hunt consumer cannot run. Install it or set AISOC_RETRO_HUNT_ENABLED=false."
        ) from exc

    brokers = (settings.KAFKA_BOOTSTRAP_SERVERS or "").strip()
    if not brokers:
        raise PermanentConsumerFault(
            "KAFKA_BOOTSTRAP_SERVERS is empty, so there is no intel topic to consume. Set it or set AISOC_RETRO_HUNT_ENABLED=false."
        )

    consumer = AIOKafkaConsumer(
        settings.KAFKA_TOPIC_THREAT_INTEL,
        bootstrap_servers=brokers,
        group_id=settings.RETRO_HUNT_CONSUMER_GROUP,
        enable_auto_commit=True,
        auto_offset_reset="latest",
        **kafka_client_kwargs(),
    )
    await consumer.start()
    logger.info(
        "retro_hunt_consumer subscribed topic=%s group=%s",
        str(settings.KAFKA_TOPIC_THREAT_INTEL).replace("\r", "").replace("\n", " ")[:64],
        str(settings.RETRO_HUNT_CONSUMER_GROUP).replace("\r", "").replace("\n", " ")[:64],
    )
    return consumer


async def run_forever() -> None:
    """Consume ``NEW_IOC`` until cancelled. Owned by the API ``lifespan``."""
    if not _enabled():
        logger.info("retro_hunt_consumer disabled (AISOC_RETRO_HUNT_ENABLED is not set)")
        return

    failures = TickFailures("retro_hunt_consumer", logger)
    backoff = _RECONNECT_BACKOFF_SECONDS

    while True:
        consumer = None
        try:
            consumer = await _build_consumer()
            backoff = _RECONNECT_BACKOFF_SECONDS
            failures.record_success()

            async for message in consumer:
                payload = parse_intel_event(message.value)
                if payload is None:
                    # Poison or irrelevant. Skipped without penalising the
                    # subscription: one bad message is not a reason to stop
                    # consuming a topic that is otherwise fine.
                    continue
                kev = cve_from_event(payload)
                if kev is not None:
                    try:
                        await handle_kev_indicator(*kev)
                    except Exception as exc:  # noqa: BLE001 - keep consuming
                        logger.exception("retro_hunt.kev_fan_out_failed err=%s", type(exc).__name__)
                    continue

                indicator = indicator_from_event(payload)
                if indicator is None:
                    routing = route_feed_type(str((payload.get("data") or {}).get("type") or ""))
                    if routing.unknown:
                        logger.info(
                            "retro_hunt.unroutable_type reason=%s",
                            str(routing.reason or "").replace("\r", "").replace("\n", " ")[:200],
                        )
                    continue
                try:
                    await handle_indicator(indicator)
                except Exception as exc:  # noqa: BLE001 - keep consuming
                    logger.exception("retro_hunt.fan_out_failed err=%s", type(exc).__name__)

        except asyncio.CancelledError:
            raise
        except PermanentConsumerFault as exc:
            # Naming the action and stopping. Retrying a misconfiguration
            # turns it into churn an operator has to read past.
            logger.error("retro_hunt_consumer stopped permanently: %s", str(exc).replace("\r", "").replace("\n", " ")[:300])
            return
        except Exception as exc:  # noqa: BLE001 - transient broker faults
            failures.record_failure(exc)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)
        finally:
            if consumer is not None:
                with contextlib.suppress(Exception):
                    await consumer.stop()


__all__ = [
    "PermanentConsumerFault",
    "handle_indicator",
    "indicator_from_event",
    "parse_intel_event",
    "run_forever",
]
