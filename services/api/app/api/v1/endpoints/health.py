"""Pipeline health endpoint — operator-facing snapshot of the SOC pipeline.

Backs ``GET /api/v1/health/pipeline`` (v1.5 SOC Console parity).

Returns a 5-row strip describing the health of each stage of the
pipeline ``ingest → normalize → fuse → correlate → alert``. The shape
matches the ``PipelineHealth`` Pydantic model declared alongside the
funnel response in ``endpoints/metrics.py`` so the funnel and pipeline-
health views can share the same schema package.

Honest-measurement principles
-----------------------------

The plan calls for ``{backlog, p95_latency_ms, error_rate, status}`` per
stage. We compute each cell from data we *actually have* — no synthetic
fillers, no fake percentiles. When a column is genuinely unknowable
without deeper instrumentation (e.g. fusion-engine job timings), the
response is ``0`` (numeric) or ``unknown`` (status). The SOC Console UI
renders zeros as "n/a" pills rather than zero-bars so operators don't
read absence as "all good".

Per-stage definitions
---------------------

* **ingest** — events arriving from connectors. ``status`` aggregates
  ``app.services.connector_freshness`` across all enabled connectors
  (worst-of). ``backlog`` is the number of enabled connectors that
  haven't fired an event within 2× their per-category cadence (the
  ``red`` band in ``connector_freshness``). ``error_rate`` is
  ``unhealthy / enabled`` from ``Connector.health_status``.
  ``p95_latency_ms`` is left at 0 — we don't carry a source-side
  timestamp on the wire to compute true ingest lag.

* **normalize** — raw event JSON → structured ``Alert`` fields
  (event_time, src/dst, MITRE, severity). ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (created_at - event_time)`` for
  alerts in the last hour where ``event_time`` was set. ``backlog``
  is 0 (no queue at this layer in the current pipeline). ``error_rate``
  is 0 — parse errors are not yet surfaced to Postgres.

* **fuse** — events grouped into alerts. ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (last_seen - first_seen)`` for
  alerts in the window. ``backlog`` is 0 (the fusion engine doesn't
  queue alerts — it emits or drops). ``error_rate`` is 0.

* **correlate** — multi-event correlation. ``backlog`` is the count of
  recent *single-event* alerts (``jsonb_array_length(source_event_ids)
  = 1``) in the window — alerts that haven't yet been merged into a
  richer incident. ``p95_latency_ms`` is left at 0 (the fusion service
  doesn't emit per-correlation-job timing yet).

* **alert** — alert visible to analyst. ``backlog`` is the open queue
  depth (``status in ('new','triaging','in_progress')`` AND
  ``first_seen_at IS NULL``). ``p95_latency_ms`` is
  ``percentile_cont(0.95) WITHIN GROUP (first_seen_at - created_at)``
  — i.e. MTTD p95. ``error_rate`` is 0.

Status ladder
-------------

Each stage's status follows the same ladder used by
``connector_freshness``: ``unknown | green | yellow | red``. The
thresholds for latency-driven stages are read from two configurable
knobs in ``app.core.config``:

* ``AISOC_PIPELINE_STALE_WARN_SECONDS`` (default 600) — green ceiling
* ``AISOC_PIPELINE_STALE_DOWN_SECONDS`` (default 1800) — yellow ceiling

Any stage with no data in the window collapses to ``unknown`` rather
than ``green``, mirroring the "never paint green on absence of data"
rule in ``connector_freshness``.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter
from sqlalchemy import and_, func, select

from app.api.v1.deps import AuthUser, DBSession
from app.api.v1.endpoints.metrics import PipelineHealth, PipelineStage
from app.core.config import settings
from app.models.alert import Alert
from app.models.connector import Connector
from app.services.connector_freshness import compute_freshness

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/health", tags=["health"])


# ───────────────────────────── Status helpers ────────────────────────────────


# Order from best to worst. ``unknown`` is slightly worse than ``green`` so a
# tenant with one brand-new (never-seen-an-event) connector still reports
# ``unknown`` overall rather than ``green`` — we never paint green on absence
# of data. Matches the convention enforced by ``connector_freshness``.
_STATUS_RANK: dict[str, int] = {"green": 0, "unknown": 1, "yellow": 2, "red": 3}


def _status_from_latency(
    *,
    p95_seconds: float | None,
    warn_seconds: int,
    down_seconds: int,
) -> str:
    """Map a p95 latency to ``unknown|green|yellow|red``.

    ``None`` (no data in the window) → ``unknown``; we deliberately do
    not return ``green`` for absence of data.
    """
    if p95_seconds is None:
        return "unknown"
    if p95_seconds <= warn_seconds:
        return "green"
    if p95_seconds <= down_seconds:
        return "yellow"
    return "red"


def _worst_status(statuses: list[str]) -> str:
    """Aggregate a list of statuses to the worst entry on ``_STATUS_RANK``."""
    if not statuses:
        return "unknown"
    return max(statuses, key=lambda s: _STATUS_RANK.get(s, 1))


# Postgres ``percentile_cont(p)`` returns ``double precision``. SQLAlchemy
# exposes it via the ``func`` namespace; we wrap the (admittedly verbose)
# ``WITHIN GROUP (ORDER BY ...)`` expression here so the per-stage helpers
# below stay readable.
def _p95_seconds_expr(expr: Any) -> Any:
    """Build a SQLA expression for ``percentile_cont(0.95) WITHIN GROUP``.

    ``expr`` is the per-row scalar to take the percentile of (already in
    seconds — callers pass ``func.extract('epoch', ...)``).
    """
    return func.percentile_cont(0.95).within_group(expr)


# ─────────────────────────────── ingest stage ────────────────────────────────


async def _ingest_stage(db, tenant_id, *, now: datetime) -> PipelineStage:
    """Build the ``ingest`` row from connector freshness aggregates.

    Reads every Connector for the tenant, runs ``compute_freshness``
    per row (which honours per-instance cadence overrides via
    ``connector_config.expected_cadence_seconds``), then rolls the
    per-connector statuses up to a single worst-of verdict.
    """
    rows = (
        await db.execute(
            select(
                Connector.category,
                Connector.last_event_at,
                Connector.health_status,
                Connector.is_enabled,
                Connector.connector_config,
            ).where(Connector.tenant_id == tenant_id)
        )
    ).all()

    enabled = [r for r in rows if r.is_enabled]
    if not enabled:
        # No enabled connectors → nothing is flowing on purpose. Status
        # ``unknown`` rather than red so a fresh tenant doesn't see a
        # paged alert before they've onboarded anything.
        return PipelineStage(
            stage="ingest",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    statuses: list[str] = []
    backlog = 0
    unhealthy = 0
    for r in enabled:
        override: int | None = None
        if isinstance(r.connector_config, dict):
            raw_override = r.connector_config.get("expected_cadence_seconds")
            if isinstance(raw_override, (int, float)) and raw_override > 0:
                override = int(raw_override)
        verdict = compute_freshness(
            category=r.category,
            last_event_at=r.last_event_at,
            now=now,
            override_seconds=override,
        )
        statuses.append(verdict.status)
        if verdict.status == "red":
            backlog += 1
        if r.health_status == "unhealthy":
            unhealthy += 1

    error_rate = round(unhealthy / len(enabled), 4) if enabled else 0.0
    return PipelineStage(
        stage="ingest",
        backlog=backlog,
        p95_latency_ms=0.0,
        error_rate=error_rate,
        status=_worst_status(statuses),
    )


# ───────────────────────────── normalize stage ───────────────────────────────


async def _normalize_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``normalize`` row from event_time → created_at lag.

    The "normalize" step in the AiSOC pipeline is the transition from
    raw event JSON (carrying a vendor-side ``event_time``) to a fully
    structured ``Alert`` row in Postgres. The p95 lag between the two
    is the most honest single-number proxy for normalization latency.
    """
    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.created_at - Alert.event_time))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.event_time.isnot(None),
            )
        )
    )
    if p95_seconds is None:
        return PipelineStage(
            stage="normalize",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    p95_seconds = max(0.0, float(p95_seconds))
    return PipelineStage(
        stage="normalize",
        backlog=0,
        p95_latency_ms=round(p95_seconds * 1000.0, 2),
        error_rate=0.0,
        status=_status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        ),
    )


# ─────────────────────────────── fuse stage ──────────────────────────────────


async def _fuse_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``fuse`` row from first_seen → last_seen spread.

    A single Alert can absorb many raw events. The spread between the
    earliest and latest contributing event (first_seen → last_seen)
    is the closest single-number proxy for fusion latency we can
    compute without instrumenting the fusion service itself.
    """
    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.last_seen - Alert.first_seen))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.first_seen.isnot(None),
                Alert.last_seen.isnot(None),
            )
        )
    )
    if p95_seconds is None:
        return PipelineStage(
            stage="fuse",
            backlog=0,
            p95_latency_ms=0.0,
            error_rate=0.0,
            status="unknown",
        )

    p95_seconds = max(0.0, float(p95_seconds))
    return PipelineStage(
        stage="fuse",
        backlog=0,
        p95_latency_ms=round(p95_seconds * 1000.0, 2),
        error_rate=0.0,
        status=_status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        ),
    )


# ───────────────────────────── correlate stage ───────────────────────────────


async def _correlate_stage(
    db,
    tenant_id,
    *,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``correlate`` row from single-event-alert backlog.

    Backlog = alerts in the window with exactly one source event (i.e.
    not yet correlated). Status is ``green`` if at least one alert in
    the window has multiple source events (correlation engine is
    working), ``yellow`` if alerts exist but none are multi-event
    (correlation engine is idle), and ``unknown`` if there are no
    alerts at all in the window.
    """
    single_event = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= window_start,
                    Alert.created_at < window_end,
                    func.jsonb_array_length(Alert.source_event_ids) == 1,
                )
            )
        )
        or 0
    )
    multi_event = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.created_at >= window_start,
                    Alert.created_at < window_end,
                    func.jsonb_array_length(Alert.source_event_ids) >= 2,
                )
            )
        )
        or 0
    )

    total = int(single_event) + int(multi_event)
    if total == 0:
        status = "unknown"
    elif multi_event > 0:
        status = "green"
    else:
        status = "yellow"

    return PipelineStage(
        stage="correlate",
        backlog=int(single_event),
        p95_latency_ms=0.0,
        error_rate=0.0,
        status=status,
    )


# ─────────────────────────────── alert stage ─────────────────────────────────


async def _alert_stage(
    db,
    tenant_id,
    *,
    warn_seconds: int,
    down_seconds: int,
    window_start: datetime,
    window_end: datetime,
) -> PipelineStage:
    """Build the ``alert`` row from MTTD p95 + open-queue depth.

    Backlog is the open-queue depth (alerts visible to an analyst that
    haven't been viewed yet). ``p95_latency_ms`` is MTTD p95 — the
    p95 wall-clock gap between ``created_at`` (the alert appeared in
    Postgres) and ``first_seen_at`` (the analyst opened it).
    """
    unacked = (
        await db.scalar(
            select(func.count()).where(
                and_(
                    Alert.tenant_id == tenant_id,
                    Alert.status.in_(("new", "triaging", "in_progress")),
                    Alert.first_seen_at.is_(None),
                )
            )
        )
        or 0
    )

    p95_seconds = await db.scalar(
        select(_p95_seconds_expr(func.extract("epoch", Alert.first_seen_at - Alert.created_at))).where(
            and_(
                Alert.tenant_id == tenant_id,
                Alert.created_at >= window_start,
                Alert.created_at < window_end,
                Alert.first_seen_at.isnot(None),
            )
        )
    )

    if p95_seconds is None:
        # No alerts have been seen by an analyst in the window. If
        # there are unacked alerts in the queue we report ``yellow``
        # (the analyst is behind); otherwise ``unknown`` (no data).
        status = "yellow" if unacked > 0 else "unknown"
        latency_ms = 0.0
    else:
        p95_seconds = max(0.0, float(p95_seconds))
        latency_ms = round(p95_seconds * 1000.0, 2)
        status = _status_from_latency(
            p95_seconds=p95_seconds,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
        )

    return PipelineStage(
        stage="alert",
        backlog=int(unacked),
        p95_latency_ms=latency_ms,
        error_rate=0.0,
        status=status,
    )


# ─────────────────────────────── endpoint ────────────────────────────────────


@router.get("/pipeline", response_model=PipelineHealth)
async def get_pipeline_health(
    user: AuthUser,
    db: DBSession,
) -> PipelineHealth:
    """Return a 5-stage health snapshot of the SOC pipeline for the tenant.

    Stages: ``ingest → normalize → fuse → correlate → alert``. See the
    module docstring for what each cell measures and why some columns
    are intentionally ``0`` until deeper instrumentation lands.

    The window for latency / backlog computations is the last hour.
    The ``status`` ladder is ``unknown | green | yellow | red`` and
    follows the same convention as
    ``app.services.connector_freshness``.
    """
    now = datetime.now(UTC)
    window_start = now - timedelta(hours=1)
    window_end = now

    warn_seconds = int(getattr(settings, "AISOC_PIPELINE_STALE_WARN_SECONDS", 600) or 600)
    down_seconds = int(getattr(settings, "AISOC_PIPELINE_STALE_DOWN_SECONDS", 1800) or 1800)

    stages = [
        await _ingest_stage(db, user.tenant_id, now=now),
        await _normalize_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
        await _fuse_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
        await _correlate_stage(
            db,
            user.tenant_id,
            window_start=window_start,
            window_end=window_end,
        ),
        await _alert_stage(
            db,
            user.tenant_id,
            warn_seconds=warn_seconds,
            down_seconds=down_seconds,
            window_start=window_start,
            window_end=window_end,
        ),
    ]

    return PipelineHealth(
        overall_status=_worst_status([s.status for s in stages]),
        stages=stages,
        generated_at=now,
    )
