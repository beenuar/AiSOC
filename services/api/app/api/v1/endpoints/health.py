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
from sqlalchemy import and_, func, select, text

from app.api.v1.deps import AuthUser, DBSession
from app.api.v1.endpoints.metrics import PipelineHealth, PipelineStage
from app.core.config import settings
from app.models.alert import Alert
from app.models.connector import Connector
from app.services.audit_hash import verify_chain
from app.services.connector_freshness import compute_freshness
from app.services.fleet_health import assess_fleet
from app.services.replay_evaluation.vendors import replayable_connector_ids

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
            if isinstance(raw_override, int | float) and raw_override > 0:
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


@router.get("/fleet")
async def get_fleet_health(
    user: AuthUser,
    db: DBSession,
) -> dict[str, Any]:
    """Which connectors have quietly stopped working.

    Every field this reads was already being written — `last_sync`,
    `error_count`, `oauth_refresh_failures`, `last_schema_drift_at` — and
    nothing read them together. That produces the failure this platform is
    least able to tolerate: a connector stops polling, alerts from that
    source stop arriving, and the console looks calm, because an absence of
    alerts is indistinguishable from an absence of threats.

    Staleness is judged per connector against its own configured cadence.
    A single global threshold would page constantly on daily connectors or
    stay silent on five-minute ones, and a surface that pages constantly is
    a surface that gets muted.
    """
    rows = (await db.execute(select(Connector).where(Connector.tenant_id == user.tenant_id))).scalars().all()
    return assess_fleet(list(rows)).to_dict()


@router.get("/dead-letters")
async def get_dead_letters(
    user: AuthUser,
    db: DBSession,
    limit: int = 50,
    hours: int = 24,
) -> dict[str, Any]:
    """Events the pipeline refused, and why.

    Three DLQ implementations existed and none could answer this: one
    wrote a log line, one wrote to a Kafka topic with no consumer, one
    forgot on restart. Events were being dropped correctly and invisibly —
    and an invisible drop is indistinguishable from an event that never
    arrived, which is the worse of the two and the one nobody investigates.

    Returns the breakdown by reason as well as the rows. A list of fifty
    dropped events is data; "forty-eight of them failed schema validation
    on the same topic" is a finding.
    """
    since = datetime.now(UTC) - timedelta(hours=max(1, min(hours, 720)))
    capped = max(1, min(limit, 500))

    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT id, topic, reason, schema_version, payload_excerpt,
                       source_event_id, occurred_at, acknowledged_at
                FROM aisoc_dead_letters
                WHERE tenant_id = :tid AND occurred_at >= :since
                ORDER BY occurred_at DESC
                LIMIT :lim
                """
                ),
                {"tid": user.tenant_id, "since": since, "lim": capped},
            )
        )
        .mappings()
        .all()
    )

    by_reason = (
        (
            await db.execute(
                text(
                    """
                SELECT reason, count(*) AS n
                FROM aisoc_dead_letters
                WHERE tenant_id = :tid AND occurred_at >= :since
                GROUP BY reason
                ORDER BY n DESC
                """
                ),
                {"tid": user.tenant_id, "since": since},
            )
        )
        .mappings()
        .all()
    )

    total = sum(int(r["n"]) for r in by_reason)
    return {
        "window_hours": hours,
        "total": total,
        # Present even when zero, and labelled: "no dead letters" is a
        # real answer and should not look like a broken panel.
        "by_reason": [{"reason": r["reason"], "count": int(r["n"])} for r in by_reason],
        "truncated": len(rows) >= capped,
        "dead_letters": [
            {
                "id": str(r["id"]),
                "topic": r["topic"],
                "reason": r["reason"],
                "schema_version": r["schema_version"],
                "payload_excerpt": r["payload_excerpt"],
                "source_event_id": r["source_event_id"],
                "occurred_at": r["occurred_at"].isoformat() if r["occurred_at"] else None,
                "acknowledged": r["acknowledged_at"] is not None,
            }
            for r in rows
        ],
    }


@router.get("/audit-chain")
async def get_audit_chain_health(
    user: AuthUser,
    db: DBSession,
) -> dict[str, Any]:
    """Whether the audit log's tamper-evidence actually covers this tenant.

    `apps/docs/docs/operations/security.md` states that every state-changing
    action is appended to an immutable, hash-chained log. That claim is only
    true of rows that carry a hash, and the one signal that a row did not was
    a `logger.warning` — which fired on every `alerts.explain` against a
    default install for as long as a best-effort cost write could abort the
    transaction underneath it. Nobody noticed, because an append-only log
    going quiet looks exactly like an idle one.

    So the question gets a surface. `unchained` counts rows this tenant holds
    with no `entry_hash`, split into the ones written before migration 043
    (which never had one and are not a defect) and the ones written after it
    (which are). A reviewer asking "is the chain intact?" gets a number rather
    than a grep.

    `verified` replays the chain with `verify_chain` over the most recent
    window, so a row that was rewritten in place is found rather than assumed
    absent.
    """
    window = 500

    counts = (
        (
            await db.execute(
                text(
                    """
            SELECT
              count(*) FILTER (WHERE entry_hash IS NULL)     AS unchained,
              count(*) FILTER (WHERE entry_hash IS NOT NULL) AS chained,
              count(*)                                       AS total,
              min(created_at) FILTER (WHERE entry_hash IS NULL) AS oldest_unchained,
              max(created_at) FILTER (WHERE entry_hash IS NULL) AS newest_unchained
            FROM audit_log
            WHERE tenant_id = :tid
            """
                ),
                {"tid": user.tenant_id},
            )
        )
        .mappings()
        .one()
    )

    rows = (
        (
            await db.execute(
                text(
                    """
                SELECT id, tenant_id, actor_id, actor_email, actor_ip,
                       action, resource, resource_id, changes, metadata, created_at,
                       prev_hash, entry_hash
                FROM audit_log
                WHERE tenant_id = :tid
                ORDER BY created_at DESC, id DESC
                LIMIT :lim
                """
                ),
                {"tid": user.tenant_id, "lim": window},
            )
        )
        .mappings()
        .all()
    )
    replay = [dict(r) for r in reversed(rows)]
    intact, bad_index, reason = verify_chain(replay)

    unchained = int(counts["unchained"] or 0)
    return {
        # Two facts, reported separately, because they have different causes
        # and a single boolean would hide that. `chain_complete` is about rows
        # written with no hash at all — what a failed chain computation
        # produces, and what `aisoc_audit_chain_failures_total` counts.
        # `replay_intact` is about the links between rows that do have one.
        "chain_complete": unchained == 0,
        "total_rows": int(counts["total"] or 0),
        "chained_rows": int(counts["chained"] or 0),
        # Every row here is one the tamper-evidence claim does not cover.
        # Migration 043 made the columns nullable so existing deployments
        # could adopt the chain without a flag day, so a non-zero count on an
        # old tenant may be legacy — the timestamps say which.
        "unchained_rows": unchained,
        "oldest_unchained_at": counts["oldest_unchained"].isoformat() if counts["oldest_unchained"] else None,
        "newest_unchained_at": counts["newest_unchained"].isoformat() if counts["newest_unchained"] else None,
        "replay_window": len(replay),
        # A replay break is not always tampering. Two audit writers in one
        # request — a handler calling `emit_audit` and `audit_middleware`
        # writing its own row on a separate session — can resolve the same
        # head and fork the chain, and a fork is indistinguishable from a
        # removed row. That is a real, open defect in the writer, documented
        # on `app.services.audit._resolve_prev_hash`; it is reported here
        # rather than hidden, because hiding it is what made the chain's
        # failure invisible in the first place.
        "replay_intact": intact,
        "replay_broken_at_index": bad_index,
        "replay_reason": reason,
        # The counter is the alertable half; this is the on-demand half.
        "metric": "aisoc_audit_chain_failures_total",
    }


@router.get("/shadow-reconciliation")
async def get_shadow_reconciliation_health(
    user: AuthUser,
    db: DBSession,
) -> dict[str, Any]:
    """Whether closures made in this tenant's own SIEM are being polled back.

    Gap-closure Phase 2.1 (D15).

    A sweep that silently stopped and a sweep with nothing to do look identical
    from outside, and that ambiguity is what made the original gap invisible:
    the reconciler existed, nothing called it, and the only symptom available
    to an operator was a scorecard that never filled in. So this reports the
    subscription in every state, including the healthy one and the idle one,
    and names which it is.

    ``state`` is one of:

    ``disabled``    the operator has not switched the sweep on. Not a fault,
                    and not a healthy idle sweep either.
    ``not_measuring`` the sweep runs, but this tenant has no alert class in
                    shadow mode, so there is nothing to reconcile.
    ``no_connector``  this tenant is measuring and has no enabled connector of
                    a type with a closed-finding reader. Agreement is being
                    measured on AiSOC closures only, which is the honest answer
                    and is stated rather than left to be inferred.
    ``blocked``     at least one connector needs an operator. The reason is a
                    sentence, and it will not clear by waiting.
    ``degraded``    at least one connector is failing transiently and is being
                    retried.
    ``ok``          every configured connector polled.
    """
    enabled = bool(settings.SHADOW_RECONCILE_ENABLED)

    measuring = (
        (
            await db.execute(
                text(
                    """
                    SELECT alert_class, COALESCE(enabled_at, updated_at) AS since
                    FROM aisoc_shadow_mode
                    WHERE tenant_id = :tid AND enabled IS TRUE
                    ORDER BY alert_class
                    """
                ),
                {"tid": user.tenant_id},
            )
        )
        .mappings()
        .all()
    )

    rows = (
        (
            await db.execute(
                text(
                    """
                    SELECT s.connector_id, s.vendor, s.watermark_at, s.last_run_at, s.last_status,
                           s.last_detail, s.last_considered, s.last_matched, s.consecutive_failures,
                           s.blocked_reason, s.blocked_at, s.retry_after, c.name AS connector_name
                    FROM aisoc_shadow_reconcile_state s
                    LEFT JOIN connectors c ON c.id = s.connector_id AND c.tenant_id = s.tenant_id
                    WHERE s.tenant_id = :tid
                    ORDER BY s.last_run_at DESC NULLS LAST
                    """
                ),
                {"tid": user.tenant_id},
            )
        )
        .mappings()
        .all()
    )

    # Which of this tenant's connectors the sweep *could* poll, asked of the
    # same table the sweep asks so the two cannot disagree about what counts.
    pollable = int(
        (
            await db.execute(
                text(
                    """
                    SELECT COUNT(*)::int FROM connectors
                    WHERE tenant_id = :tid AND is_enabled IS TRUE AND connector_type = ANY(:replayable)
                    """
                ),
                {"tid": user.tenant_id, "replayable": replayable_connector_ids()},
            )
        ).scalar_one()
        or 0
    )

    blocked = [r for r in rows if r["blocked_reason"]]
    failing = [r for r in rows if r["last_status"] == "transient"]

    if not enabled:
        state = "disabled"
        summary = (
            "The shadow-reconciliation sweep is switched off, so closures your analysts make in your own "
            "SIEM are not being polled back. Agreement is measured on closures made in AiSOC only."
        )
    elif not measuring:
        state = "not_measuring"
        summary = "No alert class is in shadow mode for this tenant, so there is nothing to reconcile."
    elif pollable == 0:
        state = "no_connector"
        summary = (
            "This tenant is measuring but has no enabled connector of a type with a closed-finding reader "
            f"({', '.join(replayable_connector_ids())}). Agreement is measured on closures made in AiSOC only."
        )
    elif blocked:
        state = "blocked"
        summary = f"{len(blocked)} connector(s) need an operator before reconciliation can resume."
    elif failing:
        state = "degraded"
        summary = f"{len(failing)} connector(s) are failing transiently and are being retried."
    else:
        state = "ok"
        summary = f"Polling {pollable} connector(s) for closures made in your own SIEM."

    return {
        "state": state,
        "summary": summary,
        "enabled": enabled,
        "interval_seconds": int(settings.SHADOW_RECONCILE_INTERVAL_SECONDS) if enabled else None,
        "measuring_classes": [r["alert_class"] for r in measuring],
        "pollable_connectors": pollable,
        "supported_connector_types": replayable_connector_ids(),
        "connectors": [
            {
                "connector_id": str(r["connector_id"]),
                "connector_name": r["connector_name"],
                "vendor": r["vendor"],
                "status": r["last_status"],
                "detail": r["last_detail"],
                "watermark_at": r["watermark_at"].isoformat() if r["watermark_at"] else None,
                "last_run_at": r["last_run_at"].isoformat() if r["last_run_at"] else None,
                "closures_read": int(r["last_considered"] or 0),
                "closures_matched": int(r["last_matched"] or 0),
                "consecutive_failures": int(r["consecutive_failures"] or 0),
                "needs_operator": bool(r["blocked_reason"]),
                "blocked_reason": r["blocked_reason"],
                "blocked_at": r["blocked_at"].isoformat() if r["blocked_at"] else None,
                "retry_after": r["retry_after"].isoformat() if r["retry_after"] else None,
            }
            for r in rows
        ],
    }
