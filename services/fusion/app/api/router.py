from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.alert import AnalystFeedback, FusedAlert, FusionDecision, RawAlert
from app.security.tenant_scope import (
    TenantPrincipal,
    require_console_or_service_auth,
    scoped_tenant_or_403,
)
from app.services.dlq_replay import MAX_REPLAY_MESSAGES, ReplayRefused, replay_from_offset
from app.workers.consumer import FusionWorker

#: The console reaches this service *directly* through a Next rewrite when
#: `FUSION_URL` is set, so these routes are internet-reachable and must
#: establish the tenant from the caller's credential rather than from a query
#: parameter. See app/security/tenant_scope.py.
ScopedPrincipal = Annotated[TenantPrincipal, Depends(require_console_or_service_auth)]

router = APIRouter()

_worker_ref: FusionWorker | None = None


def set_worker(worker: FusionWorker) -> None:
    global _worker_ref
    _worker_ref = worker


@router.get("/health")
async def health():
    return {"status": "healthy", "service": "aisoc-fusion"}


@router.get("/metrics")
async def metrics():
    """Consumer counters, plus the two durability backlogs.

    ``LakeWriter.metrics()`` existed and nothing read it, so the archive
    backlog, the capacity pressure and the quarantined rows were computed on
    every call to a method with no caller. A gap nobody can see is the same
    as a gap nobody reported, which is the shape this service has shipped
    before.

    ``None`` in either section means "could not be read", never zero: an
    unreadable backlog rendered as an empty one is how a stuck relay and a
    stalled archive both look healthy.
    """
    if _worker_ref is None:
        return {"status": "worker not started"}
    body: dict = {"status": "ok", "metrics": _worker_ref.get_metrics()}

    lake = _worker_ref.lake
    body["lake"] = lake.metrics() | {"degraded": lake.archive_degraded} if lake is not None else None

    pending, oldest_seconds = await _worker_ref.pending_notifications()
    body["notifications"] = {"pending": pending, "oldest_seconds": oldest_seconds}
    return body


@router.get("/scale-hint")
async def scale_hint():
    """Lag-based autoscaling signal (parity 6.9 / depth 4.4).

    AiSOC publishes this and does not act on it. An autoscaler belongs to
    the cluster, not to the application; ADR-0012 records why, and
    `apps/docs/docs/operations/performance.md` shows the KEDA
    `ScaledObject` that consumes it.

    Unauthenticated for the same reason `/metrics` is: a scaler scrapes
    it on the cluster network and it carries no tenant data — a lag count
    and a replica suggestion.
    """
    if _worker_ref is None:
        # Not a zero. A hint of "one replica, no backlog" from a service
        # whose worker never started is a scaler being told everything is
        # fine by a process that is not consuming anything.
        return {"status": "worker not started", "lag_measured": False}
    hint = await _worker_ref.scale_hint()
    return {"status": "ok", **hint}


@router.get("/ml/status")
async def ml_status(principal: ScopedPrincipal):
    """Return current ML model training status."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    return _worker_ref.engine.ml_scorer.status()


@router.post("/ml/feedback")
async def submit_feedback(feedback: AnalystFeedback, principal: ScopedPrincipal):
    """Submit analyst feedback to improve ML ranker."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    await _worker_ref.engine.ml_scorer.record_feedback(feedback)
    return {"status": "accepted", "alert_id": str(feedback.alert_id)}


@router.post("/ml/retrain")
async def trigger_retrain(principal: ScopedPrincipal):
    """Manually trigger ML model retraining."""
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    result = await _worker_ref.engine.ml_scorer.retrain()
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Synchronous fusion entrypoint (Issue #190)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/process", response_model=FusedAlert)
async def process_alert(alert: RawAlert, principal: ScopedPrincipal) -> FusedAlert:
    """Run a single ``RawAlert`` through the full fusion pipeline.

    The Kafka consumer path (``FusionWorker``) is still the production
    ingest route; this synchronous HTTP entrypoint exists so other
    services — notably the agents service's ``DetectAgent`` — can drive
    the fusion pipeline directly without standing up a Kafka producer,
    and so the contract is testable from a regular HTTP client.

    Behaviour matches the Kafka path exactly: the same ``FusionEngine``
    instance is reused (``_worker_ref.engine``), so deduplication,
    correlation, ML scoring, confidence labelling, RBA rollups, and
    narrative generation all run with the same state as the live
    consumer. A duplicate alert returns a ``FusionDecision.DUPLICATE``
    envelope; a new alert returns a fully scored ``FusedAlert``.
    """
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    return await _worker_ref.engine.process(alert)


# ─────────────────────────────────────────────────────────────────────────────
# Risk-Based Alerting (entity rollup)
# ─────────────────────────────────────────────────────────────────────────────


def _require_entity_risk():
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    eng = _worker_ref.engine.entity_risk
    if eng is None:
        raise HTTPException(status_code=503, detail="Entity risk engine not configured")
    if not eng.enabled:
        raise HTTPException(status_code=404, detail="Entity risk engine is disabled")
    return eng


@router.get("/entity-risk/queue")
async def entity_risk_queue(
    principal: ScopedPrincipal,
    tenant_id: UUID | None = None,
    limit: int = Query(default=25, ge=1, le=200),
    promoted_only: bool = False,
):
    """Return the top entities by current decayed risk score for a tenant.

    The entity-centric queue replaces the per-alert queue when RBA is
    enabled — analysts work the highest-risk entities and the contributing
    alerts are surfaced as evidence. Closes the 2026 KPI bar of
    ``alert-to-incident ratio ≥ 50:1``.

    ``tenant_id`` is an optional *filter*, not a selector: it is intersected
    with the credential's scope, so naming a tenant the caller does not hold
    returns 403 rather than that tenant's queue. Omitting it reads the
    caller's own tenant.
    """
    scoped = scoped_tenant_or_403(principal, tenant_id)
    eng = _require_entity_risk()
    records = await eng.top_entities(scoped, limit=limit, promoted_only=promoted_only)
    return {
        "tenant_id": str(scoped),
        "threshold": eng.threshold,
        "entities": [r.to_dict() for r in records],
    }


@router.get("/entity-risk/stats")
async def entity_risk_stats(principal: ScopedPrincipal, tenant_id: UUID | None = None):
    """Tenant-scoped queue stats for dashboards (banding, totals, threshold)."""
    scoped = scoped_tenant_or_403(principal, tenant_id)
    eng = _require_entity_risk()
    return {"tenant_id": str(scoped), **(await eng.stats(scoped))}


@router.get("/entity-risk/{entity_type}/{entity_value}")
async def entity_risk_detail(
    entity_type: str,
    entity_value: str,
    principal: ScopedPrincipal,
    tenant_id: UUID | None = None,
):
    """Return the full risk record (contributing alerts + severity histogram)
    for a single entity, used by the alert-detail drawer."""
    scoped = scoped_tenant_or_403(principal, tenant_id)
    if entity_type == "ip":
        entity_type = "src_ip"
    eng = _require_entity_risk()
    record = await eng.get(scoped, entity_type, entity_value)
    if record is None:
        raise HTTPException(status_code=404, detail="entity_not_found")
    return record.to_dict()


# ─────────────────────────────────────────────────────────────────────────────
# Detection confidence + explainability (Wave 1)
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/confidence/score")
async def score_confidence(alert: RawAlert, principal: ScopedPrincipal):
    """Run an alert through the confidence + explainability scorer in
    isolation and return the rationale chain.

    This is the same ``ConfidenceScorer`` that the live fusion pipeline
    uses, exposed here so the UI / detection lab can preview a confidence
    score without round-tripping through Kafka. The scorer is pure and
    stateless — no side effects on dedup / correlation / RBA state.

    Returns the projection of the alert as a ``FusedAlert``-shaped object
    where ``confidence_label`` / ``confidence_score`` /
    ``confidence_rationale`` are populated and other downstream fields
    are left at their defaults.
    """
    if _worker_ref is None or _worker_ref.engine is None:
        raise HTTPException(status_code=503, detail="Fusion worker not ready")
    scorer = _worker_ref.engine.confidence_scorer

    fused = FusedAlert(
        id=alert.id,
        tenant_id=alert.tenant_id,
        incident_id=None,
        fusion_decision=FusionDecision.NEW_INCIDENT,
        duplicate_of=None,
        alert=alert,
    )
    scored = scorer.score(fused)
    return {
        "alert_id": str(scored.id),
        "confidence_label": scored.confidence_label.value,
        "confidence_score": scored.confidence_score,
        "rationale": [f.model_dump() for f in scored.confidence_rationale],
    }


# ─────────────────────────────────────────────────────────────────────────────
# Dead-letter replay (deferral 5b)
# ─────────────────────────────────────────────────────────────────────────────


class DlqReplayRequest(BaseModel):
    """A bounded, explicit range to re-read and re-validate.

    Every field is required except ``execute``, which defaults to a dry run.
    There is no "replay the backlog" shape: a range somebody typed is a range
    somebody is accountable for, and an inferred one is a mis-click away from
    re-injecting a week of traffic.
    """

    topic: str
    partition: int = Field(ge=0)
    start_offset: int = Field(ge=0)
    max_messages: int = Field(default=100, ge=1, le=MAX_REPLAY_MESSAGES)
    #: Off by default at every layer. A replay nobody previewed is a replay
    #: nobody has checked the cause of.
    execute: bool = False


@router.post("/dlq/replay")
async def replay_dead_letters(request: DlqReplayRequest, principal: ScopedPrincipal) -> dict:
    """Re-read a range of refused messages and produce only what now passes.

    This service owns the execution because it owns the three things a safe
    replay needs in one place: the topic, the producer, and the validator
    that refused the messages in the first place. The operator door is
    ``POST /api/v1/health/dead-letters/replay`` on the API, which holds the
    permission, the tenant session and the audit row — the same split as
    ``siem_writeback`` and the playbook action bridge, and for the same
    reason.

    A message that still fails validation is refused a second time rather
    than produced. That is the property that stops a replay reproducing the
    outage that filled the queue.
    """
    try:
        outcome = await replay_from_offset(
            topic=request.topic,
            partition=request.partition,
            start_offset=request.start_offset,
            max_messages=request.max_messages,
            execute=request.execute,
        )
    except ReplayRefused as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001 — a broker fault is a 502, not a 500
        raise HTTPException(status_code=502, detail=f"replay could not run: {type(exc).__name__}: {exc}") from exc
    return outcome.as_dict()
