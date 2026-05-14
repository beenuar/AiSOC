"""Alert management endpoints."""

import logging
import re
import uuid
from datetime import UTC, datetime
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import and_, func, select, update
from sqlalchemy.exc import IntegrityError

from app.api.v1.deps import AuthUser, DBSession, require_permission
from app.db.rls import TenantDBSession
from app.models.alert import Alert
from app.services.alert_queue import (
    AlertAlreadyClaimedError,
    AlertNotFoundError,
    QueueResponse,
    build_queue,
    claim_alert,
)
from app.services.alert_rail import (
    MiniTimelineEvent,
    RecommendedAction,
    RelatedEntity,
    build_rail_envelope,
)
from app.services.event_sanitiser import (
    SubmitPayloadTooLarge,
    sanitise_event_batch,
)
from app.services.narrative_loader import build_narrative
from app.services.narrative_projection import project_alert_to_narrative_inputs
from app.services.timestamp_bounds import coerce_with_bounds, now_utc

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])

# ─── idempotency-key validation ─────────────────────────────────────────────
# Per RFC draft "The Idempotency-Key HTTP Header Field", clients pick an
# opaque key. We restrict the alphabet so the key can be stored as TEXT
# without breaking the DB column (128 chars, ASCII-safe, no whitespace).
# Anything else is a 400 — better to reject early than mint a partial
# row that can't be looked up on retry.
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:\-]{8,128}$")


class AlertResponse(BaseModel):
    id: uuid.UUID
    tenant_id: uuid.UUID
    title: str
    description: str | None
    severity: str
    status: str
    priority: int
    category: str | None
    mitre_tactics: list
    mitre_techniques: list
    connector_type: str | None
    ai_score: float | None
    ai_summary: str | None
    ai_recommendations: list
    # Fusion confidence (W3). `confidence` is an integer 0-100; the band is
    # carried in `confidence_label` (high/medium/low) and the contributing
    # factors in `confidence_rationale`. All three can be NULL for legacy
    # alerts created before the fusion service emitted confidence.
    confidence: int | None = None
    confidence_label: str | None = None
    confidence_rationale: list | None = None
    disposition: str | None = None
    affected_ips: list
    affected_hosts: list
    affected_users: list
    case_id: uuid.UUID | None
    tags: list
    event_time: datetime
    first_seen: datetime
    last_seen: datetime
    snoozed_until: datetime | None = None
    snoozed_by_id: uuid.UUID | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertDetailResponse(AlertResponse):
    """Alert response enriched with everything the Investigation Rail needs.

    The list endpoint stays on the smaller :class:`AlertResponse` shape
    to keep paginated payloads light. The detail endpoint promotes to
    this enriched shape so the rail renders without extra round-trips:

    * ``narrative`` — deterministic correlation prose. Cached on the
      ``Alert`` row by the fusion service; lazily filled by the
      endpoint when missing (legacy rows). Always a string by the
      time it leaves the API.
    * ``related_entities`` — pivotable entities grouped by
      principal / network / workflow / tenant.
    * ``mini_timeline`` — up to ``MAX_TIMELINE_EVENTS`` recent events
      merged from the case timeline and the audit log.
    * ``recommended_actions`` — normalised structured actions from
      the ResponderAgent (or the legacy list-of-strings shape).
    """

    narrative: str | None = None
    related_entities: list[RelatedEntity] = []
    mini_timeline: list[MiniTimelineEvent] = []
    recommended_actions: list[RecommendedAction] = []


class AlertSnoozeRequest(BaseModel):
    """Snooze an alert from the mobile responder PWA."""

    duration_minutes: int | None = None
    until: datetime | None = None
    reason: str | None = None


class AlertListResponse(BaseModel):
    items: list[AlertResponse]
    total: int
    page: int
    page_size: int
    pages: int


class AlertUpdateRequest(BaseModel):
    status: str | None = None
    priority: int | None = None
    tags: list[str] | None = None
    assigned_to_id: uuid.UUID | None = None
    case_id: uuid.UUID | None = None


class AlertStatsResponse(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_status: dict[str, int]
    new_last_24h: int
    critical_open: int


class AlertSubmitRequest(BaseModel):
    """Direct-write alert submission payload.

    The founder-flow demo (`aisoc submit <file>`) and any operator who wants
    to land a hand-crafted alert on the local dev stack without a connector
    POST one of these. The body intentionally mirrors the ingest envelope
    used by real connectors so the same fixture works against either path:

        { connector_id, connector_type, source_format, events: [...] }

    The single payload synthesises one ``Alert`` row, written directly into
    the tenant's database, so the result is visible in
    ``GET /api/v1/alerts`` and the web console within the same second.
    This deliberately bypasses the Kafka detection/correlation pipeline
    (which fresh clones don't run by default) so the documented "alert in
    seconds" promise in the quickstart actually holds.
    """

    events: list[dict] = []
    connector_id: str | None = None
    connector_type: str | None = None
    source_format: str | None = None
    title: str | None = None
    description: str | None = None
    severity: str | None = None
    tags: list[str] | None = None


# Map vendor-native severity strings to the canonical AiSOC severity ladder.
# Keep this in sync with the five-tier ladder documented in AGENTS.md
# (info | low | medium | high | critical).
_SEVERITY_MAP = {
    "info": "info",
    "informational": "info",
    "debug": "info",
    "low": "low",
    "minor": "low",
    "warning": "low",
    "medium": "medium",
    "moderate": "medium",
    "warn": "medium",
    "high": "high",
    "error": "high",
    "major": "high",
    "critical": "critical",
    "crit": "critical",
    "severe": "critical",
    "fatal": "critical",
    "emergency": "critical",
}
_SEVERITY_PRIORITY = {
    "info": 10,
    "low": 30,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def _normalize_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    return _SEVERITY_MAP.get(raw.strip().lower(), "medium")


def _max_severity(values: list[str]) -> str:
    """Pick the highest severity from a list using the canonical ladder."""
    ladder = ["info", "low", "medium", "high", "critical"]
    best = "info"
    for v in values:
        if ladder.index(v) > ladder.index(best):
            best = v
    return best


def _coerce_published(event: dict, now: datetime | None = None) -> tuple[datetime | None, bool]:
    """Extract a bounded event timestamp from an OCSF / Okta-shaped dict.

    Thin wrapper around :func:`app.services.timestamp_bounds.coerce_with_bounds`
    that gives the rest of this module a stable, locally-named helper. The
    underlying function scans the canonical timestamp fields
    (``published`` / ``time`` / ``@timestamp`` / ``timestamp`` / ``eventTime``),
    parses strings, ``datetime`` objects, and Unix epochs (seconds **or**
    milliseconds), and clamps out-of-window values to the configured
    ``MIN_AGE`` / ``MAX_FUTURE`` window so a broken connector can't poison
    SLA timers with a 1970 or 2099 timestamp.

    Returns ``(datetime | None, was_clamped)`` — ``was_clamped`` is ``True``
    iff the parsed timestamp had to be pinned to a boundary, useful so the
    caller can audit-tag the resulting alert.
    """
    return coerce_with_bounds(event, now=now)


def _synthesise_alert_from_events(
    *,
    tenant_id: uuid.UUID,
    events: list[dict],
    connector_type: str | None,
    override_title: str | None,
    override_description: str | None,
    override_severity: str | None,
    override_tags: list[str] | None,
    idempotency_key: str | None = None,
) -> Alert:
    """Build a single ``Alert`` row that represents the submitted event batch.

    The shape of incoming events is intentionally loose — they may be raw
    OCSF, Okta system-log entries, or any dict with the usual suspects
    (``displayMessage``, ``severity``, ``actor``, ``client``, ``published``).
    The function extracts what it can and falls back to safe defaults.

    Callers should hand us **already sanitised** events
    (:func:`app.services.event_sanitiser.sanitise_event_batch`) so that
    bearer tokens / API keys / passwords embedded in connector payloads
    never reach ``alerts.raw_event``. We do **not** redact in here because
    we still want to surface the raw shape for diagnostics — sanitisation
    is the endpoint's responsibility, this function trusts its input.

    ``idempotency_key`` is plumbed through to the resulting ORM instance
    so the caller can persist it atomically with the row. The synthesise
    function itself does no lookup — that's the endpoint's job.
    """
    first = events[0] if events else {}

    # Title
    title = override_title or first.get("displayMessage") or first.get("eventType") or first.get("name") or "AiSOC submitted alert"

    # Severity: pick the highest in the batch unless overridden
    severities = [_normalize_severity(e.get("severity")) for e in events]
    severity = _normalize_severity(override_severity) if override_severity else (_max_severity(severities) if severities else "medium")
    priority = _SEVERITY_PRIORITY[severity]

    # Description: count + first event hint
    description = override_description or (f"Submitted via aisoc submit / API. {len(events)} event(s) in batch. First event: {title}.")

    # Affected entities
    affected_ips: list[str] = []
    affected_hosts: list[str] = []
    affected_users: list[str] = []
    earliest: datetime | None = None
    latest: datetime | None = None
    # We need a single ``now`` reference so every timestamp in the batch
    # is clamped against the same window — otherwise a batch that takes
    # 50ms to process could clamp the first event's "max future" to one
    # value and the last event's to another, which would be confusing
    # to debug and arguably wrong.
    now = now_utc()
    any_clamped = False

    for event in events:
        actor = event.get("actor") or {}
        client = event.get("client") or {}

        # User: collect candidate identifiers in priority order; skip the
        # actor entirely if *any* of them already appears in
        # ``affected_users`` (i.e. we've already recorded this person under
        # a different identifier in an earlier event).
        actor_identifiers = [
            actor[key] for key in ("alternateId", "displayName", "email", "name", "id") if isinstance(actor.get(key), str) and actor[key]
        ]
        if actor_identifiers and not any(ident in affected_users for ident in actor_identifiers):
            affected_users.append(actor_identifiers[0])

        # IP from client
        ip = client.get("ipAddress") or client.get("ip")
        if isinstance(ip, str) and ip and ip not in affected_ips:
            affected_ips.append(ip)

        # Host from client geographicalContext or client.id
        geo = client.get("geographicalContext") or {}
        host_hint = client.get("device") or client.get("id") or geo.get("city")
        if isinstance(host_hint, str) and host_hint and host_hint not in affected_hosts:
            affected_hosts.append(host_hint)

        # Timestamps — bounded against MIN_AGE / MAX_FUTURE so a broken
        # connector emitting 1970-01-01 or 2099-12-31 doesn't poison the
        # SLA timers or push the alert outside the retention window.
        ts, clamped = _coerce_published(event, now=now)
        if clamped:
            any_clamped = True
        if ts is not None:
            if earliest is None or ts < earliest:
                earliest = ts
            if latest is None or ts > latest:
                latest = ts

    event_time = latest or earliest or now
    first_seen = earliest or now
    last_seen = latest or now

    # Tags: combine override + a marker so demo alerts are recognisable.
    # When *any* event in the batch had its timestamp clamped, drop an
    # ``ts-clamped`` tag so analysts (and the audit log) can spot a
    # source-side timestamp problem without re-running the math.
    tags = list(override_tags or [])
    if "submitted" not in tags:
        tags.append("submitted")
    if connector_type and connector_type not in tags:
        tags.append(connector_type)
    if any_clamped and "ts-clamped" not in tags:
        tags.append("ts-clamped")

    return Alert(
        tenant_id=tenant_id,
        title=title,
        description=description,
        severity=severity,
        status="new",
        priority=priority,
        category="identity" if "okta" in (connector_type or "").lower() else None,
        connector_type=connector_type,
        # JSONB list columns: populate explicitly so the response model
        # validation never trips on ``None`` for fresh inserts (the
        # ``default=list`` column default only fires after a real flush
        # against Postgres, not in unit tests with a mocked session).
        mitre_tactics=[],
        mitre_techniques=[],
        ai_recommendations=[],
        affected_ips=affected_ips,
        affected_hosts=affected_hosts,
        affected_users=affected_users,
        tags=tags,
        raw_event={
            "events": events,
            "connector_type": connector_type,
            "source": "aisoc-submit-api",
            "timestamps_clamped": any_clamped,
        },
        event_time=event_time,
        first_seen=first_seen,
        last_seen=last_seen,
        created_at=now,
        updated_at=now,
        idempotency_key=idempotency_key,
    )


@router.post(
    "/submit",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
)
async def submit_alert(
    payload: AlertSubmitRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
    idempotency_key: Annotated[
        str | None,
        Header(
            alias="Idempotency-Key",
            description=(
                "Optional opaque client-supplied key (8–128 chars, "
                "[A-Za-z0-9._:-]). When supplied, a retry of the same key "
                "for the same tenant returns the existing alert with HTTP "
                "200 instead of creating a duplicate."
            ),
        ),
    ] = None,
) -> AlertResponse:
    """Submit one alert directly from an OCSF event batch.

    This is the destination for `aisoc submit <file>` and the local-dev fast
    path documented in the quickstart. We deliberately bypass the Kafka
    detect/correlate/fuse pipeline (which fresh clones don't run by default)
    so that a hand-crafted fixture lands in the database — and therefore in
    ``GET /api/v1/alerts`` and the web console — within the same second.

    **Hardening (Batch 8 / H-5)**:

    * **Payload caps** — events are first run through
      :func:`app.services.event_sanitiser.sanitise_event_batch`, which
      enforces ``AISOC_SUBMIT_MAX_EVENTS`` (default 200), per-event size
      ``AISOC_SUBMIT_MAX_EVENT_BYTES`` (default 64 KiB), and total batch
      size ``AISOC_SUBMIT_MAX_TOTAL_BYTES`` (default 1 MiB). Violations
      return ``413 Payload Too Large`` rather than the 200 OK + truncated
      alert we used to silently emit.
    * **Secret redaction** — the sanitiser also redacts keys matching
      common secret patterns (``password``, ``token``, ``api_key``, …)
      *before* the payload is persisted to ``alerts.raw_event``, so a
      leaky connector cannot smuggle bearer tokens into the alert table
      where they would be visible to every analyst with ``alerts:read``.
    * **Idempotency** — when the client supplies an ``Idempotency-Key``
      header, the resulting alert is keyed ``(tenant_id, idempotency_key)``
      via a partial unique index (migration ``044``). A retry of the
      same key resolves to the existing row and returns HTTP ``200``
      instead of creating a duplicate, so at-least-once connectors and
      the ``aisoc submit`` CLI can retry safely on network blips.
    * **Timestamp bounds** — event timestamps outside the configured
      retention window are clamped (see
      :mod:`app.services.timestamp_bounds`); the resulting alert is
      tagged ``ts-clamped`` so analysts can see the connector misbehaved.

    Authorisation: requires ``alerts:write``. In development mode the
    auth bypass in :mod:`app.api.v1.deps` resolves to the deterministic
    demo tenant, so the documented ``aisoc submit`` CLI works against a
    fresh clone with no token plumbing.
    """
    if not payload.events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="events must be a non-empty list",
        )

    # Validate Idempotency-Key shape early so a bad header fails fast
    # and never costs us a DB round-trip. We only enforce the regex when
    # the client *supplied* a key — the column itself remains nullable.
    if idempotency_key is not None:
        idempotency_key = idempotency_key.strip()
        if not _IDEMPOTENCY_KEY_RE.match(idempotency_key):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=("Idempotency-Key must be 8–128 ASCII chars matching [A-Za-z0-9._:-]"),
            )

        # Cheap check first — if a row with this (tenant, key) already
        # exists, return it without doing any sanitisation/synthesis
        # work. This is the hot path for connector retries.
        existing = await db.execute(
            select(Alert).where(
                and_(
                    Alert.tenant_id == current_user.tenant_id,
                    Alert.idempotency_key == idempotency_key,
                )
            )
        )
        cached = existing.scalar_one_or_none()
        if cached is not None:
            logger.info(
                "alert.submitted.idempotent_hit",
                extra={
                    "alert_id": str(cached.id),
                    "tenant_id": str(cached.tenant_id),
                    "idempotency_key": idempotency_key,
                },
            )
            return AlertResponse.model_validate(cached)

    # Sanitise the batch: redact secrets and enforce size caps. Only the
    # *batch-length* cap raises ``SubmitPayloadTooLarge`` (translated to
    # HTTP 413) — per-event and total-bytes overruns are handled inline
    # by the sanitiser by replacing oversized payloads with a small
    # truncation marker, so one rogue event doesn't drop the rest of the
    # batch. The ``stats`` dict gives us a one-line audit summary of what
    # was redacted/truncated.
    try:
        sanitised_events, sanitise_stats = sanitise_event_batch(payload.events)
    except SubmitPayloadTooLarge as exc:
        logger.warning(
            "alert.submit.payload_too_large",
            extra={
                "tenant_id": str(current_user.tenant_id),
                "reason": str(exc),
                "raw_event_count": len(payload.events),
            },
        )
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(exc),
        ) from exc

    alert = _synthesise_alert_from_events(
        tenant_id=current_user.tenant_id,
        events=sanitised_events,
        connector_type=payload.connector_type,
        override_title=payload.title,
        override_description=payload.description,
        override_severity=payload.severity,
        override_tags=payload.tags,
        idempotency_key=idempotency_key,
    )

    db.add(alert)
    try:
        await db.flush()
    except IntegrityError as exc:
        # Race condition: another concurrent request landed the same
        # (tenant_id, idempotency_key) between our SELECT above and our
        # INSERT. The partial unique index from migration 044 catches
        # this — rather than 500ing, roll back and return whichever row
        # actually won the race, preserving the idempotency contract.
        await db.rollback()
        if idempotency_key is None:
            # Not an idempotency race — re-raise as a generic 500 so
            # the operator sees the real issue (e.g. NOT NULL violation
            # on a column we forgot to populate).
            logger.exception("alert.submit.integrity_error")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to persist alert",
            ) from exc

        existing = await db.execute(
            select(Alert).where(
                and_(
                    Alert.tenant_id == current_user.tenant_id,
                    Alert.idempotency_key == idempotency_key,
                )
            )
        )
        cached = existing.scalar_one_or_none()
        if cached is None:
            # The unique index complained but no row is visible — this
            # really is a 500. Don't pretend it succeeded.
            logger.exception(
                "alert.submit.idempotency_race_no_row",
                extra={
                    "tenant_id": str(current_user.tenant_id),
                    "idempotency_key": idempotency_key,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="failed to persist alert",
            ) from exc

        logger.info(
            "alert.submitted.idempotent_race_resolved",
            extra={
                "alert_id": str(cached.id),
                "tenant_id": str(cached.tenant_id),
                "idempotency_key": idempotency_key,
            },
        )
        return AlertResponse.model_validate(cached)

    await db.refresh(alert)

    logger.info(
        "alert.submitted",
        extra={
            "alert_id": str(alert.id),
            "tenant_id": str(alert.tenant_id),
            "severity": alert.severity,
            "events": len(sanitised_events),
            "connector_type": payload.connector_type,
            "idempotency_key": idempotency_key,
            "timestamps_clamped": "ts-clamped" in (alert.tags or []),
            "redacted_keys": sanitise_stats.get("redacted", 0),
            "truncated_events": sanitise_stats.get("truncated", 0),
        },
    )

    return AlertResponse.model_validate(alert)


@router.get("", response_model=AlertListResponse)
async def list_alerts(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    severity: str | None = Query(default=None),
    status: str | None = Query(default=None),
    category: str | None = Query(default=None),
    assigned_to_me: bool = Query(default=False),
    search: str | None = Query(default=None),
    min_confidence: int | None = Query(default=None, ge=0, le=100),
    confidence_label: str | None = Query(default=None),
) -> AlertListResponse:
    """List alerts for the current tenant with filtering and pagination.

    `min_confidence` / `confidence_label` let the queue workbench (PR-5) and
    /alerts page filter on the fusion-emitted confidence signal (W3). Alerts
    that pre-date the confidence column will have NULL and therefore won't
    match either filter — that's intentional; analysts who care about
    confidence should only see alerts that actually carry the signal.
    """
    filters = [Alert.tenant_id == current_user.tenant_id]

    if severity:
        filters.append(Alert.severity == severity)
    if status:
        filters.append(Alert.status == status)
    if category:
        filters.append(Alert.category == category)
    if assigned_to_me:
        filters.append(Alert.assigned_to_id == current_user.user_id)
    if min_confidence is not None:
        filters.append(Alert.confidence >= min_confidence)
    if confidence_label is not None:
        if confidence_label not in {"high", "medium", "low"}:
            # NOTE: the local `status` query parameter shadows the
            # `fastapi.status` module here, so use the literal 400.
            raise HTTPException(
                status_code=400,
                detail="confidence_label must be one of: high, medium, low",
            )
        filters.append(Alert.confidence_label == confidence_label)

    # Count
    count_result = await db.execute(select(func.count()).select_from(Alert).where(and_(*filters)))
    total = count_result.scalar_one()

    # Fetch
    offset = (page - 1) * page_size
    result = await db.execute(select(Alert).where(and_(*filters)).order_by(Alert.created_at.desc()).offset(offset).limit(page_size))
    alerts = result.scalars().all()

    return AlertListResponse(
        items=[AlertResponse.model_validate(a) for a in alerts],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size,
    )


@router.get("/stats", response_model=AlertStatsResponse)
async def get_alert_stats(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> AlertStatsResponse:
    """Get alert statistics for the dashboard."""
    from datetime import timedelta

    tenant_filter = Alert.tenant_id == current_user.tenant_id

    # Total count
    total_result = await db.execute(select(func.count()).select_from(Alert).where(tenant_filter))
    total = total_result.scalar_one()

    # By severity
    sev_result = await db.execute(select(Alert.severity, func.count()).where(tenant_filter).group_by(Alert.severity))
    by_severity = {row[0]: row[1] for row in sev_result.all()}

    # By status
    status_result = await db.execute(select(Alert.status, func.count()).where(tenant_filter).group_by(Alert.status))
    by_status = {row[0]: row[1] for row in status_result.all()}

    # New last 24h
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    new_24h_result = await db.execute(select(func.count()).select_from(Alert).where(and_(tenant_filter, Alert.created_at >= cutoff)))
    new_last_24h = new_24h_result.scalar_one()

    # Critical open
    crit_result = await db.execute(
        select(func.count())
        .select_from(Alert)
        .where(and_(tenant_filter, Alert.severity == "critical", Alert.status.in_(["new", "triaging", "in_progress"])))
    )
    critical_open = crit_result.scalar_one()

    return AlertStatsResponse(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        new_last_24h=new_last_24h,
        critical_open=critical_open,
    )


# NOTE: `/queue` is defined here — *before* `/{alert_id}` — on purpose.
# FastAPI matches routes top-down, so a static path must precede the
# parametric path of the same depth or the framework will route
# `GET /alerts/queue` into `get_alert(alert_id="queue")` and 422.
@router.get("/queue", response_model=QueueResponse)
async def get_alert_queue(
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: TenantDBSession,
    owner: Literal["me", "unassigned", "all"] = Query(default="all"),
    period: Literal["24h", "7d", "30d", "all"] = Query(default="all"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
) -> QueueResponse:
    """Investigation Queue workbench feed.

    Returns the prioritised list of alerts the analyst should work on
    next: alerts assigned to them, followed by unassigned
    critical/high alerts, ordered by SLA due time.

    The endpoint also returns ``counts`` for both buckets unconditionally
    so the topbar badge and the workbench tabs can render without an
    extra round-trip.
    """
    return await build_queue(
        db,
        tenant_id=current_user.tenant_id,
        user_id=current_user.user_id,
        owner=owner,
        period=period,
        page=page,
        page_size=page_size,
    )


@router.get("/{alert_id}", response_model=AlertDetailResponse)
async def get_alert(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:read"))],
    db: DBSession,
) -> AlertDetailResponse:
    """Get a single alert by ID, enriched with Investigation Rail data.

    The endpoint returns the standard alert fields plus everything the
    rail needs to render in one shot:

    * a deterministic ``narrative`` (lazily filled and persisted if the
      row was created before fusion started emitting it),
    * ``related_entities`` grouped for pivot,
    * a compact ``mini_timeline``,
    * normalised ``recommended_actions``.

    The lazy-fill is best-effort: if the narrative builder ever raises
    we log and return the alert with ``narrative=None`` so the page
    keeps rendering. The frontend already handles the null case.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # ── Lazy-fill narrative for legacy rows ─────────────────────────────
    # New alerts get a narrative at fusion time. Older rows predate that
    # column being populated; the first detail-view read materialises
    # and persists one so we only pay the cost once per row.
    if not alert.narrative:
        try:
            inputs = project_alert_to_narrative_inputs(alert)
            narrative_text = build_narrative(inputs)
            if narrative_text:
                alert.narrative = narrative_text
                await db.execute(update(Alert).where(Alert.id == alert.id).values(narrative=narrative_text, updated_at=datetime.now(UTC)))
                await db.commit()
        except Exception:  # noqa: BLE001 — never let narrative kill a detail view
            logger.warning(
                "narrative lazy-fill failed for alert %s; serving without narrative",
                alert.id,
                exc_info=True,
            )

    envelope = await build_rail_envelope(db, alert)

    # ``model_validate`` against the parent class to inherit field
    # coercion, then merge the rail fields. We don't add the rail data
    # to the ORM model — keeping the envelope construction in the view
    # layer means the rail can evolve without migrations.
    payload = AlertDetailResponse.model_validate(alert)
    return payload.model_copy(
        update={
            "narrative": alert.narrative,
            "related_entities": envelope.related_entities,
            "mini_timeline": envelope.mini_timeline,
            "recommended_actions": envelope.recommended_actions,
        }
    )


@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: uuid.UUID,
    request: AlertUpdateRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: DBSession,
) -> AlertResponse:
    """Update alert status, priority, tags, assignment, or case link."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    updates: dict = {}
    if request.status is not None:
        updates["status"] = request.status
        if request.status in ("resolved", "false_positive", "closed"):
            updates["resolved_at"] = datetime.now(UTC)
    if request.priority is not None:
        updates["priority"] = request.priority
    if request.tags is not None:
        updates["tags"] = request.tags
    if request.assigned_to_id is not None:
        updates["assigned_to_id"] = request.assigned_to_id
        updates["assigned_at"] = datetime.now(UTC)
    if request.case_id is not None:
        updates["case_id"] = request.case_id

    if updates:
        updates["updated_at"] = datetime.now(UTC)
        await db.execute(update(Alert).where(Alert.id == alert_id).values(**updates))
        await db.commit()
        await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/escalate", response_model=AlertResponse)
async def escalate_alert(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: DBSession,
) -> AlertResponse:
    """Escalate an alert (raises severity by one level)."""
    severity_ladder = ["info", "low", "medium", "high", "critical"]

    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    current_idx = severity_ladder.index(alert.severity) if alert.severity in severity_ladder else 2
    new_severity = severity_ladder[min(current_idx + 1, len(severity_ladder) - 1)]

    await db.execute(update(Alert).where(Alert.id == alert_id).values(severity=new_severity, updated_at=datetime.now(UTC)))
    await db.commit()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/claim", response_model=AlertResponse)
async def claim_alert_endpoint(
    alert_id: uuid.UUID,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> AlertResponse:
    """Atomically claim an unassigned alert for the current user.

    Returns ``409 Conflict`` if the alert is already assigned to someone
    else — the claim is a compare-and-set on ``assigned_to_id``, so two
    analysts racing for the same alert never both win.
    """
    try:
        alert = await claim_alert(
            db,
            alert_id=alert_id,
            tenant_id=current_user.tenant_id,
            user_id=current_user.user_id,
        )
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except AlertAlreadyClaimedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return AlertResponse.model_validate(alert)


@router.post("/{alert_id}/snooze", response_model=AlertResponse)
async def snooze_alert(
    alert_id: uuid.UUID,
    body: AlertSnoozeRequest,
    current_user: Annotated[AuthUser, Depends(require_permission("alerts:write"))],
    db: TenantDBSession,
) -> AlertResponse:
    """Defer an alert for a fixed window from the mobile responder PWA.

    Either ``duration_minutes`` or ``until`` must be supplied. The alert
    re-surfaces in the queue once ``snoozed_until`` is in the past.
    """
    from datetime import timedelta

    if body.duration_minutes is None and body.until is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either duration_minutes or until must be provided",
        )

    if body.until is not None:
        snoozed_until = body.until.astimezone(UTC) if body.until.tzinfo else body.until.replace(tzinfo=UTC)
    else:
        if (body.duration_minutes or 0) <= 0 or (body.duration_minutes or 0) > 60 * 24 * 30:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="duration_minutes must be between 1 and 43200 (30 days)",
            )
        snoozed_until = datetime.now(UTC) + timedelta(minutes=body.duration_minutes or 0)

    result = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.tenant_id == current_user.tenant_id))
    alert = result.scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            snoozed_until=snoozed_until,
            snoozed_by_id=current_user.user_id,
            updated_at=datetime.now(UTC),
        )
    )
    await db.commit()
    await db.refresh(alert)

    return AlertResponse.model_validate(alert)
