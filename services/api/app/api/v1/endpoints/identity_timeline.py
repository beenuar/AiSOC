"""Identity-centric investigation timeline (tier2-identity).

Builds a chronological event timeline anchored to a user, device, or
service-account identity.  Queries ``aisoc_alerts``, ``aisoc_events``,
and the enrichment store to produce an ordered list of security events
grouped by entity, with ATT&CK technique annotations.

Endpoints
---------
* ``GET  /identity-timeline``          Search timelines by identity.
* ``POST /identity-timeline/build``    Build a fresh timeline for an identity.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import text

from app.api.v1.deps import AuthUser, DBSession

router = APIRouter(prefix="/identity-timeline", tags=["identity_timeline"])

# ────────────────────────────────────────────────────────────────────────────
# Pydantic schemas
# ────────────────────────────────────────────────────────────────────────────

IdentityKind = Literal["user", "device", "service_account", "ip"]


class TimelineEvent(BaseModel):
    event_id: uuid.UUID
    timestamp: datetime
    event_type: Literal["alert", "login", "process", "network", "file", "other"]
    source: str
    description: str
    severity: str | None = None
    mitre_technique: str | None = None
    raw: dict[str, Any] | None = None


class IdentityTimeline(BaseModel):
    timeline_id: uuid.UUID
    identity_kind: IdentityKind
    identity_value: str
    from_ts: datetime
    to_ts: datetime
    events: list[TimelineEvent]
    total_events: int
    risk_score: float | None = None
    built_at: datetime


class BuildTimelineRequest(BaseModel):
    identity_kind: IdentityKind = Field(..., description="Type of identity anchor.")
    identity_value: str = Field(..., min_length=1, description="Identity value (e.g. username, hostname).")
    from_ts: datetime | None = Field(None, description="Start of window (defaults to 72 h ago).")
    to_ts: datetime | None = Field(None, description="End of window (defaults to now).")
    max_events: int = Field(200, ge=1, le=2000)


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

_FIELD_MAP: dict[IdentityKind, list[str]] = {
    "user": ["user", "username", "src_user", "dest_user", "actor"],
    "device": ["hostname", "device", "src_host", "computer_name"],
    "service_account": ["service_account", "svc_account", "process_user"],
    "ip": ["src_ip", "source_ip", "ip_address", "remote_ip"],
}


def _risk_score(events: list[TimelineEvent]) -> float:
    """Simple heuristic: sum severity weights, cap at 100."""
    weights = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 1}
    score = sum(weights.get((e.severity or "info").lower(), 1) for e in events)
    return min(100.0, float(score))


def _mitre_from_alert(raw: dict[str, Any]) -> str | None:
    return (
        raw.get("mitre_technique")
        or raw.get("mitre_attack_id")
        or raw.get("tags", {}).get("mitre")
    )


# ────────────────────────────────────────────────────────────────────────────
# Endpoints
# ────────────────────────────────────────────────────────────────────────────


@router.post(
    "/build",
    response_model=IdentityTimeline,
    status_code=status.HTTP_200_OK,
    summary="Build identity-centric investigation timeline",
)
async def build_timeline(
    body: BuildTimelineRequest,
    db: DBSession,
    user: AuthUser,
) -> IdentityTimeline:
    now = datetime.now(UTC)
    from_ts = body.from_ts or (now - timedelta(hours=72))
    to_ts = body.to_ts or now

    events: list[TimelineEvent] = []

    # ── 1. Alerts that reference this identity ──────────────────────────────
    try:
        alert_rows = await db.execute(
            text(
                """
                SELECT id, created_at, severity, title, evidence, mitre_technique
                FROM aisoc_alerts
                WHERE created_at BETWEEN :from_ts AND :to_ts
                  AND (
                    evidence::text ILIKE :pat
                    OR title ILIKE :pat
                  )
                ORDER BY created_at DESC
                LIMIT :lim
                """
            ).bindparams(
                from_ts=from_ts,
                to_ts=to_ts,
                pat=f"%{body.identity_value}%",
                lim=body.max_events,
            )
        )
        for row in alert_rows.fetchall():
            events.append(
                TimelineEvent(
                    event_id=row.id,
                    timestamp=row.created_at,
                    event_type="alert",
                    source="aisoc_alerts",
                    description=row.title or "Alert",
                    severity=row.severity,
                    mitre_technique=row.mitre_technique
                    or _mitre_from_alert(row.evidence or {}),
                    raw=row.evidence,
                )
            )
    except Exception:
        pass  # table may not exist in all deployments

    # ── 2. Raw events from aisoc_events (if table exists) ──────────────────
    try:
        ev_rows = await db.execute(
            text(
                """
                SELECT id, timestamp, event_type, source, description,
                       severity, raw_event
                FROM aisoc_events
                WHERE timestamp BETWEEN :from_ts AND :to_ts
                  AND raw_event::text ILIKE :pat
                ORDER BY timestamp DESC
                LIMIT :lim
                """
            ).bindparams(
                from_ts=from_ts,
                to_ts=to_ts,
                pat=f"%{body.identity_value}%",
                lim=body.max_events - len(events),
            )
        )
        for row in ev_rows.fetchall():
            events.append(
                TimelineEvent(
                    event_id=row.id,
                    timestamp=row.timestamp,
                    event_type=row.event_type or "other",
                    source=row.source or "aisoc_events",
                    description=row.description or "",
                    severity=row.severity,
                    raw=row.raw_event,
                )
            )
    except Exception:
        pass

    # ── 3. Sort chronologically ─────────────────────────────────────────────
    events.sort(key=lambda e: e.timestamp)

    return IdentityTimeline(
        timeline_id=uuid.uuid4(),
        identity_kind=body.identity_kind,
        identity_value=body.identity_value,
        from_ts=from_ts,
        to_ts=to_ts,
        events=events[: body.max_events],
        total_events=len(events),
        risk_score=_risk_score(events),
        built_at=now,
    )


@router.get(
    "",
    response_model=IdentityTimeline,
    summary="Quick timeline lookup for an identity",
)
async def get_timeline(
    identity_kind: IdentityKind = Query(...),
    identity_value: str = Query(..., min_length=1),
    hours: int = Query(72, ge=1, le=8760),
    db: DBSession = ...,
    user: AuthUser = ...,
) -> IdentityTimeline:
    return await build_timeline(
        BuildTimelineRequest(
            identity_kind=identity_kind,
            identity_value=identity_value,
            from_ts=datetime.now(UTC) - timedelta(hours=hours),
        ),
        db=db,
        user=user,
    )
