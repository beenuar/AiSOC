"""Assemble structured data for the Investigation Rail on `/alerts`.

The `/alerts` page in v1.5 shows an always-on right rail that surfaces
*everything* an analyst needs to triage a single alert without bouncing
between tabs:

* A deterministic correlation **narrative** (already cached on the row
  by the fusion service or lazily filled here — see
  ``app/services/narrative_projection.py``).
* **Related entities** grouped into four columns the analyst pivots
  from (principal, network, workflow, tenant). Each entity carries
  enough metadata for the frontend to deep-link into AttackGraphView
  without an extra round trip.
* A condensed **mini timeline** — at most ``MAX_TIMELINE_EVENTS``
  recent events drawn from the alert's case ledger (if any) and the
  audit log. Same data shape as the ledger's ``LedgerEvent`` so the
  rail can reuse ``apps/web/src/components/cases/InvestigationLedger.tsx``
  rendering primitives.
* **Recommended actions** — read straight off ``Alert.ai_recommendations``
  which the ResponderAgent populates at investigation-close time. The
  endpoint normalises both the new structured shape and legacy
  list-of-strings rows so old demos keep rendering.

The assembler is deliberately *pure with respect to its DB session*:
every read is `select(...)` + `await db.execute(...)`. No write paths.
This keeps the lazy-fill flow in the alerts endpoint trivially
restartable on failure — the rail data is a view, not a side-effect.

AiSOC — open-source AI Security Operations Center (MIT License)
Author: Beenu Arora <beenu@cyble.com>
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert
from app.models.audit import AuditLog
from app.models.case import CaseTimeline

# ─── Tunables ────────────────────────────────────────────────────────────────


# How many timeline events the rail surfaces. The plan calls for "last
# 6" — small enough to scan without scrolling, large enough to anchor
# the analyst's mental model. Both case-timeline and audit-log sources
# are merged then truncated.
MAX_TIMELINE_EVENTS = 6


# ─── Public Pydantic shapes ──────────────────────────────────────────────────


class RelatedEntity(BaseModel):
    """One pivotable entity attached to an alert.

    The ``kind`` field is the *concrete* entity type (``host``, ``ip``,
    ``user``, ``rule``, …) — the frontend keys icons and pivot routes
    off it. The ``group`` field is the rail column the entity renders
    under (``principal``, ``network``, ``workflow``, ``tenant``). One
    entity belongs to exactly one group; we don't duplicate rows.
    """

    group: str = Field(description="Rail column: principal | network | workflow | tenant")
    kind: str = Field(description="Concrete entity type: host | ip | user | rule | mitre | …")
    value: str = Field(description="Canonical identifier rendered in the chip")
    label: str | None = Field(default=None, description="Optional human-friendly label")
    pivot: str | None = Field(
        default=None,
        description=("Frontend route to deep-link into AttackGraphView (or another workbench). When None the chip is informational only."),
    )


class MiniTimelineEvent(BaseModel):
    """One event in the alert's condensed timeline.

    Modelled after ``LedgerEvent`` in the ledger UI so the rail can
    reuse the same row renderer. Fields the rail doesn't need
    (``input_hash``/``output_hash``/``duration_ms``) are always
    ``None``/``0`` for non-investigation events. The frontend knows
    to hide those affordances when they're empty.
    """

    id: str
    ts: datetime
    kind: str = Field(description="audit | case_comment | status_change | investigation | …")
    agent: str = Field(description="actor — system | analyst@… | agent-id")
    summary: str = Field(description="One-line description, plain text")
    payload: dict[str, Any] | None = Field(default=None)
    duration_ms: int = 0


class RecommendedAction(BaseModel):
    """Structured action emitted by the ResponderAgent at investigation close.

    Tolerates the legacy list-of-strings shape that older demo seeds
    used (string → ``action`` with priority ``99`` and risk ``"low"``).
    The plan calls for the structured shape; this is a migration aid.
    """

    priority: int = Field(default=99, ge=1)
    action: str
    rationale: str | None = None
    risk: str = Field(default="low", description="low | medium | high")


# ─── Internal helpers ────────────────────────────────────────────────────────


def _norm_str(value: Any) -> str | None:
    """Trim and discard empties. Returns ``None`` for non-strings."""
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _from_blob(blob: Any, keys: Iterable[str]) -> str | None:
    """Pull the first non-empty string at any of ``keys`` from a dict-ish blob."""
    if not isinstance(blob, dict):
        return None
    for key in keys:
        value = _norm_str(blob.get(key))
        if value:
            return value
    return None


def _dedup_strs(values: Iterable[Any]) -> list[str]:
    """Stable dedup; case-insensitive but preserves first-seen casing."""
    seen: set[str] = set()
    out: list[str] = []
    for v in values:
        s = _norm_str(v)
        if not s:
            continue
        key = s.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(s)
    return out


# ─── Related entities ────────────────────────────────────────────────────────


@dataclass(slots=True)
class _EntityBucket:
    """In-flight collector that dedups within a (group, kind, value) tuple."""

    entities: list[RelatedEntity]
    _seen: set[tuple[str, str, str]]

    @classmethod
    def empty(cls) -> _EntityBucket:
        return cls(entities=[], _seen=set())

    def add(
        self,
        *,
        group: str,
        kind: str,
        value: str | None,
        label: str | None = None,
        pivot: str | None = None,
    ) -> None:
        v = _norm_str(value)
        if not v:
            return
        key = (group, kind, v.lower())
        if key in self._seen:
            return
        self._seen.add(key)
        self.entities.append(RelatedEntity(group=group, kind=kind, value=v, label=label, pivot=pivot))


def build_related_entities(alert: Alert) -> list[RelatedEntity]:
    """Produce the rail's Related Entities list from an ``Alert`` row.

    The function is pure — no DB I/O, no clock reads. Same row →
    same output. Pivot URLs use the same `?entity=…` query the
    AttackGraphView already parses, so the rail "just works" when
    the analyst clicks through.
    """
    bucket = _EntityBucket.empty()
    raw_event = alert.raw_event if isinstance(alert.raw_event, dict) else {}
    enrichment = alert.enrichment_data if isinstance(alert.enrichment_data, dict) else {}

    # ── Principal ───────────────────────────────────────────────────────
    # Hosts and users an analyst would isolate / disable. We promote
    # the denormalised columns first, then mine the raw event blob
    # for fields the connector didn't curate into a top-level column.
    for host in _dedup_strs(alert.affected_hosts or ()):
        bucket.add(
            group="principal",
            kind="host",
            value=host,
            pivot=f"/attack-graph?entity=host:{host}",
        )
    for user in _dedup_strs(alert.affected_users or ()):
        bucket.add(
            group="principal",
            kind="user",
            value=user,
            pivot=f"/attack-graph?entity=user:{user}",
        )
    for asset in _dedup_strs(alert.affected_assets or ()):
        bucket.add(
            group="principal",
            kind="asset",
            value=asset,
            pivot=f"/attack-graph?entity=asset:{asset}",
        )

    # ── Network ─────────────────────────────────────────────────────────
    for ip in _dedup_strs(alert.affected_ips or ()):
        bucket.add(
            group="network",
            kind="ip",
            value=ip,
            pivot=f"/attack-graph?entity=ip:{ip}",
        )
    dst_ip = _from_blob(raw_event, ("dst_ip", "destination_ip", "remote_ip"))
    if dst_ip:
        bucket.add(
            group="network",
            kind="ip",
            value=dst_ip,
            label="destination",
            pivot=f"/attack-graph?entity=ip:{dst_ip}",
        )
    domain = _from_blob(raw_event, ("domain", "target_domain", "host_domain"))
    if domain:
        bucket.add(
            group="network",
            kind="domain",
            value=domain,
            pivot=f"/attack-graph?entity=domain:{domain}",
        )
    url = _from_blob(raw_event, ("url", "request_url", "uri"))
    if url:
        bucket.add(group="network", kind="url", value=url)

    # ── Workflow ────────────────────────────────────────────────────────
    # The "what" of the alert — rule name, MITRE coverage, tags that
    # describe the detection logic. These pivot into detection
    # tuning / coverage explorers rather than the entity graph.
    rule_name = _from_blob(raw_event, ("rule_name", "rule", "detection")) or alert.connector_type
    if rule_name:
        bucket.add(group="workflow", kind="rule", value=rule_name)
    for tactic_obj in alert.mitre_tactics or ():
        if isinstance(tactic_obj, str):
            name = _norm_str(tactic_obj)
            if name:
                bucket.add(group="workflow", kind="mitre_tactic", value=name)
        elif isinstance(tactic_obj, dict):
            tid = _norm_str(tactic_obj.get("id"))
            tname = _norm_str(tactic_obj.get("name"))
            display = tid or tname
            if display:
                bucket.add(
                    group="workflow",
                    kind="mitre_tactic",
                    value=display,
                    label=tname if (tname and tid) else None,
                )
    for tech_obj in alert.mitre_techniques or ():
        if isinstance(tech_obj, str):
            name = _norm_str(tech_obj)
            if name:
                bucket.add(group="workflow", kind="mitre_technique", value=name)
        elif isinstance(tech_obj, dict):
            tid = _norm_str(tech_obj.get("id") or tech_obj.get("technique_id"))
            tname = _norm_str(tech_obj.get("name") or tech_obj.get("technique"))
            display = tid or tname
            if display:
                bucket.add(
                    group="workflow",
                    kind="mitre_technique",
                    value=display,
                    label=tname if (tname and tid) else None,
                    pivot=f"/detection/tuning?technique={tid}" if tid else None,
                )

    # ── Tenant ──────────────────────────────────────────────────────────
    # Workspace / org-level pivots. The connector type lives here
    # because "which data source did this fire on" is an
    # organisational question, not a workflow one.
    if alert.connector_type:
        bucket.add(group="tenant", kind="connector", value=alert.connector_type)
    if alert.case_id is not None:
        bucket.add(
            group="tenant",
            kind="case",
            value=str(alert.case_id),
            pivot=f"/cases/{alert.case_id}",
        )
    # RBA promotion entity surfaces *which* identity drove this alert
    # over its risk threshold — show it as a tenant-level pivot so
    # analysts can navigate to the entity risk queue.
    rba_block = enrichment.get("rba_top_promotion") if isinstance(enrichment, dict) else None
    if isinstance(rba_block, dict):
        rba_entity = _norm_str(rba_block.get("entity"))
        if rba_entity:
            bucket.add(
                group="tenant",
                kind="rba_entity",
                value=rba_entity,
                label="risk promotion",
                pivot=f"/alerts?view=entities&entity={rba_entity}",
            )

    return bucket.entities


# ─── Mini timeline ───────────────────────────────────────────────────────────


def _audit_event(row: AuditLog) -> MiniTimelineEvent:
    """Project an ``AuditLog`` row into the rail's timeline shape."""
    payload: dict[str, Any] | None = None
    if isinstance(row.changes, dict) and row.changes:
        payload = dict(row.changes)
    elif isinstance(row.metadata_, dict) and row.metadata_:
        payload = dict(row.metadata_)
    actor = row.actor_email or (str(row.actor_id) if row.actor_id else "system")
    return MiniTimelineEvent(
        id=str(row.id),
        ts=row.created_at,
        kind=row.action or "audit",
        agent=actor,
        summary=_summarise_audit(row),
        payload=payload,
    )


def _summarise_audit(row: AuditLog) -> str:
    """One-line audit summary that reads in the rail without payload exposure.

    Audit rows are intentionally low-fidelity — they describe *what
    happened*, not *why*. The rail's audience is a human analyst, so
    we render a compact action-on-resource line and let the user click
    through to the full ledger / case timeline for richer detail.
    """
    action = row.action or "audit"
    if row.resource:
        return f"{action} on {row.resource}".strip()
    return action


def _case_event(row: CaseTimeline) -> MiniTimelineEvent:
    """Project a ``CaseTimeline`` row into the rail's timeline shape."""
    actor = "system" if row.is_automated else (str(row.user_id) if row.user_id else "system")
    payload: dict[str, Any] | None = None
    if isinstance(row.event_metadata, dict) and row.event_metadata:
        payload = dict(row.event_metadata)
    return MiniTimelineEvent(
        id=str(row.id),
        ts=row.created_at,
        kind=row.event_type or "case_event",
        agent=actor,
        summary=row.content or row.event_type or "case event",
        payload=payload,
    )


async def build_mini_timeline(
    db: AsyncSession,
    alert: Alert,
    *,
    limit: int = MAX_TIMELINE_EVENTS,
) -> list[MiniTimelineEvent]:
    """Assemble the rail's mini-timeline for a single alert.

    Sources, in priority order:

    1. ``CaseTimeline`` rows for the alert's case (if any) — these are
       the richest because they include analyst comments and agent
       turn-by-turn decisions.
    2. ``AuditLog`` rows whose ``resource == 'alert'`` and
       ``resource_id == str(alert.id)`` — covers status/assignment
       changes that don't go through a case.

    Both feeds are merged, sorted newest-first, and capped at
    ``limit``. The function is read-only and tenant-scoped at the
    query level (case timeline already filters by case → tenant; audit
    log we filter by ``tenant_id == alert.tenant_id`` defensively).
    """
    events: list[MiniTimelineEvent] = []

    # ── Case timeline ───────────────────────────────────────────────────
    if alert.case_id is not None:
        case_q = select(CaseTimeline).where(CaseTimeline.case_id == alert.case_id).order_by(CaseTimeline.created_at.desc()).limit(limit)
        case_rows = (await db.execute(case_q)).scalars().all()
        events.extend(_case_event(row) for row in case_rows)

    # ── Audit log ───────────────────────────────────────────────────────
    # We query a slightly larger window so the merge step has enough
    # rows to satisfy ``limit`` after we've already inserted case
    # events. The audit table is indexed on (tenant_id, created_at),
    # so this is cheap.
    audit_q = (
        select(AuditLog)
        .where(
            AuditLog.tenant_id == alert.tenant_id,
            AuditLog.resource == "alert",
            AuditLog.resource_id == str(alert.id),
        )
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
    )
    audit_rows = (await db.execute(audit_q)).scalars().all()
    events.extend(_audit_event(row) for row in audit_rows)

    # ── Merge + cap ─────────────────────────────────────────────────────
    events.sort(key=lambda e: e.ts, reverse=True)
    return events[:limit]


# ─── Recommended actions ─────────────────────────────────────────────────────


def build_recommended_actions(alert: Alert) -> list[RecommendedAction]:
    """Normalise ``Alert.ai_recommendations`` for rendering in the rail.

    The ResponderAgent emits a list of dicts of the form::

        {"priority": 1, "action": "Isolate host …", "rationale": "…", "risk": "high"}

    Older demo seeds wrote a list of bare strings. We accept both and
    drop everything else (silently — the rail isn't the right surface
    to surface a schema error). When no actions are present the rail
    falls back to the analyst's own playbook.
    """
    raw = alert.ai_recommendations
    if not isinstance(raw, list):
        return []
    out: list[RecommendedAction] = []
    for idx, item in enumerate(raw):
        if isinstance(item, str):
            text = _norm_str(item)
            if not text:
                continue
            out.append(RecommendedAction(priority=idx + 1, action=text))
            continue
        if not isinstance(item, dict):
            continue
        action = _norm_str(item.get("action"))
        if not action:
            continue
        try:
            priority = int(item.get("priority", idx + 1))
        except (TypeError, ValueError):
            priority = idx + 1
        if priority < 1:
            priority = 1
        risk = _norm_str(item.get("risk")) or "low"
        if risk.lower() not in {"low", "medium", "high"}:
            risk = "low"
        rationale = _norm_str(item.get("rationale"))
        out.append(
            RecommendedAction(
                priority=priority,
                action=action,
                rationale=rationale,
                risk=risk.lower(),
            )
        )
    # Stable sort by priority so the rail renders in the order the
    # agent intended even when sources are mixed.
    out.sort(key=lambda a: a.priority)
    return out


# ─── Convenience composite ───────────────────────────────────────────────────


class RailEnvelope(BaseModel):
    """Composite payload returned alongside the alert detail response."""

    related_entities: list[RelatedEntity]
    mini_timeline: list[MiniTimelineEvent]
    recommended_actions: list[RecommendedAction]


async def build_rail_envelope(db: AsyncSession, alert: Alert) -> RailEnvelope:
    """Build the full rail envelope in a single helper.

    Convenience wrapper for the alerts endpoint — avoids the caller
    having to import three symbols. Keeping it tiny so each subroutine
    stays individually unit-testable.
    """
    return RailEnvelope(
        related_entities=build_related_entities(alert),
        mini_timeline=await build_mini_timeline(db, alert),
        recommended_actions=build_recommended_actions(alert),
    )


__all__ = [
    "MAX_TIMELINE_EVENTS",
    "MiniTimelineEvent",
    "RailEnvelope",
    "RecommendedAction",
    "RelatedEntity",
    "build_mini_timeline",
    "build_rail_envelope",
    "build_recommended_actions",
    "build_related_entities",
]
