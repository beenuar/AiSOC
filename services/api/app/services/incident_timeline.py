"""One chronology for an incident: its alerts, and the events behind them.

Every other timeline in this product shows one granularity. The alert rail
shows six workflow events; the case timeline shows status changes and
"Alert linked: …" markers stamped at *ingest* time; the attack chain shows
alerts ranked by relevance; the investigator report shows at most five
alert metadata rows. None of them answers the question an analyst actually
asks of an incident — what happened, in order.

The links to answer it already existed and nothing walked them:

    aisoc_cases.alert_ids → alerts → alerts.source_event_ids
                                   → ClickHouse aisoc.raw_events

Two things sit between those links and have to be handled rather than
assumed.

**The lake's event id is not always the alert's event id.** ``LakeWriter``
stores ``event_id`` as the ingest id when that id is already a UUID, and as
a UUIDv5 *derived* from it otherwise — while ``alerts.source_event_ids``
keeps the ingest id verbatim. Matching the stored strings directly
therefore returns nothing at all for every producer whose ids are not
UUIDs, and returns it silently, as an empty result that looks like a quiet
estate. :func:`lake_event_id` mirrors the writer's derivation so the join
is the same identity on both sides.

**``source_event_ids`` is capped at 200 per alert.** Past that the alert
still deduplicates and the list simply stops growing, so "the events shown"
is not "the events there were". The timeline publishes that rather than
letting a reader infer completeness.

And the honest-state rule applies throughout: a lake that is not deployed
(the core profile ships without ClickHouse) and a lake that answered "no
rows" are different facts and must never render the same.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.db.clickhouse import LakeQueryNotConfiguredError

logger = logging.getLogger("aisoc.incident_timeline")

#: Mirror of ``services/fusion/app/services/lake_writer.py``. The lake row's
#: identity is derived with this namespace, so a reader that wants to find
#: the row for an ingest id must derive it the same way. Pinned by a test
#: that recomputes the namespace rather than trusting this constant.
_EVENT_ID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://aisoc.dev/fusion/lake/event-id")

#: The ceiling ``AlertSink`` applies to ``source_event_ids``. An alert
#: holding exactly this many ids is the one case where the list is known to
#: be incomplete.
SOURCE_EVENT_ID_CAP = 200

#: Bound on the lake read. A case can link many alerts, each naming up to
#: 200 events; a timeline is read by a human and does not need all of them
#: in one response.
MAX_EVENTS = 500

DISCLAIMER = (
    "Times are taken from the source records themselves. This is a chronology "
    "of what was observed, not a confirmed account of what caused what."
)


def lake_event_id(raw_id: Any) -> str | None:
    """The lake's ``event_id`` for an ingest id, or None if there isn't one.

    A UUID passes through; anything else is derived exactly the way the lake
    writer derives it. Returns None for an absent or empty id rather than
    minting a random one, because a random id matches no row and would turn
    "this alert names no event" into "the lake has lost it".
    """
    if raw_id is None:
        return None
    text = str(raw_id).strip()
    if not text:
        return None
    try:
        return str(uuid.UUID(text))
    except (ValueError, AttributeError, TypeError):
        return str(uuid.uuid5(_EVENT_ID_NAMESPACE, f"ingest:{text}"))


@dataclass(frozen=True)
class TimelineAlert:
    """The alert-side input: one row of ``alerts`` the case links."""

    id: uuid.UUID
    title: str
    severity: str
    event_time: datetime
    status: str
    incident_id: uuid.UUID | None
    chain_id: str | None
    chain_position: int | None
    chain_stage: str | None
    source_event_ids: list[str]
    connector_type: str | None
    mitre_techniques: list[str]


@dataclass
class TimelineEntry:
    """One moment in the chronology — an alert, or an event behind one."""

    kind: str  # "alert" | "event"
    at: datetime
    title: str
    #: Set on both kinds: an event names the alert it helped produce, which
    #: is what lets the view nest it under that alert.
    alert_id: uuid.UUID | None = None
    severity: str | None = None
    chain_stage: str | None = None
    chain_position: int | None = None
    connector_type: str | None = None
    mitre_techniques: list[str] = field(default_factory=list)
    #: Event-only: the lake columns worth showing beside the action.
    action: str | None = None
    user_name: str | None = None
    hostname: str | None = None
    source_ip: str | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "at": self.at.isoformat(),
            "title": self.title,
            "alert_id": str(self.alert_id) if self.alert_id else None,
        }
        if self.kind == "alert":
            out.update(
                {
                    "severity": self.severity,
                    "chain_stage": self.chain_stage,
                    "chain_position": self.chain_position,
                    "connector_type": self.connector_type,
                    "mitre_techniques": self.mitre_techniques,
                }
            )
        else:
            out.update(
                {
                    "action": self.action,
                    "user_name": self.user_name,
                    "hostname": self.hostname,
                    "source_ip": self.source_ip,
                }
            )
        return out


@dataclass
class IncidentTimeline:
    entries: list[TimelineEntry]
    alert_count: int
    event_count: int
    #: False when the lake could not answer. Distinct from an empty result:
    #: "nobody looked" and "nothing there" are different facts.
    events_available: bool
    events_unavailable_reason: str | None
    #: True when at least one alert sits on the 200-id ceiling, so the event
    #: set shown is known to be partial.
    source_event_ids_truncated: bool
    truncation_note: str
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [e.to_dict() for e in self.entries],
            "alert_count": self.alert_count,
            "event_count": self.event_count,
            "events_available": self.events_available,
            "events_unavailable_reason": self.events_unavailable_reason,
            "source_event_ids_truncated": self.source_event_ids_truncated,
            "truncation_note": self.truncation_note,
            "disclaimer": self.disclaimer,
        }


#: ``event_id`` and ``tenant_id`` are UUID columns, so both are bound as
#: ``uuid.UUID`` objects and let the driver serialise them — comparing a
#: UUID column against a String is the type mismatch this lake has been
#: bitten by before. The ``IN %(name)s`` form (no surrounding parentheses)
#: is the driver's own list expansion, matching the other lake readers.
_EVENTS_SQL = """
SELECT event_id, event_time, action, user_name, src_hostname, source_ip
  FROM aisoc.raw_events
 WHERE tenant_id = %(tenant_id)s
   AND event_id IN %(event_ids)s
 ORDER BY event_time
 LIMIT %(limit)s
"""

LakeQuery = Callable[..., Awaitable[Any]]


async def build_incident_timeline(
    *,
    alerts: list[TimelineAlert],
    tenant_id: uuid.UUID,
    lake_query: LakeQuery,
    max_events: int = MAX_EVENTS,
) -> IncidentTimeline:
    """Interleave a case's alerts with the lake events that produced them."""
    ordered = sorted(alerts, key=lambda a: (_utc(a.event_time), str(a.id)))

    entries: list[TimelineEntry] = [
        TimelineEntry(
            kind="alert",
            at=_utc(a.event_time),
            title=a.title,
            alert_id=a.id,
            severity=a.severity,
            chain_stage=a.chain_stage,
            chain_position=a.chain_position,
            connector_type=a.connector_type,
            mitre_techniques=list(a.mitre_techniques),
        )
        for a in ordered
    ]

    # Which lake row belongs to which alert. Built before the query so the
    # events can be attributed without a second pass.
    owner: dict[str, uuid.UUID] = {}
    truncated = False
    for a in ordered:
        if len(a.source_event_ids) >= SOURCE_EVENT_ID_CAP:
            truncated = True
        for raw in a.source_event_ids:
            resolved = lake_event_id(raw)
            # First writer wins: an event folded onto two alerts is shown
            # under the first that claimed it rather than duplicated.
            if resolved and resolved not in owner:
                owner[resolved] = a.id

    events_available = True
    unavailable_reason: str | None = None
    event_entries: list[TimelineEntry] = []

    if owner:
        try:
            result = await lake_query(
                _EVENTS_SQL,
                params={
                    "tenant_id": tenant_id,
                    "event_ids": [uuid.UUID(e) for e in owner],
                    "limit": max_events,
                },
            )
        except LakeQueryNotConfiguredError as exc:
            # The reason is the condition, not the driver's words for it.
            # `LakeQueryNotConfiguredError` exists so the API answers
            # "not configured" rather than leaking a driver import or a
            # client-construction failure to the caller, and one of the
            # three places it is raised interpolates the underlying
            # exception — which can carry the configured host. Say what
            # is true and log the detail for the operator instead.
            logger.warning("incident_timeline.lake_not_configured detail=%s", str(exc)[:200])
            events_available = False
            unavailable_reason = (
                "The event lake is not configured on this deployment, so the raw events behind these alerts cannot be shown."
            )
        except Exception as exc:  # noqa: BLE001 — a lake outage must not lose the alerts
            logger.warning("incident_timeline.lake_read_failed error=%s", str(exc)[:200])
            events_available = False
            unavailable_reason = (
                "The event lake did not answer, so the raw events behind these alerts "
                "are not shown. This is a read failure, not an empty result."
            )
        else:
            event_entries = _entries_from_rows(result, owner)

    entries.extend(event_entries)
    entries.sort(key=lambda e: (e.at, 0 if e.kind == "event" else 1))

    note = ""
    if truncated:
        note = (
            f"At least one alert reached the {SOURCE_EVENT_ID_CAP}-event provenance "
            f"ceiling, so more events contributed to this incident than are listed."
        )

    return IncidentTimeline(
        entries=entries,
        alert_count=len(ordered),
        event_count=len(event_entries),
        events_available=events_available,
        events_unavailable_reason=unavailable_reason,
        source_event_ids_truncated=truncated,
        truncation_note=note,
    )


def _entries_from_rows(result: Any, owner: dict[str, uuid.UUID]) -> list[TimelineEntry]:
    """Lake rows → timeline entries, skipping anything unreadable.

    A row whose timestamp cannot be read is dropped rather than given an
    invented position in the chronology; it would otherwise sort to the
    epoch and read as the first thing that happened.
    """
    columns = [str(c) for c in getattr(result, "columns", [])]
    index = {name: i for i, name in enumerate(columns)}
    out: list[TimelineEntry] = []
    for row in getattr(result, "rows", []):

        def cell(name: str, _row: Any = row) -> Any:
            position = index.get(name)
            return _row[position] if position is not None and position < len(_row) else None

        at = cell("event_time")
        if not isinstance(at, datetime):
            continue
        event_id = str(cell("event_id") or "")
        action = cell("action")
        out.append(
            TimelineEntry(
                kind="event",
                at=_utc(at),
                title=str(action or "event"),
                alert_id=owner.get(event_id),
                action=str(action) if action else None,
                user_name=_text(cell("user_name")),
                hostname=_text(cell("src_hostname")),
                source_ip=_text(cell("source_ip")),
            )
        )
    return out


def _utc(value: datetime) -> datetime:
    """Every timestamp in the chronology on one clock.

    The lake's ``event_time`` is ``DateTime64(3, 'UTC')`` and the driver
    hands it back **naive**, while an alert's ``event_time`` arrives from
    Postgres timezone-aware. Sorting the two together raises
    ``TypeError: can't compare offset-naive and offset-aware datetimes`` —
    which no stubbed-lake test can reach, because a stub returns whatever
    the test constructed. A naive lake value is UTC by the column's own
    definition, so it is labelled rather than converted.
    """
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _text(value: Any) -> str | None:
    """Lake String columns default to '' — an empty string is absence."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None
