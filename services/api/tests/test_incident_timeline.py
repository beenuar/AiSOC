"""One chronology for a case: its alerts, and the events behind them.

Every timeline surface in the tree is single-granularity. The alert rail
shows six *workflow* events; the case timeline shows status changes and
"Alert linked: …" markers stamped at ingest time rather than event time;
the attack chain shows ≤50 alerts ranked by relevance; the investigator
report shows ≤5 alert metadata rows. None of them shows what actually
happened: the alerts of an incident interleaved with the raw events that
produced them, in the order they occurred.

The data to do it has been there all along — ``aisoc_cases.alert_ids`` →
``alerts`` → ``alerts.source_event_ids`` → ClickHouse ``aisoc.raw_events``
— with two traps between the links, and these tests pin both:

* the lake stores ``event_id`` as a UUID *derivation* of the ingest id
  when that id is not already a UUID, so matching the stored strings
  verbatim silently returns nothing for every non-UUID producer;
* ``source_event_ids`` stops at 200 per alert, so "events shown" is not
  "events there were" and the difference has to be published rather than
  quietly dropped.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from app.db.clickhouse import LakeQueryNotConfiguredError
from app.services.incident_timeline import (
    TimelineAlert,
    build_incident_timeline,
    lake_event_id,
)

TENANT = uuid.UUID("00000000-0000-0000-0000-0000000004a1")
T0 = datetime(2026, 5, 14, 8, 0, 0, tzinfo=UTC)


def _alert(
    *,
    offset_minutes: int,
    title: str,
    source_event_ids: list[str] | None = None,
    chain_stage: str | None = None,
    chain_position: int | None = None,
    severity: str = "high",
) -> TimelineAlert:
    return TimelineAlert(
        id=uuid.uuid4(),
        title=title,
        severity=severity,
        event_time=T0 + timedelta(minutes=offset_minutes),
        status="new",
        incident_id=None,
        chain_id="chain-1" if chain_stage else None,
        chain_position=chain_position,
        chain_stage=chain_stage,
        source_event_ids=list(source_event_ids or []),
        connector_type="crowdstrike_falcon",
        mitre_techniques=["T1003"],
    )


class _Lake:
    """A stub lake that records the SQL it was asked for."""

    def __init__(self, rows: list[dict] | None = None, raises: Exception | None = None) -> None:
        self.rows = rows or []
        self.raises = raises
        self.calls: list[tuple[str, dict]] = []

    async def __call__(self, sql: str, *, params: dict | None = None, **_kw):
        self.calls.append((sql, params or {}))
        if self.raises is not None:
            raise self.raises
        columns = ["event_id", "event_time", "action", "user_name", "src_hostname", "source_ip"]
        return type("R", (), {"columns": columns, "rows": [[r.get(c) for c in columns] for r in self.rows]})()


# ── the id mapping, which is the whole join ──────────────────────────────


def test_a_uuid_ingest_id_is_used_verbatim() -> None:
    known = "8f14e45f-ceea-467a-9f1a-4a1b2c3d4e5f"
    assert lake_event_id(known) == known


def test_a_non_uuid_ingest_id_maps_to_the_lake_s_derived_uuid() -> None:
    """The lake writer derives a UUIDv5 for ids that are not UUIDs. Matching
    the raw string instead returns nothing, for every such producer."""
    derived = lake_event_id("evt-phish-001")
    assert derived is not None
    assert uuid.UUID(derived)
    assert derived != "evt-phish-001"
    # Deterministic: the same ingest id always resolves to the same row.
    assert lake_event_id("evt-phish-001") == derived


def test_the_derivation_matches_the_lake_writer_byte_for_byte() -> None:
    """Pinned against fusion's own namespace. If the writer's namespace
    ever changes, this fails rather than the timeline silently emptying."""
    namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://aisoc.dev/fusion/lake/event-id")
    assert lake_event_id("evt-1") == str(uuid.uuid5(namespace, "ingest:evt-1"))


def test_an_empty_id_resolves_to_nothing_rather_than_a_random_uuid() -> None:
    assert lake_event_id("") is None
    assert lake_event_id(None) is None


# ── the chronology ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_alerts_are_ordered_by_event_time_not_by_insertion() -> None:
    alerts = [
        _alert(offset_minutes=30, title="later"),
        _alert(offset_minutes=0, title="earlier"),
    ]
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=_Lake())
    assert [e.title for e in timeline.entries if e.kind == "alert"] == ["earlier", "later"]


@pytest.mark.asyncio
async def test_events_interleave_with_the_alerts_in_real_time_order() -> None:
    alerts = [_alert(offset_minutes=10, title="alert A", source_event_ids=["evt-1"])]
    lake = _Lake(
        rows=[
            {
                "event_id": lake_event_id("evt-1"),
                "event_time": T0 + timedelta(minutes=2),
                "action": "process_create",
                "user_name": "svc",
                "src_hostname": "WIN-1",
                "source_ip": "10.0.0.1",
            }
        ]
    )
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=lake)
    kinds = [e.kind for e in timeline.entries]
    assert kinds == ["event", "alert"], "the event at t+2 precedes the alert at t+10"


@pytest.mark.asyncio
async def test_every_event_names_the_alert_it_belongs_to() -> None:
    alerts = [_alert(offset_minutes=10, title="A", source_event_ids=["evt-1"])]
    lake = _Lake(rows=[{"event_id": lake_event_id("evt-1"), "event_time": T0, "action": "x"}])
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=lake)
    event = next(e for e in timeline.entries if e.kind == "event")
    assert event.alert_id == alerts[0].id


# ── honest states ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_a_lake_that_is_not_configured_reads_as_unavailable_not_as_zero_events() -> None:
    """On the core profile ClickHouse is simply not deployed. 'No events'
    and 'nobody looked' must never render the same."""
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=["evt-1"])]
    lake = _Lake(raises=LakeQueryNotConfiguredError("CLICKHOUSE_HOST is not configured"))

    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=lake)

    assert timeline.events_available is False
    assert "not configured" in (timeline.events_unavailable_reason or "").lower()
    assert not [e for e in timeline.entries if e.kind == "event"]
    # The alerts are still a timeline; losing the lake does not lose them.
    assert [e.kind for e in timeline.entries] == ["alert"]


@pytest.mark.asyncio
async def test_a_lake_that_errors_says_so_rather_than_reporting_an_empty_estate() -> None:
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=["evt-1"])]
    lake = _Lake(raises=RuntimeError("clickhouse refused the connection"))

    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=lake)

    assert timeline.events_available is False
    assert timeline.events_unavailable_reason
    assert timeline.entries, "the alert chronology survives a lake outage"


@pytest.mark.asyncio
async def test_a_lake_with_nothing_to_say_is_available_and_empty() -> None:
    """Distinct from the two above: it answered, and the answer was none."""
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=["evt-1"])]
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=_Lake(rows=[]))

    assert timeline.events_available is True
    assert timeline.events_unavailable_reason is None
    assert not [e for e in timeline.entries if e.kind == "event"]


@pytest.mark.asyncio
async def test_an_alert_at_the_source_event_ceiling_publishes_what_was_omitted() -> None:
    """``source_event_ids`` stops at 200 per alert, so the timeline cannot
    claim to show every event — it says how many it could not name."""
    capped = [f"evt-{i}" for i in range(200)]
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=capped)]

    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=_Lake())

    assert timeline.source_event_ids_truncated is True
    assert "200" in timeline.truncation_note


@pytest.mark.asyncio
async def test_an_uncapped_alert_makes_no_truncation_claim() -> None:
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=["evt-1", "evt-2"])]
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=_Lake())
    assert timeline.source_event_ids_truncated is False
    assert timeline.truncation_note == ""


@pytest.mark.asyncio
async def test_the_lake_read_is_scoped_to_the_tenant() -> None:
    alerts = [_alert(offset_minutes=0, title="A", source_event_ids=["evt-1"])]
    lake = _Lake()
    await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=lake)

    sql, params = lake.calls[0]
    assert "tenant_id" in sql
    assert params["tenant_id"] == TENANT
    # Bound as UUIDs: the columns are UUID-typed and a String comparison
    # is the type mismatch this lake has hit before.
    assert all(isinstance(e, uuid.UUID) for e in params["event_ids"])


@pytest.mark.asyncio
async def test_no_lake_read_is_issued_when_no_alert_names_an_event() -> None:
    """A query with an empty IN list is a round trip that cannot match."""
    lake = _Lake()
    await build_incident_timeline(alerts=[_alert(offset_minutes=0, title="A")], tenant_id=TENANT, lake_query=lake)
    assert lake.calls == []


@pytest.mark.asyncio
async def test_the_chronology_carries_the_chain_stage_for_grouping() -> None:
    alerts = [
        _alert(offset_minutes=0, title="recon", chain_stage="reconnaissance", chain_position=1),
        _alert(offset_minutes=5, title="exec", chain_stage="execution", chain_position=2),
    ]
    timeline = await build_incident_timeline(alerts=alerts, tenant_id=TENANT, lake_query=_Lake())
    stages = [e.chain_stage for e in timeline.entries if e.kind == "alert"]
    assert stages == ["reconnaissance", "execution"]


@pytest.mark.asyncio
async def test_the_timeline_states_what_it_is_rather_than_implying_causation() -> None:
    timeline = await build_incident_timeline(alerts=[_alert(offset_minutes=0, title="A")], tenant_id=TENANT, lake_query=_Lake())
    assert "not" in timeline.disclaimer.lower()
    assert "chronolog" in timeline.disclaimer.lower()
