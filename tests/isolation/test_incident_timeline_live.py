"""The incident timeline against both real stores.

The unit suite proves the shape of the chronology with a stubbed lake.
What it cannot prove is the thing most likely to be wrong: that the join
between ``alerts.source_event_ids`` and ClickHouse ``aisoc.raw_events``
actually matches rows on a real deployment.

It is a join across two databases through an id that is *rewritten in
transit*. ``LakeWriter`` stores ``event_id`` as the ingest id when that id
is already a UUID and as a UUIDv5 derivation of it otherwise, while the
alert keeps the ingest id verbatim. A reader that compares the stored
strings matches nothing for every non-UUID producer — and matches nothing
*silently*, as an empty result indistinguishable from a quiet estate. So
this suite seeds the lake the way fusion seeds it, both ways, and asserts
the events come back.

Tenant isolation is asserted in the same breath: a second tenant's event
carrying the same ingest id must not appear in the first tenant's
timeline.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_CLICKHOUSE_HOST", "").strip(),
        reason="ISOLATION_CLICKHOUSE_HOST is not set; this suite needs live infrastructure",
    ),
]

if os.environ.get("ISOLATION_CLICKHOUSE_HOST"):
    os.environ.setdefault("CLICKHOUSE_HOST", os.environ["ISOLATION_CLICKHOUSE_HOST"])
    os.environ.setdefault("CLICKHOUSE_PORT", os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    os.environ.setdefault("CLICKHOUSE_USER", os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"))
    os.environ.setdefault("CLICKHOUSE_PASSWORD", os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""))
    os.environ.setdefault("CLICKHOUSE_DATABASE", "aisoc")

_API = Path(__file__).resolve().parents[2] / "services" / "api"
import sys  # noqa: E402

if str(_API) not in sys.path:
    sys.path.insert(0, str(_API))

from app.services.incident_timeline import (  # noqa: E402
    TimelineAlert,
    build_incident_timeline,
)


def _as_the_lake_writer_stores_it(ingest_id: str) -> uuid.UUID:
    """The seed side of the join, derived independently.

    Deliberately NOT `incident_timeline.lake_event_id`: if the fixture and
    the reader share one helper, breaking the helper breaks both sides
    together and the suite still passes. Re-deriving here from the lake
    writer's own namespace means the reader has to agree with the writer,
    not merely with itself.
    """
    try:
        return uuid.UUID(ingest_id)
    except ValueError:
        namespace = uuid.uuid5(uuid.NAMESPACE_URL, "https://aisoc.dev/fusion/lake/event-id")
        return uuid.uuid5(namespace, f"ingest:{ingest_id}")


TENANT = uuid.UUID("33333333-3333-3333-3333-333333333333")
OTHER_TENANT = uuid.UUID("44444444-4444-4444-4444-444444444444")

#: One of each, because the derivation only bites the second kind.
UUID_INGEST_ID = "8f14e45f-ceea-467a-9f1a-4a1b2c3d4e5f"
OPAQUE_INGEST_ID = "evt-crowdstrike-7781"

T0 = datetime(2026, 5, 14, 8, 0, 0)


def _client():  # noqa: ANN202
    driver = pytest.importorskip("clickhouse_driver")
    return driver.Client(
        host=os.environ["ISOLATION_CLICKHOUSE_HOST"],
        port=int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000")),
        user=os.environ.get("ISOLATION_CLICKHOUSE_USER", "default"),
        password=os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", ""),
    )


@pytest.fixture(scope="module")
def lake():
    """The product's own schema, seeded the way the lake writer seeds it.

    The API's settings are bound to this ClickHouse explicitly rather than
    through the environment. `Settings` reads a `.env` file when one is
    present, and a developer running this against a local stack has one —
    so env bridging alone silently points the suite at whichever lake that
    file names, and the failure looks like a product defect.
    """
    from app.core.config import settings

    settings.CLICKHOUSE_HOST = os.environ["ISOLATION_CLICKHOUSE_HOST"]
    settings.CLICKHOUSE_PORT = int(os.environ.get("ISOLATION_CLICKHOUSE_PORT", "9000"))
    settings.CLICKHOUSE_USER = os.environ.get("ISOLATION_CLICKHOUSE_USER", "default")
    settings.CLICKHOUSE_PASSWORD = os.environ.get("ISOLATION_CLICKHOUSE_PASSWORD", "")
    settings.CLICKHOUSE_DATABASE = "aisoc"

    client = _client()
    root = Path(os.environ.get("ISOLATION_REPO_ROOT", "."))
    ddl = (root / "services" / "api" / "clickhouse" / "001_init.sql").read_text(encoding="utf-8")
    lines = [ln for ln in ddl.splitlines() if not ln.strip().startswith("--")]
    for statement in (s.strip() for s in "\n".join(lines).split(";")):
        if statement:
            client.execute(statement)

    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")
    client.execute(
        "INSERT INTO aisoc.raw_events "
        "(event_id, tenant_id, event_time, class_uid, category_uid, severity_id, "
        "severity, src_hostname, user_name, action, raw_payload) VALUES",
        [
            # Written exactly as LakeWriter would: the id it stores for each
            # ingest id, not the ingest id itself.
            (
                _as_the_lake_writer_stores_it(UUID_INGEST_ID),
                TENANT,
                T0 + timedelta(minutes=2),
                2001,
                2,
                4,
                "high",
                "WIN-DC01",
                "svc-backup",
                "process_create",
                "{}",
            ),
            (
                _as_the_lake_writer_stores_it(OPAQUE_INGEST_ID),
                TENANT,
                T0 + timedelta(minutes=4),
                2001,
                2,
                4,
                "high",
                "WIN-DC01",
                "svc-backup",
                "lsass_access",
                "{}",
            ),
            # Same opaque ingest id, different tenant. Must never surface.
            (
                _as_the_lake_writer_stores_it(OPAQUE_INGEST_ID),
                OTHER_TENANT,
                T0 + timedelta(minutes=3),
                2001,
                2,
                4,
                "high",
                "OTHER-HOST",
                "other-user",
                "other_tenant_action",
                "{}",
            ),
        ],
    )
    yield client
    client.execute("TRUNCATE TABLE IF EXISTS aisoc.raw_events")


def _alert(ids: list[str], *, minutes: int = 10, stage: str | None = None) -> TimelineAlert:
    return TimelineAlert(
        id=uuid.uuid4(),
        title="Credential dumping via LSASS access",
        severity="critical",
        event_time=T0 + timedelta(minutes=minutes),
        status="new",
        incident_id=None,
        chain_id="chain-live" if stage else None,
        chain_position=1 if stage else None,
        chain_stage=stage,
        source_event_ids=ids,
        connector_type="crowdstrike_falcon",
        mitre_techniques=["T1003"],
    )


async def _timeline(alerts, tenant=TENANT):  # noqa: ANN001, ANN202
    from app.db.clickhouse import execute_lake_query

    return await build_incident_timeline(alerts=alerts, tenant_id=tenant, lake_query=execute_lake_query)


async def test_a_uuid_ingest_id_finds_its_event(lake) -> None:  # noqa: ANN001
    timeline = await _timeline([_alert([UUID_INGEST_ID])])

    assert timeline.events_available is True
    actions = [e.action for e in timeline.entries if e.kind == "event"]
    assert actions == ["process_create"]


async def test_an_opaque_ingest_id_finds_its_event_through_the_derivation(lake) -> None:  # noqa: ANN001
    """The regression that matters: comparing the stored strings directly
    returns nothing here, and returns it as a plausible empty result."""
    timeline = await _timeline([_alert([OPAQUE_INGEST_ID])])

    assert timeline.events_available is True
    actions = [e.action for e in timeline.entries if e.kind == "event"]
    assert actions == ["lsass_access"], (
        "the lake rewrites a non-UUID ingest id into a UUIDv5; a reader that does not mirror that derivation silently matches no rows"
    )


async def test_events_and_alerts_interleave_in_real_time_order(lake) -> None:  # noqa: ANN001
    timeline = await _timeline([_alert([UUID_INGEST_ID, OPAQUE_INGEST_ID], minutes=10)])

    kinds = [e.kind for e in timeline.entries]
    assert kinds == ["event", "event", "alert"], kinds
    assert [e.at for e in timeline.entries] == sorted(e.at for e in timeline.entries)


async def test_another_tenants_event_never_enters_this_timeline(lake) -> None:  # noqa: ANN001
    """Both tenants hold an event under the same ingest id, so the only
    thing keeping them apart is the tenant predicate."""
    timeline = await _timeline([_alert([OPAQUE_INGEST_ID])])

    actions = [e.action for e in timeline.entries if e.kind == "event"]
    assert "other_tenant_action" not in actions
    assert len(actions) == 1


async def test_every_returned_event_is_attributed_to_its_alert(lake) -> None:  # noqa: ANN001
    alert = _alert([UUID_INGEST_ID, OPAQUE_INGEST_ID])
    timeline = await _timeline([alert])

    events = [e for e in timeline.entries if e.kind == "event"]
    assert events
    assert all(e.alert_id == alert.id for e in events)


async def test_an_alert_naming_an_event_the_lake_does_not_hold_is_not_an_error(lake) -> None:  # noqa: ANN001
    """A purge or a retention drop removes the event, not the alert."""
    timeline = await _timeline([_alert(["evt-this-was-purged"])])

    assert timeline.events_available is True, "the lake answered; it simply had no row"
    assert [e.kind for e in timeline.entries] == ["alert"]
    assert timeline.event_count == 0


async def test_the_chain_stage_survives_the_round_trip(lake) -> None:  # noqa: ANN001
    timeline = await _timeline([_alert([UUID_INGEST_ID], stage="credential-access")])

    alert_entry = next(e for e in timeline.entries if e.kind == "alert")
    assert alert_entry.chain_stage == "credential-access"
    assert alert_entry.chain_position == 1
