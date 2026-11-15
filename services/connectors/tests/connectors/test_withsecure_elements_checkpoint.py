"""The WithSecure Elements window opens at the createdTimestamp cursor.

The BCD list is read oldest first, 50 a page and at most 25 pages a poll, so a
burst of BCDs can outrun one poll; and a run of failed polls leaves a gap the
next clock-derived window would slide past. Opening the request at the
persisted cursor catches both up on the next successful poll. These tests
drive the real connector and the real checkpoint machinery with only the HTTP
transport faked, mirroring `test_eset_protect_checkpoint.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.connectors.test_withsecure_elements import Vendor, _incident, _no_detections, _page, _serving


def _requested_lookback_seconds(vendor: Vendor) -> float:
    """The window the last BCD request actually asked for."""
    request = vendor.on("/incidents/v1/incidents")[-1]
    start = datetime.fromisoformat(request.url.params["createdTimestampStart"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(request.url.params["createdTimestampEnd"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@pytest.mark.asyncio
async def test_no_cursor_keeps_todays_window() -> None:
    """First poll: the request covers since_seconds, not the lookback cap."""
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint(None)

    await connector.fetch_alerts(since_seconds=300)

    assert _requested_lookback_seconds(vendor) == 300


@pytest.mark.asyncio
async def test_the_window_opens_at_the_cursor_and_catches_up() -> None:
    """A cursor eight hours back widens the request and the missed BCD is raised."""
    eight_hours = 8 * 3600
    cursor_time = datetime.now(UTC) - timedelta(seconds=eight_hours)
    missed = _incident("11111111-1111-4111-8111-111111111111", created=eight_hours - 600)

    vendor = Vendor(_serving(_page([missed])), detections=_no_detections)
    connector = vendor.connector()
    connector.set_checkpoint({"time": _stamp(cursor_time), "id": "22222222-2222-4222-8222-222222222222"})

    out = await connector.fetch_alerts(since_seconds=300)

    requested = _requested_lookback_seconds(vendor)
    assert eight_hours <= requested <= eight_hours + connector.checkpoint_overlap_seconds + 2, (
        f"the request asked for {requested}s; the cursor sits {eight_hours}s back, so the window must open there"
    )
    assert [event["external_id"] for event in out] == ["11111111-1111-4111-8111-111111111111"]


@pytest.mark.asyncio
async def test_a_bcd_at_the_cursor_is_dropped_as_already_read() -> None:
    """The overlap re-reads the BCD the cursor names; apply_checkpoint drops it."""
    cursor_time = datetime.now(UTC) - timedelta(seconds=3600)
    already_read = {**_incident("33333333-3333-4333-8333-333333333333"), "createdTimestamp": _stamp(cursor_time)}
    vendor = Vendor(_serving(_page([already_read])), detections=_no_detections)
    connector = vendor.connector()
    connector.set_checkpoint({"time": _stamp(cursor_time), "id": "33333333-3333-4333-8333-333333333333"})

    out = await connector.fetch_alerts(since_seconds=300)

    assert out == [], "the BCD the cursor itself names was re-raised instead of deduplicated"
    assert vendor.on("/incidents/v1/detections") == [], "a BCD dropped by the cursor was still enriched"


@pytest.mark.asyncio
async def test_the_staged_advance_lands_on_the_newest_creation_read() -> None:
    """The cursor advances to the newest createdTimestamp, not the wall clock."""
    older = _incident("55555555-5555-4555-8555-555555555555", created=240)
    newest = _incident("44444444-4444-4444-8444-444444444444", created=120)

    vendor = Vendor(_serving(_page([older, newest])), detections=_no_detections)
    connector = vendor.connector()
    connector.set_checkpoint(None)

    out = await connector.fetch_alerts(since_seconds=300)
    assert len(out) == 2

    staged = connector.get_checkpoint()
    assert staged == {"time": newest["createdTimestamp"], "id": "44444444-4444-4444-8444-444444444444"}


@pytest.mark.asyncio
async def test_a_suppressed_bcd_does_not_advance_the_cursor() -> None:
    """Only raised BCDs move the cursor, so a suppressed one is never what it rests on."""
    raised = _incident("66666666-6666-4666-8666-666666666666", created=240)
    merged = _incident("77777777-7777-4777-8777-777777777777", created=120, status="closed", resolution="merged")

    vendor = Vendor(_serving(_page([raised, merged])), detections=_no_detections)
    connector = vendor.connector()
    connector.set_checkpoint(None)

    await connector.fetch_alerts(since_seconds=300)

    staged = connector.get_checkpoint()
    assert staged is not None and staged["id"] == "66666666-6666-4666-8666-666666666666"


@pytest.mark.asyncio
async def test_growth_is_bounded_by_the_lookback_cap() -> None:
    """An ancient cursor widens to the cap, not to infinity."""
    ancient = datetime.now(UTC) - timedelta(days=30)
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint({"time": _stamp(ancient), "id": "88888888-8888-4888-8888-888888888888"})

    await connector.fetch_alerts(since_seconds=300)

    assert _requested_lookback_seconds(vendor) == connector.max_checkpoint_lookback_seconds
