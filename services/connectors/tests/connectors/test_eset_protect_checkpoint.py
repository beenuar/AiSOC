"""The ESET window opens at the cursor, so a late-uploading endpoint is swept (#1890).

ESET filters `/v1/detections` on `occurTime` — the moment the detection
happened on the endpoint. A laptop that spent the night offline uploads its
detections the next morning stamped with last night's times, inside windows
already polled; the clock-derived `[now - since, now]` succeeded on every
one of those polls and would never request the backlog. These tests drive
the real connector and the real checkpoint machinery with only the HTTP
transport faked, mirroring `test_wazuh_checkpoint_backfill.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.connectors.test_eset_protect import Vendor, _detection, _page, _serving


def _requested_lookback_seconds(vendor: Vendor) -> float:
    """The window the last detections request actually asked for."""
    request = vendor.on("/v1/detections")[-1]
    start = datetime.fromisoformat(request.url.params["startTime"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(request.url.params["endTime"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


@pytest.mark.asyncio
async def test_no_cursor_keeps_todays_window() -> None:
    """First poll: the request covers since_seconds, not the lookback cap."""
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint(None)

    await connector.fetch_alerts(since_seconds=300)

    # The request adds one second because endTime is exclusive.
    assert 300 <= _requested_lookback_seconds(vendor) <= 302


@pytest.mark.asyncio
async def test_the_window_opens_at_the_cursor_and_sweeps_the_backlog() -> None:
    """A cursor eight hours back widens the request and the backlog is raised."""
    eight_hours = 8 * 3600
    cursor_time = datetime.now(UTC) - timedelta(seconds=eight_hours)
    backlog = _detection("11111111-1111-1111-1111-111111111111", occurred=eight_hours - 600)

    vendor = Vendor(detections=_serving(_page([backlog])))
    connector = vendor.connector()
    connector.set_checkpoint({"time": cursor_time.isoformat(), "id": "22222222-2222-2222-2222-222222222222"})

    out = await connector.fetch_alerts(since_seconds=300)

    requested = _requested_lookback_seconds(vendor)
    assert eight_hours <= requested <= eight_hours + connector.checkpoint_overlap_seconds + 32, (
        f"the request asked for {requested}s; the cursor sits {eight_hours}s back, so the window must open there"
    )
    assert [event["external_id"] for event in out] == ["11111111-1111-1111-1111-111111111111"], (
        "the late-uploaded detection inside an already-polled window was not raised"
    )


@pytest.mark.asyncio
async def test_a_row_at_the_cursor_is_dropped_as_already_read() -> None:
    """The overlap re-reads the row the cursor names; apply_checkpoint drops it."""
    cursor_time = datetime.now(UTC) - timedelta(seconds=3600)
    already_read = {
        **_detection("33333333-3333-3333-3333-333333333333"),
        "occurTime": cursor_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    vendor = Vendor(detections=_serving(_page([already_read])))
    connector = vendor.connector()
    connector.set_checkpoint({"time": cursor_time.strftime("%Y-%m-%dT%H:%M:%SZ"), "id": "33333333-3333-3333-3333-333333333333"})

    out = await connector.fetch_alerts(since_seconds=300)

    assert out == [], "the row the cursor itself names was re-raised instead of deduplicated"


@pytest.mark.asyncio
async def test_the_staged_advance_lands_on_the_newest_occur_time_read() -> None:
    """The cursor advances to the newest occurTime, not the wall clock."""
    newest = _detection("44444444-4444-4444-4444-444444444444", occurred=120)
    older = _detection("55555555-5555-5555-5555-555555555555", occurred=240)

    vendor = Vendor(detections=_serving(_page([older, newest])))
    connector = vendor.connector()
    connector.set_checkpoint(None)

    out = await connector.fetch_alerts(since_seconds=300)
    assert len(out) == 2

    staged = connector.get_checkpoint()
    assert staged is not None, "a poll that read rows must stage a cursor advance"
    staged_time = datetime.fromisoformat(str(staged["time"]).replace("Z", "+00:00"))
    newest_time = datetime.fromisoformat(str(newest["occurTime"]).replace("Z", "+00:00"))
    assert staged_time == newest_time, f"cursor staged at {staged_time}, newest row read was {newest_time}"
    assert staged["id"] == "44444444-4444-4444-4444-444444444444"


@pytest.mark.asyncio
async def test_growth_is_bounded_by_the_lookback_cap() -> None:
    """An ancient cursor widens to the cap, not to infinity."""
    ancient = datetime.now(UTC) - timedelta(days=30)
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint({"time": ancient.isoformat(), "id": "66666666-6666-6666-6666-666666666666"})

    await connector.fetch_alerts(since_seconds=300)

    requested = _requested_lookback_seconds(vendor)
    cap = connector.max_checkpoint_lookback_seconds
    assert cap <= requested <= cap + connector.checkpoint_overlap_seconds + 32, f"requested {requested}s against a cap of {cap}s"
