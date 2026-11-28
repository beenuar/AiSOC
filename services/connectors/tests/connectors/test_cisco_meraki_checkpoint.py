"""The Cisco Meraki window opens at the `ts` cursor.

Security events are read oldest first, 1000 a page and at most 25 pages a
poll, so a burst can outrun one poll, a 429 can cut one short, and a run of
failed polls leaves a gap the next clock-derived window would slide past.
Opening the request at the persisted cursor catches all three up on the next
successful poll. These tests drive the real connector and the real checkpoint
machinery with only the HTTP transport faked, mirroring
`test_withsecure_elements_checkpoint.py`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from tests.connectors.test_cisco_meraki import _FILE, _IDS, _TLS, Vendor, _page, _serving


def _requested_lookback_seconds(vendor: Vendor) -> float:
    """The window the last request actually asked for."""
    params = vendor.requests[-1].url.params
    start = datetime.fromisoformat(params["t0"].replace("Z", "+00:00"))
    end = datetime.fromisoformat(params["t1"].replace("Z", "+00:00"))
    return (end - start).total_seconds()


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _ago(seconds: int) -> str:
    return _stamp(datetime.now(UTC) - timedelta(seconds=seconds))


@pytest.mark.asyncio
async def test_no_cursor_keeps_the_overlapped_clock_window() -> None:
    """First poll: two intervals (#1971), not the lookback cap."""
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint(None)

    await connector.fetch_alerts(since_seconds=300)

    assert _requested_lookback_seconds(vendor) == 600


@pytest.mark.asyncio
async def test_the_window_opens_at_the_cursor_and_catches_up() -> None:
    """A cursor eight hours back widens the request and the missed event is raised."""
    eight_hours = 8 * 3600
    missed = {**_IDS, "ts": _ago(eight_hours - 600)}

    vendor = Vendor(_serving(_page([missed])))
    connector = vendor.connector()
    connector.set_checkpoint({"time": _ago(eight_hours), "id": "f" * 32})

    out = await connector.fetch_alerts(since_seconds=300)

    requested = _requested_lookback_seconds(vendor)
    assert eight_hours <= requested <= eight_hours + connector.checkpoint_overlap_seconds + 2, (
        f"the request asked for {requested}s; the cursor sits {eight_hours}s back, so the window must open there"
    )
    assert [event["created_at"] for event in out] == [missed["ts"]]


@pytest.mark.asyncio
async def test_an_event_the_overlap_re_reads_is_raised_once() -> None:
    """The second poll re-reads the first poll's event; its digest matches the cursor and it is dropped."""
    event = {**_IDS, "ts": _ago(100)}

    first = Vendor(_serving(_page([event]))).connector()
    assert len(await first.fetch_alerts(since_seconds=300)) == 1
    staged = first.get_checkpoint()
    assert staged is not None

    second = Vendor(_serving(_page([event]))).connector()
    second.set_checkpoint(staged)
    assert await second.fetch_alerts(since_seconds=300) == [], "the event the overlap re-read was raised a second time"


@pytest.mark.asyncio
async def test_the_staged_advance_lands_on_the_newest_event_read() -> None:
    """The cursor advances to the newest detection time, not the wall clock."""
    older = {**_IDS, "ts": _ago(240)}
    newest = {**_FILE, "ts": _ago(120)}

    vendor = Vendor(_serving(_page([older, newest])))
    connector = vendor.connector()
    connector.set_checkpoint(None)

    out = await connector.fetch_alerts(since_seconds=300)
    assert len(out) == 2

    staged = connector.get_checkpoint()
    (newest_out,) = [event for event in out if event["event_type"] == "File Scanned"]
    assert staged == {"time": newest["ts"], "id": newest_out["external_id"]}


@pytest.mark.asyncio
async def test_an_unrated_event_does_not_advance_the_cursor() -> None:
    """Only raised events move the cursor, so a skipped one is never what it rests on."""
    raised = {**_IDS, "ts": _ago(240)}
    skipped = {**_TLS, "ts": _ago(120)}

    vendor = Vendor(_serving(_page([raised, skipped])))
    connector = vendor.connector()
    connector.set_checkpoint(None)

    await connector.fetch_alerts(since_seconds=300)

    staged = connector.get_checkpoint()
    assert staged is not None and staged["time"] == raised["ts"]


@pytest.mark.asyncio
async def test_growth_is_bounded_by_the_lookback_cap() -> None:
    """An ancient cursor widens to the cap, not to infinity."""
    vendor = Vendor()
    connector = vendor.connector()
    connector.set_checkpoint({"time": _stamp(datetime.now(UTC) - timedelta(days=30)), "id": "f" * 32})

    await connector.fetch_alerts(since_seconds=300)

    assert _requested_lookback_seconds(vendor) == connector.max_checkpoint_lookback_seconds
