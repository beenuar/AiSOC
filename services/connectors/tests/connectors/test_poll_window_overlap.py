"""Consecutive polls must cover contiguous time (#1971).

Huntress, Cisco Secure Endpoint and Sophos Central each asked the vendor for
the last ``since_seconds`` seconds, with no persisted cursor and no overlap.
The scheduler runs polls with ``max_instances=1``, so a poll that overruns
its interval has its next run skipped, and the poll after that opens one
interval later than the poll before the skip. The interval in between was
never requested.

The fix is two parts. Each connector now asks for two intervals instead of
one, so a single skipped run is covered with no cursor needed, and each
declares a persisted cursor (as ESET and WithSecure do), so a longer gap is
covered by a window that opens at the cursor. ``apply_checkpoint`` drops the
rows the overlap re-reads, so the extra read costs a re-request, never a
lost row, and a row re-read inside the overlap is raised once.

Each test here runs two polls with only the HTTP transport and the clock
faked, and the cursor tests seed the checkpoint the way the scheduler does
between polls.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from app.connectors import cisco_secure_endpoint as cisco_module
from app.connectors import huntress as huntress_module
from app.connectors import sophos_central as sophos_module

from tests.connectors.test_cisco_secure_endpoint import _EVENT as _CISCO_EVENT
from tests.connectors.test_cisco_secure_endpoint import Vendor as CiscoVendor
from tests.connectors.test_cisco_secure_endpoint import _page as _cisco_page
from tests.connectors.test_huntress import _REPORT as _HUNTRESS_REPORT
from tests.connectors.test_huntress import Vendor as HuntressVendor
from tests.connectors.test_huntress import _page as _huntress_page
from tests.connectors.test_sophos_central import _ALERT as _SOPHOS_ALERT
from tests.connectors.test_sophos_central import Vendor as SophosVendor
from tests.connectors.test_sophos_central import _page as _sophos_page

T0 = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
INTERVAL = 300
SECOND_POLL_AT = T0 + timedelta(seconds=2 * INTERVAL)


class _Clock:
    """A frozen clock, moved between polls."""

    def __init__(self, moment: datetime) -> None:
        self.moment = moment


def _freeze_datetime(monkeypatch: pytest.MonkeyPatch, module: object, clock: _Clock) -> None:
    class Frozen(datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ANN001 - mirrors datetime.now
            return clock.moment if tz is not None else clock.moment.replace(tzinfo=None)

    monkeypatch.setattr(module, "datetime", Frozen)


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


def _instant(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


@pytest.mark.asyncio
async def test_cisco_second_poll_reaches_back_over_a_skipped_run(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, cisco_module, clock)
    vendor = CiscoVendor()

    await vendor.connector().fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    await vendor.connector().fetch_alerts(since_seconds=INTERVAL)

    second_start = _instant(vendor.requests[-1].url.params["start_date"])
    assert second_start <= T0, (
        f"the second poll asked from {second_start.isoformat()}; the first poll ended at {T0.isoformat()}, "
        "so events in between were never requested"
    )


@pytest.mark.asyncio
async def test_cisco_a_row_in_the_overlap_is_raised_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The overlap re-reads the previous interval; the cursor seeded from
    the first poll is what keeps the row from being raised twice."""
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, cisco_module, clock)
    event = {**_CISCO_EVENT, "id": 7000000000000000001, "date": _iso(T0 - timedelta(seconds=100))}
    vendor = CiscoVendor(lambda request: httpx.Response(200, json=_cisco_page([event])))

    first = vendor.connector()
    out_first = await first.fetch_alerts(since_seconds=INTERVAL)
    assert [row["external_id"] for row in out_first] == ["7000000000000000001"]
    staged = first.get_checkpoint()
    assert staged is not None and staged["id"] == "7000000000000000001"

    clock.moment = T0 + timedelta(seconds=INTERVAL)
    second = vendor.connector()
    second.set_checkpoint(staged)
    out_second = await second.fetch_alerts(since_seconds=INTERVAL)

    assert out_second == [], "the row the overlap re-read was raised a second time"


@pytest.mark.asyncio
async def test_sophos_second_poll_reaches_back_over_a_skipped_run(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, sophos_module, clock)
    monkeypatch.setattr(sophos_module, "time", SimpleNamespace(time=lambda: clock.moment.timestamp()))
    vendor = SophosVendor()

    await vendor.connector().fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    await vendor.connector().fetch_alerts(since_seconds=INTERVAL)

    second_start = datetime.fromtimestamp(int(vendor.alert_requests()[-1].url.params["from_date"]), UTC)
    assert second_start <= T0, (
        f"the second poll asked from {second_start.isoformat()}; the first poll ended at {T0.isoformat()}, "
        "so alerts in between were never requested"
    )


@pytest.mark.asyncio
async def test_sophos_a_row_in_the_overlap_is_raised_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """The overlap re-reads the previous interval; the cursor seeded from
    the first poll is what keeps the alert from being raised twice."""
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, sophos_module, clock)
    monkeypatch.setattr(sophos_module, "time", SimpleNamespace(time=lambda: clock.moment.timestamp()))
    alert = {
        **_SOPHOS_ALERT,
        "id": "alert-overlap-1",
        "created_at": _iso(T0 - timedelta(seconds=100)),
        "when": _iso(T0 - timedelta(seconds=100)),
    }
    vendor = SophosVendor(lambda request: httpx.Response(200, json=_sophos_page([alert], has_more=False)))

    first = vendor.connector()
    out_first = await first.fetch_alerts(since_seconds=INTERVAL)
    assert [row["external_id"] for row in out_first] == ["alert-overlap-1"]
    staged = first.get_checkpoint()
    assert staged is not None and staged["id"] == "alert-overlap-1"

    clock.moment = T0 + timedelta(seconds=INTERVAL)
    second = vendor.connector()
    second.set_checkpoint(staged)
    out_second = await second.fetch_alerts(since_seconds=INTERVAL)

    assert out_second == [], "the alert the overlap re-read was raised a second time"


@pytest.mark.asyncio
async def test_huntress_a_report_sent_in_the_gap_is_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, huntress_module, clock)
    gap_report = {
        **_HUNTRESS_REPORT,
        "id": 9002,
        "sent_at": _iso(T0 + timedelta(seconds=250)),
        "updated_at": _iso(T0 + timedelta(seconds=250)),
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/incident_reports":
            return httpx.Response(200, json=_huntress_page([gap_report] if clock.moment == SECOND_POLL_AT else []))
        return httpx.Response(404, json={})

    vendor = HuntressVendor(handler)
    await vendor.connector().fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    out = await vendor.connector().fetch_alerts(since_seconds=INTERVAL)

    assert [event["external_id"] for event in out] == ["9002"], (
        "a report delivered 250 seconds after the first poll began was never raised: no poll's window covered it"
    )


@pytest.mark.asyncio
async def test_huntress_a_cursor_hours_back_widens_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The overlap covers one skipped run; a cursor hours back covers a
    longer gap, because the window opens at the cursor rather than the
    clock."""
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, huntress_module, clock)
    late_report = {
        **_HUNTRESS_REPORT,
        "id": 9003,
        "sent_at": _iso(T0 - timedelta(seconds=3500)),
        "updated_at": _iso(T0 - timedelta(seconds=3500)),
    }
    vendor = HuntressVendor(lambda request: httpx.Response(200, json=_huntress_page([late_report])))

    connector = vendor.connector()
    connector.set_checkpoint({"time": _iso(T0 - timedelta(seconds=3600)), "id": "9001"})
    out = await connector.fetch_alerts(since_seconds=INTERVAL)

    assert [event["external_id"] for event in out] == ["9003"], (
        "a report delivered inside a window the cursor should have opened was never raised"
    )
