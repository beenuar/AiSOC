"""Consecutive polls must cover contiguous time.

Huntress, Cisco Secure Endpoint and Sophos Central each ask the vendor for
the last ``since_seconds`` seconds, with no persisted cursor and no overlap.
That is only lossless if every poll starts exactly one interval after the
last. The scheduler runs polls with ``max_instances=1``, so a poll that
overruns its interval has its next run skipped by APScheduler. The poll after
that then covers one interval later than the poll before the skip, and the
interval between them is never requested.

Each test here runs two polls: the first at T0, the second at T0 + 600 with a
300-second interval, as happens when the run at T0 + 300 is skipped. The
second poll must reach back to T0, the end of the first poll's window. Only
the HTTP transport and the clock are faked. These tests fail on the current
code and are expected to pass once consecutive windows overlap or the
connectors persist a cursor.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest
from app.connectors import cisco_secure_endpoint as cisco_module
from app.connectors import huntress as huntress_module
from app.connectors import sophos_central as sophos_module
from app.connectors.cisco_secure_endpoint import CiscoSecureEndpointConnector
from app.connectors.huntress import HuntressConnector
from app.connectors.sophos_central import SophosCentralConnector

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


def _instant(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


@pytest.mark.asyncio
async def test_cisco_second_poll_reaches_back_to_the_first_polls_window(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, cisco_module, clock)
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"data": [], "metadata": {}})

    transport = httpx.MockTransport(handler)
    await CiscoSecureEndpointConnector("nam", "id", "key", transport=transport).fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    await CiscoSecureEndpointConnector("nam", "id", "key", transport=transport).fetch_alerts(since_seconds=INTERVAL)

    second_start = _instant(requests[-1].url.params["start_date"])
    assert second_start <= T0, (
        f"the second poll asked from {second_start.isoformat()}; the first poll ended at {T0.isoformat()}, "
        "so events in between were never requested"
    )


@pytest.mark.asyncio
async def test_sophos_second_poll_reaches_back_to_the_first_polls_window(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    monkeypatch.setattr(sophos_module, "time", SimpleNamespace(time=lambda: clock.moment.timestamp()))
    alert_requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "id.sophos.com":
            return httpx.Response(200, json={"access_token": "token", "expires_in": 3600})
        if host == "api.central.sophos.com" and request.url.path == "/whoami/v1":
            return httpx.Response(
                200,
                json={
                    "id": "57ca9a6b-885f-4e36-95ec-290548c26059",
                    "idType": "tenant",
                    "apiHosts": {"dataRegion": "https://api-eu01.central.sophos.com"},
                },
            )
        alert_requests.append(request)
        return httpx.Response(200, json={"items": [], "has_more": False, "next_cursor": ""})

    transport = httpx.MockTransport(handler)
    await SophosCentralConnector("id", "secret", transport=transport).fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    await SophosCentralConnector("id", "secret", transport=transport).fetch_alerts(since_seconds=INTERVAL)

    second_start = datetime.fromtimestamp(int(alert_requests[-1].url.params["from_date"]), UTC)
    assert second_start <= T0, (
        f"the second poll asked from {second_start.isoformat()}; the first poll ended at {T0.isoformat()}, "
        "so alerts in between were never requested"
    )


@pytest.mark.asyncio
async def test_huntress_report_sent_in_the_gap_is_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _Clock(T0)
    _freeze_datetime(monkeypatch, huntress_module, clock)
    gap_report = {
        "id": 9001,
        "subject": "Foothold on WIN-FIN-01",
        "sent_at": (T0 + timedelta(seconds=100)).isoformat().replace("+00:00", "Z"),
        "updated_at": (T0 + timedelta(seconds=100)).isoformat().replace("+00:00", "Z"),
        "status": "sent",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/incident_reports":
            return httpx.Response(200, json={"incident_reports": [gap_report] if clock.moment == SECOND_POLL_AT else [], "pagination": {}})
        return httpx.Response(404, json={})

    transport = httpx.MockTransport(handler)
    await HuntressConnector("key", "secret", transport=transport).fetch_alerts(since_seconds=INTERVAL)
    clock.moment = SECOND_POLL_AT
    out = await HuntressConnector("key", "secret", transport=transport).fetch_alerts(since_seconds=INTERVAL)

    assert [event["external_id"] for event in out] == ["9001"], (
        "a report delivered 100 seconds after the first poll began was never raised: no poll's window covered it"
    )
