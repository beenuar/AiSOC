"""A Workspace poll window ends where Google has actually published the data.

Google documents a lag between an event happening and that event being
answerable, and says in terms that it applies to the API this connector uses
— https://support.google.com/a/answer/7061566:

    Lag times indicate the delay between when a log event occurs and when the
    data for that event is available in Admin console reports and log events.
    The following lag times apply to log events data from the audit and
    investigation page, security investigation tool, alert center, and the
    Admin SDK Reports API.

The table is per application, and the spread is three orders of magnitude:
Admin, Drive, Devices and Login events are "Near real time (couple of
minutes)" while **Token log events are "A couple of hours"**.

``fetch_alerts`` asked for ``startTime = now - since_seconds`` with no
``endTime``, and the scheduler starts the next window where this one ended.
So the part of each window Google had not published yet was read once, came
back empty, and was never requeried — the same defect as #1706, where Duo's
two-minute delay cost roughly 40% of authentications at the default
300-second interval. For an application whose lag exceeds the poll interval
outright, as Token's does by a factor of about twenty-four, the loss is not a
fraction: **nothing from that application is ever ingested.**

These tests replay a sequence of consecutive polls against a transport that
withholds an event until it is older than its application's documented lag,
which is what Google's API does. An event that happened is expected to arrive
exactly once, late if need be, rather than never.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.connectors import google_workspace
from app.connectors.google_workspace import GoogleWorkspaceConnector
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#: What the vendor withholds, per application, in the emulated estate. Taken
#: from Google's published table so the test states the vendor's behaviour
#: rather than the connector's assumption about it.
_VENDOR_LAG_S = {"login": 120, "admin": 120, "drive": 120, "mobile": 120, "token": 7200}

_POLL_INTERVAL_S = 300


@pytest.fixture(scope="module")
def service_account_json() -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return json.dumps(
        {
            "type": "service_account",
            "project_id": "example-project",
            "private_key": pem,
            "client_email": "aisoc@example-project.iam.gserviceaccount.com",
            "token_uri": "https://oauth2.googleapis.com/token",
        }
    )


class _Estate:
    """A Workspace tenant that publishes each event only once it is old enough."""

    def __init__(self, origin: datetime) -> None:
        self.now = origin
        # One event per application, one per minute, over an hour.
        self.events: list[tuple[str, datetime, str]] = [
            (app, origin + timedelta(minutes=minute), f"{app}-{minute}") for app in _VENDOR_LAG_S for minute in range(60)
        ]

    def handler(self, request: httpx.Request) -> httpx.Response:
        if "token" in request.url.path and request.url.host == "oauth2.googleapis.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})

        app = request.url.path.rsplit("/", 1)[-1]
        start = _parse(request.url.params.get("startTime"))
        end = _parse(request.url.params.get("endTime")) or self.now
        published_before = self.now - timedelta(seconds=_VENDOR_LAG_S[app])

        items = [
            {
                "id": {"time": _iso(when), "uniqueQualifier": uid, "applicationName": app},
                "events": [{"name": "event"}],
            }
            for a, when, uid in self.events
            # The vendor's two independent conditions: the caller's time
            # filter, and whether this estate has published the row yet.
            if a == app and (start is None or when >= start) and when <= end and when < published_before
        ]
        return httpx.Response(200, json={"items": items})


def _iso(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _parse(raw: str | None) -> datetime | None:
    if not raw:
        return None
    return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.000Z").replace(tzinfo=UTC)


def _freeze(monkeypatch: pytest.MonkeyPatch, estate: _Estate) -> None:
    class _Clock(datetime):
        # Subclassing `datetime` keeps every other use of the name in the
        # module working while only `now` is replaced. mypy reads this as an
        # incompatible override because typeshed types `datetime.now` through
        # overloads that a plain classmethod cannot restate; the substitution
        # is sound for the one call the connector makes, so the finding is
        # suppressed here rather than by widening the tree's config.
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # type: ignore[override]  # noqa: ARG003 — signature match
            return estate.now

    monkeypatch.setattr(google_workspace, "datetime", _Clock)


async def _replay(connector: GoogleWorkspaceConnector, estate: _Estate, polls: int) -> list[str]:
    """Run consecutive polls the way the scheduler does and collect what arrives."""
    seen: list[str] = []
    for _ in range(polls):
        estate.now = estate.now + timedelta(seconds=_POLL_INTERVAL_S)
        for row in await connector.fetch_alerts(since_seconds=_POLL_INTERVAL_S):
            uid = (row.get("raw_event") or {}).get("id", {}).get("uniqueQualifier")
            if uid:
                seen.append(uid)
    return seen


@pytest.mark.asyncio
async def test_a_near_real_time_application_loses_nothing_at_the_window_boundary(
    monkeypatch: pytest.MonkeyPatch, service_account_json: str
) -> None:
    """Every Admin event eventually arrives, despite the couple-of-minutes lag."""
    estate = _Estate(datetime(2031, 5, 1, 12, 0, tzinfo=UTC))
    _freeze(monkeypatch, estate)
    monkeypatch.setattr(google_workspace.httpx, "AsyncClient", _factory(estate))
    connector = GoogleWorkspaceConnector(admin_email="a@b.c", service_account_json=service_account_json)

    seen = await _replay(connector, estate, polls=30)

    minutes = sorted(int(uid.split("-")[1]) for uid in seen if uid.startswith("admin-"))
    assert len(minutes) >= 40, "the replay must actually cover most of the estate's timeline"

    # The defect's signature is a periodic hole, not a short tail: each poll
    # read the part of its window Google had not published and moved on, so
    # the arrived minutes skip. A correct window leaves no minute unread.
    covered = set(minutes)
    missing = sorted(set(range(min(minutes), max(minutes) + 1)) - covered)
    assert not missing, (
        f"gaps at the window boundaries: events inside the vendor's publication lag "
        f"were read once while withheld and never requeried (missing {missing})"
    )

    # Consecutive windows share their boundary instant, so an event landing
    # exactly on it is delivered by both polls. That is deliberate and is the
    # safe direction — the same trade the connector cursor documents, where
    # re-emitting "is what fusion and the lake can collapse; it never drops
    # one". What must not happen is a third copy, which would mean the shift
    # is re-reading whole windows rather than abutting them.
    repeats = {uid: n for uid, n in Counter(seen).items() if n > 2}
    assert not repeats, f"an event was delivered more than twice, so windows overlap rather than abut: {repeats}"


@pytest.mark.asyncio
async def test_an_application_whose_lag_exceeds_the_interval_is_ingested_at_all(
    monkeypatch: pytest.MonkeyPatch, service_account_json: str
) -> None:
    """Token events arrive late rather than never.

    Google publishes Token log events after "a couple of hours", about
    twenty-four poll intervals. With the window pinned to `now`, no poll ever
    overlapped the part of the timeline Google had published, so the count
    was not reduced — it was zero.
    """
    estate = _Estate(datetime(2031, 5, 1, 12, 0, tzinfo=UTC))
    _freeze(monkeypatch, estate)
    monkeypatch.setattr(google_workspace.httpx, "AsyncClient", _factory(estate))
    connector = GoogleWorkspaceConnector(admin_email="a@b.c", service_account_json=service_account_json)

    seen = await _replay(connector, estate, polls=48)

    token = [uid for uid in seen if uid.startswith("token-")]
    assert token, "not one Token log event was ever ingested on any poll"


def _factory(estate: _Estate) -> Any:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(estate.handler)
        return real_client(*args, **kwargs)

    return factory
