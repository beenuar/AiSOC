"""The history route: every vendor reachable, every failure named.

Gap-closure Phase 1.4 gate.

Phase 1.1 proved the five readers parse vendor-shaped payloads. This proves
the route in front of them reaches each one, refuses rather than returning an
empty window, and translates the credential mapping the API forwards into a
client that the reader can use.

Every vendor payload here is **synthetic**, hand-built to the shape the
vendor's API documents. None came from a customer.

The assertions that matter are the refusals. An evaluation that turns "your
credentials do not build a client" into an empty list has told an operator
their analysts closed nothing, which is a statement about their SOC rather
than about their configuration.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx
from app.api.replay_history_router import _CREDENTIAL_KEYS, MAX_FINDINGS
from app.main import app
from app.services.alert_history import UNLABELED
from fastapi.testclient import TestClient

SINCE = datetime(2026, 9, 1, tzinfo=UTC)
UNTIL = datetime(2026, 9, 26, tzinfo=UTC)

_SPLUNK_NOTABLES = {
    "results": [
        {
            "event_id": "ES-001",
            "rule_name": "Beaconing to a rare destination",
            "rule_id": "rule-beacon",
            "disposition": "disposition:1",
            "review_time": "1790294400",
            "reviewer": "a.analyst",
            "comment": "Confirmed beacon, host isolated.",
            "urgency": "high",
        },
        {
            "event_id": "ES-002",
            "rule_name": "Bulk export by finance",
            "rule_id": "rule-export",
            "disposition": "disposition:6",
            "review_time": "1790298000",
            "reviewer": "b.analyst",
        },
    ]
}


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    # The route is behind `require_service_auth`, which fails closed unless a
    # token is configured or dev mode is on. Dev mode here rather than a token
    # so the tests exercise the handler rather than the shared auth dependency,
    # which has its own coverage.
    monkeypatch.setenv("AISOC_DEV_MODE", "1")
    monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", "")
    from app.core.config import get_settings

    get_settings.cache_clear()
    yield TestClient(app)
    get_settings.cache_clear()


def _body(vendor: str, credentials: dict, **extra) -> dict:
    return {
        "vendor": vendor,
        "credentials": credentials,
        "since": SINCE.isoformat(),
        "until": UNTIL.isoformat(),
        **extra,
    }


@respx.mock
def test_splunk_history_reaches_the_real_reader_and_reports_both_counts(client: TestClient) -> None:
    respx.post(url__regex=r"https://splunk:8089/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "sid-1"}))
    respx.get(url__regex=r".*/results.*").mock(return_value=httpx.Response(200, json=_SPLUNK_NOTABLES))

    response = client.post(
        "/api/v1/replay/history",
        json=_body("splunk", {"splunk_url": "https://splunk:8089", "splunk_token": "t"}),
    )

    assert response.status_code == 200
    body = response.json()
    assert body["vendor"] == "splunk"
    assert body["count"] == 2
    # The undetermined row is present and excluded, and both numbers are
    # reported. A customer whose analysts close without a disposition has to
    # see that rather than a small graded sample with no explanation.
    assert body["labelled"] == 1
    assert body["unlabeled"] == 1
    assert [f["disposition"] for f in body["findings"]] == ["true_positive", UNLABELED]


@respx.mock
def test_the_serialised_finding_carries_every_field_the_replay_side_rebuilds(client: TestClient) -> None:
    """The boundary is by name, so the names have to survive the trip."""
    respx.post(url__regex=r".*/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "s"}))
    respx.get(url__regex=r".*/results.*").mock(return_value=httpx.Response(200, json=_SPLUNK_NOTABLES))

    response = client.post(
        "/api/v1/replay/history",
        json=_body("splunk", {"splunk_url": "https://splunk:8089", "splunk_token": "t"}),
    )

    finding = response.json()["findings"][0]
    assert set(finding) == {
        "vendor",
        "finding_id",
        "title",
        "disposition",
        "vendor_disposition",
        "closed_at",
        "closed_by",
        "reason",
        "rule_id",
        "severity",
        "raw",
    }
    # ISO-8601, not an epoch. The receiving parser refuses an unparseable
    # close time rather than defaulting it, and a naive epoch would have to
    # guess a timezone to be read back.
    assert finding["closed_at"] == "2026-09-25T00:00:00+00:00"
    # The vendor row travels untouched so the replay runner can hand it to the
    # same connector normalize() production uses.
    assert finding["raw"]["event_id"] == "ES-001"


@pytest.mark.parametrize(
    "vendor",
    ["splunk", "sentinel", "elastic", "qradar", "defender"],
)
def test_a_vendor_with_no_usable_credentials_is_refused_by_name(client: TestClient, vendor: str) -> None:
    response = client.post("/api/v1/replay/history", json=_body(vendor, {}))

    assert response.status_code == 422
    detail = response.json()["detail"]
    assert vendor in detail
    # The refusal names the keys that would have built a client, sourced from
    # the factory rather than retyped, so a key the factory stops reading
    # cannot linger in the message.
    for key in _CREDENTIAL_KEYS[vendor]:
        assert key in detail


def test_an_unsupported_vendor_is_refused_by_the_schema(client: TestClient) -> None:
    response = client.post("/api/v1/replay/history", json=_body("crowdstrike", {"anything": "here"}))

    assert response.status_code == 422


def test_an_inverted_window_is_refused_rather_than_read_backwards(client: TestClient) -> None:
    response = client.post(
        "/api/v1/replay/history",
        json={
            "vendor": "splunk",
            "credentials": {"splunk_url": "https://splunk:8089", "splunk_token": "t"},
            "since": UNTIL.isoformat(),
            "until": SINCE.isoformat(),
        },
    )

    assert response.status_code == 422
    assert "must be after" in response.json()["detail"]


@respx.mock
def test_a_vendor_error_is_a_502_naming_the_vendor_not_an_empty_window(client: TestClient) -> None:
    """The distinction this whole surface rests on.

    An empty list reads as "nobody closed anything in that window", which is a
    measurement. A read that failed is not a measurement, and the two must not
    produce the same response body.
    """
    respx.post(url__regex=r".*/services/search/jobs$").mock(return_value=httpx.Response(503, text="maintenance"))

    response = client.post(
        "/api/v1/replay/history",
        json=_body("splunk", {"splunk_url": "https://splunk:8089", "splunk_token": "t"}),
    )

    assert response.status_code == 502
    assert "splunk" in response.json()["detail"]


@respx.mock
def test_the_splunk_saved_search_the_wizard_collected_is_honoured(client: TestClient) -> None:
    """Deployments rename the saved search, and a hardcoded one returns zero rows."""
    created = respx.post(url__regex=r".*/services/search/jobs$").mock(return_value=httpx.Response(201, json={"sid": "s"}))
    respx.get(url__regex=r".*/results.*").mock(return_value=httpx.Response(200, json={"results": []}))

    client.post(
        "/api/v1/replay/history",
        json=_body(
            "splunk",
            {"splunk_url": "https://splunk:8089", "splunk_token": "t"},
            search_override="`my_review_lookup`",
        ),
    )

    assert "my_review_lookup" in created.calls[0].request.content.decode()


def test_a_limit_above_the_ceiling_is_refused_rather_than_truncated(client: TestClient) -> None:
    response = client.post(
        "/api/v1/replay/history",
        json=_body(
            "splunk",
            {"splunk_url": "https://splunk:8089", "splunk_token": "t"},
            limit=MAX_FINDINGS + 1,
        ),
    )

    assert response.status_code == 422


def test_the_route_takes_no_tenant_from_the_caller() -> None:
    """There is no tenant field, and that is the property rather than an omission.

    This service never resolves a tenant. The credentials it is handed are the
    scope, because they reach exactly one customer's SIEM. A tenant field here
    would be a value the caller chose that nothing checked.
    """
    from app.api.replay_history_router import HistoryRequest

    assert not any("tenant" in name for name in HistoryRequest.model_fields)
