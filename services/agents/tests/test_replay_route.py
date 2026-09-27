"""The replay route: the tenant comes from the credential, and nothing is written.

Gap-closure Phase 1.4 gate.

Phase 1.2 proved the runner splits, freezes and writes nothing. This proves
the route in front of it resolves the tenant from the caller's credential
rather than from the request, refuses a history it cannot read rather than
grading a partial one, and reaches the production normalizer over HTTP rather
than substituting a mapping of its own.

The tenant assertions are the ones that matter. The tenant travels into the
envelope handed to triage, so a caller-supplied tenant would decide which
customer's business-context rules and institutional memory the graded verdict
was produced under.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest
from app.api.replay_router import MAX_FINDINGS, ReplayRequest
from app.main import app
from fastapi.testclient import TestClient

_BASE = datetime(2026, 3, 1, tzinfo=UTC)
_TENANT = "11111111-2222-3333-4444-555555555555"
_SERVICE_TOKEN = "service-token-for-tests"

_NOTABLE = {
    "event_id": "ES-1",
    "rule_id": "rule-42",
    "search_name": "Suspicious PowerShell",
    "urgency": "high",
    "disposition": "disposition:1",
    "src": "192.0.2.10",
    "host": "WS-01",
    "_time": "1772323200",
}


def _finding_payload(index: int, *, disposition: str = "false_positive") -> dict[str, Any]:
    """One ``ClosedFinding.as_dict()`` row, as the actions service sends it."""
    raw = {**_NOTABLE, "event_id": f"ES-{index:03d}"}
    return {
        "vendor": "splunk",
        "finding_id": f"ES-{index:03d}",
        "title": "Suspicious PowerShell",
        "disposition": disposition,
        "vendor_disposition": "disposition:1",
        "closed_at": (_BASE + timedelta(hours=index)).isoformat(),
        "closed_by": "a.analyst",
        "reason": None,
        "rule_id": "rule-42",
        "severity": "high",
        "raw": raw,
    }


def _normalized(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": "splunk",
        "external_id": raw.get("event_id", ""),
        "title": raw.get("search_name") or "Splunk Notable Event",
        "severity": "high",
        "src_ip": raw.get("src"),
        "hostname": raw.get("host"),
        "raw_event": raw,
        "created_at": raw.get("_time"),
    }


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", _SERVICE_TOKEN)
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "")
    # No console secret configured, so only the service path is available and
    # the tenant has to arrive on the header rather than in a token claim.
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.delenv("AISOC_DEV_MODE", raising=False)
    return TestClient(app)


@pytest.fixture
def connectors(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    """Stand in for the connectors service's ``POST /connectors/{id}/normalize``.

    Patched at the transport rather than at ``fetch_normalized`` so the route
    still builds the request, sends the headers and validates the response
    shape. Patching the function would prove the route calls something.
    """
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        import json

        rows = json.loads(request.content)["rows"]
        return httpx.Response(200, json={"rows": [_normalized(row) for row in rows]})

    real_client = httpx.AsyncClient

    def _factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr("app.replay.connector_normalizer.httpx.AsyncClient", _factory)
    return seen


def _headers(tenant: str | None = _TENANT) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {_SERVICE_TOKEN}"}
    if tenant is not None:
        headers["X-AiSOC-Tenant-ID"] = tenant
    return headers


def _body(count: int = 20, **extra: Any) -> dict[str, Any]:
    return {
        "connector_id": "splunk",
        "findings": [_finding_payload(i, disposition="true_positive" if i % 4 == 0 else "false_positive") for i in range(count)],
        **extra,
    }


def test_a_replay_runs_the_test_window_and_reports_its_method(client: TestClient, connectors: list[httpx.Request]) -> None:
    response = client.post("/api/v1/replay/run", json=_body(20), headers=_headers())

    assert response.status_code == 200
    body = response.json()
    # 70/30 by time: 14 train, 6 test, and only the test window is replayed.
    assert len(body["decisions"]) == 6
    assert body["method"]["split"]["train_findings"] == 14
    assert body["method"]["split"]["test_findings"] == 6
    assert body["method"]["tenant_id"] == _TENANT
    # What production *would* have written, per sink, intercepted rather than
    # performed. A number rather than an absence: a replay that never reached
    # the writeback branch and a replay whose writeback was suppressed look
    # identical from outside, and only the counter tells them apart.
    attempted = body["method"]["shadow_writes_attempted"]
    assert set(attempted) == {
        "cache_verdict",
        "persist_auto_triage",
        "record_outcome",
        "write_back_disposition",
    }
    assert all(count == len(body["decisions"]) for count in attempted.values())
    # The gaps a replayed envelope does not carry travel into every report.
    assert body["method"]["envelope_limits"]


def test_a_service_token_with_no_tenant_header_is_refused_rather_than_widened(client: TestClient, connectors: list[httpx.Request]) -> None:
    """An absent scope is empty, never every scope.

    Every cross-tenant leak this codebase has had took this shape: a scope
    that was absent rather than narrow, and a read that treated absent as
    "no filter".
    """
    response = client.post("/api/v1/replay/run", json=_body(10), headers=_headers(tenant=None))

    assert response.status_code == 403
    assert not connectors


def test_no_credential_at_all_is_a_401(client: TestClient) -> None:
    response = client.post("/api/v1/replay/run", json=_body(10))

    assert response.status_code == 401


def test_the_request_carries_no_tenant_field() -> None:
    """The tenant is not something a caller can name here."""
    assert not any("tenant" in name for name in ReplayRequest.model_fields)


def test_the_tenant_the_credential_named_is_the_one_forwarded_to_connectors(client: TestClient, connectors: list[httpx.Request]) -> None:
    other = "99999999-8888-7777-6666-555555555555"

    client.post("/api/v1/replay/run", json=_body(10), headers=_headers(tenant=other))

    assert connectors
    assert connectors[0].headers["X-AiSOC-Tenant-ID"] == other


def test_an_unparseable_close_time_is_refused_rather_than_defaulted(client: TestClient, connectors: list[httpx.Request]) -> None:
    """A finding with an invented close time is a leak wearing a plausible timestamp.

    It lands on whichever side of the train/test split the default happens to
    fall, which can put a finding in the test window whose answer is already
    inside the frozen context.
    """
    body = _body(10)
    body["findings"][3]["closed_at"] = "the day before yesterday"

    response = client.post("/api/v1/replay/run", json=body, headers=_headers())

    assert response.status_code == 422
    assert "closed_at" in response.json()["detail"]
    assert not connectors


def test_a_normalizer_that_cannot_be_reached_is_a_502_not_a_substituted_mapping(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Replay has no degraded mode here.

    Grading the agent on a mapping written inside this service would measure a
    pipeline nobody runs, and the output has the same shape as the real thing.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="connectors is down")

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "app.replay.connector_normalizer.httpx.AsyncClient",
        lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )

    response = client.post("/api/v1/replay/run", json=_body(10), headers=_headers())

    assert response.status_code == 502
    assert "normalizer" in response.json()["detail"]


def test_a_window_above_the_ceiling_is_refused_rather_than_truncated(client: TestClient, connectors: list[httpx.Request]) -> None:
    # Assert the constant is what the message quotes, rather than restating it.
    assert MAX_FINDINGS == 2000
    findings: list[dict[str, Any]] = [_finding_payload(i) for i in range(3)] * 700  # 2100 rows
    body: dict[str, Any] = {"connector_id": "splunk", "findings": findings}

    response = client.post("/api/v1/replay/run", json=body, headers=_headers())

    assert response.status_code == 422
    assert str(MAX_FINDINGS) in response.json()["detail"]


def test_a_frozen_context_is_captured_at_the_split_the_runner_chose(client: TestClient, connectors: list[httpx.Request]) -> None:
    """The snapshot has to be taken at the split instant or it is not a freeze.

    A statement recorded after the split is dropped, and the count of drops
    travels into the report so the freeze is not claimed to be tighter than
    it is.
    """
    after_split = (_BASE + timedelta(hours=19)).isoformat()
    before_split = (_BASE + timedelta(hours=2)).isoformat()
    body = _body(
        20,
        context={
            "statements": [
                {"statement": "finance bulk exports are expected", "created_at": before_split},
                {"statement": "this alert was a true positive", "created_at": after_split},
            ],
            "priors": {},
        },
    )

    response = client.post("/api/v1/replay/run", json=body, headers=_headers())

    assert response.status_code == 200
    frozen = response.json()["method"]["frozen_context"]
    assert frozen["statements_frozen"] == 1
    assert frozen["statements_dropped_after_split"] == 1


def test_two_runs_over_one_history_produce_identical_decisions_through_the_route(
    client: TestClient, connectors: list[httpx.Request]
) -> None:
    """The phase's acceptance bar, at this link.

    Latency is excluded and nothing else is: it is a wall-clock measurement
    and will never repeat. Every other field is a property of the input and
    the code.
    """
    body = _body(20)

    def _decisions() -> list[dict[str, Any]]:
        response = client.post("/api/v1/replay/run", json=body, headers=_headers())
        assert response.status_code == 200
        rows = []
        for decision in response.json()["decisions"]:
            decision.pop("latency_ms")
            rows.append(decision)
        return rows

    first = _decisions()
    second = _decisions()
    assert first == second
    assert len(first) == 6


def test_the_route_is_registered_on_the_service(client: TestClient) -> None:
    """A router nobody includes is the failure this phase exists to close.

    Read off the served OpenAPI document rather than ``app.routes``: this
    FastAPI holds included routers lazily, so ``app.routes`` lists wrappers
    and a membership test against it passes vacuously.
    """
    schema = client.get("/openapi.json").json()
    assert "/api/v1/replay/run" in schema["paths"]


def test_a_console_token_carries_its_own_tenant(monkeypatch: pytest.MonkeyPatch) -> None:
    """The browser path does not use the service header at all.

    Recorded because the two credential shapes resolve differently and only
    one of them may name a tenant in a header.
    """
    import base64
    import hashlib
    import hmac
    import json
    import time

    secret = "a-console-secret-at-least-32-characters-long"
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setenv("SECRET_KEY", secret)
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", _SERVICE_TOKEN)

    def _segment(payload: dict[str, Any]) -> str:
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    tenant = str(uuid.uuid4())
    header = _segment({"alg": "HS256", "typ": "JWT"})
    claims = _segment({"sub": "analyst", "tenant_id": tenant, "type": "access", "exp": int(time.time()) + 600})
    signature = hmac.new(secret.encode(), f"{header}.{claims}".encode(), hashlib.sha256).digest()
    token = f"{header}.{claims}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        rows = json.loads(request.content)["rows"]
        return httpx.Response(200, json={"rows": [_normalized(row) for row in rows]})

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        "app.replay.connector_normalizer.httpx.AsyncClient",
        lambda *a, **kw: real_client(*a, **{**kw, "transport": httpx.MockTransport(handler)}),
    )

    response = TestClient(app).post(
        "/api/v1/replay/run",
        json=_body(10),
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["method"]["tenant_id"] == tenant
    # Filtered to the normalize call rather than taking the first request
    # seen: the patched client is process-wide and anything else the service
    # does over httpx lands in the same list.
    normalize_calls = [r for r in seen if r.url.path.endswith("/normalize")]
    assert normalize_calls
    assert normalize_calls[0].headers["X-AiSOC-Tenant-ID"] == tenant
