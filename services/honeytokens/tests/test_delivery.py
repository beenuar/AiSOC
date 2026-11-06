"""Where a tripped honeytoken goes, and what happens when it cannot get there.

GHSA-9q6p-m345-h3hj. Two properties are under test and they fail differently:

* **F57** — with no webhook configured, a trip must still reach somewhere.
  Asserted on the **request** rather than on a parsed result, because the two
  defects worth catching live there: a push with no `Authorization` is
  answered 401 by our own ingest service and reads to an operator as the
  receiver rejecting us, and a push whose `connector_type` has no normalizer
  profile is filed as category 4 and silently never promoted to an alert. A
  mock that returns 200 to anything cannot see either.

* **F58** — a failure must be classified. A bare retry loop would turn a
  wrong URL into permanent churn and still never tell anybody, so the test
  pins which status codes are retried and which are terminal, and that a
  terminal one names the reason.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import httpx
import pytest
from app.services import delivery
from app.services.delivery import Disposition, deliver, trip_payload

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _payload() -> dict:
    return trip_payload(
        honeytoken_id=uuid.UUID("7f1a0f1e-0000-4000-8000-000000000001"),
        tenant_id=TENANT,
        token_type="aws_key",
        token_name="decoy-prod-deploy-key",
        trigger_id=uuid.UUID("7f1a0f1e-0000-4000-8000-000000000002"),
        source_ip="203.0.113.17",
        triggered_at=datetime(2026, 11, 5, tzinfo=UTC),
    )


class _Recorder:
    """Stands in for httpx.AsyncClient and keeps the request it was given."""

    def __init__(self, *, status: int = 200, raises: Exception | None = None) -> None:
        self.status = status
        self.raises = raises
        self.requests: list[dict] = []

    def __call__(self, *args, **kwargs):  # constructed as httpx.AsyncClient(...)
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, *, headers=None, content=None, json=None):
        self.requests.append({"url": url, "headers": dict(headers or {}), "content": content, "json": json})
        if self.raises is not None:
            raise self.raises
        return httpx.Response(self.status, request=httpx.Request("POST", url))


@pytest.fixture
def no_webhook(monkeypatch):
    """The shipped layout: no webhook is configured anywhere."""
    monkeypatch.setattr(delivery.settings, "alert_webhook_url", "", raising=False)
    monkeypatch.setattr(delivery.settings, "alert_webhook_secret", "", raising=False)
    monkeypatch.setenv("INGEST_SERVICE_URL", "http://ingest-worker:8080")
    monkeypatch.setenv("AISOC_SERVICE_TOKEN", "svc-token-abc")


# ── F57: a trip reaches the spine with no webhook configured ──────────────


@pytest.mark.asyncio
async def test_with_no_webhook_the_trip_is_pushed_to_the_ingest_spine(monkeypatch, no_webhook) -> None:
    """The defect: this used to log at info and return False."""
    recorder = _Recorder(status=202)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    result = await deliver(_payload())

    assert result.disposition is Disposition.DELIVERED
    assert len(recorder.requests) == 1, "the trip reached nobody"
    req = recorder.requests[0]
    assert req["url"] == "http://ingest-worker:8080/v1/ingest/batch"


@pytest.mark.asyncio
async def test_the_push_carries_the_credential_and_the_tenant(monkeypatch, no_webhook) -> None:
    """A push with no Authorization is answered 401 by our own service.

    That 401 reads to an operator as the customer's receiver rejecting us,
    which is the recorded failure mode for internal service-to-service calls
    in this repository.
    """
    recorder = _Recorder(status=202)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    await deliver(_payload())

    headers = recorder.requests[0]["headers"]
    assert headers.get("Authorization") == "Bearer svc-token-abc"
    assert headers.get("X-Tenant-ID") == str(TENANT), "the tenant must travel as a header, not only in the body"


@pytest.mark.asyncio
async def test_the_push_declares_the_connector_type_the_normalizer_profiles(monkeypatch, no_webhook) -> None:
    """`honeytoken` must match the profile in the Go normalizer.

    A connector type with no profile falls to the lenient fallback, is filed
    as category 4 Network Activity, and `should_promote()` never turns it
    into an alert — archived to the lake and never seen, which is this
    advisory's own symptom one layer down.
    """
    recorder = _Recorder(status=202)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    await deliver(_payload())

    body = recorder.requests[0]["json"]
    assert body["connector_type"] == "honeytoken"
    assert len(body["events"]) == 1
    assert body["events"][0]["trigger_id"] == "7f1a0f1e-0000-4000-8000-000000000002"


@pytest.mark.asyncio
async def test_a_configured_webhook_still_wins(monkeypatch) -> None:
    """An existing deployment keeps the behaviour it has."""
    monkeypatch.setattr(delivery.settings, "alert_webhook_url", "https://receiver.example/hook", raising=False)
    monkeypatch.setattr(delivery.settings, "alert_webhook_secret", "s3cret", raising=False)
    recorder = _Recorder(status=200)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    result = await deliver(_payload())

    assert result.delivered
    req = recorder.requests[0]
    assert req["url"] == "https://receiver.example/hook"
    assert req["headers"]["X-AiSOC-Signature"].startswith("sha256=")
    assert json.loads(req["content"])["event"] == "honeytoken.triggered"


@pytest.mark.asyncio
async def test_a_missing_service_token_names_the_variable_rather_than_earning_a_401(monkeypatch, no_webhook) -> None:
    monkeypatch.delenv("AISOC_SERVICE_TOKEN", raising=False)
    recorder = _Recorder(status=200)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    result = await deliver(_payload())

    assert result.disposition is Disposition.DEAD
    assert "AISOC_SERVICE_TOKEN" in result.detail
    assert recorder.requests == [], "a push with no credential should not be attempted at all"


# ── F58: permanent and transient are really distinguished ─────────────────


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (200, Disposition.DELIVERED),
        (202, Disposition.DELIVERED),
        (408, Disposition.RETRY),
        (429, Disposition.RETRY),
        (500, Disposition.RETRY),
        (503, Disposition.RETRY),
        (400, Disposition.DEAD),
        (401, Disposition.DEAD),
        (403, Disposition.DEAD),
        (404, Disposition.DEAD),
    ],
)
@pytest.mark.asyncio
async def test_status_codes_are_classified_not_merely_retried(monkeypatch, no_webhook, status, expected) -> None:
    """Retrying a 404 for a day produces load and no alert; a 503 is worth retrying."""
    monkeypatch.setattr(delivery.httpx, "AsyncClient", _Recorder(status=status))
    result = await deliver(_payload())
    assert result.disposition is expected, f"{status} classified {result.disposition}"


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectError("connection refused"),
        httpx.ReadTimeout("timed out"),
        httpx.RemoteProtocolError("server disconnected"),
    ],
)
@pytest.mark.asyncio
async def test_a_receiver_that_is_down_is_retryable(monkeypatch, no_webhook, exc) -> None:
    """The case the advisory names: a trip during a restart must not be lost."""
    monkeypatch.setattr(delivery.httpx, "AsyncClient", _Recorder(raises=exc))
    result = await deliver(_payload())
    assert result.disposition is Disposition.RETRY
    assert type(exc).__name__ in result.detail


@pytest.mark.asyncio
async def test_a_webhook_without_a_secret_is_dead_not_retried(monkeypatch) -> None:
    """No number of retries produces an HMAC secret."""
    monkeypatch.setattr(delivery.settings, "alert_webhook_url", "https://receiver.example/hook", raising=False)
    monkeypatch.setattr(delivery.settings, "alert_webhook_secret", "", raising=False)
    recorder = _Recorder(status=200)
    monkeypatch.setattr(delivery.httpx, "AsyncClient", recorder)

    result = await deliver(_payload())

    assert result.disposition is Disposition.DEAD
    assert "SECRET" in result.detail.upper()
    assert recorder.requests == [], "an unsigned alert must not be sent"


def test_the_backoff_grows_and_is_capped() -> None:
    """A fixed short retry against a long outage is a denial of service on the receiver."""
    waits = [delivery.backoff_seconds(n) for n in range(1, delivery.MAX_ATTEMPTS + 1)]
    assert waits == sorted(waits), f"backoff must not shrink: {waits}"
    assert waits[0] < waits[-1], "a flat backoff is not a backoff"
    assert delivery.backoff_seconds(delivery.MAX_ATTEMPTS + 50) == waits[-1], "the backoff must be capped"
