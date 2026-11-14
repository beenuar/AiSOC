"""The worker's half of the loop: post the verdict, decide nothing, never raise.

By the time this runs the verdict is already durable in the ledger and on the
alerts row. An exception escaping here would re-drive the whole triage through
the bounded-retry path and eventually dead-letter an alert that was triaged
perfectly well, so every failure mode has to come back as ``None``.

It also must not hold an opinion about what may be written. The policy lives
in the actions service; a copy here would be a second policy that disagrees
with the first the day one of them changes.
"""

from __future__ import annotations

import httpx
import pytest
from app.investigator import siem_writeback

TENANT = "11111111-1111-1111-1111-111111111111"
ALERT = "22222222-2222-2222-2222-222222222222"


class _Response:
    def __init__(self, status_code: int = 200, payload: object | None = None, *, bad_json: bool = False) -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {"mode": "dry_run", "executed": False, "outcomes": []}
        self._bad_json = bad_json

    def json(self) -> object:
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class _Client:
    """Minimal async context manager standing in for ``httpx.AsyncClient``."""

    def __init__(self, response: object = None, error: Exception | None = None) -> None:
        self._response = response or _Response()
        self._error = error
        self.calls: list[dict] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers or {}})
        if self._error is not None:
            raise self._error
        return self._response


@pytest.fixture(autouse=True)
def _token(monkeypatch):
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "shared-secret-value")
    monkeypatch.delenv("AISOC_SIEM_WRITEBACK_ENABLED", raising=False)


def _install(monkeypatch, client: _Client) -> None:
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kwargs: client)


@pytest.mark.asyncio
async def test_posts_the_verdict_with_the_service_token(monkeypatch) -> None:
    client = _Client()
    _install(monkeypatch, client)

    report = await siem_writeback.write_back_disposition(
        tenant_id=TENANT,
        alert_id=ALERT,
        disposition="false_positive",
        confidence=0.91,
        rationale="Matches a known scanner fingerprint.",
    )

    assert report == {"mode": "dry_run", "executed": False, "outcomes": []}
    call = client.calls[0]
    assert call["url"].endswith(f"/api/v1/alerts/{ALERT}/source-writeback")
    assert call["headers"]["X-AiSOC-Service-Token"] == "shared-secret-value"
    assert call["json"]["disposition"] == "false_positive"
    assert call["json"]["tenant_id"] == TENANT
    assert call["json"]["confidence"] == pytest.approx(0.91)


@pytest.mark.asyncio
async def test_no_token_means_no_call(monkeypatch) -> None:
    """Without the shared secret the API refuses by design; skip loudly."""
    monkeypatch.delenv("AISOC_AGENTS_SERVICE_TOKEN", raising=False)
    client = _Client()
    _install(monkeypatch, client)

    assert await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id=ALERT, disposition="benign") is None
    assert client.calls == []


@pytest.mark.asyncio
async def test_disabled_flag_stops_the_call(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_ENABLED", "0")
    client = _Client()
    _install(monkeypatch, client)

    assert await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id=ALERT, disposition="benign") is None
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("disposition", ["needs_review", "resolved", "", "closed"])
async def test_verdicts_the_api_would_refuse_cost_no_round_trip(monkeypatch, disposition: str) -> None:
    client = _Client()
    _install(monkeypatch, client)

    assert await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id=ALERT, disposition=disposition) is None
    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "client",
    [
        _Client(error=httpx.ConnectError("refused")),
        _Client(error=httpx.ReadTimeout("slow")),
        _Client(response=_Response(status_code=401)),
        _Client(response=_Response(status_code=500)),
        _Client(response=_Response(bad_json=True)),
        _Client(response=_Response(payload=["not", "a", "dict"])),
    ],
)
async def test_every_failure_mode_returns_none_rather_than_raising(monkeypatch, client: _Client) -> None:
    _install(monkeypatch, client)
    assert await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id=ALERT, disposition="benign") is None


@pytest.mark.asyncio
async def test_missing_identifiers_are_a_no_op(monkeypatch) -> None:
    client = _Client()
    _install(monkeypatch, client)
    assert await siem_writeback.write_back_disposition(tenant_id="", alert_id=ALERT, disposition="benign") is None
    assert await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id="", disposition="benign") is None
    assert client.calls == []


@pytest.mark.asyncio
async def test_the_worker_does_not_decide_whether_to_execute(monkeypatch) -> None:
    """Execution is the API's call. The worker must not send a hint either way."""
    monkeypatch.setenv("AISOC_SIEM_WRITEBACK_EXECUTE", "1")
    client = _Client()
    _install(monkeypatch, client)

    await siem_writeback.write_back_disposition(tenant_id=TENANT, alert_id=ALERT, disposition="benign")

    body = client.calls[0]["json"]
    assert "dry_run" not in body
    assert "execute" not in body
