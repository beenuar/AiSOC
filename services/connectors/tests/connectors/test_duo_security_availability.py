"""Duo authentication-log polling reads the entries Duo has made available."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from app.connectors import duo_security
from app.connectors.duo_security import DuoSecurityConnector

_START = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
# Duo serves an authentication "up to as recently as two minutes before the API request".
_DELAY = timedelta(minutes=2)


class _Clock:
    now_value = _START

    @classmethod
    def now(cls, tz=None):  # noqa: ANN001, ANN206
        return cls.now_value


class _FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):  # noqa: ANN001, ANN206
        return _Clock.now(tz)


def _entry(at: datetime) -> dict:
    ms = int(at.timestamp()) * 1000
    return {"txid": f"tx-{ms}", "timestamp": ms // 1000, "isotimestamp": at.isoformat(), "result": "success"}


@pytest.mark.asyncio
async def test_back_to_back_polls_read_every_authentication(monkeypatch: pytest.MonkeyPatch) -> None:
    # One authentication every 10 seconds across the two poll windows.
    entries = [_entry(_START - timedelta(minutes=10) + timedelta(seconds=10 * i)) for i in range(90)]

    def handler(request: httpx.Request) -> httpx.Response:
        available_until = int((_Clock.now_value - _DELAY).timestamp()) * 1000
        lo, hi = int(request.url.params["mintime"]), int(request.url.params["maxtime"])
        served = [e for e in entries if lo <= e["timestamp"] * 1000 <= min(hi, available_until)]
        return httpx.Response(200, json={"stat": "OK", "response": {"authlogs": served, "metadata": {}}})

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(duo_security.httpx, "AsyncClient", factory)
    monkeypatch.setattr(duo_security, "datetime", _FrozenDatetime)
    connector = DuoSecurityConnector(integration_key="DIXXXX", secret_key="secret", api_hostname="api-x.duosecurity.com")  # noqa: S106 — test

    seen: set[str] = set()
    for poll_at in (_START, _START + timedelta(minutes=5)):
        _Clock.now_value = poll_at
        seen.update(e["external_id"] for e in await connector.fetch_alerts(since_seconds=300))

    # Everything that happened from five minutes before the first poll up to
    # what Duo had made available by the second has to be read by one of them.
    first_window_start = _START - timedelta(minutes=5)
    expected = {e["txid"] for e in entries if first_window_start.timestamp() <= e["timestamp"] <= (_Clock.now_value - _DELAY).timestamp()}
    assert expected - seen == set(), f"{len(expected - seen)} authentication(s) never read"
