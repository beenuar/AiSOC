"""Entra ID audit polling follows Microsoft Graph's @odata.nextLink."""

from __future__ import annotations

import httpx
import pytest
from app.connectors import azure_entra
from app.connectors.azure_entra import AzureEntraConnector


def _collection(prefix: str, count: int) -> list[dict]:
    return [{"id": f"{prefix}-{i}", "activityDateTime": "2099-01-01T00:00:00Z", "riskLevelAggregated": "high"} for i in range(count)]


@pytest.mark.asyncio
async def test_fetch_alerts_follows_next_link_on_both_feeds(monkeypatch: pytest.MonkeyPatch) -> None:
    feeds = {"directoryAudits": _collection("audit", 450), "signIns": _collection("signin", 230)}
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok"})
        feed = request.url.path.rsplit("/", 1)[-1]
        requested.append(f"{feed}?{request.url.params.get('$skiptoken', '')}")
        start = int(request.url.params.get("$skiptoken", "0"))
        page = feeds[feed][start : start + 200]
        body: dict = {"value": page}
        if start + 200 < len(feeds[feed]):
            # Graph's link carries the original query and an opaque skip token.
            body["@odata.nextLink"] = str(request.url.copy_merge_params({"$skiptoken": str(start + 200)}))
        return httpx.Response(200, json=body)

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(azure_entra.httpx, "AsyncClient", factory)
    connector = AzureEntraConnector(tenant_id="tenant", client_id="id", client_secret="secret")  # noqa: S106 — test

    out = await connector.fetch_alerts()

    assert requested == [
        "directoryAudits?",
        "directoryAudits?200",
        "directoryAudits?400",
        "signIns?",
        "signIns?200",
    ]
    assert len(out) == 450 + 230
