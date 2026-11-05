"""Google Workspace activity polling follows the Reports API's nextPageToken."""

from __future__ import annotations

import json
import time

import httpx
import pytest
from app.connectors import google_workspace
from app.connectors.google_workspace import GoogleWorkspaceConnector


def _activity(app: str, i: int) -> dict:
    return {
        "id": {"applicationName": app, "uniqueQualifier": f"{app}-{i}", "time": "2099-01-01T00:00:00.000Z"},
        "actor": {"email": f"user{i}@example.com"},
        "events": [{"name": "login_success"}],
    }


@pytest.mark.asyncio
async def test_fetch_alerts_follows_next_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    login = [_activity("login", i) for i in range(1200)]
    tokens_seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        app = request.url.path.rsplit("/", 1)[-1]
        if app != "login":
            return httpx.Response(200, json={"kind": "admin#reports#activities"})
        token = request.url.params.get("pageToken")
        tokens_seen.append(token)
        start = 0 if token is None else int(token)
        size = int(request.url.params["maxResults"])
        body: dict = {"items": login[start : start + size]}
        if start + size < len(login):
            body["nextPageToken"] = str(start + size)
        return httpx.Response(200, json=body)

    real_client = httpx.AsyncClient

    def factory(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(google_workspace.httpx, "AsyncClient", factory)
    sa = {"client_email": "sa@example.iam.gserviceaccount.com", "private_key": "unused", "token_uri": "https://oauth2.googleapis.com/token"}
    connector = GoogleWorkspaceConnector(admin_email="admin@example.com", service_account_json=json.dumps(sa))
    # A cached token keeps the test on the read path rather than the JWT exchange.
    connector._tokens[google_workspace._SCOPE] = ("tok", time.time() + 3600)

    out = await connector.fetch_alerts()

    assert tokens_seen == [None, "500", "1000"]
    assert len(out) == 1200
