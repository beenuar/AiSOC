"""Microsoft collection reads follow the vendor's paging link to the end.

Both Microsoft Graph and Azure Resource Manager answer a capped collection
request with the first page plus a link to the next one, and both document
that a client must keep following that link until it stops being returned:

* Graph — https://learn.microsoft.com/en-us/graph/paging
  "To read all results, you must continue to call Microsoft Graph with the
  ``@odata.nextLink`` property returned in each response until the
  ``@odata.nextLink`` property is no longer returned."
* Sentinel — https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list
  ``IncidentList.nextLink`` is "The link to the next page of items", and
  ``$skipToken`` "is only used if a previous operation returned a partial
  result. If a previous response contains a nextLink element, the value of
  the nextLink element will include a skiptoken parameter".

Reading only the first page is unrecoverable here rather than merely slow.
``fetch_alerts`` derives its window from the clock with no checkpoint and the
scheduler passes the poll interval as ``since_seconds``, so consecutive
windows abut: whatever a truncated page left behind falls before the next
window's lower bound and is never requested again.

Both connectors also order newest-first, so the entries dropped are the
*oldest* in the window — the start of whatever burst caused the overflow.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.connectors import azure_defender, microsoft_sentinel
from app.connectors.azure_defender import AzureDefenderConnector
from app.connectors.microsoft_sentinel import MicrosoftSentinelConnector


def _rows(prefix: str, count: int) -> list[dict[str, Any]]:
    """Rows carrying the fields each connector's ``normalize`` reads."""
    return [
        {
            "id": f"{prefix}-{i}",
            "name": f"{prefix}-{i}",
            "title": f"{prefix} {i}",
            "createdDateTime": "2099-01-01T00:00:00Z",
            "severity": "medium",
            "properties": {
                "title": f"{prefix} {i}",
                "severity": "Medium",
                "status": "New",
                "createdTimeUtc": "2099-01-01T00:00:00Z",
                "incidentNumber": i,
            },
        }
        for i in range(count)
    ]


def _paged_handler(
    total: int,
    page_size: int,
    requested: list[str],
    *,
    link_key: str,
    token_key: str,
) -> Any:
    """Serve ``total`` rows ``page_size`` at a time behind a paging link.

    The link carries the whole original query plus the skip token, which is
    the shape both vendors document and the only shape a client is allowed to
    reuse verbatim.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.microsoftonline.com":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3600})
        start = int(request.url.params.get(token_key, "0"))
        requested.append(str(start))
        body: dict[str, Any] = {"value": _rows("row", total)[start : start + page_size]}
        if start + page_size < total:
            body[link_key] = str(request.url.copy_merge_params({token_key: str(start + page_size)}))
        return httpx.Response(200, json=body)

    return handler


def _mock_client(monkeypatch: pytest.MonkeyPatch, module: Any, handler: Any) -> None:
    real_client = httpx.AsyncClient

    def factory(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", factory)


@pytest.mark.asyncio
async def test_defender_reads_every_page_of_a_truncated_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """450 Defender alerts in one window arrive in full, not the newest 200."""
    requested: list[str] = []
    _mock_client(
        monkeypatch,
        azure_defender,
        _paged_handler(450, 200, requested, link_key="@odata.nextLink", token_key="$skiptoken"),
    )
    connector = AzureDefenderConnector(tenant_id="t", client_id="c", client_secret="s")  # noqa: S106 — test

    out = await connector.fetch_alerts()

    assert requested == ["0", "200", "400"], "every page of the window must be requested"
    assert len(out) == 450, "reading one page silently discards the oldest 250 alerts of the window"


@pytest.mark.asyncio
async def test_sentinel_reads_every_page_of_a_truncated_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """230 Sentinel incidents in one window arrive in full, not the newest 100."""
    requested: list[str] = []
    _mock_client(
        monkeypatch,
        microsoft_sentinel,
        _paged_handler(230, 100, requested, link_key="nextLink", token_key="$skipToken"),
    )
    connector = MicrosoftSentinelConnector(
        tenant_id="t",
        client_id="c",
        client_secret="s",  # noqa: S106 — test
        subscription_id="sub",
        resource_group="rg",
        workspace="ws",
    )

    out = await connector.fetch_alerts()

    assert requested == ["0", "100", "200"], "every page of the window must be requested"
    assert len(out) == 230, "reading one page silently discards the oldest 130 incidents of the window"
