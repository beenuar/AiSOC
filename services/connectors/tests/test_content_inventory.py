"""The /content inventory legs against mock vendors (WS1.2).

Each case drives the REAL connector method over a mocked HTTP transport
shaped from the vendor's published response schema — the house mock-vendor
convention. What is pinned: only scheduled/correlation Splunk searches
survive the filter, Elastic's ATT&CK mapping is carried where the author
set one, paging follows the vendor's own contract, and the route refuses
(501) for connectors that never opted in.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
from app.connectors.elastic import ElasticConnector
from app.connectors.splunk import SplunkConnector


def _transport(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


@pytest.mark.asyncio
async def test_splunk_lists_only_scheduled_and_correlation_searches(monkeypatch: pytest.MonkeyPatch) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/services/saved/searches"
        assert request.headers["Authorization"] == "Bearer tok"
        return httpx.Response(
            200,
            json={
                "entry": [
                    {
                        "name": "Threat - Brute Force - Rule",
                        "id": "https://splunk/servicesNS/.../Threat%20-%20Brute%20Force",
                        "content": {
                            "is_scheduled": True,
                            "action.correlationsearch.enabled": "1",
                            "search": "index=auth action=failure | stats count by user",
                            "cron_schedule": "*/5 * * * *",
                            "disabled": False,
                        },
                    },
                    {
                        "name": "ad-hoc leftover",
                        "id": "x",
                        "content": {"is_scheduled": False, "search": "index=main"},
                    },
                ]
            },
        )

    real_client = httpx.AsyncClient

    def _client(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("verify", None)
        return real_client(transport=_transport(handler), **kwargs)

    monkeypatch.setattr("app.connectors.splunk.httpx.AsyncClient", _client)
    connector = SplunkConnector(base_url="https://splunk.example:8089", token="tok")
    rules = await connector.list_detection_content()
    assert len(rules) == 1, "the ad-hoc search must not inventory"
    rule = rules[0]
    assert rule["kind"] == "correlation"
    assert rule["enabled"] is True
    assert "stats count by user" in rule["query"]


@pytest.mark.asyncio
async def test_elastic_carries_the_rules_own_attack_mapping(monkeypatch: pytest.MonkeyPatch) -> None:
    pages: list[dict[str, Any]] = [
        {
            "total": 2,
            "data": [
                {
                    "rule_id": "r-1",
                    "name": "Credential Access via LSASS",
                    "enabled": True,
                    "type": "eql",
                    "query": 'process where process.name == "procdump.exe"',
                    "severity": "high",
                    "threat": [
                        {"technique": [{"id": "T1003"}, {"id": "T1003.001"}]},
                    ],
                },
                {
                    "rule_id": "r-2",
                    "name": "No mapping set",
                    "enabled": False,
                    "type": "query",
                    "query": "event.action:logon",
                    "severity": "low",
                },
            ],
        }
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/detection_engine/rules/_find"
        assert request.headers["kbn-xsrf"] == "true"
        return httpx.Response(200, json=pages[0])

    real_client = httpx.AsyncClient

    def _client(**kwargs: Any) -> httpx.AsyncClient:
        kwargs.pop("verify", None)
        return real_client(transport=_transport(handler), **kwargs)

    monkeypatch.setattr("app.connectors.elastic.httpx.AsyncClient", _client)
    connector = ElasticConnector(base_url="https://kibana.example", api_key="k")
    rules = await connector.list_detection_content()
    assert len(rules) == 2
    mapped = next(r for r in rules if r["vendor_rule_id"] == "r-1")
    assert mapped["attack"] == ["T1003", "T1003.001"]
    unmapped = next(r for r in rules if r["vendor_rule_id"] == "r-2")
    assert unmapped["attack"] == [], "absent stays empty, never guessed"
    assert unmapped["enabled"] is False


def test_the_content_route_refuses_unopted_connectors() -> None:
    """Mounted bare (the vuln-visibility precedent), so the refusal under
    test is the route's own 501 and not the service middleware's auth."""
    from app.api.router import router
    from app.security.tenant_scope import require_console_or_service_auth
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    # The router-level auth is the service middleware's concern, proven in
    # its own suite; here the subject is the route's 501 refusal.
    app.dependency_overrides[require_console_or_service_auth] = lambda: None
    client = TestClient(app)
    response = client.post(
        "/api/v1/connectors/proofpoint/content",
        json={"auth_config": {}, "connector_config": {}},
    )
    assert response.status_code == 501
    assert "does not expose a detection-content inventory" in response.json()["detail"]
