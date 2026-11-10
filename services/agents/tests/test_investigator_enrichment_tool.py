"""The investigator's ``enrich_ioc`` tool must reach the real enrichment service.

Two independent defects made the agent's in-run IOC enrichment silently fail
while fusion's fuse-time enrichment worked:

* **Wrong default port.** ``enrich_ioc`` fell back to ``http://enrichment:8080``
  when ``ENRICHMENT_SERVICE_URL`` was unset — and the ``agents`` service sets no
  such override. The enrichment service listens on **8082** inside the compose
  network (``8080`` is only the host-side published port), so the agent's call
  raised "All connection attempts failed" and the investigation report recorded
  "IP enrichment failed". Fusion worked because compose pins its
  ``ENRICHMENT_SERVICE_URL`` to ``http://enrichment:8082`` explicitly.
* **Wrong request field.** The body sent ``{"value", "type"}`` but the service's
  ``POST /enrich`` contract requires ``ioc_type`` (``enricher.EnrichRequest`` ->
  ``json:"ioc_type"``) and answers ``400 {"error":"ioc_type is required"}``
  otherwise — so even on the right port the call would 400.

The stub below mirrors that real contract: it is registered only at the
in-cluster URL the service actually listens on and rejects a body missing
``ioc_type`` with the same 400. The test drives the module's *default* URL (no
env override), so it pins both the port and the request shape through real
httpx transport — a route that merely checked a constant would miss the field.
"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import httpx
import pytest
import respx

# Match the path-mutation pattern used by the rest of services/agents/tests/.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

#: Where the enrichment service is actually reachable from another container on
#: the compose network — the container port, not the host-published one.
_IN_CLUSTER_ENRICHMENT = "http://enrichment:8082"


def _reload_tools(monkeypatch: pytest.MonkeyPatch):
    """Reload the tools module with no ENRICHMENT_SERVICE_URL, so its built-in
    default is what the test exercises (the deployed ``agents`` condition)."""
    monkeypatch.delenv("ENRICHMENT_SERVICE_URL", raising=False)
    module = importlib.import_module("app.investigator.tools")
    return importlib.reload(module)


def _enrichment_contract(request: httpx.Request) -> httpx.Response:
    """Stand in for the real ``POST /enrich``: ``ioc_type`` is mandatory."""
    body = json.loads(request.content or b"{}")
    if not body.get("ioc_type"):
        return httpx.Response(400, json={"error": "ioc_type is required", "code": 400})
    return httpx.Response(
        200,
        json={
            "ioc_type": body["ioc_type"],
            "value": body.get("value"),
            "risk_score": 100,
            "malicious_votes": 16,
            "verdict": "malicious",
            "sources": [{"name": "virustotal"}, {"name": "abuseipdb"}],
        },
    )


@respx.mock
async def test_enrich_ioc_reaches_service_on_default_url(monkeypatch: pytest.MonkeyPatch):
    module = _reload_tools(monkeypatch)
    route = respx.post(f"{_IN_CLUSTER_ENRICHMENT}/enrich").mock(side_effect=_enrichment_contract)

    result = await module.enrich_ioc("185.220.101.1", "ip")

    # The call reached the service at its real in-cluster URL …
    assert route.called, (
        "enrich_ioc did not reach the enrichment service at "
        f"{_IN_CLUSTER_ENRICHMENT}; default _ENRICHMENT_URL is {module._ENRICHMENT_URL!r}"
    )
    # … carrying the field the contract requires …
    sent = json.loads(route.calls.last.request.content)
    assert sent.get("ioc_type") == "ip", f"request body must use ioc_type, got {sent!r}"
    # … and it got a real enrichment result, not the swallowed-error dict.
    assert "error" not in result, f"enrich_ioc returned an error: {result!r}"
    assert result.get("risk_score") == 100
    assert result.get("ioc_type") == "ip"
