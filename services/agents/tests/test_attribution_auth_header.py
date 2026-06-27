"""The investigation agent forwards the threatintel shared secret when set.

When ``AISOC_THREATINTEL_SERVICE_TOKEN`` is configured, the agent's
attribution call must carry ``Authorization: Bearer <token>`` so a
``threatintel`` service that enforces the gate accepts it; when unset, no
auth header is sent (internal-only default). Network mocked with respx.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest
import respx

# Match the path-mutation pattern used by the rest of services/agents/tests/.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))

_BASE = "http://ti-test:8005"


def _reload_agent(monkeypatch: pytest.MonkeyPatch, token: str | None):
    monkeypatch.setenv("AISOC_THREATINTEL_URL", _BASE)
    if token is None:
        monkeypatch.delenv("AISOC_THREATINTEL_SERVICE_TOKEN", raising=False)
    else:
        monkeypatch.setenv("AISOC_THREATINTEL_SERVICE_TOKEN", token)
    module = importlib.import_module("app.agents.investigation_agent")
    return importlib.reload(module)


@respx.mock
async def test_forwards_bearer_when_token_set(monkeypatch: pytest.MonkeyPatch):
    module = _reload_agent(monkeypatch, "s3cret-token")
    route = respx.post(f"{_BASE}/api/v1/actors/attribute").mock(
        return_value=httpx.Response(200, json={"actor_id": "unknown"}),
    )
    await module._call_attribution_service(iocs=[], mitre_techniques=["T1566"], case_metadata={})
    assert route.calls.last.request.headers.get("authorization") == "Bearer s3cret-token"


@respx.mock
async def test_no_auth_header_when_token_unset(monkeypatch: pytest.MonkeyPatch):
    module = _reload_agent(monkeypatch, None)
    route = respx.post(f"{_BASE}/api/v1/actors/attribute").mock(
        return_value=httpx.Response(200, json={"actor_id": "unknown"}),
    )
    await module._call_attribution_service(iocs=[], mitre_techniques=["T1566"], case_metadata={})
    header_names = {k.lower() for k in route.calls.last.request.headers.keys()}
    assert "authorization" not in header_names
