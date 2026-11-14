"""
Unit tests for ``app.tools.fusion`` — the HTTP client that drives the
fusion service's ``POST /process`` endpoint (Issue #190).

We mock the network with :mod:`respx` so the suite stays offline-safe.
Contract being locked in:

* happy path: the client posts the raw alert as JSON to
  ``{FUSION_SERVICE_URL}/process`` and returns the response body as a
  dict.
* the URL is built from ``FUSION_SERVICE_URL`` (default
  ``http://fusion:8003``) plus the ``/process`` suffix — *not*
  ``/api/fusion/process``. This is the regression guard for the path
  mismatch we caught during initial wiring.
* an optional ``api_token`` is forwarded as a Bearer header.
* non-2xx responses raise :class:`httpx.HTTPStatusError` (we MUST NOT
  swallow fusion failures — see the module docstring rationale).
* transport failures raise :class:`httpx.HTTPError`.

We also lock in ``DetectAgent.process`` as a thin delegate to this
client: it must pass through ``raw_alert`` and ``api_token`` unchanged
and return whatever the client returns.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

# Match the path-mutation pattern used by the rest of services/agents/tests/.
_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def raw_alert() -> dict[str, Any]:
    """Minimal ``RawAlert``-shaped dict the fusion service would accept."""
    return {
        "id": "alert-fixture-1",
        "tenant_id": "tenant-a",
        "source": "edr",
        "severity": "high",
        "title": "Suspicious PowerShell encoded command",
        "description": "Powershell -enc base64...",
        "timestamp": "2026-05-19T12:00:00Z",
        "raw_fields": {"host": "lab-1", "user": "alice"},
    }


@pytest.fixture
def fused_alert(raw_alert: dict[str, Any]) -> dict[str, Any]:
    """A representative ``FusedAlert`` envelope as returned by /process."""
    return {
        "alert": raw_alert,
        "fusion_decision": "NEW_INCIDENT",
        "incident_id": "inc-fixture-1",
        "priority_score": 0.72,
        "confidence_label": "high",
    }


@pytest.fixture
def fusion_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Pin ``FUSION_SERVICE_URL`` to a deterministic value for the test."""
    url = "http://fusion-test:8003"
    monkeypatch.setenv("FUSION_SERVICE_URL", url)
    # The module reads the env at import time, so reload it under the
    # patched env. We use ``importlib.import_module`` (rather than
    # ``import app.tools.fusion as fusion_module``) so CodeQL's
    # py/import-and-import-from rule doesn't flag this file as mixing
    # ``import`` and ``from ... import``; the test bodies already use
    # ``from app.tools.fusion import process_alert`` after this reload.
    import importlib

    fusion_module = importlib.import_module("app.tools.fusion")
    importlib.reload(fusion_module)
    return url


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


async def test_process_alert_posts_to_root_process_endpoint(
    raw_alert: dict[str, Any],
    fused_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """Client must hit ``/process`` at the root, **not** ``/api/fusion/process``.

    Regression guard: the agents service's ``DetectAgent.process`` reached
    a 404 in early wiring because the client was posting to a stale path
    that didn't match where the fusion service mounts its router. The
    test fails loudly if anyone reintroduces that mismatch.
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url, assert_all_called=True) as router:
        route = router.post("/process").mock(
            return_value=httpx.Response(200, json=fused_alert),
        )

        result = await process_alert(raw_alert)

    assert result == fused_alert
    assert route.called
    # The request body is exactly the raw alert we passed in — the client
    # is a thin pass-through, not a transformer.
    assert route.calls.last.request.read() == httpx.Request("POST", f"{fusion_url}/process", json=raw_alert).read()


async def test_process_alert_forwards_bearer_token(
    raw_alert: dict[str, Any],
    fused_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """An ``api_token`` arg is forwarded as ``Authorization: Bearer ...``.

    The fusion service can enforce auth on ``/process``; the agents-side
    client must pass through the caller's token unmodified.
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url, assert_all_called=True) as router:
        route = router.post("/process").mock(
            return_value=httpx.Response(200, json=fused_alert),
        )

        await process_alert(raw_alert, api_token="tok-123")

    assert route.calls.last.request.headers["authorization"] == "Bearer tok-123"


async def test_process_alert_no_token_omits_authorization_header(
    raw_alert: dict[str, Any],
    fused_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """When no token is provided we MUST NOT send a bare/blank Bearer header.

    A blank Authorization header would force the fusion service to reject
    legitimate unauthenticated calls; this test pins the "absent is
    absent" contract.
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url, assert_all_called=True) as router:
        route = router.post("/process").mock(
            return_value=httpx.Response(200, json=fused_alert),
        )

        await process_alert(raw_alert)

    assert "authorization" not in {k.lower() for k in route.calls.last.request.headers}


# ---------------------------------------------------------------------------
# Error handling — fusion failures MUST propagate
# ---------------------------------------------------------------------------


async def test_process_alert_raises_on_503_when_worker_not_ready(
    raw_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """A 503 from the fusion worker MUST raise ``HTTPStatusError``.

    Per the module docstring, the fusion plane is the primary detection
    path: if it's down, callers must know. Silently swallowing the error
    and returning a fake envelope would lose alerts.
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url) as router:
        router.post("/process").mock(
            return_value=httpx.Response(503, json={"detail": "Fusion worker not ready"}),
        )

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await process_alert(raw_alert)

    assert exc_info.value.response.status_code == 503


async def test_process_alert_raises_on_422_for_malformed_payload(
    fusion_url: str,
) -> None:
    """A 422 from FastAPI validation MUST raise ``HTTPStatusError``.

    Garbage in, loud failure out. The agent that called us needs the
    feedback to fix its payload, not a silent ``None``.
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url) as router:
        router.post("/process").mock(
            return_value=httpx.Response(422, json={"detail": "validation error"}),
        )

        with pytest.raises(httpx.HTTPStatusError) as exc_info:
            await process_alert({"not": "a real alert"})

    assert exc_info.value.response.status_code == 422


async def test_process_alert_raises_on_transport_failure(
    raw_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """A transport-level failure (connect error, timeout) MUST propagate.

    We assert the broader ``httpx.HTTPError`` so the test stays stable
    across the specific exception type httpx picks for a side-effect
    (it varies between connect errors and timeouts).
    """
    from app.tools.fusion import process_alert

    async with respx.mock(base_url=fusion_url) as router:
        router.post("/process").mock(side_effect=httpx.ConnectError("boom"))

        with pytest.raises(httpx.HTTPError):
            await process_alert(raw_alert)


# ---------------------------------------------------------------------------
# DetectAgent.process — delegate contract
# ---------------------------------------------------------------------------


async def test_detect_agent_process_delegates_to_fusion_client(
    raw_alert: dict[str, Any],
    fused_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """``DetectAgent.process`` is a thin façade over ``process_alert``.

    The public agent surface promises that ``DetectAgent.process`` runs
    the full fusion pipeline; the implementation route is the HTTP client
    above. This test guards that contract end-to-end with a mocked HTTP
    transport so we exercise the *actual* code path the production
    DetectAgent uses, not a monkeypatched stub.
    """
    from app.agents import DetectAgent

    async with respx.mock(base_url=fusion_url, assert_all_called=True) as router:
        router.post("/process").mock(
            return_value=httpx.Response(200, json=fused_alert),
        )

        result = await DetectAgent.process(raw_alert)

    assert result == fused_alert


async def test_detect_agent_process_forwards_api_token(
    raw_alert: dict[str, Any],
    fused_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """The keyword-only ``api_token`` must reach the fusion service."""
    from app.agents import DetectAgent

    async with respx.mock(base_url=fusion_url, assert_all_called=True) as router:
        route = router.post("/process").mock(
            return_value=httpx.Response(200, json=fused_alert),
        )

        await DetectAgent.process(raw_alert, api_token="downstream-tok")

    assert route.calls.last.request.headers["authorization"] == "Bearer downstream-tok"


async def test_detect_agent_process_propagates_fusion_errors(
    raw_alert: dict[str, Any],
    fusion_url: str,
) -> None:
    """``DetectAgent.process`` MUST raise when fusion raises.

    A silent fallback here would hide a degraded detection plane behind
    a green ``DetectAgent`` call — exactly the failure mode the module
    docstring warns about.
    """
    from app.agents import DetectAgent

    async with respx.mock(base_url=fusion_url) as router:
        router.post("/process").mock(
            return_value=httpx.Response(500, json={"detail": "oops"}),
        )

        with pytest.raises(httpx.HTTPStatusError):
            await DetectAgent.process(raw_alert)
