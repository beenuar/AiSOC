"""
Smoke test for the hello-connector tutorial example.

Two jobs:

1. Catch tutorial drift. The example file under
   ``app/connectors/_examples/hello_connector.py`` is shown verbatim in
   ``apps/docs/docs/connectors/hello-connector.md``. If someone edits
   the example, this test fails noisily, which forces the docs PR to
   re-check the snippets.

2. Prove the example is honest. Every method the tutorial walks the
   reader through (``schema``, ``capabilities``, ``test_connection``,
   ``fetch_alerts``, ``normalize``) is exercised here against mocked
   httpbin responses. The tutorial says "this works" — these tests are
   the receipts.

We deliberately *don't* assert that ``HelloConnector`` shows up in
``CONNECTOR_REGISTRY``: it must not. Test ``test_not_registered`` pins
that invariant so a well-meaning contributor doesn't accidentally
promote the tutorial example into the live catalog.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from app.connectors import CONNECTOR_REGISTRY
from app.connectors._examples.hello_connector import HelloConnector
from app.connectors.base import Capability

# ---------------------------------------------------------------------------
# Identity / registration invariants
# ---------------------------------------------------------------------------


def test_not_registered():
    """The tutorial example must NOT be in the live registry.

    If this fails, somebody added ``HelloConnector`` to
    ``_CONNECTOR_CLASSES`` in ``app/connectors/__init__.py``. Either
    revert that, or move the example out of ``_examples/`` into a real
    connector module (and update the tutorial accordingly).
    """
    assert "hello" not in CONNECTOR_REGISTRY


def test_identity_attributes():
    """Identity attributes are the public-facing contract, so pin them."""
    assert HelloConnector.connector_id == "hello"
    assert HelloConnector.connector_name == "Hello (Tutorial)"
    assert HelloConnector.connector_category == "saas"


# ---------------------------------------------------------------------------
# schema()
# ---------------------------------------------------------------------------


def test_schema_shape():
    """Schema must be wizard-renderable: required fields present, secret
    fields marked, docs link populated."""
    schema = HelloConnector.schema().to_dict()

    assert schema["connector_id"] == "hello"
    assert schema["category"] == "saas"
    assert schema["docs_url"] == "/docs/connectors/hello-connector"

    field_names = [f["name"] for f in schema["fields"]]
    assert field_names == ["api_token", "base_url"]

    # The token must be marked secret so the credential vault encrypts it.
    api_token = next(f for f in schema["fields"] if f["name"] == "api_token")
    assert api_token["type"] == "secret"

    # ``base_url`` is optional with a sensible default — verify both flags.
    base_url = next(f for f in schema["fields"] if f["name"] == "base_url")
    assert base_url["required"] is False
    assert base_url["default"] == "https://httpbin.org"


def test_capabilities_are_read_only():
    """Tutorial connector is read-only by design — the only capability
    it should declare is ``PULL_ALERTS``. Any drift here likely means
    someone added a kinetic verb to the example without thinking
    through the implications for new contributors copying it."""
    assert HelloConnector.capabilities() == (Capability.PULL_ALERTS,)


# ---------------------------------------------------------------------------
# test_connection()
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_success():
    """200 from /status/200 → success."""
    respx.get("https://httpbin.org/status/200").mock(return_value=httpx.Response(200))
    conn = HelloConnector(api_token="t")
    result = await conn.test_connection()
    assert result == {"success": True, "connector": "hello"}


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_bad_status():
    """Non-200 → structured failure, not a raised exception. The wizard
    relies on this shape to render the error inline."""
    respx.get("https://httpbin.org/status/200").mock(return_value=httpx.Response(503))
    conn = HelloConnector(api_token="t")
    result = await conn.test_connection()
    assert result["success"] is False
    assert "503" in result["error"]
    assert result["connector"] == "hello"


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_network_error():
    """Network failures (DNS, TLS, timeout) must also surface as a
    structured failure rather than bubbling exceptions up to the API
    layer (which would render as a 500 to the operator)."""
    respx.get("https://httpbin.org/status/200").mock(side_effect=httpx.ConnectError("boom"))
    conn = HelloConnector(api_token="t")
    result = await conn.test_connection()
    assert result["success"] is False
    assert "ConnectError" in result["error"]


@respx.mock
@pytest.mark.asyncio
async def test_test_connection_respects_base_url_override():
    """A custom base_url must actually be used. Catches the classic
    bug of saving the override into ``self._base_url`` but forgetting
    to swap out the hard-coded constant in the URL builder."""
    respx.get("https://httpbin.local/status/200").mock(return_value=httpx.Response(200))
    conn = HelloConnector(api_token="t", base_url="https://httpbin.local/")
    result = await conn.test_connection()
    assert result["success"] is True


# ---------------------------------------------------------------------------
# fetch_alerts()
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_returns_normalized_event():
    """Happy path: vendor responds, connector wraps the response in a
    single normalized event with the raw payload preserved."""
    respx.get("https://httpbin.org/anything").mock(
        return_value=httpx.Response(
            200,
            json={
                "url": "https://httpbin.org/anything?since_seconds=300",
                "origin": "192.0.2.10",
                "headers": {"Host": "httpbin.org"},
            },
        )
    )

    conn = HelloConnector(api_token="t")
    events = await conn.fetch_alerts(since_seconds=300)

    assert len(events) == 1
    event = events[0]
    assert event["source"] == "hello"
    assert event["category"] == "saas"
    assert event["severity"] == "info"
    # Title surfaces the URL so an operator can tell two events apart.
    assert "https://httpbin.org/anything" in event["title"]
    # alert_id should be stable for the same response (the connector
    # composes it from origin + url).
    assert event["alert_id"] == "hello:192.0.2.10:https://httpbin.org/anything?since_seconds=300"
    # raw must be preserved end-to-end so detection rules and explain
    # lineage have something to chew on.
    assert event["raw"]["origin"] == "192.0.2.10"


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_passes_since_seconds_as_query_param():
    """``since_seconds`` should land on the wire. The example's docstring
    explicitly tells readers "keep this in the signature, the scheduler
    always passes it" — so verify it actually flows through."""
    route = respx.get("https://httpbin.org/anything").mock(return_value=httpx.Response(200, json={"url": "x", "origin": "y"}))

    conn = HelloConnector(api_token="t")
    await conn.fetch_alerts(since_seconds=900)

    assert route.called
    qs = dict(route.calls[0].request.url.params)
    assert qs == {"since_seconds": "900"}


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_swallows_http_errors():
    """5xx → empty list, no raise. Polling failures are non-terminal —
    the scheduler logs and tries again next interval."""
    respx.get("https://httpbin.org/anything").mock(return_value=httpx.Response(500))
    conn = HelloConnector(api_token="t")
    events = await conn.fetch_alerts()
    assert events == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_swallows_network_errors():
    """Network errors must also be non-terminal."""
    respx.get("https://httpbin.org/anything").mock(side_effect=httpx.ReadTimeout("slow"))
    conn = HelloConnector(api_token="t")
    events = await conn.fetch_alerts()
    assert events == []


@respx.mock
@pytest.mark.asyncio
async def test_fetch_alerts_swallows_invalid_json():
    """If the vendor returns 200 with garbage in the body, we must not
    crash the polling loop. ``[]`` is the right answer here — there's
    nothing to ingest, but the connector's still "alive enough"."""
    respx.get("https://httpbin.org/anything").mock(return_value=httpx.Response(200, content=b"not json at all"))
    conn = HelloConnector(api_token="t")
    events = await conn.fetch_alerts()
    assert events == []


# ---------------------------------------------------------------------------
# normalize()
# ---------------------------------------------------------------------------


def test_normalize_preserves_raw():
    """``normalize`` must keep the original payload accessible under
    ``raw`` — detection rules and the explain endpoint both rely on it."""
    raw = {"url": "https://httpbin.org/anything", "origin": "10.0.0.1", "extra": {"k": "v"}}
    conn = HelloConnector(api_token="t")
    norm = conn.normalize(raw)
    assert norm["raw"] is raw
    assert norm["raw"]["extra"] == {"k": "v"}


def test_normalize_handles_missing_url():
    """Defensive shape: missing fields should not blow up normalization.
    The tutorial walks through this exact path so we pin it."""
    conn = HelloConnector(api_token="t")
    norm = conn.normalize({})
    assert norm["title"] == "Hello connector: pinged (no url)"
    assert norm["alert_id"] == "hello:?:(no url)"
