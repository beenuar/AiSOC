"""The LLM panel must not report Live while every call is failing (issue #1241).

``GET /api/v1/llm/status`` places no call. ``_compute_status`` decides
``effective_path`` from ``key_set`` and the air-gap policy alone, so a
deployment whose every completion times out renders the emerald **Live** pill
in Settings → Deployment & AI. The panel's own header says the indicator
"cannot drift from runtime behaviour", which is true of *which provider is
configured* and false of *whether it answers*.

What is added is a recent-outcome signal, not a probe: ``safe_chat_completions_request``
is the single chokepoint every LLM call in this service already goes through,
so the calls the product is making anyway are what the status reports. No
synthetic completion on page load, and no latency number — the honest answer to
"how fast is it" is one nobody has measured here.

The three states are deliberate, and ``unknown`` is the important one: a pod
that has placed no call has observed nothing, and saying so is different from
saying the provider is healthy. Reporting a fabricated green for an absence of
data is the defect in a different costume.
"""

from __future__ import annotations

import httpx
import pytest
from app.api.v1.endpoints.llm_status import llm_status
from app.services import llm_health
from app.services.llm_safety import safe_chat_completions_request

_MESSAGES = [{"role": "user", "content": "Summarise this alert for an analyst."}]


@pytest.fixture(autouse=True)
def _clean(monkeypatch: pytest.MonkeyPatch):
    """A live-looking configuration, and an empty outcome window."""
    for var in (
        "LLM_BASE_URL",
        "LLM_MODEL",
        "OPENAI_BASE_URL",
        "OPENAI_MODEL",
        "AISOC_LLM_MODEL",
        "LLM_GATEWAY_URL",
        "LITELLM_MASTER_KEY",
    ):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    llm_health.reset()
    yield
    llm_health.reset()


async def _call_through_the_real_chokepoint(handler) -> None:
    """Drive the real ``safe_chat_completions_request`` over a mock transport.

    Deliberately not a direct call to the recorder: the property under test is
    that the function the endpoints already use records what happened, and a
    test that records the outcome itself would pass against a recorder nothing
    calls.
    """
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await safe_chat_completions_request(
            api_key="sk-test",
            model="aisoc-triage",
            messages=_MESSAGES,
            url="http://litellm:4000/v1/chat/completions",
            client=client,
        )


def _ok(_request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})


def _timeout(request: httpx.Request) -> httpx.Response:
    raise httpx.ReadTimeout("timed out", request=request)


# ---------------------------------------------------------------------------
# The status surface
# ---------------------------------------------------------------------------


def test_no_observed_calls_reports_unknown_not_healthy() -> None:
    """An absence of evidence is reported as such, never as a green light."""
    status = llm_status()
    assert status["recent_health"] == "unknown"
    assert status["effective_path"] == "live", "configuration is still live — only the outcome is unknown"


async def test_a_timing_out_provider_is_reported_degraded() -> None:
    """The headline case: configured, reachable-looking, and answering nothing."""
    for _ in range(3):
        with pytest.raises(httpx.ReadTimeout):
            await _call_through_the_real_chokepoint(_timeout)

    status = llm_status()
    assert status["recent_health"] == "degraded", "every recent call timed out and the panel would still render the emerald Live pill"
    assert status["recent_failures"] == 3
    assert "timeout" in str(status["recent_note"]).lower() or "fail" in str(status["recent_note"]).lower(), (
        f"the operator is told nothing actionable: {status['recent_note']!r}"
    )


async def test_a_working_provider_is_reported_healthy() -> None:
    await _call_through_the_real_chokepoint(_ok)
    status = llm_status()
    assert status["recent_health"] == "healthy"
    assert status["recent_failures"] == 0


async def test_recovery_clears_the_degraded_state() -> None:
    """A provider that comes back must not stay red — this is a window, not a latch."""
    for _ in range(3):
        with pytest.raises(httpx.ReadTimeout):
            await _call_through_the_real_chokepoint(_timeout)
    assert llm_status()["recent_health"] == "degraded"

    for _ in range(5):
        await _call_through_the_real_chokepoint(_ok)

    assert llm_status()["recent_health"] == "healthy", "a recovered provider stayed red"


async def test_an_http_error_counts_as_a_failure_too() -> None:
    """A 500 from the gateway is a failed call, not just a timeout."""

    def _five_hundred(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "upstream exploded"})

    for _ in range(3):
        with pytest.raises(httpx.HTTPStatusError):
            await _call_through_the_real_chokepoint(_five_hundred)

    assert llm_status()["recent_health"] == "degraded"


def test_status_publishes_no_latency_figure() -> None:
    """No measured latency exists for this path, so none is published.

    Guards against a future 'helpful' average that would be the fabricated
    number the issue warns about.
    """
    status = llm_status()
    assert not [k for k in status if "latency" in k or "ms" in k.lower()], (
        f"status surfaced a latency-shaped field nobody measured: {sorted(status)}"
    )


# ---------------------------------------------------------------------------
# The recorder itself
# ---------------------------------------------------------------------------


async def test_a_contract_violation_is_not_counted_as_a_provider_failure() -> None:
    """Refusing to send is AiSOC working correctly, not the provider failing.

    ``LLMInputContract`` aborts before the network call. Counting that as a
    provider outage would make the panel blame the model for a prompt the
    product deliberately refused to send.
    """
    from app.services.llm_safety import LLMContractViolation

    raw_ocsf = '{"class_uid": 2001, "activity_id": 1, "metadata": {"product": {"name": "x"}, "version": "1.0"}}'
    with pytest.raises(LLMContractViolation):
        async with httpx.AsyncClient(transport=httpx.MockTransport(_ok)) as client:
            await safe_chat_completions_request(
                api_key="sk-test",
                model="aisoc-triage",
                messages=[{"role": "user", "content": raw_ocsf}],
                client=client,
            )

    status = llm_status()
    assert status["recent_health"] == "unknown", "a refused prompt was recorded as a provider outcome; nothing was ever sent"
    assert status["recent_failures"] == 0
