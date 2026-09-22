"""The SDK runs inside somebody else's agent, so its failure modes matter most.

Two properties are non-negotiable and get the most coverage here.

**Prompt content does not leave the process by default.** Prompts and model
responses routinely contain whatever a user pasted in and whatever a retrieval
step pulled out of an internal store. A SOC needs to detect abuse of the AI
without becoming the largest single collection of that text in the company.

**Instrumentation never breaks the host application.** A network failure, a bad
token or an unreachable AiSOC must degrade to a dropped span, never to an
exception escaping into the caller's request path.
"""

from __future__ import annotations

import json

import pytest
from aisoc_ai import AiSocAiClient, CaptureMode, redact, secret_kinds

RUNTIME = "https://aisoc.example.com/v1/inbox/runtime-token"
FINDINGS = "https://aisoc.example.com/v1/inbox/finding-token"


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch):
    """A client whose background worker is replaced by a capture list."""
    sent: list[tuple[str, list[dict]]] = []

    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, finding_endpoint=FINDINGS, agent_id="support-bot")
    monkeypatch.setattr(c, "_post", lambda target, spans: sent.append((target, spans)))

    def _drain_now():
        batches: dict[str, list[dict]] = {}
        while not c._queue.empty():
            target, envelope = c._queue.get_nowait()
            batches.setdefault(target, []).append(envelope)
        for target, spans in batches.items():
            c._post(target, spans)
        return sent

    c.drain_now = _drain_now  # type: ignore[attr-defined]
    return c


# ── redaction ─────────────────────────────────────────────────────────────


def test_prompt_content_is_not_transmitted_by_default():
    """The single most important property in this package."""
    result = redact("the user's private medical history", CaptureMode.HASHED)
    assert result.content is None
    assert result.sha256
    assert result.length == len("the user's private medical history")


def test_the_same_prompt_hashes_the_same_way():
    """Repeat detection is the point of sending a hash at all."""
    assert redact("abc").sha256 == redact("abc").sha256
    assert redact("abc").sha256 != redact("abd").sha256


def test_masked_mode_removes_secret_shapes():
    result = redact("key AKIAIOSFODNN7EXAMPLE and sk-abcdefghijklmnopqrstuv", CaptureMode.MASKED)
    assert "AKIAIOSFODNN7EXAMPLE" not in (result.content or "")
    assert "sk-abcdefghijklmnopqrstuv" not in (result.content or "")
    assert set(result.redacted_kinds) == {"aws_access_key", "openai_key"}


def test_full_mode_is_verbatim():
    """It exists for incident response, and must not silently half-redact."""
    text = "AKIAIOSFODNN7EXAMPLE"
    assert redact(text, CaptureMode.FULL).content == text


def test_secret_shapes_are_detectable_without_sending_content():
    """ "This prompt contained a private key" is a finding on its own."""
    assert "private_key" in secret_kinds("-----BEGIN RSA PRIVATE KEY-----\nabc")
    assert secret_kinds("nothing sensitive here") == ()


def test_none_and_empty_text_are_handled():
    assert redact(None).sha256 == ""
    assert redact(None).length == 0
    assert secret_kinds(None) == ()
    assert redact("", CaptureMode.MASKED).content == ""


def test_a_model_call_sends_a_digest_not_the_prompt(client):
    client.model_call(
        "gpt-4o",
        prompt="patient record for alice@example.com",
        response="summary text",
        prompt_tokens=120,
    )
    (_target, spans) = client.drain_now()[0]
    span = spans[0]
    assert "prompt" not in span
    assert "response" not in span
    assert span["prompt_sha256"]
    assert span["prompt_length"] == len("patient record for alice@example.com")
    # And the fact it contained an email is still reported.
    assert "email" in span["prompt_secret_kinds"]


def test_opting_into_capture_includes_masked_content(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    sent: list = []
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a", capture=CaptureMode.MASKED)
    monkeypatch.setattr(c, "_post", lambda target, spans: sent.append(spans))
    c.model_call("gpt-4o", prompt="token AKIAIOSFODNN7EXAMPLE")
    target, envelope = c._queue.get_nowait()
    c._post(target, [envelope])
    assert "[redacted:aws_access_key]" in sent[0][0]["prompt"]


# ── the routine / finding split ───────────────────────────────────────────


def test_a_finding_goes_to_the_finding_endpoint(client):
    """Findings normalize to OCSF 2001 and are always promoted.

    Sending one to the runtime endpoint would normalize it as category 6 API
    Activity, which the promoter leaves in the lake — silently downgrading a
    detected injection into routine telemetry.
    """
    client.finding("prompt_injection", "Instruction override in retrieved doc")
    (target, spans) = client.drain_now()[0]
    assert target == FINDINGS
    assert spans[0]["finding_type"] == "prompt_injection"


def test_a_tool_call_goes_to_the_runtime_endpoint(client):
    client.tool_call("search_tickets")
    (target, _spans) = client.drain_now()[0]
    assert target == RUNTIME


def test_a_finding_without_a_finding_endpoint_warns(monkeypatch: pytest.MonkeyPatch, caplog):
    """Falling back is a real downgrade, so it must be loud."""
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")
    monkeypatch.setattr(c, "_post", lambda target, spans: None)
    with caplog.at_level("WARNING"):
        c.finding("prompt_injection", "x")
    assert "will not be promoted" in caplog.text


# ── tool-call argument handling ───────────────────────────────────────────


def test_tool_argument_keys_are_sent_but_not_values(client):
    """Which parameters were used is the signal; the values are the risk."""
    client.tool_call("run_query", arguments={"sql": "SELECT * FROM patients", "limit": 10})
    (_target, spans) = client.drain_now()[0]
    span = spans[0]
    assert span["argument_keys"] == ["limit", "sql"]
    assert "SELECT * FROM patients" not in json.dumps(span)


def test_on_behalf_of_is_carried(client):
    """An agent acting autonomously and one acting for a user differ in risk."""
    client.tool_call("delete_records", on_behalf_of="alice@example.com")
    (_target, spans) = client.drain_now()[0]
    assert spans[0]["on_behalf_of"] == "alice@example.com"


# ── never break the host application ──────────────────────────────────────


def test_no_endpoint_disables_rather_than_raising():
    """An unset endpoint is how an operator turns the SDK off."""
    c = AiSocAiClient(endpoint="", agent_id="a")
    assert c.enabled is False
    assert c.tool_call("anything") is False


def test_a_transport_failure_does_not_raise(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")

    def _boom(request, timeout=None):  # noqa: ANN001
        raise OSError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    c.tool_call("search")
    target, envelope = c._queue.get_nowait()
    c._post(target, [envelope])  # must not raise
    assert c.stats()["failed_transport"] == 1


def test_a_full_queue_drops_rather_than_growing(monkeypatch: pytest.MonkeyPatch):
    """Unbounded buffering inside a customer's process is the worse failure."""
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")
    for i in range(1200):
        c.tool_call(f"tool-{i}")
    assert c._queue.qsize() <= 1000
    assert c.stats()["dropped_queue_full"] > 0


def test_counters_make_a_silent_sdk_diagnosable(client):
    client.tool_call("a")
    client.tool_call("b")
    assert client.stats()["emitted"] == 2
