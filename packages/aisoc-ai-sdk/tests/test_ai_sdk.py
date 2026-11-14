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
import threading
import time

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


# ── a span the host made unserializable ───────────────────────────────────
#
# `_emit` copies the caller's payload values into the envelope untouched, so
# anything the host passes as `resource`, `latency_ms` or `session_id` reaches
# `json.dumps` exactly as given. A `datetime`, a `Decimal`, a `set` or any
# ordinary object is not JSON-serializable, and the host has no way to know
# that the SDK requires otherwise — the public methods take `Any` and return
# `True` the moment the span is queued.
#
# The cost of getting this wrong is the worst failure this package has: the
# serialization happens on the background worker, so the exception does not
# reach the caller at all. It ends the drain loop instead, and from then on
# the SDK is permanently silent inside a customer's agent while `enabled`
# still reads `True` and every method still answers `True`.


def test_an_unserializable_span_does_not_raise_out_of_post(monkeypatch: pytest.MonkeyPatch) -> None:
    """Serializing is part of sending, so it belongs under the same guard.

    The body used to be built *above* `_post`'s `try`, which left the one
    failure the host can actually cause as the one failure not handled.
    """
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")

    c._post(RUNTIME, [{"agent_id": "a", "resource": object()}])  # must not raise

    assert c.stats()["dropped_unserializable"] == 1
    # Not a transport failure: nothing was ever put on the wire, and conflating
    # the two would send an operator to debug their network.
    assert c.stats()["failed_transport"] == 0


def test_the_worker_survives_a_post_that_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """`_drain` documents "must never raise out of this thread" — hold it to that.

    Asserted against a `_post` that raises for *any* reason rather than against
    serialization specifically: the invariant is that no fault below the loop
    can end it, and a guard written only for today's cause would not survive
    the next one.
    """
    real_drain = AiSocAiClient._drain
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")

    def _boom(target: str, spans: list[dict[str, object]]) -> None:
        # Stop first, so the loop terminates whether or not it survives — a
        # test that hangs on the fixed tree proves nothing about the broken one.
        c._stop.set()
        raise TypeError("Object of type object is not JSON serializable")

    monkeypatch.setattr(c, "_post", _boom)
    c.tool_call("search")

    real_drain(c)  # the real loop, synchronously: must return, not propagate


def test_the_worker_thread_outlives_an_unserializable_span() -> None:
    """End to end, through the real thread the host process actually runs."""
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")
    try:
        assert c._worker is not None and c._worker.is_alive()

        # The bad type is the subject of this test, not an oversight: the
        # host's type checker cannot stop a value arriving here at runtime.
        c.tool_call("poison", resource=object())  # type: ignore[arg-type]
        deadline = time.monotonic() + 10.0
        while c.stats()["dropped_unserializable"] == 0 and time.monotonic() < deadline:
            time.sleep(0.05)

        assert c.stats()["dropped_unserializable"] == 1, "the poisoned span was never accounted for"
        assert c._worker.is_alive(), "the emitter thread died; the SDK is now silent for the life of the process"
    finally:
        c._stop.set()


# ── the request deadline ──────────────────────────────────────────────────


def test_the_request_timeout_is_the_configured_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """A host that cannot afford five seconds must be able to say so.

    Asserted on the value handed to `urlopen` rather than on the attribute,
    because the attribute existing and the attribute being *used* are the two
    different claims and only the second one matters.
    """
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    seen: list[float | None] = []

    class _Response:
        status = 200

        def __enter__(self) -> _Response:
            return self

        def __exit__(self, *exc: object) -> None:
            return None

    def _capture(request: object, timeout: float | None = None) -> _Response:
        seen.append(timeout)
        return _Response()

    monkeypatch.setattr("urllib.request.urlopen", _capture)

    AiSocAiClient(endpoint=RUNTIME, agent_id="a")._post(RUNTIME, [{"agent_id": "a"}])
    AiSocAiClient(endpoint=RUNTIME, agent_id="a", timeout_seconds=0.25)._post(RUNTIME, [{"agent_id": "a"}])

    assert seen == [5.0, 0.25]


# ── concurrent emitters ───────────────────────────────────────────────────


def test_concurrent_emitters_do_not_lose_spans(monkeypatch: pytest.MonkeyPatch) -> None:
    """Instrumentation sits in whatever threading model the host already has.

    An agent serving several requests at once emits from all of them, so the
    queue and the counters are touched concurrently. Sized under the 1000-span
    bound on purpose: this asserts that nothing is lost when nothing *should*
    be lost, which is the half `test_a_full_queue_drops_rather_than_growing`
    cannot cover.
    """
    monkeypatch.setattr(AiSocAiClient, "_drain", lambda self: None)
    c = AiSocAiClient(endpoint=RUNTIME, agent_id="a")

    workers, per_worker = 10, 50

    def _emit_many(worker: int) -> None:
        for i in range(per_worker):
            c.tool_call(f"tool-{worker}-{i}")

    threads = [threading.Thread(target=_emit_many, args=(w,)) for w in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert all(not t.is_alive() for t in threads), "an emitter thread hung"
    expected = workers * per_worker
    assert c.stats()["emitted"] == expected
    assert c.stats()["dropped_queue_full"] == 0
    assert c._queue.qsize() == expected

    names = set()
    while not c._queue.empty():
        _target, envelope = c._queue.get_nowait()
        names.add(envelope["tool_name"])
    assert len(names) == expected, "spans were lost or overwritten under concurrency"
