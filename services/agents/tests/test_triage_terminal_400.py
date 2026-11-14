"""Terminal 400-class rejection: dead-letter once, never replay.

The prefill-guard incident replayed identical doomed requests every retry
attempt. A deterministic request rejection must go straight to the DLQ on
first sight and stop consuming the inference backend.
"""

from __future__ import annotations

import pytest
from app.workers import fused_alert_consumer as worker_mod
from app.workers.fused_alert_consumer import FusedAlertTriageWorker, _is_terminal_request_error

pytestmark = pytest.mark.asyncio


class FakeBadRequest(Exception):
    status_code = 400


def _worker(monkeypatch, triage_exc: Exception, max_attempts: int = 3):
    worker = FusedAlertTriageWorker(bootstrap_servers="ignored", max_attempts=max_attempts)
    calls = {"triage": 0}

    async def _boom(_msg):
        calls["triage"] += 1
        raise triage_exc

    dlq: list[dict] = []

    async def _dlq(message, *, attempts, stage, error):
        dlq.append({"attempts": attempts, "stage": stage, "error": error})

    monkeypatch.setattr(worker, "triage", _boom)
    monkeypatch.setattr(worker, "_send_to_dlq", _dlq)
    monkeypatch.setattr(worker_mod, "_RETRY_BACKOFF_S", 0.0)
    return worker, calls, dlq


async def test_terminal_400_deadletters_without_retry(monkeypatch):
    worker, calls, dlq = _worker(monkeypatch, FakeBadRequest("prefill memory guard rejected"))
    ok = await worker._process_with_retry({"id": "alert-1"})
    assert ok is False
    assert calls["triage"] == 1  # never replayed
    assert len(dlq) == 1
    assert dlq[0]["stage"] == "triage-terminal"


async def test_retryable_error_still_retries_then_dlqs(monkeypatch):
    worker, calls, dlq = _worker(monkeypatch, RuntimeError("transient"), max_attempts=3)
    ok = await worker._process_with_retry({"id": "alert-2"})
    assert ok is False
    assert calls["triage"] == 3
    assert dlq[0]["stage"] == "triage"


async def test_wrapped_bad_request_detected_through_cause_chain():
    try:
        try:
            raise FakeBadRequest("context_length_exceeded")
        except FakeBadRequest as inner:
            raise RuntimeError("wrapper") from inner
    except RuntimeError as outer:
        assert _is_terminal_request_error(outer) is True
    assert _is_terminal_request_error(RuntimeError("network blip")) is False
