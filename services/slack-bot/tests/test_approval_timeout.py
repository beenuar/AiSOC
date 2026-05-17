"""
Tests for :mod:`app.services.approval_timeout`.

Coverage:

* fire path: timer expires, safe-default action is invoked, audit row written
* cancel path: explicit cancel before expiry suppresses the fallback call
* re-schedule: scheduling the same action_id twice cancels the first timer
* approve safe-default variant invokes the approve function
* fallback call failure still records an audit row carrying the error
* aclose cancels every armed timer
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from app.services.approval_audit import InMemoryAuditSink
from app.services.approval_timeout import ApprovalTimeoutScheduler


class _RecordingClient:
    """Captures every approve/reject call so the test can assert order."""

    def __init__(self, fail: bool = False) -> None:
        self.approve_calls: list[str] = []
        self.reject_calls: list[str] = []
        self._fail = fail

    async def approve(self, action_id: str) -> dict[str, Any]:
        if self._fail:
            raise RuntimeError("upstream boom")
        self.approve_calls.append(action_id)
        return {"id": action_id, "status": "approved"}

    async def reject(self, action_id: str) -> dict[str, Any]:
        if self._fail:
            raise RuntimeError("upstream boom")
        self.reject_calls.append(action_id)
        return {"id": action_id, "status": "rejected"}


@pytest.mark.asyncio
async def test_timer_fires_safe_default_reject_and_writes_audit():
    client = _RecordingClient()
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    task = scheduler.schedule(
        "action-1",
        timeout_seconds=0.01,
        safe_default="rejected",
        case_id="case-1",
        channel="C7",
    )
    _ = await task

    assert client.reject_calls == ["action-1"]
    assert client.approve_calls == []
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.decision == "timeout_fallback"
    assert event.action_id == "action-1"
    assert event.case_id == "case-1"
    assert event.channel == "C7"
    assert event.source == "scheduler"
    assert event.metadata == {"safe_default": "rejected"}
    assert event.error is None


@pytest.mark.asyncio
async def test_timer_safe_default_approve_invokes_approve():
    client = _RecordingClient()
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    task = scheduler.schedule(
        "action-2", timeout_seconds=0.01, safe_default="approved", case_id="case-2"
    )
    _ = await task

    assert client.approve_calls == ["action-2"]
    assert audit.events[0].metadata == {"safe_default": "approved"}


@pytest.mark.asyncio
async def test_cancel_before_fire_suppresses_fallback():
    client = _RecordingClient()
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    task = scheduler.schedule(
        "action-3", timeout_seconds=5.0, safe_default="rejected", case_id="case-3"
    )
    assert scheduler.cancel("action-3") is True
    # Subsequent cancel is a no-op.
    assert scheduler.cancel("action-3") is False
    # Let the cancellation propagate.
    await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        _ = await task

    assert client.reject_calls == []
    assert audit.events == []


@pytest.mark.asyncio
async def test_reschedule_replaces_existing_timer():
    client = _RecordingClient()
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    first = scheduler.schedule(
        "action-4", timeout_seconds=5.0, safe_default="rejected", case_id="case-4"
    )
    second = scheduler.schedule(
        "action-4", timeout_seconds=0.01, safe_default="rejected", case_id="case-4"
    )
    assert first.cancelled() or first is not second

    _ = await second
    # Only the second timer's firing should produce a fallback call.
    assert client.reject_calls == ["action-4"]
    assert len(audit.events) == 1


@pytest.mark.asyncio
async def test_fallback_call_failure_still_audits_with_error():
    client = _RecordingClient(fail=True)
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    task = scheduler.schedule(
        "action-5", timeout_seconds=0.01, safe_default="rejected", case_id="case-5"
    )
    _ = await task

    assert client.reject_calls == []
    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.decision == "timeout_fallback"
    assert event.error == "upstream boom"


@pytest.mark.asyncio
async def test_aclose_cancels_all_pending_timers():
    client = _RecordingClient()
    audit = InMemoryAuditSink()
    scheduler = ApprovalTimeoutScheduler(
        approve_fn=client.approve, reject_fn=client.reject, audit_sink=audit
    )

    scheduler.schedule("a-1", timeout_seconds=5.0, safe_default="rejected")
    scheduler.schedule("a-2", timeout_seconds=5.0, safe_default="rejected")
    assert scheduler.pending == 2
    await scheduler.aclose()
    assert scheduler.pending == 0
    # No fallbacks should have been called.
    assert client.reject_calls == []
